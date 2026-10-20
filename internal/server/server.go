// Package server wires the scan loop, apply engine, logs and auth into the HTTP API and UI.
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/opswhisperer/eh-k8s-console/internal/alerts"
	"github.com/opswhisperer/eh-k8s-console/internal/apply"
	"github.com/opswhisperer/eh-k8s-console/internal/auth"
	"github.com/opswhisperer/eh-k8s-console/internal/certs"
	"github.com/opswhisperer/eh-k8s-console/internal/config"
	"github.com/opswhisperer/eh-k8s-console/internal/discovery"
	"github.com/opswhisperer/eh-k8s-console/internal/ignore"
	"github.com/opswhisperer/eh-k8s-console/internal/logs"
	"github.com/opswhisperer/eh-k8s-console/internal/model"
	"github.com/opswhisperer/eh-k8s-console/internal/policy"
	"github.com/opswhisperer/eh-k8s-console/internal/validate"
)

type Server struct {
	Cfg      *config.Config
	Auth     *auth.Auth
	Scanner  *Scanner
	Engine   *apply.Engine
	Logs     *logs.Reader
	Notifier *alerts.Notifier
	Static   fs.FS
	Log      *slog.Logger
	Version  string

	streamMu sync.Mutex
	streams  map[string]int // open log streams per identity
}

// Limits on what one request can make the console hold in memory.
const (
	maxStreamsPerUser = 3
	maxStreamsTotal   = 25
	maxLogSince       = 24 * time.Hour
	maxFetchLines     = 100000
	fetchBytesPerPod  = 2 << 20
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func decode(r *http.Request, v any) error {
	if !auth.IsJSON(r) {
		return errors.New("send the body as JSON with Content-Type: application/json")
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("bad request body: %w", err)
	}
	return nil
}

func who(r *http.Request) string {
	if id := auth.From(r.Context()); id != nil {
		return id.User
	}
	return "unknown"
}

// Handler returns the full HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	a := s.Auth
	a.Routes(mux)
	v, o, ad := auth.Viewer, auth.Operator, auth.Admin

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /api/info", s.handleInfo)

	mux.HandleFunc("GET /api/state", a.Require(v, s.handleState))
	mux.HandleFunc("POST /api/scan", a.Require(o, s.handleScan))
	mux.HandleFunc("GET /api/settings", a.Require(v, s.handleSettings))
	mux.HandleFunc("POST /api/plan", a.Require(v, s.handlePlan))
	mux.HandleFunc("POST /api/apply", a.Require(o, s.handleApply))
	mux.HandleFunc("GET /api/rollout", a.Require(v, s.handleRollout))
	mux.HandleFunc("GET /api/history", a.Require(v, s.handleHistory))
	mux.HandleFunc("GET /api/history/{n}", a.Require(v, s.handleRevision))
	mux.HandleFunc("POST /api/history/{n}/rollback", a.Require(v, s.handleRollbackPlan))

	mux.HandleFunc("GET /api/certs", a.Require(v, s.handleCerts))
	mux.HandleFunc("POST /api/certs/probe", a.Require(o, s.handleCertProbe))
	mux.HandleFunc("POST /api/certs/candidate", a.Require(o, s.handleCertCandidate))

	mux.HandleFunc("GET /api/logs/stream", a.Require(v, s.handleLogStream))
	mux.HandleFunc("GET /api/logs", a.Require(v, s.handleLogFetch))
	mux.HandleFunc("GET /api/events", a.Require(v, s.handleEvents))
	mux.HandleFunc("GET /api/ignore", a.Require(v, s.handleIgnoreList))
	mux.HandleFunc("POST /api/ignore/test", a.Require(v, s.handleIgnoreTest))
	mux.HandleFunc("POST /api/ignore", a.Require(o, s.handleIgnoreAdd))
	mux.HandleFunc("POST /api/ignore/remove", a.Require(o, s.handleIgnoreRemove))

	mux.HandleFunc("GET /api/policy", a.Require(v, s.handlePolicy))
	mux.HandleFunc("POST /api/policy/evaluate", a.Require(v, s.handleEvaluate))
	mux.HandleFunc("GET /api/annotations", a.Require(v, s.handleAnnotations))
	mux.HandleFunc("GET /api/pods", a.Require(v, s.handlePods))
	mux.HandleFunc("GET /api/nodes", a.Require(v, s.handleNodes))
	mux.HandleFunc("POST /api/annotate", a.Require(o, s.handleAnnotate))

	mux.HandleFunc("GET /api/export/helm-values", a.Require(v, s.handleExportHelm))
	mux.HandleFunc("GET /api/export/manifests", a.Require(v, s.handleExportManifests))
	mux.HandleFunc("POST /api/export", a.Require(v, s.handleExportProposed))
	mux.HandleFunc("POST /api/alerts/test", a.Require(ad, s.handleAlertTest))

	if s.Static != nil {
		files := http.FileServerFS(s.Static)
		mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The policy goes on the page only: the brand SVGs carry their own <style>, which a
			// policy sent with them would block. Source Sans 3 (ExtraHop's typeface) comes from
			// Google Fonts.
			if r.URL.Path == "/" || strings.HasSuffix(r.URL.Path, ".html") {
				w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
			}
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "same-origin")
			files.ServeHTTP(w, r)
		}))
	}
	return a.Middleware(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	st := s.Scanner.Latest()
	if st != nil && time.Since(st.At) > 3*s.Cfg.ScanInterval.Duration+time.Minute {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "scan loop stalled"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.Scanner.Latest() == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "first scan pending"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"version": s.Version, "readOnly": s.Cfg.ReadOnly, "namespace": s.Cfg.Integration.Namespace,
		"annotations": s.Cfg.Integration.Annotations.Enabled, "autoSync": s.Cfg.Certs.AutoSync, "certSource": s.Cfg.Certs.Source != nil,
		"webhooks": len(s.Cfg.Alerts.Webhooks)})
}

// ---- state & settings ----

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	st := s.Scanner.Latest()
	if st == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "first scan still running"})
		return
	}
	out := map[string]any{"at": st.At, "durationMs": st.Duration.Milliseconds(), "error": st.Err, "findings": st.Findings,
		"counts": st.Counts(), "certs": st.Certs, "logs": st.Logs, "ignoredLogs": st.IgnoredLogs, "readOnly": s.Cfg.ReadOnly}
	if s.Notifier != nil {
		out["notifyErrors"] = s.Notifier.Errors()
	}
	if snap := st.Snap; snap != nil {
		out["workloads"] = snap.Workloads
		out["secrets"] = snap.Secrets
		out["helm"] = snap.Helm
		out["configMapFound"] = snap.ConfigMapFound
		out["namespace"] = snap.Namespace
		p := policy.FromConfig(snap.ConfigData)
		out["policy"] = map[string]any{"policy": p, "mode": policy.DetectMode(p)}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	st := s.Scanner.Scan(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"at": st.At, "counts": st.Counts()})
}

type settingView struct {
	model.Setting
	Value     string          `json:"value"`
	Present   bool            `json:"present"`
	Consumers []string        `json:"consumers"`
	SetBy     []discovery.Ref `json:"setBy"`
	Linked    []discovery.Ref `json:"linked,omitempty"`
	Certs     []certs.Info    `json:"certs,omitempty"`
	Problems  []string        `json:"problems,omitempty"`
	Options   []string        `json:"options,omitempty"`
}

type secretView struct {
	model.SecretSetting
	Name           string                    `json:"name"`
	Exists         bool                      `json:"exists"`
	Length         int                       `json:"length"`
	ManagedBy      string                    `json:"managedBy,omitempty"`
	ExternalSecret *discovery.ExternalSecret `json:"externalSecret,omitempty"`
	Consumers      []string                  `json:"consumers"`
	// PairOK: for a key pair, whether this private key matches the ConfigMap's public key
	// (nil when it could not be checked).
	PairOK *bool `json:"pairOK,omitempty"`
}

type imageView struct {
	Workload  string `json:"workload"`
	Component string `json:"component"`
	Container string `json:"container"`
	Image     string `json:"image"`
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Scanner.Snapshot(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	var settings []settingView
	for _, st := range model.Settings {
		v, ok := snap.ConfigData[st.Key]
		sv := settingView{Setting: st, Value: v, Present: ok, Consumers: discovery.WorkloadsUsing(snap.Consumers(st.Key)), SetBy: snap.Consumers(st.Key)}
		for _, la := range model.LinkedArgs {
			if la.Setting == st.Key {
				sv.Linked = append(sv.Linked, snap.ArgRefs(la.Flag)...)
			}
		}
		if st.Type == model.TypePEM {
			cs, problems := certs.ParseBundle(v)
			sv.Certs, sv.Problems = certs.DescribeAll(cs, time.Now()), problems
		}
		if st.Type == model.TypeNSList {
			sv.Options = snap.Namespaces
		}
		settings = append(settings, sv)
	}
	var secrets []secretView
	for _, ss := range model.Secrets {
		name := ss.SecretName(s.Cfg.Integration.Prefix)
		sv := secretView{SecretSetting: ss, Name: name, Consumers: discovery.WorkloadsUsing(snap.SecretConsumers(name, ss.Key))}
		if si := snap.Secret(name); si != nil {
			sv.Exists, sv.Length, sv.ManagedBy, sv.ExternalSecret = si.Exists, si.Keys[ss.Key], si.ManagedBy, si.ExternalSecret
			if ss.PublicKey != "" && si.Exists {
				if pub, err := model.DecodeKey(snap.ConfigData[ss.PublicKey]); err == nil {
					switch validate.KeyPairMatches(si.Value(ss.Key), pub) {
					case validate.PairMatch:
						ok := true
						sv.PairOK = &ok
					case validate.PairMismatch:
						bad := false
						sv.PairOK = &bad
					}
				}
			}
		}
		secrets = append(secrets, sv)
	}
	var images []imageView
	for _, wl := range snap.Workloads {
		for _, c := range wl.PodSpec.Containers {
			images = append(images, imageView{wl.Name, wl.Component, c.Name, c.Image})
		}
	}
	p := policy.FromConfig(snap.ConfigData)
	writeJSON(w, http.StatusOK, map[string]any{"settings": settings, "groups": model.Groups, "secrets": secrets, "images": images,
		"listSeparator": s.Cfg.Integration.ListSeparator, "modes": policy.Modes, "mode": policy.DetectMode(p),
		"helm": snap.Helm, "readOnly": s.Cfg.ReadOnly, "configMapFound": snap.ConfigMapFound})
}

// ---- plan / apply ----

func planHash(p *apply.Plan) string {
	b, _ := json.Marshal(struct {
		C []apply.FieldChange
		R []apply.Restart
	}{p.Changes, p.Restarts})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

type planResponse struct {
	*apply.Plan
	Hash         string `json:"hash"`
	RequiredRole string `json:"requiredRole"`
}

// requiredRole: operators may refresh the sensor certificate and restart workloads; everything
// else, and forcing past blocks, needs admin.
func requiredRole(ch apply.Change) string {
	if ch.Force || len(ch.Secrets) > 0 || len(ch.Images) > 0 || len(ch.Args) > 0 || len(ch.Remove) > 0 {
		return auth.Admin
	}
	for k := range ch.Config {
		if k != "sensorCert" {
			return auth.Admin
		}
	}
	return auth.Operator
}

func (s *Server) plan(ctx context.Context, ch apply.Change) (*apply.Plan, error) {
	return s.planFrom(ctx, ch, false)
}

// planFrom plans against the shared snapshot, or a fresh one (apply must see the live state).
func (s *Server) planFrom(ctx context.Context, ch apply.Change, fresh bool) (*apply.Plan, error) {
	get := s.Scanner.Snapshot
	if fresh {
		get = s.Scanner.FreshSnapshot
	}
	snap, err := get(ctx)
	if err != nil {
		return nil, err
	}
	return s.Engine.Plan(snap, ch)
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	var ch apply.Change
	if err := decode(r, &ch); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	// A plan reveals whether a proposed secret equals the stored one ("no change"), so only
	// admins, who may set secrets anyway, can plan secret changes.
	if len(ch.Secrets) > 0 && !auth.From(r.Context()).Can(auth.Admin) {
		writeErr(w, http.StatusForbidden, errors.New("planning Secret changes needs the admin role"))
		return
	}
	p, err := s.plan(r.Context(), ch)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, planResponse{p, planHash(p), requiredRole(ch)})
}

type applyRequest struct {
	Change apply.Change `json:"change"`
	// Hash is the plan hash the user reviewed; the apply is refused if the plan changed since.
	Hash string `json:"hash"`
	Kind string `json:"kind,omitempty"`
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	if s.Cfg.ReadOnly {
		writeErr(w, http.StatusForbidden, errors.New("this console is read-only (readOnly: true)"))
		return
	}
	var req applyRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if role := requiredRole(req.Change); !auth.From(r.Context()).Can(role) {
		writeErr(w, http.StatusForbidden, fmt.Errorf("this change needs the %s role", role))
		return
	}
	p, err := s.planFrom(r.Context(), req.Change, true)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if pemData, ok := req.Change.Config["sensorCert"]; ok {
		if code, err := s.checkCertChange(r.Context(), pemData, auth.From(r.Context()), req.Change.Force); err != nil {
			writeErr(w, code, err)
			return
		}
	}
	if req.Hash == "" || planHash(p) != req.Hash {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "the cluster changed since you reviewed this change; review it again", "plan": planResponse{p, planHash(p), requiredRole(req.Change)}})
		return
	}
	kind := "apply"
	switch req.Kind {
	case "rollback", "cert-refresh", "restart":
		kind = req.Kind
	}
	res, err := s.Engine.Apply(r.Context(), p, who(r), kind)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "result": res})
		return
	}
	go s.Scanner.Scan(context.WithoutCancel(r.Context()))
	writeJSON(w, http.StatusOK, res)
}

// checkCertChange enforces on the server what the UI only suggests: a new sensorCert must trust the
// sensor's current certificate (admins may force past that), and an operator may store only
// certificates the sensor itself presents or that verified its chain, never an arbitrary anchor.
func (s *Server) checkCertChange(ctx context.Context, pemData string, id *auth.Identity, force bool) (int, error) {
	snap, err := s.Scanner.FreshSnapshot(ctx)
	if err != nil {
		return http.StatusBadGateway, err
	}
	a := s.Scanner.ProbeCerts(ctx, snap)
	admin := id.Can(auth.Admin)
	if err := certs.VerifyCandidate(pemData, a.Probe, SensorName(snap.ConfigData), time.Now()); err != nil && !(admin && force) {
		return http.StatusBadRequest, fmt.Errorf("refused: %w", err)
	}
	if a.Probe == nil || len(a.Probe.Chain) == 0 {
		if admin && force {
			return 0, nil
		}
		return http.StatusBadRequest, errors.New("refused: the sensor could not be probed, so the bundle can't be checked (an admin can force it)")
	}
	if admin {
		return 0, nil
	}
	allowed := map[string]bool{}
	for _, c := range a.Probe.Chain {
		allowed[c.SHA256] = true
	}
	for _, mode := range []string{certs.ModeCAChain, certs.ModeFullChain} {
		if b, err := certs.BuildBundle(a, mode); err == nil {
			cs, _ := certs.ParseBundle(b)
			for _, c := range cs {
				allowed[certs.Fingerprint(c)] = true
			}
		}
	}
	cs, _ := certs.ParseBundle(pemData)
	for _, c := range cs {
		if !allowed[certs.Fingerprint(c)] {
			return http.StatusForbidden, fmt.Errorf("operators can store only certificates the sensor presents (or the root that verified them); %s isn't one. An admin can apply this bundle", c.Subject)
		}
	}
	return 0, nil
}

func (s *Server) handleRollout(w http.ResponseWriter, r *http.Request) {
	names := strings.Split(r.URL.Query().Get("names"), ",")
	writeJSON(w, http.StatusOK, s.Engine.Rollouts(r.Context(), names))
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	h, err := s.Engine.History(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) handleRevision(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	rev, err := s.Engine.Revision(r.Context(), n)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, rev)
}

func (s *Server) handleRollbackPlan(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	rev, err := s.Engine.Revision(r.Context(), n)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	snap, err := s.Scanner.Snapshot(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	ch := apply.RollbackChange(snap, rev)
	p, err := s.Engine.Plan(snap, ch)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"change": ch, "plan": planResponse{p, planHash(p), auth.Admin}})
}

// ---- certificates ----

func (s *Server) handleCerts(w http.ResponseWriter, r *http.Request) {
	st := s.Scanner.Latest()
	if st == nil || st.Certs == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("no certificate assessment yet"))
		return
	}
	writeJSON(w, http.StatusOK, st.Certs)
}

func (s *Server) handleCertProbe(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Scanner.Snapshot(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, s.Scanner.ProbeCerts(r.Context(), snap))
}

type candidateRequest struct {
	// Mode ca-chain | full-chain builds from a fresh probe; PEM uses pasted certificates.
	Mode string `json:"mode,omitempty"`
	PEM  string `json:"pem,omitempty"`
}

// handleCertCandidate builds a new sensorCert value and checks it would trust the sensor. The
// user then reviews it as a normal plan (sensorCert change) before applying.
func (s *Server) handleCertCandidate(w http.ResponseWriter, r *http.Request) {
	var req candidateRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	snap, err := s.Scanner.Snapshot(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	a := s.Scanner.ProbeCerts(r.Context(), snap)
	pemOut := req.PEM
	if pemOut == "" {
		pemOut, err = certs.BuildBundle(a, req.Mode)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	cs, problems := certs.ParseBundle(pemOut)
	verr := certs.VerifyCandidate(pemOut, a.Probe, SensorName(snap.ConfigData), time.Now())
	out := map[string]any{"pem": pemOut, "certs": certs.DescribeAll(cs, time.Now()), "problems": problems, "probe": a.Probe, "trusts": verr == nil}
	if verr != nil {
		out["error"] = verr.Error()
	}
	if a.Probe == nil || a.Probe.Error != "" {
		out["warning"] = "The sensor could not be probed, so this bundle could not be checked against it."
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- logs ----

func (s *Server) logTargets(ctx context.Context, q map[string][]string) ([]logs.Target, error) {
	snap, err := s.Scanner.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	var out []logs.Target
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	comp, podName, node := get("component"), get("pod"), get("node")
	for _, t := range logs.Targets(snap) {
		if comp != "" && t.Component != comp || podName != "" && t.Pod != podName || node != "" && t.Node != node {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

func durationParam(v string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	return def
}

func (s *Server) handleLogStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}
	targets, err := s.logTargets(r.Context(), r.URL.Query())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	tail := s.Cfg.Logs.TailLines
	if n, err := strconv.ParseInt(r.URL.Query().Get("tail"), 10, 64); err == nil && n >= 0 && n <= 5000 {
		tail = n
	}
	release, err := s.openStream(who(r))
	if err != nil {
		writeErr(w, http.StatusTooManyRequests, err)
		return
	}
	defer release()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ctx := r.Context()
	lines := s.Logs.Follow(ctx, targets, logs.FollowOptions{TailLines: tail, Previous: r.URL.Query().Get("previous") == "true"})
	keep := time.NewTicker(20 * time.Second)
	defer keep.Stop()
	fmt.Fprintf(w, "event: targets\ndata: %d\n\n", len(targets))
	fl.Flush()
	for {
		select {
		case <-ctx.Done():
			return
		case <-keep.C:
			fmt.Fprint(w, ": keep-alive\n\n")
			fl.Flush()
		case l, ok := <-lines:
			if !ok {
				fmt.Fprint(w, "event: end\ndata: {}\n\n")
				fl.Flush()
				return
			}
			b, _ := json.Marshal(l)
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		}
	}
}

// openStream admits a log stream if the caller and the server are under their limits.
func (s *Server) openStream(user string) (func(), error) {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	if s.streams == nil {
		s.streams = map[string]int{}
	}
	total := 0
	for _, n := range s.streams {
		total += n
	}
	if s.streams[user] >= maxStreamsPerUser {
		return nil, fmt.Errorf("you already have %d live log streams open; close one first", maxStreamsPerUser)
	}
	if total >= maxStreamsTotal {
		return nil, errors.New("too many live log streams are open; try again shortly")
	}
	s.streams[user]++
	return func() {
		s.streamMu.Lock()
		defer s.streamMu.Unlock()
		if s.streams[user]--; s.streams[user] <= 0 {
			delete(s.streams, user)
		}
	}, nil
}

func (s *Server) handleLogFetch(w http.ResponseWriter, r *http.Request) {
	targets, err := s.logTargets(r.Context(), r.URL.Query())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	since := durationParam(r.URL.Query().Get("since"), time.Hour)
	if since > maxLogSince {
		since = maxLogSince
	}
	lines := s.Logs.Fetch(r.Context(), targets, logs.FollowOptions{Since: since, Previous: r.URL.Query().Get("previous") == "true",
		LimitBytes: fetchBytesPerPod, MaxLines: maxFetchLines})
	if r.URL.Query().Get("format") == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="extrahop-integration-logs.txt"`)
		for _, l := range lines {
			fmt.Fprintf(w, "%s %s/%s %s\n", l.Pod, l.Component, l.Container, l.Raw)
		}
		return
	}
	writeJSON(w, http.StatusOK, lines)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Scanner.Snapshot(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	ev, err := s.Logs.Events(r.Context(), snap)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

// ---- log ignore rules ----

type ignoreMatch struct {
	Component string `json:"component"`
	Level     string `json:"level"`
	Signature string `json:"signature"`
	Count     int    `json:"count"`
	IgnoredBy string `json:"ignoredBy,omitempty"`
}

// recentSignatures returns every recurring warning/error from the last scan, hidden or not.
func (s *Server) recentSignatures() []ignoreMatch {
	st := s.Scanner.Latest()
	if st == nil {
		return nil
	}
	var out []ignoreMatch
	for _, list := range [][]validate.LogStat{st.Logs, st.IgnoredLogs} {
		for _, l := range list {
			out = append(out, ignoreMatch{l.Component, l.Level, l.Signature, l.Count, l.IgnoredBy})
		}
	}
	return out
}

// shortDuration prints 1h0m0s as 1h and 30m0s as 30m.
func shortDuration(d time.Duration) string {
	return strings.TrimSuffix(strings.TrimSuffix(d.String(), "0s"), "0m")
}

func (s *Server) handleIgnoreList(w http.ResponseWriter, r *http.Request) {
	type ruleView struct {
		ignore.Rule
		Matches []ignoreMatch `json:"matches"`
		Hidden  int           `json:"hidden"`
	}
	var rules []ruleView
	recent := s.recentSignatures()
	if s.Scanner.Ignore != nil {
		for _, rule := range s.Scanner.Ignore.Rules() {
			rv := ruleView{Rule: rule, Matches: []ignoreMatch{}}
			for _, m := range recent {
				if m.IgnoredBy == rule.Pattern {
					rv.Matches = append(rv.Matches, m)
					rv.Hidden += m.Count
				}
			}
			rules = append(rules, rv)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "window": shortDuration(s.Cfg.Logs.SignatureWindow.Duration), "readOnly": s.Cfg.ReadOnly || s.Scanner.Ignore == nil})
}

func (s *Server) handleIgnoreTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pattern string `json:"pattern"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	re, err := ignore.Validate(req.Pattern)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	matches := []ignoreMatch{}
	total := 0
	for _, m := range s.recentSignatures() {
		if re.MatchString(m.Signature) {
			matches = append(matches, m)
			total += m.Count
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "matches": matches, "total": total, "window": shortDuration(s.Cfg.Logs.SignatureWindow.Duration)})
}

func (s *Server) handleIgnoreAdd(w http.ResponseWriter, r *http.Request) {
	if s.Scanner.Ignore == nil {
		writeErr(w, http.StatusNotFound, errors.New("ignore rules are not available"))
		return
	}
	var req struct {
		Pattern string `json:"pattern"`
		Note    string `json:"note"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	rule, err := s.Scanner.Ignore.Add(r.Context(), req.Pattern, req.Note, who(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.Log.Info("ignore rule added", "user", who(r), "pattern", rule.Pattern, "note", rule.Note)
	go s.Scanner.Scan(context.WithoutCancel(r.Context()))
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) handleIgnoreRemove(w http.ResponseWriter, r *http.Request) {
	if s.Scanner.Ignore == nil {
		writeErr(w, http.StatusNotFound, errors.New("ignore rules are not available"))
		return
	}
	var req struct {
		Pattern string `json:"pattern"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.Scanner.Ignore.Remove(r.Context(), req.Pattern); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.Log.Info("ignore rule removed", "user", who(r), "pattern", req.Pattern)
	go s.Scanner.Scan(context.WithoutCancel(r.Context()))
	writeJSON(w, http.StatusOK, map[string]string{"removed": req.Pattern})
}

// ---- policy & annotations ----

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Scanner.Snapshot(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	p := policy.FromConfig(snap.ConfigData)
	order := s.order()
	rows, nodes := policy.Overview(order, p, snap.Namespaces)
	var exceptions []map[string]any
	for _, a := range snap.Annotated {
		e := map[string]any{"annotated": a}
		if len(order) > 0 {
			switch a.Kind {
			case "Pod", "Deployment", "StatefulSet", "DaemonSet":
				e["decision"] = policy.Evaluate(order, p, policy.Endpoint{Kind: policy.Pod, Namespace: a.Namespace, Name: a.Name, Annotation: a.Rule})
			case "Node":
				e["decision"] = policy.Evaluate(order, p, policy.Endpoint{Kind: policy.Node, Name: a.Name, Annotation: a.Rule})
			}
		}
		exceptions = append(exceptions, e)
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": p, "mode": policy.DetectMode(p), "modes": policy.Modes, "namespaces": rows, "nodes": nodes,
		"order": order, "preview": len(order) > 0, "annotationKinds": s.Cfg.Policy.AnnotationKinds,
		"exceptions": exceptions, "annotationsEnabled": s.Cfg.Integration.Annotations.Enabled,
		"notes": []string{policy.RestartNoteConfig, policy.RestartNoteAnnotation}})
}

type evaluateRequest struct {
	// Config optionally overrides ConfigMap values (to preview a pending change).
	Config map[string]string `json:"config,omitempty"`
	Peers  []policy.Endpoint `json:"peers"`
}

func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	var req evaluateRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Peers) == 0 || len(req.Peers) > 2 {
		writeErr(w, http.StatusBadRequest, errors.New("give one or two peers"))
		return
	}
	order := s.order()
	if len(order) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("the preview is off: set policy.order in the config"))
		return
	}
	snap, err := s.Scanner.Snapshot(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	data := map[string]string{}
	for k, v := range snap.ConfigData {
		data[k] = v
	}
	for k, v := range req.Config {
		data[k] = v
	}
	writeJSON(w, http.StatusOK, policy.Evaluate(order, policy.FromConfig(data), req.Peers...))
}

// order is the configured evaluation order (validated at start-up).
func (s *Server) order() []policy.Step {
	o, _ := policy.ParseOrder(s.Cfg.Policy.Order)
	return o
}

func (s *Server) handleAnnotations(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Scanner.Snapshot(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": s.Cfg.Integration.Annotations.Enabled, "annotated": snap.Annotated,
		"scope": s.Cfg.Integration.Annotations, "annotation": discovery.MirrorAnnotation})
}

func (s *Server) handlePods(w http.ResponseWriter, r *http.Request) {
	if !s.Cfg.Integration.Annotations.Enabled {
		writeErr(w, http.StatusNotFound, errors.New("annotation editing is disabled"))
		return
	}
	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		writeErr(w, http.StatusBadRequest, errors.New("namespace is required"))
		return
	}
	l, err := s.Scanner.Clients.Kube.CoreV1().Pods(ns).List(r.Context(), metav1.ListOptions{LabelSelector: r.URL.Query().Get("selector"), Limit: 1000})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	out := make([]pod, 0, len(l.Items))
	for i := range l.Items {
		out = append(out, podRow(&l.Items[i], s.Cfg.Integration.Annotations))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Namespace+out[i].Name < out[j].Namespace+out[j].Name })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	if !s.Cfg.Integration.Annotations.Enabled {
		writeErr(w, http.StatusNotFound, errors.New("annotation editing is disabled"))
		return
	}
	l, err := s.Scanner.Clients.Kube.CoreV1().Nodes().List(r.Context(), metav1.ListOptions{})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	type node struct {
		Name string `json:"name"`
		Rule string `json:"rule,omitempty"`
	}
	var out []node
	for _, n := range l.Items {
		out = append(out, node{n.Name, n.Annotations[discovery.MirrorAnnotation]})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAnnotate(w http.ResponseWriter, r *http.Request) {
	var req apply.AnnotateRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if s.Cfg.ReadOnly && !req.DryRun {
		writeErr(w, http.StatusForbidden, errors.New("this console is read-only (readOnly: true)"))
		return
	}
	// Annotating running pods and nodes is non-disruptive (operator). Changing workload
	// templates rolls pods in other teams' namespaces, so it needs admin.
	if req.Mode == apply.ModePersist || req.Mode == apply.ModeBoth || hasWorkloadTarget(req.Targets) {
		if !auth.From(r.Context()).Can(auth.Admin) && !req.DryRun {
			writeErr(w, http.StatusForbidden, errors.New("changing workload templates needs the admin role"))
			return
		}
	}
	res, err := s.Engine.Annotate(r.Context(), req, s.Cfg.Integration.Annotations, who(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if !req.DryRun {
		go s.Scanner.Scan(context.WithoutCancel(r.Context()))
	}
	writeJSON(w, http.StatusOK, res)
}

func hasWorkloadTarget(ts []apply.Target) bool {
	for _, t := range ts {
		if t.Kind == "Deployment" || t.Kind == "StatefulSet" || t.Kind == "DaemonSet" {
			return true
		}
	}
	return false
}

// ---- export ----

func (s *Server) handleExportHelm(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Scanner.Snapshot(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	withSecrets := r.URL.Query().Get("secrets") == "true"
	if withSecrets && !auth.From(r.Context()).Can(auth.Admin) {
		writeErr(w, http.StatusForbidden, errors.New("exporting secret values needs the admin role"))
		return
	}
	if withSecrets {
		s.Log.Info("exported Helm values with secrets", "user", who(r))
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="extrahop-kubernetes-integration-values.yaml"`)
	fmt.Fprint(w, apply.HelmValues(snap, s.Cfg.Integration.Prefix, withSecrets))
}

func (s *Server) handleExportManifests(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Scanner.Snapshot(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	out, err := apply.Manifests(snap)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="extrahop-kubernetes-integration.yaml"`)
	fmt.Fprint(w, out)
}

// handleExportProposed exports the state a pending change would produce (GitOps users).
func (s *Server) handleExportProposed(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Change apply.Change `json:"change"`
		Format string       `json:"format"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	req.Change.Secrets = nil // never exported here
	p, err := s.plan(r.Context(), req.Change)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	if req.Format == "helm" {
		fmt.Fprint(w, apply.HelmValues(p.Proposed(), s.Cfg.Integration.Prefix, false))
		return
	}
	out, err := apply.Manifests(p.Proposed())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	fmt.Fprint(w, out)
}

func (s *Server) handleAlertTest(w http.ResponseWriter, r *http.Request) {
	if s.Notifier == nil || len(s.Cfg.Alerts.Webhooks) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("no webhooks configured (alerts.webhooks)"))
		return
	}
	writeJSON(w, http.StatusOK, s.Notifier.Test(r.Context()))
}
