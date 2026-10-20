package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/opswhisperer/eh-k8s-console/internal/alerts"
	"github.com/opswhisperer/eh-k8s-console/internal/apply"
	"github.com/opswhisperer/eh-k8s-console/internal/auth"
	"github.com/opswhisperer/eh-k8s-console/internal/certs"
	"github.com/opswhisperer/eh-k8s-console/internal/config"
	"github.com/opswhisperer/eh-k8s-console/internal/discovery"
	"github.com/opswhisperer/eh-k8s-console/internal/ignore"
	"github.com/opswhisperer/eh-k8s-console/internal/logs"
	"github.com/opswhisperer/eh-k8s-console/internal/testfix"
)

type harness struct {
	srv                 *httptest.Server
	kube                *fake.Clientset
	admin, viewer, oper string
	scanner             *Scanner
}

func newHarness(t *testing.T, mutate func(*config.Config)) *harness {
	t.Helper()
	dir := t.TempDir()
	adminKey, adminHash := auth.NewAPIKey()
	viewKey, viewHash := auth.NewAPIKey()
	opKey, opHash := auth.NewAPIKey()
	keys := filepath.Join(dir, "keys.yaml")
	os.WriteFile(keys, []byte("- {name: a, hash: "+adminHash+", role: admin}\n- {name: v, hash: "+viewHash+", role: viewer}\n- {name: o, hash: "+opHash+", role: operator}\n"), 0o600)

	cfg := config.Default()
	cfg.Auth.Modes = []string{"apikey"}
	cfg.Auth.APIKeys.File = keys
	if mutate != nil {
		mutate(cfg)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := auth.New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	kube := testfix.Clientset(t, testfix.Options{})
	eng := &apply.Engine{Kube: kube, Namespace: testfix.NS, Prefix: testfix.Prefix, HistoryKeep: 5, Log: log}
	eng.ValidateOpts.Prefix, eng.ValidateOpts.ListSep = testfix.Prefix, ","
	lr := &logs.Reader{Kube: kube, Namespace: testfix.NS}
	noNet := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("no network in tests")
	}
	sc := &Scanner{Cfg: cfg, Clients: discovery.Clients{Kube: kube}, Logs: nil, Engine: eng, Collector: alerts.NewCollector(), Log: log, Dial: noNet, SkipNetwork: true}
	sc.Scan(context.Background())
	s := &Server{Cfg: cfg, Auth: a, Scanner: sc, Engine: eng, Logs: lr, Log: log, Version: "test",
		Static: fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>console</title>")}}}
	h := &harness{srv: httptest.NewServer(s.Handler()), kube: kube, admin: adminKey, viewer: viewKey, oper: opKey, scanner: sc}
	t.Cleanup(h.srv.Close)
	return h
}

func (h *harness) do(t *testing.T, key, method, path string, body any, out any) int {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if out != nil {
		json.NewDecoder(res.Body).Decode(out)
	}
	return res.StatusCode
}

func TestStateSettingsAndStatic(t *testing.T) {
	h := newHarness(t, nil)
	if code := h.do(t, "", "GET", "/api/state", nil, nil); code != 401 {
		t.Fatalf("anonymous state = %d", code)
	}
	var st map[string]any
	if code := h.do(t, h.viewer, "GET", "/api/state", nil, &st); code != 200 {
		t.Fatalf("state = %d", code)
	}
	if st["certs"].(map[string]any)["state"] != "UNREACHABLE" {
		t.Fatalf("cert state = %v", st["certs"])
	}
	var settings struct {
		Settings []struct {
			Key       string   `json:"key"`
			Value     string   `json:"value"`
			Consumers []string `json:"consumers"`
		} `json:"settings"`
		Secrets []map[string]any `json:"secrets"`
	}
	h.do(t, h.viewer, "GET", "/api/settings", nil, &settings)
	if len(settings.Settings) < 10 || len(settings.Secrets) != 3 {
		t.Fatalf("settings = %+v", settings)
	}
	for _, sec := range settings.Secrets {
		for k, v := range sec {
			if s, ok := v.(string); ok && strings.Contains(s, "test-api-key") {
				t.Fatalf("secret value exposed in %s", k)
			}
		}
	}
	res, _ := http.Get(h.srv.URL + "/")
	if res.StatusCode != 200 || !strings.Contains(res.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("static = %d csp=%q", res.StatusCode, res.Header.Get("Content-Security-Policy"))
	}
	if code := h.do(t, "", "GET", "/healthz", nil, nil); code != 200 {
		t.Fatalf("healthz = %d", code)
	}
}

func TestPlanApplyWithHashAndRoles(t *testing.T) {
	h := newHarness(t, nil)
	change := apply.Change{Config: map[string]string{"skipNamespaces": "apps"}, Reason: "quiet apps"}
	var plan struct {
		Hash         string          `json:"hash"`
		RequiredRole string          `json:"requiredRole"`
		Restarts     []apply.Restart `json:"restarts"`
	}
	if code := h.do(t, h.viewer, "POST", "/api/plan", change, &plan); code != 200 || plan.Hash == "" {
		t.Fatalf("plan = %d %+v", code, plan)
	}
	if plan.RequiredRole != "admin" || len(plan.Restarts) != 1 {
		t.Fatalf("plan = %+v", plan)
	}
	if code := h.do(t, h.oper, "POST", "/api/apply", map[string]any{"change": change, "hash": plan.Hash}, nil); code != 403 {
		t.Fatalf("operator apply of a filtering change = %d, want 403", code)
	}
	if code := h.do(t, h.admin, "POST", "/api/apply", map[string]any{"change": change, "hash": "stale"}, nil); code != 409 {
		t.Fatalf("stale hash = %d, want 409", code)
	}
	var res apply.Result
	if code := h.do(t, h.admin, "POST", "/api/apply", map[string]any{"change": change, "hash": plan.Hash}, &res); code != 200 || res.Revision != 1 {
		t.Fatalf("apply = %d %+v", code, res)
	}
	cm, _ := h.kube.CoreV1().ConfigMaps(testfix.NS).Get(context.Background(), testfix.CM, metav1.GetOptions{})
	if cm.Data["skipNamespaces"] != "apps" {
		t.Fatal("ConfigMap not changed")
	}
	var hist []apply.Summary
	h.do(t, h.viewer, "GET", "/api/history", nil, &hist)
	if len(hist) != 1 || hist[0].User != "apikey:a" {
		t.Fatalf("history = %+v", hist)
	}
	// Operators can restart workloads.
	restart := apply.Change{Restart: []string{testfix.Prefix + "metadata-forwarder"}}
	h.do(t, h.oper, "POST", "/api/plan", restart, &plan)
	if code := h.do(t, h.oper, "POST", "/api/apply", map[string]any{"change": restart, "hash": plan.Hash, "kind": "restart"}, nil); code != 200 {
		t.Fatalf("operator restart = %d", code)
	}
}

func TestReadOnlyRefusesApply(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.ReadOnly = true })
	change := apply.Change{Config: map[string]string{"clusterName": "x"}}
	var plan struct{ Hash string }
	h.do(t, h.admin, "POST", "/api/plan", change, &plan)
	if code := h.do(t, h.admin, "POST", "/api/apply", map[string]any{"change": change, "hash": plan.Hash}, nil); code != 403 {
		t.Fatalf("read-only apply = %d", code)
	}
}

func TestPolicyEndpoints(t *testing.T) {
	peers := map[string]any{
		"config": map[string]string{"kubernetesNamespacedTrafficRule": "skip"},
		"peers":  []map[string]string{{"kind": "pod", "namespace": "apps"}, {"kind": "external"}},
	}
	h := newHarness(t, nil)
	var pol map[string]any
	if code := h.do(t, h.viewer, "GET", "/api/policy", nil, &pol); code != 200 || pol["mode"] != "all-except" || pol["preview"] != false {
		t.Fatalf("policy without an order = %d mode=%v preview=%v", code, pol["mode"], pol["preview"])
	}
	if code := h.do(t, h.viewer, "POST", "/api/policy/evaluate", peers, nil); code != 400 {
		t.Fatalf("evaluate without an order = %d, want 400", code)
	}

	h = newHarness(t, func(c *config.Config) {
		c.Policy.Order = []string{"namespace:mirror-list", "namespace:rule", "cluster:rule"}
	})
	var d struct {
		Mirror bool
		Rule   int
		Step   string
	}
	h.do(t, h.viewer, "POST", "/api/policy/evaluate", peers, &d)
	if d.Mirror || d.Step != "namespace:rule" || d.Rule != 2 {
		t.Fatalf("evaluate = %+v", d)
	}
	h.do(t, h.viewer, "GET", "/api/policy", nil, &pol)
	if pol["preview"] != true || pol["namespaces"] == nil {
		t.Fatalf("policy with an order = %v", pol)
	}
	if code := h.do(t, h.oper, "POST", "/api/annotate", map[string]any{"targets": []map[string]string{{"kind": "Node", "name": "n1"}}, "rule": "skip"}, nil); code != 400 {
		t.Fatalf("annotate with feature off = %d, want 400", code)
	}
}

func TestScanTimesOutQuickly(t *testing.T) {
	h := newHarness(t, nil)
	start := time.Now()
	h.scanner.Scan(context.Background())
	if time.Since(start) > 3*time.Second {
		t.Fatal("scan too slow with an unreachable sensor")
	}
}

func TestIgnoreRuleEndpoints(t *testing.T) {
	h := newHarness(t, nil)
	h.scanner.Ignore = ignore.NewStore(h.kube, testfix.NS, "eh-k8s-console-ignore", []string{"^from config$"}, false)
	rule := map[string]string{"pattern": "^stopped reading packets on cali<id>: packet poll failed$", "note": "interface churn"}
	if code := h.do(t, h.viewer, "POST", "/api/ignore", rule, nil); code != 403 {
		t.Fatalf("viewer add = %d, want 403", code)
	}
	var test struct {
		Valid bool
		Error string
	}
	h.do(t, h.viewer, "POST", "/api/ignore/test", map[string]string{"pattern": ".*"}, &test)
	if test.Valid || test.Error == "" {
		t.Fatalf("catch-all pattern must be reported invalid: %+v", test)
	}
	if code := h.do(t, h.oper, "POST", "/api/ignore", rule, nil); code != 200 {
		t.Fatalf("operator add = %d", code)
	}
	var list struct {
		Rules []struct {
			Pattern, Source, CreatedBy string
		}
	}
	h.do(t, h.viewer, "GET", "/api/ignore", nil, &list)
	if len(list.Rules) != 2 || list.Rules[0].Source != "config" || list.Rules[1].CreatedBy != "apikey:o" {
		t.Fatalf("rules = %+v", list.Rules)
	}
	if code := h.do(t, h.oper, "POST", "/api/ignore/remove", map[string]string{"pattern": "^from config$"}, nil); code != 400 {
		t.Fatalf("removing a config rule = %d, want 400", code)
	}
	if code := h.do(t, h.oper, "POST", "/api/ignore/remove", map[string]string{"pattern": rule["pattern"]}, nil); code != 200 {
		t.Fatalf("remove = %d", code)
	}
}

func TestSecurityGuards(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Integration.Annotations.Enabled = true })
	// Viewers and operators can't probe secret values through plans.
	secret := map[string]any{"secrets": []map[string]string{{"name": testfix.Prefix + "sensor-api-credentials", "key": "apiKey", "value": "guess"}}}
	if code := h.do(t, h.oper, "POST", "/api/plan", secret, nil); code != 403 {
		t.Fatalf("operator planning a secret = %d, want 403", code)
	}
	if code := h.do(t, h.admin, "POST", "/api/plan", secret, nil); code != 200 {
		t.Fatalf("admin planning a secret = %d", code)
	}
	// Bodies must be JSON (text/plain is the browser's preflight-free CSRF route).
	req, _ := http.NewRequest("POST", h.srv.URL+"/api/plan", strings.NewReader(`{"config":{"clusterName":"x"}}`))
	req.Header.Set("Authorization", "Bearer "+h.admin)
	req.Header.Set("Content-Type", "text/plain")
	if res, _ := http.DefaultClient.Do(req); res.StatusCode != 400 {
		t.Fatalf("text/plain body = %d, want 400", res.StatusCode)
	}
	// The pod picker can't list the whole cluster.
	if code := h.do(t, h.viewer, "GET", "/api/pods", nil, nil); code != 400 {
		t.Fatalf("pods without namespace = %d, want 400", code)
	}
}

func TestLogStreamLimits(t *testing.T) {
	s := &Server{}
	var releases []func()
	for i := 0; i < maxStreamsPerUser; i++ {
		r, err := s.openStream("u")
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, r)
	}
	if _, err := s.openStream("u"); err == nil {
		t.Fatal("per-user stream limit not enforced")
	}
	releases[0]()
	if _, err := s.openStream("u"); err != nil {
		t.Fatal("released slot not reusable")
	}
}

// fakeSensor serves a TLS chain (leaf for sensor.example.com issued by an intermediate) and
// returns a dialer that sends every connection to it, plus PEMs for building bundles.
func fakeSensor(t *testing.T) (dial func(context.Context, string, string) (net.Conn, error), roots *x509.CertPool, caChain, attacker string) {
	t.Helper()
	mk := func(cn string, parent *x509.Certificate, pkey *ecdsa.PrivateKey, ca bool, dns ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), IsCA: ca, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: dns}
		signer, sk := tmpl, k
		if parent != nil {
			signer, sk = parent, pkey
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &k.PublicKey, sk)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, k
	}
	root, rk := mk("Root", nil, nil, true)
	inter, ik := mk("Issuing", root, rk, true)
	leaf, lk := mk("sensor.example.com", inter, ik, false, "sensor.example.com")
	evil, _ := mk("Attacker CA", nil, nil, true)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw, inter.Raw}, PrivateKey: lk}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = c.(*tls.Conn).Handshake(); c.Close() }(c)
		}
	}()
	pool := x509.NewCertPool()
	pool.AddCert(root)
	d := &net.Dialer{}
	dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, ln.Addr().String())
	}
	return dial, pool, certs.EncodeBundle([]*x509.Certificate{inter, root}), certs.EncodeBundle([]*x509.Certificate{inter, root, evil})
}

func TestOperatorCannotPlantACertificate(t *testing.T) {
	h := newHarness(t, nil)
	dial, roots, caChain, withAttacker := fakeSensor(t)
	h.scanner.Dial, h.scanner.Roots = dial, roots
	apply := func(key, pemData string, force bool) int {
		change := map[string]any{"config": map[string]string{"sensorCert": pemData}, "force": force}
		var plan struct{ Hash string }
		h.do(t, h.admin, "POST", "/api/plan", change, &plan)
		return h.do(t, key, "POST", "/api/apply", map[string]any{"change": change, "hash": plan.Hash, "kind": "cert-refresh"}, nil)
	}
	if code := apply(h.oper, withAttacker, false); code != 403 {
		t.Fatalf("operator adding a foreign CA = %d, want 403", code)
	}
	if code := apply(h.oper, caChain, false); code != 200 {
		t.Fatalf("operator storing the sensor's own CA chain = %d, want 200", code)
	}
	unrelated := withAttacker[strings.LastIndex(withAttacker, "-----BEGIN CERTIFICATE-----"):]
	if code := apply(h.admin, unrelated, false); code != 400 {
		t.Fatalf("admin storing a bundle that doesn't trust the sensor = %d, want 400", code)
	}
}
