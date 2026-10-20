package server

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/opswhisperer/eh-k8s-console/internal/alerts"
	"github.com/opswhisperer/eh-k8s-console/internal/apply"
	"github.com/opswhisperer/eh-k8s-console/internal/certs"
	"github.com/opswhisperer/eh-k8s-console/internal/config"
	"github.com/opswhisperer/eh-k8s-console/internal/discovery"
	"github.com/opswhisperer/eh-k8s-console/internal/finding"
	"github.com/opswhisperer/eh-k8s-console/internal/ignore"
	"github.com/opswhisperer/eh-k8s-console/internal/logs"
	"github.com/opswhisperer/eh-k8s-console/internal/state"
	"github.com/opswhisperer/eh-k8s-console/internal/validate"
)

// Scanner rediscovers, probes and validates on a timer and feeds metrics and alerts.
type Scanner struct {
	Cfg       *config.Config
	Clients   discovery.Clients
	Logs      *logs.Reader
	Engine    *apply.Engine
	Collector *alerts.Collector
	Notifier  *alerts.Notifier
	Log       *slog.Logger
	// Dial and Roots are replaceable in tests.
	Dial  certs.Dialer
	Roots *x509.CertPool
	// SkipNetwork disables the DNS/TCP checks (tests).
	SkipNetwork bool
	// Ignore holds the log ignore rules (config + console-managed).
	Ignore *ignore.Store

	mu      sync.RWMutex
	last    *state.State
	running sync.Mutex
}

func (s *Scanner) Latest() *state.State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.last
}

func (s *Scanner) discoveryOptions() discovery.Options {
	i := s.Cfg.Integration
	return discovery.Options{Namespace: i.Namespace, Prefix: i.Prefix, ConfigMap: i.ConfigMap, Annotations: i.Annotations.Enabled}
}

// Snapshot takes a fresh snapshot (used before planning a change).
func (s *Scanner) Snapshot(ctx context.Context) (*discovery.Snapshot, error) {
	return discovery.Discover(ctx, s.Clients, s.discoveryOptions())
}

func (s *Scanner) validateOptions() validate.Options {
	return validate.Options{Prefix: s.Cfg.Integration.Prefix, ListSep: s.Cfg.Integration.ListSeparator, AnnotationKinds: s.Cfg.Policy.AnnotationKinds}
}

// SensorName returns the TLS name the forwarders verify.
func SensorName(d map[string]string) string {
	if n := d["serverNameOverride"]; n != "" {
		return n
	}
	return d["mgmtTarget"]
}

// ProbeCerts probes the sensor and assesses sensorCert.
func (s *Scanner) ProbeCerts(ctx context.Context, snap *discovery.Snapshot) *certs.Assessment {
	c := s.Cfg.Certs
	th := certs.Thresholds{LeafWarnDays: c.LeafWarnDays, LeafCriticalDays: c.LeafCriticalDays, AnchorWarnDays: c.AnchorWarnDays}
	var probe *certs.Probe
	if host := snap.ConfigData["mgmtTarget"]; host != "" {
		probe = certs.ProbeTLS(ctx, s.Dial, net.JoinHostPort(host, fmt.Sprint(c.ProbePort)), SensorName(snap.ConfigData), c.ProbeTimeout.Duration)
	}
	a := certs.Assess(snap.ConfigData["sensorCert"], probe, SensorName(snap.ConfigData), s.Roots, th, time.Now())

	// The session-key forwarder talks to a second port; check it presents the same certificate.
	if len(snap.ArgRefs("-server")) > 0 && probe != nil && probe.Error == "" && len(probe.Chain) > 0 {
		skp := certs.ProbeTLS(ctx, s.Dial, net.JoinHostPort(snap.ConfigData["mgmtTarget"], fmt.Sprint(c.SessionKeyPort)), SensorName(snap.ConfigData), c.ProbeTimeout.Duration)
		switch {
		case skp.Error != "":
			a.Findings = append(a.Findings, finding.Finding{Severity: finding.Info, Source: "certs", Code: "session_key_port", Setting: "mgmtTarget",
				Message: fmt.Sprintf("Could not read a certificate on the session-key port %s (%s). The port is only needed when TLS decryption is enabled on the sensor.", skp.Addr, skp.Error)})
		case len(skp.Chain) > 0 && skp.Chain[0].SHA256 != probe.Chain[0].SHA256:
			a.Findings = append(a.Findings, finding.Finding{Severity: finding.Warning, Source: "certs", Code: "session_key_cert_differs", Setting: "sensorCert",
				Message: fmt.Sprintf("The session-key port presents a different certificate (%s) from the management port (%s).", certs.ShortFP(skp.Chain[0].SHA256), certs.ShortFP(probe.Chain[0].SHA256)),
				Fix:     "Make sure sensorCert trusts both, or that the sensor uses one certificate."})
		}
	}
	return a
}

// Scan runs one full check. Only one scan runs at a time.
func (s *Scanner) Scan(ctx context.Context) *state.State {
	s.running.Lock()
	defer s.running.Unlock()
	start := time.Now()
	st := &state.State{At: start}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		st.Err = err.Error()
		st.Findings = []finding.Finding{{Severity: finding.Critical, Source: "runtime", Code: "scan_failed", Message: "Cannot read the integration: " + err.Error(),
			Fix: "Check this app's RBAC and that integration.namespace is right."}}
		s.publish(ctx, st)
		return st
	}
	st.Snap = snap
	if snap.ConfigMapFound {
		st.Certs = s.ProbeCerts(ctx, snap)
	}
	var netFindings []finding.Finding
	if !s.SkipNetwork && snap.ConfigMapFound {
		netFindings = validate.CheckNetwork(ctx, validate.Network{Timeout: s.Cfg.Certs.ProbeTimeout.Duration, Dial: s.Dial}, snap, s.Cfg.Certs.ProbePort)
	}
	if s.Ignore != nil {
		if err := s.Ignore.Load(ctx); err != nil {
			s.Log.Warn("loading ignore rules", "err", err)
		}
	}
	if s.Logs != nil {
		lines := s.Logs.Fetch(ctx, logs.Targets(snap), logs.FollowOptions{Since: s.Cfg.Logs.SignatureWindow.Duration})
		st.Logs, st.IgnoredLogs = splitIgnored(logs.Signatures(lines, s.Cfg.Logs.SignatureWindow.Duration), s.Ignore)
	}
	var extra []finding.Finding
	if !s.Cfg.ReadOnly && st.Certs != nil {
		extra = append(extra, s.syncCerts(ctx, snap, st.Certs)...)
	}
	st.Findings = validate.Run(validate.Input{Snap: snap, Opts: s.validateOptions(), Certs: st.Certs, Net: netFindings, Logs: st.Logs, LogErrorsPerHour: s.Cfg.Logs.WarnPerHour})
	st.Findings = append(st.Findings, extra...)
	for _, e := range snap.Errors {
		st.Findings = append(st.Findings, finding.Finding{Severity: finding.Info, Source: "runtime", Code: "partial_read", Message: e,
			Fix: "Grant the missing permission, or turn off the feature that needs it."})
	}
	validate.Sort(st.Findings)
	st.Duration = time.Since(start)
	s.publish(ctx, st)
	return st
}

func (s *Scanner) publish(ctx context.Context, st *state.State) {
	s.mu.Lock()
	s.last = st
	s.mu.Unlock()
	if s.Collector != nil {
		s.Collector.Update(st)
	}
	if s.Notifier != nil {
		s.Notifier.Observe(ctx, st.Findings)
	}
}

// syncCerts keeps sensorCert in step with a configured source, or (opt-in) with the sensor.
func (s *Scanner) syncCerts(ctx context.Context, snap *discovery.Snapshot, a *certs.Assessment) []finding.Finding {
	var out []finding.Finding
	current := snap.ConfigData["sensorCert"]
	if src := s.Cfg.Certs.Source; src != nil {
		want, err := s.readSource(ctx, src)
		if err != nil {
			return append(out, finding.Finding{Severity: finding.Warning, Source: "certs", Code: "cert_source_unreadable", Setting: "sensorCert",
				Message: fmt.Sprintf("Cannot read certs.source %s %s/%s key %s: %v", src.Kind, src.Namespace, src.Name, src.Key, err)})
		}
		if strings.TrimSpace(want) != strings.TrimSpace(current) {
			if err := certs.VerifyCandidate(want, a.Probe, SensorName(snap.ConfigData), time.Now()); err != nil {
				return append(out, finding.Finding{Severity: finding.Critical, Source: "certs", Code: "cert_source_untrusted", Setting: "sensorCert",
					Message: fmt.Sprintf("certs.source %s/%s changed, but %v. sensorCert was left unchanged.", src.Namespace, src.Name, err)})
			}
			out = append(out, s.applyCert(ctx, snap, want, "cert-source-sync", fmt.Sprintf("sync from %s %s/%s", src.Kind, src.Namespace, src.Name))...)
		}
		return out
	}
	if s.Cfg.Certs.AutoSync {
		if pemOut, ok, _ := certs.AutoSyncAllowed(a, current); ok {
			out = append(out, s.applyCert(ctx, snap, pemOut, "cert-auto-sync", "auto-sync: the sensor's certificate chain changed (public CA, name matches)")...)
		}
	}
	return out
}

func (s *Scanner) readSource(ctx context.Context, src *config.CertSource) (string, error) {
	core := s.Clients.Kube.CoreV1()
	if src.Kind == "Secret" {
		sec, err := core.Secrets(src.Namespace).Get(ctx, src.Name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		v, ok := sec.Data[src.Key]
		if !ok {
			return "", fmt.Errorf("no key %s", src.Key)
		}
		return string(v), nil
	}
	cm, err := core.ConfigMaps(src.Namespace).Get(ctx, src.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	v, ok := cm.Data[src.Key]
	if !ok {
		return "", fmt.Errorf("no key %s", src.Key)
	}
	return v, nil
}

func (s *Scanner) applyCert(ctx context.Context, snap *discovery.Snapshot, pemData, kind, reason string) []finding.Finding {
	p, err := s.Engine.Plan(snap, apply.Change{Config: map[string]string{"sensorCert": pemData}, Reason: reason})
	if err == nil && p.Empty {
		return nil
	}
	if err == nil && !p.Blocked {
		_, err = s.Engine.Apply(ctx, p, "eh-k8s-console", kind)
	} else if err == nil {
		err = fmt.Errorf("blocked: %s", p.BlockReason)
	}
	if err != nil {
		return []finding.Finding{{Severity: finding.Critical, Source: "certs", Code: kind + "_failed", Setting: "sensorCert", Message: "Updating sensorCert automatically failed: " + err.Error()}}
	}
	s.Log.Info("sensorCert updated", "kind", kind, "reason", reason)
	return []finding.Finding{{Severity: finding.Info, Source: "certs", Code: kind, Setting: "sensorCert", Message: "sensorCert was updated automatically (" + reason + ")."}}
}

// splitIgnored separates recurring errors that an ignore rule hides.
func splitIgnored(stats []validate.LogStat, rules *ignore.Store) (active, ignored []validate.LogStat) {
	for _, st := range stats {
		if rule, ok := rules.Match(st.Signature); ok {
			st.IgnoredBy = rule.Pattern
			ignored = append(ignored, st)
			continue
		}
		active = append(active, st)
	}
	return active, ignored
}

// Run scans on the configured interval until ctx ends.
func (s *Scanner) Run(ctx context.Context) {
	t := time.NewTicker(s.Cfg.ScanInterval.Duration)
	defer t.Stop()
	s.Scan(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Scan(ctx)
		}
	}
}

// pod is a pod row for the annotation picker.
type pod struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
	Owner     string            `json:"owner,omitempty"`
	Rule      string            `json:"rule,omitempty"`
	Node      string            `json:"node,omitempty"`
	Editable  bool              `json:"editable"`
	Phase     string            `json:"phase"`
	PodIP     string            `json:"podIP,omitempty"`
	HostNet   bool              `json:"hostNetwork,omitempty"`
}

func podRow(p *corev1.Pod, scope config.Annotations) pod {
	r := pod{Namespace: p.Namespace, Name: p.Name, Labels: p.Labels, Rule: p.Annotations[discovery.MirrorAnnotation], Node: p.Spec.NodeName,
		Editable: scope.Editable(p.Namespace), Phase: string(p.Status.Phase), PodIP: p.Status.PodIP, HostNet: p.Spec.HostNetwork}
	for _, o := range p.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			r.Owner = o.Kind + "/" + o.Name
		}
	}
	return r
}
