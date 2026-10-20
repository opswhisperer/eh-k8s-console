// Package alerts exports scan results as Prometheus metrics, webhook notifications and
// Kubernetes Events.
package alerts

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/opswhisperer/eh-k8s-console/internal/certs"
	"github.com/opswhisperer/eh-k8s-console/internal/finding"
	"github.com/opswhisperer/eh-k8s-console/internal/state"
)

// Collector builds metrics from the latest scan on every scrape.
type Collector struct {
	mu   sync.RWMutex
	last *state.State
}

func NewCollector() *Collector { return &Collector{} }

func (c *Collector) Update(s *state.State) {
	c.mu.Lock()
	c.last = s
	c.mu.Unlock()
}

var (
	dScanOK        = prometheus.NewDesc("ehk_scan_success", "1 if the last scan of the integration succeeded.", nil, nil)
	dScanTime      = prometheus.NewDesc("ehk_last_scan_timestamp_seconds", "Unix time of the last scan.", nil, nil)
	dCertState     = prometheus.NewDesc("ehk_cert_state", "1 for the current sensor-certificate state (OK, ROTATED_TRUSTED, BROKEN, SNI_MISMATCH, UNREACHABLE, INVALID_BUNDLE).", []string{"state"}, nil)
	dCertNotAfter  = prometheus.NewDesc("ehk_cert_not_after_seconds", "Expiry (unix time) of each certificate: source=bundle for sensorCert, source=live for what the sensor presents.", []string{"source", "role", "subject", "fingerprint", "anchor"}, nil)
	dCertTrusted   = prometheus.NewDesc("ehk_cert_trusted_by_bundle", "1 if the sensor's live chain verifies against sensorCert the way the forwarders check it.", nil, nil)
	dCertPublic    = prometheus.NewDesc("ehk_cert_public_ca", "1 if the sensor's chain verifies against public roots.", nil, nil)
	dCertLeafDrift = prometheus.NewDesc("ehk_cert_leaf_changed", "1 if the sensor's leaf certificate is not the one in sensorCert.", nil, nil)
	dProbeOK       = prometheus.NewDesc("ehk_cert_probe_success", "1 if the sensor's certificate could be read.", nil, nil)
	dFindings      = prometheus.NewDesc("ehk_findings", "Current findings by severity, source and code.", []string{"severity", "source", "code"}, nil)
	dLogErrors     = prometheus.NewDesc("ehk_log_error_signatures", "Error/warning log lines per signature in the scan window (top 25).", []string{"component", "level", "signature"}, nil)
	dReady         = prometheus.NewDesc("ehk_workload_ready", "Ready pods per integration workload.", []string{"workload", "kind", "component"}, nil)
	dDesired       = prometheus.NewDesc("ehk_workload_desired", "Desired pods per integration workload.", []string{"workload", "kind", "component"}, nil)
	dRestarts      = prometheus.NewDesc("ehk_pod_restarts", "Container restarts per integration pod.", []string{"pod", "component", "node"}, nil)
)

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{dScanOK, dScanTime, dCertState, dCertNotAfter, dCertTrusted, dCertPublic, dCertLeafDrift, dProbeOK, dFindings, dLogErrors, dReady, dDesired, dRestarts} {
		ch <- d
	}
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	s := c.last
	c.mu.RUnlock()
	if s == nil {
		return
	}
	g := func(d *prometheus.Desc, v float64, lv ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, lv...)
	}
	g(dScanOK, b2f(s.Err == ""))
	g(dScanTime, float64(s.At.Unix()))
	if a := s.Certs; a != nil {
		for _, st := range certs.AllStates {
			g(dCertState, b2f(a.State == st), string(st))
		}
		anchor := ""
		if a.Anchor != nil {
			anchor = a.Anchor.SHA256
		}
		for _, ci := range a.Bundle {
			g(dCertNotAfter, float64(ci.NotAfter.Unix()), "bundle", ci.Role, ci.Subject, ci.SHA256, map[bool]string{true: "true", false: "false"}[ci.SHA256 == anchor])
		}
		if a.Probe != nil {
			for _, ci := range a.Probe.Chain {
				g(dCertNotAfter, float64(ci.NotAfter.Unix()), "live", ci.Role, ci.Subject, ci.SHA256, "false")
			}
		}
		g(dCertTrusted, b2f(a.TrustedByBundle))
		g(dCertPublic, b2f(a.PublicCA))
		g(dCertLeafDrift, b2f(a.LeafChanged))
		g(dProbeOK, b2f(a.Probe != nil && a.Probe.Error == "" && len(a.Probe.Chain) > 0))
	}
	type key struct{ sev, src, code string }
	counts := map[key]int{}
	for _, f := range s.Findings {
		counts[key{string(f.Severity), f.Source, f.Code}]++
	}
	for k, n := range counts {
		g(dFindings, float64(n), k.sev, k.src, k.code)
	}
	for i, l := range s.Logs {
		if i >= 25 {
			break
		}
		g(dLogErrors, float64(l.Count), l.Component, l.Level, l.Signature)
	}
	if s.Snap != nil {
		for _, w := range s.Snap.Workloads {
			g(dReady, float64(w.Ready), w.Name, w.Kind, w.Component)
			g(dDesired, float64(w.Desired), w.Name, w.Kind, w.Component)
			for _, p := range w.Pods {
				g(dRestarts, float64(p.Restarts), p.Name, w.Component, p.Node)
			}
		}
	}
}

// Firing returns findings at or above min, keyed for deduplication.
func Firing(fs []finding.Finding, min finding.Severity) map[string]finding.Finding {
	out := map[string]finding.Finding{}
	for _, f := range fs {
		if finding.AtLeast(f.Severity, min) {
			out[Key(f)] = f
		}
	}
	return out
}

// Key identifies a finding across scans (message text can vary, e.g. day counts).
func Key(f finding.Finding) string { return f.Source + "/" + f.Code + "/" + f.Setting }
