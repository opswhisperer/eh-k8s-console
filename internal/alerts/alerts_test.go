package alerts

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/opswhisperer/eh-k8s-console/internal/certs"
	"github.com/opswhisperer/eh-k8s-console/internal/config"
	"github.com/opswhisperer/eh-k8s-console/internal/finding"
	"github.com/opswhisperer/eh-k8s-console/internal/state"
	"github.com/opswhisperer/eh-k8s-console/internal/validate"
)

type sink struct {
	mu   sync.Mutex
	msgs []map[string]any
}

func (s *sink) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		s.mu.Lock()
		s.msgs = append(s.msgs, m)
		s.mu.Unlock()
	}))
}

var broken = finding.Finding{Severity: finding.Critical, Source: "certs", Code: "chain_untrusted", Setting: "sensorCert", Message: "sensorCert does not trust the sensor", Fix: "Refresh it"}
var note = finding.Finding{Severity: finding.Info, Source: "certs", Code: "leaf_rotated", Setting: "sensorCert", Message: "renewed"}

func notifier(t *testing.T, url string, store StateStore) *Notifier {
	return &Notifier{Webhooks: []config.Webhook{{Name: "apprise", URL: url, Format: "apprise", MinSeverity: "warning", Tag: "ops"}},
		Cluster: "demo", Store: store, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestNotifiesOnlyTransitionsAndSurvivesRestart(t *testing.T) {
	s := &sink{}
	srv := s.server()
	defer srv.Close()
	ctx := context.Background()
	store := &ConfigMapStore{Kube: fake.NewSimpleClientset(), Namespace: "extrahop", Name: "eh-k8s-console-alerts"}

	n := notifier(t, srv.URL, store)
	n.Observe(ctx, []finding.Finding{broken, note})
	n.Observe(ctx, []finding.Finding{broken, note}) // unchanged: nothing sent
	if len(s.msgs) != 1 {
		t.Fatalf("sent %d, want 1", len(s.msgs))
	}
	if s.msgs[0]["type"] != "failure" || s.msgs[0]["tag"] != "ops" || !strings.Contains(s.msgs[0]["body"].(string), "Fix: Refresh it") {
		t.Fatalf("apprise payload = %v", s.msgs[0])
	}
	if strings.Contains(s.msgs[0]["body"].(string), "renewed") {
		t.Fatal("info findings must not reach a warning-level webhook")
	}

	// A new notifier (pod restart) loads the stored state and does not repeat the alert.
	n2 := notifier(t, srv.URL, store)
	n2.Observe(ctx, []finding.Finding{broken})
	if len(s.msgs) != 1 {
		t.Fatalf("restart re-sent: %d messages", len(s.msgs))
	}
	n2.Observe(ctx, nil)
	if len(s.msgs) != 2 || s.msgs[1]["type"] != "success" {
		t.Fatalf("resolution = %v", s.msgs)
	}
}

func TestFailedDeliveryIsRetried(t *testing.T) {
	fail := true
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusFailedDependency)
			return
		}
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		got = append(got, m)
	}))
	defer srv.Close()
	kube := fake.NewSimpleClientset()
	n := notifier(t, srv.URL, &ConfigMapStore{Kube: kube, Namespace: "extrahop", Name: "alerts"})
	n.Events = &EventRecorder{Kube: kube, Namespace: "extrahop", ConfigMap: "cm"}
	ctx := context.Background()

	n.Observe(ctx, []finding.Finding{broken})
	if len(n.Errors()) != 1 {
		t.Fatal("delivery error not reported")
	}
	fail = false
	n.Observe(ctx, []finding.Finding{broken}) // retried now that the webhook works
	if len(got) != 1 || got[0]["type"] != "failure" {
		t.Fatalf("retry sent %v", got)
	}
	if len(n.Errors()) != 0 {
		t.Fatal("error not cleared after success")
	}
	evs, _ := kube.CoreV1().Events("extrahop").List(ctx, metav1.ListOptions{})
	if len(evs.Items) != 1 {
		t.Fatalf("the Event must be recorded once, not again on retry: %d", len(evs.Items))
	}
	n.Observe(ctx, []finding.Finding{broken})
	if len(got) != 1 {
		t.Fatal("unchanged findings must not be resent")
	}
}

func TestEventsRecorded(t *testing.T) {
	kube := fake.NewSimpleClientset()
	n := &Notifier{Events: &EventRecorder{Kube: kube, Namespace: "extrahop", ConfigMap: "cm"}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	n.Observe(context.Background(), []finding.Finding{broken})
	evs, _ := kube.CoreV1().Events("extrahop").List(context.Background(), metav1.ListOptions{})
	if len(evs.Items) != 1 || evs.Items[0].Type != "Warning" || evs.Items[0].InvolvedObject.Name != "cm" {
		t.Fatalf("events = %+v", evs.Items)
	}
}

func TestMetrics(t *testing.T) {
	c := NewCollector()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	c.Update(&state.State{At: time.Now(),
		Certs:    &certs.Assessment{State: certs.StateRotatedTrusted, TrustedByBundle: true, PublicCA: true, LeafChanged: true},
		Findings: []finding.Finding{broken, note},
		Logs:     []validate.LogStat{{Component: "metadata-forwarder", Level: "error", Signature: "x [device_not_found]", Count: 42}},
	})
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP ehk_cert_leaf_changed 1 if the sensor's leaf certificate is not the one in sensorCert.
# TYPE ehk_cert_leaf_changed gauge
ehk_cert_leaf_changed 1
# HELP ehk_log_error_signatures Error/warning log lines per signature in the scan window (top 25).
# TYPE ehk_log_error_signatures gauge
ehk_log_error_signatures{component="metadata-forwarder",level="error",signature="x [device_not_found]"} 42
`), "ehk_cert_leaf_changed", "ehk_log_error_signatures"); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(c, "ehk_cert_state"); n != len(certs.AllStates) {
		t.Fatalf("ehk_cert_state series = %d", n)
	}
}

func TestDeliveryErrorsNeverShowTheURL(t *testing.T) {
	n := notifier(t, "http://127.0.0.1:1/services/T000/B000/SECRETTOKEN?token=abc", nil)
	n.Observe(context.Background(), []finding.Finding{broken})
	for name, msg := range n.Errors() {
		if strings.Contains(msg, "SECRETTOKEN") || strings.Contains(msg, "token=abc") || strings.Contains(msg, "/services/") {
			t.Fatalf("webhook %s error leaks the URL: %s", name, msg)
		}
		return
	}
	t.Fatal("expected a delivery error")
}
