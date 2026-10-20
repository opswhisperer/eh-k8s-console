package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
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
