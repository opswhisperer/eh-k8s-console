package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	neturl "net/url"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/opswhisperer/eh-k8s-console/internal/config"
	"github.com/opswhisperer/eh-k8s-console/internal/finding"
)

// Transition is a finding that started or stopped firing.
type Transition struct {
	Status  string          `json:"status"` // firing | resolved
	Finding finding.Finding `json:"finding"`
}

// SinkState is what each destination was last told: sink name -> firing findings by Key.
// Sinks are tracked separately so a failed webhook is retried without repeating the others.
type SinkState map[string]map[string]finding.Finding

// StateStore remembers what was already notified, so a restart does not repeat every alert.
type StateStore interface {
	Load(ctx context.Context) (SinkState, error)
	Save(ctx context.Context, st SinkState) error
}

// ConfigMapStore keeps notifier state in a ConfigMap.
type ConfigMapStore struct {
	Kube      kubernetes.Interface
	Namespace string
	Name      string
}

func (s *ConfigMapStore) Load(ctx context.Context) (SinkState, error) {
	cm, err := s.Kube.CoreV1().ConfigMaps(s.Namespace).Get(ctx, s.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := SinkState{}
	if raw := cm.Data["sinks.json"]; raw != "" {
		return out, json.Unmarshal([]byte(raw), &out)
	}
	return out, nil
}

func (s *ConfigMapStore) Save(ctx context.Context, st SinkState) error {
	b, _ := json.Marshal(st)
	data := map[string]string{"sinks.json": string(b)}
	cms := s.Kube.CoreV1().ConfigMaps(s.Namespace)
	cm, err := cms.Get(ctx, s.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cms.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: s.Name, Namespace: s.Namespace,
			Labels: map[string]string{"app.kubernetes.io/managed-by": "eh-k8s-console"}}, Data: data},
			metav1.CreateOptions{FieldManager: "eh-k8s-console"})
		return err
	}
	if err != nil {
		return err
	}
	cm.Data = data
	_, err = cms.Update(ctx, cm, metav1.UpdateOptions{FieldManager: "eh-k8s-console"})
	return err
}

// Notifier sends transitions to webhooks and records Events.
type Notifier struct {
	Webhooks []config.Webhook
	Cluster  string
	BaseURL  string
	Store    StateStore
	Events   *EventRecorder
	HTTP     *http.Client
	Log      *slog.Logger

	mu      sync.Mutex
	loaded  bool
	state   SinkState
	sendErr map[string]string
}

const eventsSink = "k8s-events"

// diff returns what changed between what a sink was told and what is firing now.
func diff(told, now map[string]finding.Finding) []Transition {
	var ts []Transition
	for k, f := range now {
		if old, ok := told[k]; !ok || old.Severity != f.Severity {
			ts = append(ts, Transition{"firing", f})
		}
	}
	for k, f := range told {
		if _, ok := now[k]; !ok {
			ts = append(ts, Transition{"resolved", f})
		}
	}
	sort.Slice(ts, func(i, j int) bool { return Key(ts[i].Finding) < Key(ts[j].Finding) })
	return ts
}

// Observe compares the current findings with what each sink was last told and sends the
// differences. A sink whose delivery fails keeps its old state, so the next scan retries it.
// Info findings reach only webhooks that ask for them (minSeverity: info); Events skip them.
func (n *Notifier) Observe(ctx context.Context, fs []finding.Finding) []Transition {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.loaded {
		n.loaded = true
		if n.Store != nil {
			if prev, err := n.Store.Load(ctx); err != nil {
				n.log().Warn("loading alert state", "err", err)
			} else if prev != nil {
				n.state = prev
			}
		}
	}
	if n.state == nil {
		n.state = SinkState{}
	}
	var all []Transition
	changed := false
	for _, w := range n.Webhooks {
		now := Firing(fs, finding.Severity(w.MinSeverity))
		ts := diff(n.state[w.Name], now)
		if len(ts) == 0 {
			continue
		}
		if err := n.send(ctx, w, ts); err != nil {
			n.log().Error("sending notification", "webhook", w.Name, "err", err, "pending", len(ts))
			if n.sendErr == nil {
				n.sendErr = map[string]string{}
			}
			n.sendErr[w.Name] = err.Error()
			continue
		}
		delete(n.sendErr, w.Name)
		n.state[w.Name] = now
		all = append(all, ts...)
		changed = true
	}
	if n.Events != nil {
		now := Firing(fs, finding.Warning)
		ts := diff(n.state[eventsSink], now)
		for _, t := range ts {
			n.Events.Record(ctx, t)
		}
		if len(ts) > 0 {
			n.state[eventsSink] = now
			all = append(all, ts...)
			changed = true
		}
	}
	if changed && n.Store != nil {
		if err := n.Store.Save(ctx, n.state); err != nil {
			n.log().Warn("saving alert state", "err", err)
		}
	}
	return all
}

// Errors returns the last delivery error per webhook.
func (n *Notifier) Errors() map[string]string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := map[string]string{}
	for k, v := range n.sendErr {
		out[k] = v
	}
	return out
}

func (n *Notifier) log() *slog.Logger {
	if n.Log != nil {
		return n.Log
	}
	return slog.Default()
}

func (n *Notifier) title(ts []Transition) string {
	firing, resolved := 0, 0
	worst := finding.Info
	for _, t := range ts {
		if t.Status == "firing" {
			firing++
			if finding.Rank(t.Finding.Severity) > finding.Rank(worst) {
				worst = t.Finding.Severity
			}
		} else {
			resolved++
		}
	}
	parts := []string{}
	if firing > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", firing, map[bool]string{true: "problem", false: "problems"}[firing == 1]))
	}
	if resolved > 0 {
		parts = append(parts, fmt.Sprintf("%d resolved", resolved))
	}
	return fmt.Sprintf("ExtraHop integration (%s): %s", n.Cluster, strings.Join(parts, ", "))
}

func (n *Notifier) body(ts []Transition) string {
	var b strings.Builder
	for _, t := range ts {
		mark := map[string]string{"firing": "▲", "resolved": "✓"}[t.Status]
		fmt.Fprintf(&b, "%s [%s] %s\n", mark, t.Finding.Severity, t.Finding.Message)
		if t.Status == "firing" && t.Finding.Fix != "" {
			fmt.Fprintf(&b, "   Fix: %s\n", t.Finding.Fix)
		}
	}
	if n.BaseURL != "" {
		b.WriteString("\n" + strings.TrimRight(n.BaseURL, "/") + "/\n")
	}
	return b.String()
}

func (n *Notifier) send(ctx context.Context, w config.Webhook, ts []Transition) error {
	url := w.URL
	if url == "" {
		v, err := w.URLFrom.Read()
		if err != nil {
			return err
		}
		url = v
	}
	var payload any
	switch w.Format {
	case "apprise":
		typ := "info"
		for _, t := range ts {
			if t.Status == "firing" && t.Finding.Severity == finding.Critical {
				typ = "failure"
			} else if t.Status == "firing" && t.Finding.Severity == finding.Warning && typ != "failure" {
				typ = "warning"
			}
		}
		allResolved := true
		for _, t := range ts {
			if t.Status == "firing" {
				allResolved = false
			}
		}
		if allResolved {
			typ = "success"
		}
		p := map[string]string{"title": n.title(ts), "body": n.body(ts), "type": typ}
		if w.Tag != "" {
			p["tag"] = w.Tag
		}
		payload = p
	case "slack":
		payload = map[string]string{"text": "*" + n.title(ts) + "*\n" + n.body(ts)}
	default:
		payload = map[string]any{"cluster": n.Cluster, "title": n.title(ts), "transitions": ts, "time": time.Now().UTC()}
	}
	b, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return errors.New("the webhook URL is not valid") // never echo the URL: it may carry a token
	}
	req.Header.Set("Content-Type", "application/json")
	hc := n.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		// net/http errors quote the full URL (path and query included), and webhook URLs often
		// carry their token there: keep only the underlying cause.
		var ue *neturl.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("delivery failed: %v", ue.Err)
		}
		return errors.New("delivery failed")
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("webhook answered %s", res.Status)
	}
	return nil
}

// Test sends a one-off test notification to every webhook.
func (n *Notifier) Test(ctx context.Context) map[string]string {
	out := map[string]string{}
	t := []Transition{{"firing", finding.Finding{Severity: finding.Info, Code: "test", Source: "alerts", Message: "Test notification from eh-k8s-console."}}}
	for _, w := range n.Webhooks {
		if err := n.send(ctx, w, t); err != nil {
			out[w.Name] = err.Error()
		} else {
			out[w.Name] = "sent"
		}
	}
	return out
}

// EventRecorder writes Kubernetes Events on the integration ConfigMap.
type EventRecorder struct {
	Kube      kubernetes.Interface
	Namespace string
	ConfigMap string
}

func (r *EventRecorder) Record(ctx context.Context, t Transition) {
	typ, reason := corev1.EventTypeWarning, "IntegrationProblem"
	if t.Status == "resolved" {
		typ, reason = corev1.EventTypeNormal, "IntegrationProblemResolved"
	}
	now := metav1.Now()
	msg := t.Finding.Message
	if len(msg) > 1000 {
		msg = msg[:1000]
	}
	ev := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{GenerateName: "eh-k8s-console-", Namespace: r.Namespace},
		InvolvedObject: corev1.ObjectReference{Kind: "ConfigMap", APIVersion: "v1", Namespace: r.Namespace, Name: r.ConfigMap},
		Reason:         reason, Message: fmt.Sprintf("[%s] %s", t.Finding.Code, msg), Type: typ,
		Source:         corev1.EventSource{Component: "eh-k8s-console"},
		FirstTimestamp: now, LastTimestamp: now, Count: 1,
	}
	_, _ = r.Kube.CoreV1().Events(r.Namespace).Create(ctx, ev, metav1.CreateOptions{})
}
