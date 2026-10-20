// Package logs reads the integration's pod logs: live follow for the viewer, and a periodic scan
// that groups error lines into signatures for the dashboard, metrics and alerts.
package logs

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/opswhisperer/eh-k8s-console/internal/discovery"
	"github.com/opswhisperer/eh-k8s-console/internal/ignore"
	"github.com/opswhisperer/eh-k8s-console/internal/validate"
)

// Line is one parsed log line.
type Line struct {
	Time      time.Time         `json:"time"`
	Pod       string            `json:"pod"`
	Node      string            `json:"node,omitempty"`
	Container string            `json:"container"`
	Component string            `json:"component"`
	Level     string            `json:"level"` // error | warn | info | debug
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
	Raw       string            `json:"raw"`
	// Signature is set on warnings and errors: the normalized message used to group repeats.
	Signature string `json:"signature,omitempty"`
	// IgnoredBy is the ignore rule (pattern) that hides this line from findings and alerts.
	IgnoredBy string `json:"ignoredBy,omitempty"`
}

// Target is one container to read.
type Target struct {
	Pod       string
	Node      string
	Container string
	Component string
}

// Targets lists every container of every integration pod.
func Targets(s *discovery.Snapshot) []Target {
	var out []Target
	for _, w := range s.Workloads {
		for _, p := range w.Pods {
			for _, c := range p.Containers {
				out = append(out, Target{Pod: p.Name, Node: p.Node, Container: c, Component: w.Component})
			}
		}
	}
	return out
}

var goLogTime = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(\.\d+)? `)

// Parse reads one line as written by the kubelet with timestamps=true.
func Parse(t Target, raw string) Line {
	l := Line{Pod: t.Pod, Node: t.Node, Container: t.Container, Component: t.Component, Raw: raw, Level: "info"}
	body := raw
	if ts, rest, ok := strings.Cut(raw, " "); ok {
		if tm, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			l.Time, body = tm, rest
		}
	}
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") {
		var m map[string]any
		if json.Unmarshal([]byte(trimmed), &m) == nil {
			l.Fields = map[string]string{}
			for k, v := range m {
				switch x := v.(type) {
				case string:
					l.Fields[k] = x
				default:
					b, _ := json.Marshal(x)
					l.Fields[k] = string(b)
				}
			}
			l.Message = first(l.Fields, "msg", "message")
			if lv := strings.ToLower(first(l.Fields, "level", "severity", "lvl")); lv != "" {
				l.Level = normLevel(lv)
			}
			delete(l.Fields, "msg")
			delete(l.Fields, "message")
			delete(l.Fields, "level")
			delete(l.Fields, "time")
			return l
		}
	}
	l.Message = goLogTime.ReplaceAllString(body, "")
	low := strings.ToLower(l.Message)
	switch {
	case strings.Contains(low, "panic") || strings.Contains(low, "fatal") || strings.Contains(low, "error") || strings.Contains(low, "failed"):
		l.Level = "error"
	case strings.Contains(low, "warn"):
		l.Level = "warn"
	}
	return l
}

func first(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; v != "" {
			return v
		}
	}
	return ""
}

func normLevel(lv string) string {
	switch {
	case strings.HasPrefix(lv, "err"), lv == "fatal", lv == "panic", lv == "crit", lv == "critical":
		return "error"
	case strings.HasPrefix(lv, "warn"):
		return "warn"
	case lv == "debug", lv == "trace":
		return "debug"
	}
	return "info"
}

var (
	reUUID   = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	reK8sID  = regexp.MustCompile(`k8s-[0-9a-f]{8,}`)
	reHex    = regexp.MustCompile(`\b[0-9a-f]{16,}\b`)
	reIPPort = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b`)
	rePodSfx = regexp.MustCompile(`\b([a-z0-9-]+)-[a-z0-9]{8,10}-[a-z0-9]{5}\b`)
	reNum    = regexp.MustCompile(`\b\d+\b`)
	// Interface and object names ending in a hex id (cali53e670eb917, veth1a2b3c4d, lxc…).
	reHexTail = regexp.MustCompile(`\b([a-z_]*[g-z_])([0-9a-f]{7,})\b`)
	reErrTok  = regexp.MustCompile(`"(?:error|type)":\s*"([a-z_]+)"`)
)

// Signature normalizes a line so repeats of the same problem group together: ids, addresses
// and numbers are stripped, and error codes from embedded API bodies are kept.
func Signature(l Line) string {
	msg := l.Message
	if e := l.Fields["err"]; e != "" && !strings.Contains(msg, e) {
		msg += ": " + e
	}
	var codes []string
	seen := map[string]bool{}
	for _, src := range []string{msg, l.Fields["body"]} {
		for _, m := range reErrTok.FindAllStringSubmatch(src, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				codes = append(codes, m[1])
			}
		}
	}
	if i := strings.Index(msg, "body:"); i >= 0 {
		msg = strings.TrimSpace(msg[:i])
	}
	if i := strings.Index(msg, "{"); i >= 0 {
		msg = strings.TrimSpace(msg[:i])
	}
	for _, r := range []struct {
		re  *regexp.Regexp
		rep string
	}{{reUUID, "<uuid>"}, {reK8sID, "k8s-<id>"}, {reHex, "<hex>"}, {reIPPort, "<addr>"}, {rePodSfx, "$1-<pod>"}} {
		msg = r.re.ReplaceAllString(msg, r.rep)
	}
	msg = reHexTail.ReplaceAllStringFunc(msg, func(w string) string {
		m := reHexTail.FindStringSubmatch(w)
		if strings.ContainsAny(m[2], "0123456789") {
			return m[1] + "<id>"
		}
		return w
	})
	msg = reNum.ReplaceAllString(msg, "<n>")
	msg = strings.TrimRight(strings.TrimSpace(msg), ":,")
	if len(codes) > 0 {
		msg += " [" + strings.Join(codes, ", ") + "]"
	}
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return msg
}

// Reader fetches logs. LogStream is replaceable in tests (the fake clientset returns fixed text).
type Reader struct {
	Kube      kubernetes.Interface
	Namespace string
	// Ignore tags lines that ignore rules hide (nil: no rules).
	Ignore *ignore.Store
	// Source replaces the Kubernetes log API (tests and the demo environment).
	Source func(ctx context.Context, t Target, opts *corev1.PodLogOptions) (io.ReadCloser, error)
}

// tag adds the signature to warnings and errors and marks lines an ignore rule hides.
func (r *Reader) tag(l Line) Line {
	if l.Level != "error" && l.Level != "warn" {
		return l
	}
	l.Signature = Signature(l)
	if rule, ok := r.Ignore.Match(l.Signature); ok {
		l.IgnoredBy = rule.Pattern
	}
	return l
}

func (r *Reader) stream(ctx context.Context, t Target, opts *corev1.PodLogOptions) (io.ReadCloser, error) {
	o := *opts
	o.Container = t.Container
	o.Timestamps = true
	if r.Source != nil {
		return r.Source(ctx, t, &o)
	}
	return r.Kube.CoreV1().Pods(r.Namespace).GetLogs(t.Pod, &o).Stream(ctx)
}

// FollowOptions select what to stream.
type FollowOptions struct {
	TailLines int64
	Since     time.Duration
	Previous  bool
	// LimitBytes caps what Fetch reads per container (default 2 MiB).
	LimitBytes int64
	// MaxLines caps the total lines Fetch returns (0: no cap).
	MaxLines int
}

// Follow streams lines from every target into one channel until ctx ends. Errors opening a
// stream arrive as synthetic error lines so the viewer shows them in place.
func (r *Reader) Follow(ctx context.Context, targets []Target, fo FollowOptions) <-chan Line {
	out := make(chan Line, 256)
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t Target) {
			defer wg.Done()
			opts := &corev1.PodLogOptions{Follow: !fo.Previous, Previous: fo.Previous}
			if fo.TailLines > 0 {
				opts.TailLines = &fo.TailLines
			}
			if fo.Since > 0 {
				s := int64(fo.Since.Seconds())
				opts.SinceSeconds = &s
			}
			rc, err := r.stream(ctx, t, opts)
			if err != nil {
				select {
				case out <- Line{Time: time.Now(), Pod: t.Pod, Container: t.Container, Component: t.Component, Level: "error", Message: "cannot read logs: " + err.Error()}:
				case <-ctx.Done():
				}
				return
			}
			defer rc.Close()
			sc := bufio.NewScanner(rc)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() {
				select {
				case out <- r.tag(Parse(t, sc.Text())):
				case <-ctx.Done():
					return
				}
			}
		}(t)
	}
	go func() { wg.Wait(); close(out) }()
	return out
}

// Fetch reads (without following) and returns lines sorted by time.
func (r *Reader) Fetch(ctx context.Context, targets []Target, fo FollowOptions) []Line {
	fo.Previous = fo.Previous || false
	var lines []Line
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t Target) {
			defer wg.Done()
			limit := fo.LimitBytes
			if limit <= 0 {
				limit = 2 << 20
			}
			opts := &corev1.PodLogOptions{Previous: fo.Previous, LimitBytes: &limit}
			if fo.TailLines > 0 {
				opts.TailLines = &fo.TailLines
			}
			if fo.Since > 0 {
				s := int64(fo.Since.Seconds())
				opts.SinceSeconds = &s
			}
			rc, err := r.stream(ctx, t, opts)
			if err != nil {
				return
			}
			defer rc.Close()
			sc := bufio.NewScanner(rc)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			var local []Line
			for sc.Scan() {
				local = append(local, r.tag(Parse(t, sc.Text())))
			}
			mu.Lock()
			if fo.MaxLines > 0 && len(lines)+len(local) > fo.MaxLines {
				local = local[:max(0, fo.MaxLines-len(lines))]
			}
			lines = append(lines, local...)
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].Time.Before(lines[j].Time) })
	return lines
}

// Signatures groups error and warning lines by component and signature.
func Signatures(lines []Line, window time.Duration) []validate.LogStat {
	type key struct{ comp, level, sig string }
	counts := map[key]*validate.LogStat{}
	for _, l := range lines {
		if l.Level != "error" && l.Level != "warn" {
			continue
		}
		sig := l.Signature
		if sig == "" {
			sig = Signature(l)
		}
		k := key{l.Component, l.Level, sig}
		st := counts[k]
		if st == nil {
			st = &validate.LogStat{Component: l.Component, Level: l.Level, Signature: k.sig, Window: window}
			counts[k] = st
		}
		st.Count++
		st.Example = l.Raw
	}
	out := make([]validate.LogStat, 0, len(counts))
	for _, st := range counts {
		if len(st.Example) > 1000 {
			st.Example = st.Example[:1000] + "…"
		}
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// Event is a Kubernetes event about an integration object.
type Event struct {
	Time    time.Time `json:"time"`
	Type    string    `json:"type"`
	Reason  string    `json:"reason"`
	Object  string    `json:"object"`
	Message string    `json:"message"`
	Count   int32     `json:"count"`
}

// Events lists recent events in the integration namespace for integration objects.
func (r *Reader) Events(ctx context.Context, s *discovery.Snapshot) ([]Event, error) {
	list, err := r.Kube.CoreV1().Events(r.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	names := map[string]bool{s.ConfigMapName: true}
	for _, w := range s.Workloads {
		names[w.Name] = true
		for _, p := range w.Pods {
			names[p.Name] = true
		}
	}
	var out []Event
	for _, e := range list.Items {
		io := e.InvolvedObject
		if !names[io.Name] && !strings.HasPrefix(io.Name, strings.TrimSuffix(s.ConfigMapName, "cm")) {
			continue
		}
		t := e.LastTimestamp.Time
		if t.IsZero() {
			t = e.EventTime.Time
		}
		if t.IsZero() {
			t = e.CreationTimestamp.Time
		}
		out = append(out, Event{Time: t, Type: e.Type, Reason: e.Reason, Object: fmt.Sprintf("%s/%s", io.Kind, io.Name), Message: e.Message, Count: e.Count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out, nil
}
