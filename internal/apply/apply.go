// Package apply turns an edit into a reviewed change: it builds the proposed state, validates it,
// shows a diff and the restarts it needs, dry-runs it through the API server (so admission
// policies are checked), applies it with optimistic concurrency, and keeps a revision history.
package apply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"

	"github.com/opswhisperer/eh-k8s-console/internal/certs"
	"github.com/opswhisperer/eh-k8s-console/internal/discovery"
	"github.com/opswhisperer/eh-k8s-console/internal/finding"
	"github.com/opswhisperer/eh-k8s-console/internal/model"
	"github.com/opswhisperer/eh-k8s-console/internal/policy"
	"github.com/opswhisperer/eh-k8s-console/internal/validate"
)

const (
	FieldManager      = "eh-k8s-console"
	RestartAnnotation = "kubectl.kubernetes.io/restartedAt"
)

// Change is an edit request. Secret values are write-only: they are never echoed or logged.
type Change struct {
	Config  map[string]string `json:"config,omitempty"`
	Remove  []string          `json:"remove,omitempty"`
	Secrets []SecretChange    `json:"secrets,omitempty"`
	// Images maps "workload/container" to an image reference.
	Images map[string]string `json:"images,omitempty"`
	// Args maps "workload/container" to a full argument list (used by rollback).
	Args map[string][]string `json:"args,omitempty"`
	// Restart adds workloads to restart even if nothing they read changed.
	Restart []string `json:"restart,omitempty"`
	Reason  string   `json:"reason,omitempty"`
	// Force applies despite new critical findings or Helm ownership (admin only).
	Force bool `json:"force,omitempty"`
}

type SecretChange struct {
	Name  string `json:"name"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

// FieldChange is one changed value. Secret values show only their length.
type FieldChange struct {
	Object string `json:"object"`
	Field  string `json:"field"`
	Old    string `json:"old"`
	New    string `json:"new"`
	Secret bool   `json:"secret,omitempty"`
}

type ObjectDiff struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Diff string `json:"diff"`
}

type Restart struct {
	Kind string   `json:"kind"`
	Name string   `json:"name"`
	Why  []string `json:"why"`
	// Rolls: the pod template itself changes, so the workload rolls without a restart annotation.
	Rolls bool `json:"rolls"`
}

type Plan struct {
	Empty       bool              `json:"empty"`
	Changes     []FieldChange     `json:"changes"`
	Diffs       []ObjectDiff      `json:"diffs"`
	Restarts    []Restart         `json:"restarts"`
	Notes       []string          `json:"notes,omitempty"`
	Findings    []finding.Finding `json:"findings"`
	Introduced  []finding.Finding `json:"introduced"`
	Resolved    []finding.Finding `json:"resolved"`
	Blocked     bool              `json:"blocked"`
	BlockReason string            `json:"blockReason,omitempty"`
	Reason      string            `json:"reason,omitempty"`

	live, proposed  *discovery.Snapshot
	cmChanged       bool
	secretChanges   map[string]map[string][]byte
	templateChanged map[string]bool
	change          Change
}

type Engine struct {
	Kube         kubernetes.Interface
	Namespace    string
	Prefix       string
	ValidateOpts validate.Options
	HistoryKeep  int
	Log          *slog.Logger
	Now          func() time.Time
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func splitWC(s string) (string, string, error) {
	w, c, ok := strings.Cut(s, "/")
	if !ok || w == "" || c == "" {
		return "", "", fmt.Errorf("%q must be workload/container", s)
	}
	return w, c, nil
}

func container(spec *corev1.PodSpec, name string) *corev1.Container {
	for i := range spec.Containers {
		if spec.Containers[i].Name == name {
			return &spec.Containers[i]
		}
	}
	return nil
}

// setArg sets every occurrence of flag in args (both "-flag value" and "-flag=value" forms).
// It reports whether anything changed.
func setArg(args []string, flag, value string) bool {
	changed := false
	for _, a := range discovery.ParseArgs(args) {
		if a.Flag != flag || !a.HasValue || a.Value == value {
			continue
		}
		if a.Inline {
			args[a.Index] = flag + "=" + value
		} else {
			args[a.Index+1] = value
		}
		changed = true
	}
	return changed
}

func normalize(st *model.Setting, v, sep string) string {
	if st == nil {
		return v
	}
	switch st.Type {
	case model.TypeNSList:
		return model.JoinList(model.SplitList(v), sep)
	case model.TypePEM:
		v = strings.TrimSpace(v)
		if v != "" {
			v += "\n"
		}
		return v
	}
	return strings.TrimSpace(v)
}

// Plan builds and validates the proposed state.
func (e *Engine) Plan(live *discovery.Snapshot, ch Change) (*Plan, error) {
	if !live.ConfigMapFound {
		return nil, errors.New("the integration ConfigMap does not exist; install the integration first")
	}
	p := &Plan{live: live, proposed: live.Clone(), secretChanges: map[string]map[string][]byte{},
		templateChanged: map[string]bool{}, change: ch, Reason: ch.Reason}
	prop := p.proposed
	changedKeys := map[string]bool{}

	keys := make([]string, 0, len(ch.Config))
	for k := range ch.Config {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		st := model.Lookup(k)
		if _, exists := live.ConfigData[k]; st == nil && !exists {
			return nil, fmt.Errorf("unknown setting %q", k)
		}
		v := normalize(st, ch.Config[k], e.ValidateOpts.ListSep)
		if st != nil && st.ReadOnly {
			if live.ConfigData[k] == v {
				continue
			}
			return nil, fmt.Errorf("%s is read-only: it is half of a key pair generated on the sensor", st.Label)
		}
		old, had := live.ConfigData[k]
		if had && old == v {
			continue
		}
		prop.ConfigData[k] = v
		changedKeys[k] = true
		p.Changes = append(p.Changes, FieldChange{Object: "ConfigMap/" + live.ConfigMapName, Field: k, Old: display(k, old), New: display(k, v)})
	}
	for _, k := range ch.Remove {
		if old, ok := live.ConfigData[k]; ok {
			if st := model.Lookup(k); st != nil && st.ReadOnly {
				return nil, fmt.Errorf("%s is read-only and cannot be removed", st.Label)
			}
			if st := model.Lookup(k); st != nil && st.Required {
				return nil, fmt.Errorf("%s is required and cannot be removed", k)
			}
			delete(prop.ConfigData, k)
			changedKeys[k] = true
			p.Changes = append(p.Changes, FieldChange{Object: "ConfigMap/" + live.ConfigMapName, Field: k, Old: display(k, old), New: "(removed)"})
		}
	}
	p.cmChanged = len(changedKeys) > 0

	// Linked args follow their setting (only when that setting is part of this change, so an
	// unrelated edit never silently rewrites args).
	for _, la := range model.LinkedArgs {
		if !changedKeys[la.Setting] {
			continue
		}
		for _, w := range prop.Workloads {
			spec := w.PodSpecRef()
			for i := range spec.Containers {
				c := &spec.Containers[i]
				before := strings.Join(c.Args, " ")
				if setArg(c.Args, la.Flag, prop.ConfigData[la.Setting]) || setArg(c.Command, la.Flag, prop.ConfigData[la.Setting]) {
					p.templateChanged[w.Name] = true
					p.Changes = append(p.Changes, FieldChange{Object: w.Kind + "/" + w.Name, Field: c.Name + " arg " + la.Flag,
						Old: argValue(strings.Fields(before), la.Flag), New: prop.ConfigData[la.Setting]})
				}
			}
		}
	}

	for wc, img := range ch.Images {
		wn, cn, err := splitWC(wc)
		if err != nil {
			return nil, err
		}
		w := prop.Workload(wn)
		if w == nil {
			return nil, fmt.Errorf("unknown workload %q", wn)
		}
		c := container(w.PodSpecRef(), cn)
		if c == nil {
			return nil, fmt.Errorf("workload %s has no container %q", wn, cn)
		}
		img = strings.TrimSpace(img)
		if img == "" || c.Image == img {
			continue
		}
		p.Changes = append(p.Changes, FieldChange{Object: w.Kind + "/" + wn, Field: cn + " image", Old: c.Image, New: img})
		c.Image = img
		p.templateChanged[wn] = true
	}
	for wc, args := range ch.Args {
		wn, cn, err := splitWC(wc)
		if err != nil {
			return nil, err
		}
		w := prop.Workload(wn)
		if w == nil {
			return nil, fmt.Errorf("unknown workload %q", wn)
		}
		c := container(w.PodSpecRef(), cn)
		if c == nil {
			return nil, fmt.Errorf("workload %s has no container %q", wn, cn)
		}
		if strings.Join(c.Args, "\x00") == strings.Join(args, "\x00") {
			continue
		}
		p.Changes = append(p.Changes, FieldChange{Object: w.Kind + "/" + wn, Field: cn + " args", Old: strings.Join(c.Args, " "), New: strings.Join(args, " ")})
		c.Args = append([]string{}, args...)
		p.templateChanged[wn] = true
	}

	for _, sc := range ch.Secrets {
		si := prop.Secret(sc.Name)
		if si == nil {
			return nil, fmt.Errorf("Secret %q is not used by the integration", sc.Name)
		}
		if ss := model.LookupSecret(e.Prefix, sc.Name, sc.Key); ss != nil && ss.ReadOnly {
			return nil, fmt.Errorf("%s is read-only: it is half of a key pair generated on the sensor", ss.Label)
		}
		v := []byte(strings.TrimSpace(sc.Value))
		if len(v) == 0 {
			return nil, fmt.Errorf("Secret %s key %s: empty value", sc.Name, sc.Key)
		}
		if string(si.Value(sc.Key)) == string(v) {
			continue
		}
		if si.ManagedBy == "ExternalSecret" {
			p.Notes = append(p.Notes, fmt.Sprintf("Secret %s is synced by ExternalSecret %s: change the value in the secret store, or it will be overwritten on the next refresh.", sc.Name, si.ExternalSecret.Name))
			if !ch.Force {
				p.Blocked, p.BlockReason = true, "Secret "+sc.Name+" is managed by an ExternalSecret"
			}
		}
		si.SetSecretValue(sc.Key, v)
		if p.secretChanges[sc.Name] == nil {
			p.secretChanges[sc.Name] = map[string][]byte{}
		}
		p.secretChanges[sc.Name][sc.Key] = v
		p.Changes = append(p.Changes, FieldChange{Object: "Secret/" + sc.Name, Field: sc.Key, Old: fmt.Sprintf("(%d bytes)", si.Keys[sc.Key]), New: fmt.Sprintf("(new value, %d bytes)", len(v)), Secret: true})
	}

	prop.RefreshRefs()
	p.Empty = len(p.Changes) == 0 && len(ch.Restart) == 0
	p.Restarts = e.restarts(p, changedKeys)
	if changedKeys["kubernetesBaseTrafficRule"] || changedKeys["kubernetesNamespacedTrafficRule"] || changedKeys["mirrorNamespaces"] || changedKeys["skipNamespaces"] {
		p.Notes = append(p.Notes, policy.RestartNoteConfig)
	}
	if live.Helm != nil {
		p.Notes = append(p.Notes, fmt.Sprintf("Helm release %q manages these objects: the next helm upgrade overwrites a live change. Prefer Export → Helm values.", live.Helm.Release))
		if !ch.Force && !p.Empty {
			p.Blocked, p.BlockReason = true, "the integration is managed by Helm"
		}
	}

	p.Findings = validate.Config(prop, e.ValidateOpts)
	before := validate.Config(live, e.ValidateOpts)
	p.Introduced, p.Resolved = compare(before, p.Findings)
	for _, f := range p.Introduced {
		if f.Severity == finding.Critical && !ch.Force {
			p.Blocked = true
			if p.BlockReason == "" {
				p.BlockReason = "the change introduces a critical problem: " + f.Message
			}
		}
	}
	p.Diffs = diffs(p)
	return p, nil
}

func argValue(args []string, flag string) string {
	for _, a := range discovery.ParseArgs(args) {
		if a.Flag == flag {
			return a.Value
		}
	}
	return ""
}

// display shortens values for the change list (certificates show their fingerprints).
func display(key, v string) string {
	if key == "sensorCert" {
		return certSummary(v)
	}
	if len(v) > 120 {
		return v[:120] + "…"
	}
	return v
}

func certSummary(pemData string) string {
	cs, problems := certs.ParseBundle(pemData)
	var parts []string
	for _, c := range certs.DescribeAll(cs, time.Now()) {
		parts = append(parts, fmt.Sprintf("%s %s (%s, expires %s)", c.Role, c.Subject, certs.ShortFP(c.SHA256), c.NotAfter.Format("2006-01-02")))
	}
	parts = append(parts, problems...)
	return strings.Join(parts, "; ")
}

func identity(f finding.Finding) string { return f.Code + "|" + f.Setting + "|" + f.Message }

func compare(before, after []finding.Finding) (introduced, resolved []finding.Finding) {
	b := map[string]bool{}
	for _, f := range before {
		b[identity(f)] = true
	}
	a := map[string]bool{}
	for _, f := range after {
		a[identity(f)] = true
		if !b[identity(f)] {
			introduced = append(introduced, f)
		}
	}
	for _, f := range before {
		if !a[identity(f)] {
			resolved = append(resolved, f)
		}
	}
	return
}

func (e *Engine) restarts(p *Plan, changedKeys map[string]bool) []Restart {
	why := map[string][]string{}
	add := func(w, reason string) {
		for _, r := range why[w] {
			if r == reason {
				return
			}
		}
		why[w] = append(why[w], reason)
	}
	for k := range changedKeys {
		for _, w := range discovery.WorkloadsUsing(p.live.Consumers(k)) {
			add(w, "reads "+k)
		}
	}
	for name, keys := range p.secretChanges {
		for k := range keys {
			for _, w := range discovery.WorkloadsUsing(p.live.SecretConsumers(name, k)) {
				add(w, "reads Secret "+name+"/"+k)
			}
		}
	}
	for w := range p.templateChanged {
		add(w, "pod template changed")
	}
	for _, w := range p.change.Restart {
		if p.live.Workload(w) != nil {
			add(w, "restart requested")
		}
	}
	var out []Restart
	for name, reasons := range why {
		w := p.live.Workload(name)
		if w == nil {
			continue
		}
		sort.Strings(reasons)
		out = append(out, Restart{Kind: w.Kind, Name: name, Why: reasons, Rolls: p.templateChanged[name]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---- diffs ----

func cmYAML(data map[string]string) string {
	shown := map[string]string{}
	for k, v := range data {
		if k == "sensorCert" {
			v = "# " + strings.ReplaceAll(certSummary(v), "; ", "\n# ")
		}
		shown[k] = v
	}
	b, _ := yaml.Marshal(shown)
	return string(b)
}

type containerView struct {
	Name    string   `json:"name"`
	Image   string   `json:"image"`
	Command []string `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
}

func templateYAML(w *discovery.Workload) string {
	var cs []containerView
	for _, c := range w.PodSpecRef().Containers {
		cs = append(cs, containerView{c.Name, c.Image, c.Command, c.Args})
	}
	b, _ := yaml.Marshal(cs)
	return string(b)
}

func diffs(p *Plan) []ObjectDiff {
	var out []ObjectDiff
	if p.cmChanged {
		out = append(out, ObjectDiff{"ConfigMap", p.live.ConfigMapName, UnifiedDiff(p.live.ConfigMapName, cmYAML(p.live.ConfigData), cmYAML(p.proposed.ConfigData))})
	}
	for name := range p.templateChanged {
		lw, pw := p.live.Workload(name), p.proposed.Workload(name)
		out = append(out, ObjectDiff{lw.Kind, name, UnifiedDiff(name, templateYAML(lw), templateYAML(pw))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind+out[i].Name < out[j].Kind+out[j].Name })
	return out
}

// ---- apply ----

type Result struct {
	Revision  int      `json:"revision"`
	Applied   []string `json:"applied"`
	Restarted []string `json:"restarted"`
}

type updater struct {
	apply func(ctx context.Context, dryRun bool) error
	name  string
}

// Apply dry-runs every object, records a revision of the live state, then applies.
func (e *Engine) Apply(ctx context.Context, p *Plan, who, kind string) (*Result, error) {
	if p.Empty {
		return nil, errors.New("nothing to apply")
	}
	if p.Blocked {
		return nil, errors.New("blocked: " + p.BlockReason)
	}
	ups, err := e.updaters(ctx, p)
	if err != nil {
		return nil, err
	}
	for _, u := range ups {
		if err := u.apply(ctx, true); err != nil {
			return nil, fmt.Errorf("dry run of %s rejected: %w", u.name, err)
		}
	}
	rev, err := e.SaveRevision(ctx, p.live, p, who, kind)
	if err != nil {
		return nil, fmt.Errorf("saving history: %w", err)
	}
	res := &Result{Revision: rev}
	for _, u := range ups {
		if err := u.apply(ctx, false); err != nil {
			return res, fmt.Errorf("applying %s: %w (applied so far: %s; revision %d holds the previous state)", u.name, err, strings.Join(res.Applied, ", "), rev)
		}
		res.Applied = append(res.Applied, u.name)
	}
	for _, r := range p.Restarts {
		res.Restarted = append(res.Restarted, r.Kind+"/"+r.Name)
	}
	e.log().Info("change applied", "user", who, "kind", kind, "revision", rev, "reason", p.Reason, "objects", res.Applied, "restarts", res.Restarted, "changes", auditChanges(p.Changes))
	return res, nil
}

func auditChanges(cs []FieldChange) []string {
	var out []string
	for _, c := range cs {
		if c.Secret {
			out = append(out, c.Object+" "+c.Field+" (secret value changed)")
		} else {
			out = append(out, fmt.Sprintf("%s %s: %q -> %q", c.Object, c.Field, c.Old, c.New))
		}
	}
	return out
}

func (e *Engine) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

func opts(dry bool) metav1.UpdateOptions {
	o := metav1.UpdateOptions{FieldManager: FieldManager}
	if dry {
		o.DryRun = []string{metav1.DryRunAll}
	}
	return o
}

// updaters builds the object updates in a safe order: Secrets, then the ConfigMap, then
// workloads (whose new pods must see the new values). Each update carries the resourceVersion
// the plan was built from, so a concurrent edit makes the apply fail instead of being lost.
func (e *Engine) updaters(ctx context.Context, p *Plan) ([]updater, error) {
	var ups []updater
	core := e.Kube.CoreV1()
	names := make([]string, 0, len(p.secretChanges))
	for n := range p.secretChanges {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		keys := p.secretChanges[name]
		sec, err := core.Secrets(e.Namespace).Get(ctx, name, metav1.GetOptions{})
		create := false
		if err != nil {
			sec = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: e.Namespace,
				Labels: map[string]string{"app.kubernetes.io/part-of": discovery.PartOf}}, Type: corev1.SecretTypeOpaque}
			create = true
		}
		if sec.Data == nil {
			sec.Data = map[string][]byte{}
		}
		for k, v := range keys {
			sec.Data[k] = v
		}
		s := sec
		ups = append(ups, updater{name: "Secret/" + name, apply: func(ctx context.Context, dry bool) error {
			if create {
				o := metav1.CreateOptions{FieldManager: FieldManager}
				if dry {
					o.DryRun = []string{metav1.DryRunAll}
				}
				_, err := core.Secrets(e.Namespace).Create(ctx, s, o)
				return err
			}
			_, err := core.Secrets(e.Namespace).Update(ctx, s, opts(dry))
			return err
		}})
	}
	if p.cmChanged {
		cm := p.live.ConfigMap.DeepCopy()
		cm.Data = map[string]string{}
		for k, v := range p.proposed.ConfigData {
			cm.Data[k] = v
		}
		ups = append(ups, updater{name: "ConfigMap/" + cm.Name, apply: func(ctx context.Context, dry bool) error {
			_, err := core.ConfigMaps(e.Namespace).Update(ctx, cm, opts(dry))
			return err
		}})
	}
	stamp := e.now().UTC().Format(time.RFC3339)
	for _, r := range p.Restarts {
		w := p.proposed.Workload(r.Name)
		if !r.Rolls {
			w.TemplateAnnotations()[RestartAnnotation] = stamp
		}
		switch {
		case w.Deployment != nil:
			d := w.Deployment
			ups = append(ups, updater{name: "Deployment/" + d.Name, apply: func(ctx context.Context, dry bool) error {
				_, err := e.Kube.AppsV1().Deployments(e.Namespace).Update(ctx, d, opts(dry))
				return err
			}})
		case w.DaemonSet != nil:
			d := w.DaemonSet
			ups = append(ups, updater{name: "DaemonSet/" + d.Name, apply: func(ctx context.Context, dry bool) error {
				_, err := e.Kube.AppsV1().DaemonSets(e.Namespace).Update(ctx, d, opts(dry))
				return err
			}})
		}
	}
	return ups, nil
}

// ---- rollout status ----

type RolloutStatus struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Done    bool   `json:"done"`
	Failed  bool   `json:"failed"`
	Ready   int32  `json:"ready"`
	Updated int32  `json:"updated"`
	Desired int32  `json:"desired"`
	Message string `json:"message,omitempty"`
}

// Rollouts reports progress for the named workloads.
func (e *Engine) Rollouts(ctx context.Context, names []string) []RolloutStatus {
	var out []RolloutStatus
	for _, n := range names {
		kind, name, _ := strings.Cut(n, "/")
		switch kind {
		case "Deployment":
			d, err := e.Kube.AppsV1().Deployments(e.Namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				out = append(out, RolloutStatus{Kind: kind, Name: name, Failed: true, Message: err.Error()})
				continue
			}
			out = append(out, deploymentStatus(d))
		case "DaemonSet":
			d, err := e.Kube.AppsV1().DaemonSets(e.Namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				out = append(out, RolloutStatus{Kind: kind, Name: name, Failed: true, Message: err.Error()})
				continue
			}
			s := d.Status
			out = append(out, RolloutStatus{Kind: kind, Name: name, Ready: s.NumberReady, Updated: s.UpdatedNumberScheduled, Desired: s.DesiredNumberScheduled,
				Done: s.ObservedGeneration >= d.Generation && s.UpdatedNumberScheduled == s.DesiredNumberScheduled && s.NumberAvailable == s.DesiredNumberScheduled})
		}
	}
	return out
}

func deploymentStatus(d *appsv1.Deployment) RolloutStatus {
	desired := int32(1)
	if d.Spec.Replicas != nil {
		desired = *d.Spec.Replicas
	}
	s := d.Status
	st := RolloutStatus{Kind: "Deployment", Name: d.Name, Ready: s.ReadyReplicas, Updated: s.UpdatedReplicas, Desired: desired,
		Done: s.ObservedGeneration >= d.Generation && s.UpdatedReplicas == desired && s.AvailableReplicas == desired && s.Replicas == desired}
	for _, c := range s.Conditions {
		if c.Type == appsv1.DeploymentProgressing && c.Reason == "ProgressDeadlineExceeded" {
			st.Failed, st.Message = true, c.Message
		}
	}
	return st
}

// ---- export ----

// HelmValues renders the proposed (or live) settings as a values file for the official chart.
// Settings the chart does not support are listed in a comment.
func HelmValues(s *discovery.Snapshot, prefix string, includeSecrets bool) string {
	values := map[string]any{}
	set := func(path string, v any) {
		parts := strings.Split(path, ".")
		m := values
		for _, p := range parts[:len(parts)-1] {
			next, ok := m[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				m[p] = next
			}
			m = next
		}
		m[parts[len(parts)-1]] = v
	}
	var unsupported []string
	for _, st := range model.Settings {
		v, ok := s.ConfigData[st.Key]
		if !ok {
			continue
		}
		if st.HelmPath == "" {
			unsupported = append(unsupported, fmt.Sprintf("%s=%q", st.Key, v))
			continue
		}
		set(st.HelmPath, v)
	}
	for _, ss := range model.Secrets {
		si := s.Secret(ss.SecretName(prefix))
		if si == nil || !si.Exists {
			continue
		}
		if includeSecrets {
			set(ss.HelmPath, string(si.Value(ss.Key)))
		} else {
			set(ss.HelmPath, "<set me>")
		}
	}
	for _, w := range s.Workloads {
		for _, c := range w.PodSpec.Containers {
			switch w.Component {
			case "metadata-forwarder":
				set("metadataForwarder.image", c.Image)
			case "session-key-forwarder":
				set("sessionKeyForwarder.image", c.Image)
				set("sessionKeyForwarder.include", true)
			case "exkpkt-coordinator":
				set("exkpkt.image", c.Image)
				if len(c.Ports) > 0 {
					set("exkpkt.servicePort", fmt.Sprint(c.Ports[0].ContainerPort))
				}
			}
		}
	}
	b, _ := yaml.Marshal(values)
	head := "# Values for oci://public.ecr.aws/extrahop/charts/kubernetes-integration, exported by eh-k8s-console.\n"
	if !includeSecrets {
		head += "# Secret values are placeholders: fill them in or pass them with --set.\n"
	}
	if len(unsupported) > 0 {
		head += "# Not supported by chart 1.0.0 (set on the ConfigMap after install): " + strings.Join(unsupported, ", ") + "\n"
	}
	return head + string(b)
}

// Manifests renders the ConfigMap and workloads of a snapshot as YAML (no Secrets).
func Manifests(s *discovery.Snapshot) (string, error) {
	var docs []string
	add := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if md, ok := m["metadata"].(map[string]any); ok {
			for _, k := range []string{"managedFields", "resourceVersion", "uid", "creationTimestamp", "generation"} {
				delete(md, k)
			}
		}
		delete(m, "status")
		y, err := yaml.Marshal(m)
		if err != nil {
			return err
		}
		docs = append(docs, string(y))
		return nil
	}
	if s.ConfigMap != nil {
		cm := s.ConfigMap.DeepCopy()
		cm.Data = s.ConfigData
		cm.APIVersion, cm.Kind = "v1", "ConfigMap"
		if err := add(cm); err != nil {
			return "", err
		}
	}
	for _, w := range s.Workloads {
		if w.Deployment != nil {
			d := w.Deployment.DeepCopy()
			d.APIVersion, d.Kind = "apps/v1", "Deployment"
			if err := add(d); err != nil {
				return "", err
			}
		}
		if w.DaemonSet != nil {
			d := w.DaemonSet.DeepCopy()
			d.APIVersion, d.Kind = "apps/v1", "DaemonSet"
			if err := add(d); err != nil {
				return "", err
			}
		}
	}
	return strings.Join(docs, "---\n"), nil
}

// Proposed exposes the proposed snapshot (for export of a pending change).
func (p *Plan) Proposed() *discovery.Snapshot { return p.proposed }
