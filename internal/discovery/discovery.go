// Package discovery finds the ExtraHop Kubernetes integration's objects and works out which
// workload consumes which setting, by reading the manifests rather than assuming a layout.
package discovery

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// MirrorAnnotation overrides the namespace traffic rules for a single resource.
const MirrorAnnotation = "extrahop.com/traffic-mirror-rule"

// PartOf is the label value the official manifests put on every integration object.
const PartOf = "extrahop-kubernetes-integration"

type Options struct {
	Namespace   string
	Prefix      string
	ConfigMap   string
	Annotations bool
}

// Clients bundles the API clients discovery needs. Dynamic may be nil (no ExternalSecret info).
type Clients struct {
	Kube    kubernetes.Interface
	Dynamic dynamic.Interface
}

type Snapshot struct {
	TakenAt        time.Time         `json:"takenAt"`
	Namespace      string            `json:"namespace"`
	ConfigMapName  string            `json:"configMapName"`
	ConfigMapFound bool              `json:"configMapFound"`
	ConfigData     map[string]string `json:"configData"`
	Workloads      []*Workload       `json:"workloads"`
	Secrets        []*SecretInfo     `json:"secrets"`
	Refs           []Ref             `json:"refs"`
	Helm           *HelmInfo         `json:"helm,omitempty"`
	Namespaces     []string          `json:"namespaces"`
	Annotated      []Annotated       `json:"annotated,omitempty"`
	Errors         []string          `json:"errors,omitempty"`

	ConfigMap *corev1.ConfigMap `json:"-"`
}

type Workload struct {
	Kind               string            `json:"kind"`
	Name               string            `json:"name"`
	Component          string            `json:"component"`
	Desired            int32             `json:"desired"`
	Ready              int32             `json:"ready"`
	Updated            int32             `json:"updated"`
	Available          int32             `json:"available"`
	Generation         int64             `json:"generation"`
	ObservedGeneration int64             `json:"observedGeneration"`
	Images             map[string]string `json:"images"`
	Pods               []PodInfo         `json:"pods"`

	PodSpec  corev1.PodSpec        `json:"-"`
	Selector *metav1.LabelSelector `json:"-"`
	// Deployment or DaemonSet, exactly one set.
	Deployment *appsv1.Deployment `json:"-"`
	DaemonSet  *appsv1.DaemonSet  `json:"-"`
}

// Healthy: every desired replica is updated and ready, and the controller has seen the spec.
func (w *Workload) Healthy() bool {
	return w.ObservedGeneration >= w.Generation && w.Ready == w.Desired && w.Updated == w.Desired
}

type PodInfo struct {
	Name            string    `json:"name"`
	Node            string    `json:"node"`
	Phase           string    `json:"phase"`
	Ready           bool      `json:"ready"`
	Restarts        int32     `json:"restarts"`
	Started         time.Time `json:"started"`
	Containers      []string  `json:"containers"`
	LastTermination string    `json:"lastTermination,omitempty"`
	Waiting         string    `json:"waiting,omitempty"`
}

type SecretInfo struct {
	Name   string `json:"name"`
	Exists bool   `json:"exists"`
	// Keys maps each key to its value length; values are never exposed.
	Keys           map[string]int  `json:"keys"`
	ManagedBy      string          `json:"managedBy,omitempty"` // ExternalSecret | Helm
	ExternalSecret *ExternalSecret `json:"externalSecret,omitempty"`

	values map[string][]byte
}

// Value returns a secret value for server-side checks only; never send it to a client.
func (s *SecretInfo) Value(key string) []byte { return s.values[key] }

type ExternalSecret struct {
	Name            string `json:"name"`
	Store           string `json:"store"`
	Ready           bool   `json:"ready"`
	Reason          string `json:"reason,omitempty"`
	Message         string `json:"message,omitempty"`
	RefreshInterval string `json:"refreshInterval,omitempty"`
	RefreshTime     string `json:"refreshTime,omitempty"`
}

// Ref records one place a workload takes a setting from.
type Ref struct {
	Workload  string `json:"workload"`
	Kind      string `json:"kind"`
	Container string `json:"container"`
	// Via is how it is consumed: env:NAME, volume:NAME, arg:-flag.
	Via string `json:"via"`
	// Source: configmap | secret | arg | literal | field.
	Source string `json:"source"`
	Object string `json:"object,omitempty"`
	Key    string `json:"key"`
	// Value is set for args and literal env values only.
	Value string `json:"value,omitempty"`
}

type HelmInfo struct {
	Release string `json:"release"`
	Chart   string `json:"chart"`
}

type Annotated struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Rule      string `json:"rule"`
	// OnTemplate: the annotation is on a workload's pod template rather than the object itself.
	OnTemplate bool `json:"onTemplate,omitempty"`
	// Owner is a pod's controller (kind/name), if any.
	Owner string `json:"owner,omitempty"`
}

var esGVRs = []schema.GroupVersionResource{
	{Group: "external-secrets.io", Version: "v1", Resource: "externalsecrets"},
	{Group: "external-secrets.io", Version: "v1beta1", Resource: "externalsecrets"},
}

func (o Options) belongs(name string, lbls map[string]string) bool {
	return strings.HasPrefix(name, o.Prefix) || lbls["app.kubernetes.io/part-of"] == PartOf
}

func (o Options) component(name string, lbls map[string]string) string {
	if c := lbls["app.kubernetes.io/component"]; c != "" {
		return c
	}
	return strings.TrimPrefix(name, o.Prefix)
}

// Discover takes a snapshot. API errors on optional parts are recorded in Errors rather than
// failing the whole snapshot, so a missing permission degrades one panel, not the app.
func Discover(ctx context.Context, cl Clients, o Options) (*Snapshot, error) {
	k := cl.Kube
	s := &Snapshot{TakenAt: time.Now(), Namespace: o.Namespace, ConfigMapName: o.ConfigMap, ConfigData: map[string]string{}}

	cm, err := k.CoreV1().ConfigMaps(o.Namespace).Get(ctx, o.ConfigMap, metav1.GetOptions{})
	switch {
	case err == nil:
		s.ConfigMap, s.ConfigMapFound = cm, true
		for key, v := range cm.Data {
			s.ConfigData[key] = v
		}
		s.Helm = helmOf(cm.ObjectMeta)
	case apierrors.IsNotFound(err):
	default:
		return nil, fmt.Errorf("read ConfigMap %s/%s: %w", o.Namespace, o.ConfigMap, err)
	}

	deps, err := k.AppsV1().Deployments(o.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list Deployments: %w", err)
	}
	for i := range deps.Items {
		d := &deps.Items[i]
		if !o.belongs(d.Name, d.Labels) {
			continue
		}
		desired := int32(1)
		if d.Spec.Replicas != nil {
			desired = *d.Spec.Replicas
		}
		s.Workloads = append(s.Workloads, &Workload{
			Kind: "Deployment", Name: d.Name, Component: o.component(d.Name, d.Labels),
			Desired: desired, Ready: d.Status.ReadyReplicas, Updated: d.Status.UpdatedReplicas, Available: d.Status.AvailableReplicas,
			Generation: d.Generation, ObservedGeneration: d.Status.ObservedGeneration,
			PodSpec: d.Spec.Template.Spec, Selector: d.Spec.Selector, Deployment: d,
		})
		if s.Helm == nil {
			s.Helm = helmOf(d.ObjectMeta)
		}
	}
	dss, err := k.AppsV1().DaemonSets(o.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list DaemonSets: %w", err)
	}
	for i := range dss.Items {
		d := &dss.Items[i]
		if !o.belongs(d.Name, d.Labels) {
			continue
		}
		s.Workloads = append(s.Workloads, &Workload{
			Kind: "DaemonSet", Name: d.Name, Component: o.component(d.Name, d.Labels),
			Desired: d.Status.DesiredNumberScheduled, Ready: d.Status.NumberReady, Updated: d.Status.UpdatedNumberScheduled, Available: d.Status.NumberAvailable,
			Generation: d.Generation, ObservedGeneration: d.Status.ObservedGeneration,
			PodSpec: d.Spec.Template.Spec, Selector: d.Spec.Selector, DaemonSet: d,
		})
		if s.Helm == nil {
			s.Helm = helmOf(d.ObjectMeta)
		}
	}
	sort.Slice(s.Workloads, func(i, j int) bool { return s.Workloads[i].Name < s.Workloads[j].Name })

	pods, err := k.CoreV1().Pods(o.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		s.Errors = append(s.Errors, "list pods: "+err.Error())
	}
	secretNames := map[string]bool{}
	for _, w := range s.Workloads {
		w.Images = map[string]string{}
		for _, c := range w.PodSpec.Containers {
			w.Images[c.Name] = c.Image
		}
		s.Refs = append(s.Refs, refsOf(w)...)
		if pods != nil {
			sel, err := metav1.LabelSelectorAsSelector(w.Selector)
			if err == nil {
				for _, p := range pods.Items {
					if sel.Matches(labels.Set(p.Labels)) {
						w.Pods = append(w.Pods, podInfo(&p))
					}
				}
			}
		}
	}
	for _, r := range s.Refs {
		if r.Source == "secret" {
			secretNames[r.Object] = true
		}
	}

	esByTarget := map[string]*ExternalSecret{}
	if cl.Dynamic != nil {
		esByTarget = externalSecrets(ctx, cl.Dynamic, o.Namespace)
	}
	names := make([]string, 0, len(secretNames))
	for n := range secretNames {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		si := &SecretInfo{Name: n, Keys: map[string]int{}, values: map[string][]byte{}}
		sec, err := k.CoreV1().Secrets(o.Namespace).Get(ctx, n, metav1.GetOptions{})
		switch {
		case err == nil:
			si.Exists = true
			for key, v := range sec.Data {
				si.Keys[key] = len(v)
				si.values[key] = v
			}
			for key, v := range sec.StringData {
				si.Keys[key] = len(v)
				si.values[key] = []byte(v)
			}
			for _, or := range sec.OwnerReferences {
				if or.Kind == "ExternalSecret" {
					si.ManagedBy = "ExternalSecret"
				}
			}
			if si.ManagedBy == "" && sec.Labels["app.kubernetes.io/managed-by"] == "Helm" {
				si.ManagedBy = "Helm"
			}
		case apierrors.IsNotFound(err):
		default:
			s.Errors = append(s.Errors, fmt.Sprintf("read Secret %s: %v", n, err))
		}
		if es := esByTarget[n]; es != nil {
			si.ExternalSecret = es
			si.ManagedBy = "ExternalSecret"
		}
		s.Secrets = append(s.Secrets, si)
	}

	nsl, err := k.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		s.Errors = append(s.Errors, "list namespaces: "+err.Error())
	} else {
		for _, n := range nsl.Items {
			s.Namespaces = append(s.Namespaces, n.Name)
			if o.Annotations {
				if r, ok := n.Annotations[MirrorAnnotation]; ok {
					s.Annotated = append(s.Annotated, Annotated{Kind: "Namespace", Name: n.Name, Rule: r})
				}
			}
		}
		sort.Strings(s.Namespaces)
	}
	if o.Annotations {
		s.Annotated = append(s.Annotated, annotated(ctx, k, &s.Errors)...)
	}
	return s, nil
}

func helmOf(m metav1.ObjectMeta) *HelmInfo {
	if m.Labels["app.kubernetes.io/managed-by"] != "Helm" {
		return nil
	}
	rel := m.Annotations["meta.helm.sh/release-name"]
	if rel == "" {
		rel = m.Labels["app.kubernetes.io/instance"]
	}
	return &HelmInfo{Release: rel, Chart: m.Labels["helm.sh/chart"]}
}

func podInfo(p *corev1.Pod) PodInfo {
	pi := PodInfo{Name: p.Name, Node: p.Spec.NodeName, Phase: string(p.Status.Phase)}
	if p.Status.StartTime != nil {
		pi.Started = p.Status.StartTime.Time
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			pi.Ready = true
		}
	}
	for _, c := range p.Spec.Containers {
		pi.Containers = append(pi.Containers, c.Name)
	}
	for _, cs := range p.Status.ContainerStatuses {
		pi.Restarts += cs.RestartCount
		if t := cs.LastTerminationState.Terminated; t != nil {
			pi.LastTermination = fmt.Sprintf("%s (exit %d) at %s", t.Reason, t.ExitCode, t.FinishedAt.Format(time.RFC3339))
		}
		if w := cs.State.Waiting; w != nil {
			pi.Waiting = w.Reason
		}
	}
	return pi
}

// refsOf walks a pod spec for every setting it consumes.
func refsOf(w *Workload) []Ref {
	var out []Ref
	cmVolumes := map[string]*corev1.ConfigMapVolumeSource{}
	secretVolumes := map[string]*corev1.SecretVolumeSource{}
	for _, v := range w.PodSpec.Volumes {
		if v.ConfigMap != nil {
			cmVolumes[v.Name] = v.ConfigMap
		}
		if v.Secret != nil {
			secretVolumes[v.Name] = v.Secret
		}
	}
	containers := append(append([]corev1.Container{}, w.PodSpec.InitContainers...), w.PodSpec.Containers...)
	for _, c := range containers {
		base := Ref{Workload: w.Name, Kind: w.Kind, Container: c.Name}
		for _, e := range c.Env {
			r := base
			r.Via = "env:" + e.Name
			switch {
			case e.ValueFrom == nil:
				r.Source, r.Key, r.Value = "literal", e.Name, e.Value
			case e.ValueFrom.ConfigMapKeyRef != nil:
				r.Source, r.Object, r.Key = "configmap", e.ValueFrom.ConfigMapKeyRef.Name, e.ValueFrom.ConfigMapKeyRef.Key
			case e.ValueFrom.SecretKeyRef != nil:
				r.Source, r.Object, r.Key = "secret", e.ValueFrom.SecretKeyRef.Name, e.ValueFrom.SecretKeyRef.Key
			case e.ValueFrom.FieldRef != nil:
				r.Source, r.Key = "field", e.ValueFrom.FieldRef.FieldPath
			default:
				continue
			}
			out = append(out, r)
		}
		for _, ef := range c.EnvFrom {
			r := base
			if ef.ConfigMapRef != nil {
				r.Via, r.Source, r.Object, r.Key = "envFrom", "configmap", ef.ConfigMapRef.Name, "*"
				out = append(out, r)
			}
			if ef.SecretRef != nil {
				r.Via, r.Source, r.Object, r.Key = "envFrom", "secret", ef.SecretRef.Name, "*"
				out = append(out, r)
			}
		}
		mounted := map[string]bool{}
		for _, m := range c.VolumeMounts {
			mounted[m.Name] = true
		}
		for name, v := range cmVolumes {
			if !mounted[name] {
				continue
			}
			if len(v.Items) == 0 {
				out = append(out, Ref{Workload: w.Name, Kind: w.Kind, Container: c.Name, Via: "volume:" + name, Source: "configmap", Object: v.Name, Key: "*"})
			}
			for _, it := range v.Items {
				out = append(out, Ref{Workload: w.Name, Kind: w.Kind, Container: c.Name, Via: "volume:" + name, Source: "configmap", Object: v.Name, Key: it.Key})
			}
		}
		for name, v := range secretVolumes {
			if !mounted[name] {
				continue
			}
			if len(v.Items) == 0 {
				out = append(out, Ref{Workload: w.Name, Kind: w.Kind, Container: c.Name, Via: "volume:" + name, Source: "secret", Object: v.SecretName, Key: "*"})
			}
			for _, it := range v.Items {
				out = append(out, Ref{Workload: w.Name, Kind: w.Kind, Container: c.Name, Via: "volume:" + name, Source: "secret", Object: v.SecretName, Key: it.Key})
			}
		}
		for _, a := range ParseArgs(append(append([]string{}, c.Command...), c.Args...)) {
			r := base
			r.Via, r.Source, r.Key, r.Value = "arg:"+a.Flag, "arg", a.Flag, a.Value
			out = append(out, r)
		}
	}
	return out
}

// Arg is one flag from a container command line. Repeated flags appear once per use.
type Arg struct {
	Index int    // position of the flag in the combined command+args
	Flag  string // as written, e.g. -server
	Value string
	// Inline: written as -flag=value.
	Inline bool
	// HasValue: false for a boolean flag followed by another flag (or end).
	HasValue bool
}

// ParseArgs reads Go-style flags: -flag value, -flag=value, --flag value.
func ParseArgs(argv []string) []Arg {
	var out []Arg
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if !strings.HasPrefix(a, "-") || a == "-" || a == "--" {
			continue
		}
		if f, v, ok := strings.Cut(a, "="); ok {
			out = append(out, Arg{Index: i, Flag: f, Value: v, Inline: true, HasValue: true})
			continue
		}
		if i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
			out = append(out, Arg{Index: i, Flag: a, Value: argv[i+1], HasValue: true})
			i++
			continue
		}
		out = append(out, Arg{Index: i, Flag: a})
	}
	return out
}

func externalSecrets(ctx context.Context, d dynamic.Interface, ns string) map[string]*ExternalSecret {
	out := map[string]*ExternalSecret{}
	for _, gvr := range esGVRs {
		list, err := d.Resource(gvr).Namespace(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, it := range list.Items {
			out[esTarget(&it)] = esInfo(&it)
		}
		return out
	}
	return out
}

func esTarget(u *unstructured.Unstructured) string {
	if t, _, _ := unstructured.NestedString(u.Object, "spec", "target", "name"); t != "" {
		return t
	}
	return u.GetName()
}

func esInfo(u *unstructured.Unstructured) *ExternalSecret {
	es := &ExternalSecret{Name: u.GetName()}
	es.Store, _, _ = unstructured.NestedString(u.Object, "spec", "secretStoreRef", "name")
	if kind, _, _ := unstructured.NestedString(u.Object, "spec", "secretStoreRef", "kind"); kind != "" {
		es.Store = kind + "/" + es.Store
	}
	es.RefreshInterval, _, _ = unstructured.NestedString(u.Object, "spec", "refreshInterval")
	es.RefreshTime, _, _ = unstructured.NestedString(u.Object, "status", "refreshTime")
	conds, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	for _, c := range conds {
		m, ok := c.(map[string]any)
		if !ok || m["type"] != "Ready" {
			continue
		}
		es.Ready = m["status"] == "True"
		es.Reason, _ = m["reason"].(string)
		es.Message, _ = m["message"].(string)
	}
	return es
}

func annotated(ctx context.Context, k kubernetes.Interface, errs *[]string) []Annotated {
	var out []Annotated
	// Pods and nodes are what the coordinator honours. Workload templates are listed because that
	// is where a lasting pod annotation belongs. Services are listed so a misplaced annotation is
	// visible; the validator flags kinds the integration does not read.
	if pods, err := k.CoreV1().Pods("").List(ctx, metav1.ListOptions{}); err != nil {
		*errs = append(*errs, "list pods (annotations): "+err.Error())
	} else {
		for _, p := range pods.Items {
			if r, ok := p.Annotations[MirrorAnnotation]; ok {
				out = append(out, Annotated{Kind: "Pod", Namespace: p.Namespace, Name: p.Name, Rule: r, Owner: controllerOf(&p)})
			}
		}
	}
	if nodes, err := k.CoreV1().Nodes().List(ctx, metav1.ListOptions{}); err != nil {
		*errs = append(*errs, "list nodes (annotations): "+err.Error())
	} else {
		for _, n := range nodes.Items {
			if r, ok := n.Annotations[MirrorAnnotation]; ok {
				out = append(out, Annotated{Kind: "Node", Name: n.Name, Rule: r})
			}
		}
	}
	if svcs, err := k.CoreV1().Services("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, s := range svcs.Items {
			if r, ok := s.Annotations[MirrorAnnotation]; ok {
				out = append(out, Annotated{Kind: "Service", Namespace: s.Namespace, Name: s.Name, Rule: r})
			}
		}
	}
	if l, err := k.AppsV1().Deployments("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, d := range l.Items {
			if r, ok := d.Spec.Template.Annotations[MirrorAnnotation]; ok {
				out = append(out, Annotated{Kind: "Deployment", Namespace: d.Namespace, Name: d.Name, Rule: r, OnTemplate: true})
			}
		}
	} else {
		*errs = append(*errs, "list deployments (annotations): "+err.Error())
	}
	if l, err := k.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, d := range l.Items {
			if r, ok := d.Spec.Template.Annotations[MirrorAnnotation]; ok {
				out = append(out, Annotated{Kind: "StatefulSet", Namespace: d.Namespace, Name: d.Name, Rule: r, OnTemplate: true})
			}
		}
	}
	if l, err := k.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, d := range l.Items {
			if r, ok := d.Spec.Template.Annotations[MirrorAnnotation]; ok {
				out = append(out, Annotated{Kind: "DaemonSet", Namespace: d.Namespace, Name: d.Name, Rule: r, OnTemplate: true})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return a.Kind+"/"+a.Namespace+"/"+a.Name < b.Kind+"/"+b.Namespace+"/"+b.Name
	})
	return out
}

// controllerOf names a pod's controller. An annotation set directly on such a pod is lost when
// the pod is replaced, which the UI points out.
func controllerOf(p *corev1.Pod) string {
	for _, o := range p.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			return o.Kind + "/" + o.Name
		}
	}
	return ""
}

// Consumers returns the refs that read ConfigMap key `key` (or the whole ConfigMap).
func (s *Snapshot) Consumers(key string) []Ref {
	var out []Ref
	for _, r := range s.Refs {
		if r.Source == "configmap" && r.Object == s.ConfigMapName && (r.Key == key || r.Key == "*") {
			out = append(out, r)
		}
	}
	return out
}

// SecretConsumers returns refs to Secret name/key.
func (s *Snapshot) SecretConsumers(name, key string) []Ref {
	var out []Ref
	for _, r := range s.Refs {
		if r.Source == "secret" && r.Object == name && (r.Key == key || r.Key == "*") {
			out = append(out, r)
		}
	}
	return out
}

// ArgRefs returns every use of a command-line flag across workloads.
func (s *Snapshot) ArgRefs(flag string) []Ref {
	var out []Ref
	for _, r := range s.Refs {
		if r.Source == "arg" && r.Key == flag {
			out = append(out, r)
		}
	}
	return out
}

func (s *Snapshot) Workload(name string) *Workload {
	for _, w := range s.Workloads {
		if w.Name == name {
			return w
		}
	}
	return nil
}

func (s *Snapshot) Secret(name string) *SecretInfo {
	for _, si := range s.Secrets {
		if si.Name == name {
			return si
		}
	}
	return nil
}

// WorkloadsUsing returns the distinct workload names among refs.
func WorkloadsUsing(refs []Ref) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range refs {
		if !seen[r.Workload] {
			seen[r.Workload] = true
			out = append(out, r.Workload)
		}
	}
	sort.Strings(out)
	return out
}

// Clone deep-copies the snapshot so a proposed change can be validated without touching the
// live view. Secret values are shared (read-only).
func (s *Snapshot) Clone() *Snapshot {
	c := *s
	c.ConfigData = make(map[string]string, len(s.ConfigData))
	for k, v := range s.ConfigData {
		c.ConfigData[k] = v
	}
	if s.ConfigMap != nil {
		c.ConfigMap = s.ConfigMap.DeepCopy()
	}
	c.Workloads = make([]*Workload, len(s.Workloads))
	for i, w := range s.Workloads {
		nw := *w
		if w.Deployment != nil {
			nw.Deployment = w.Deployment.DeepCopy()
			nw.PodSpec = nw.Deployment.Spec.Template.Spec
		}
		if w.DaemonSet != nil {
			nw.DaemonSet = w.DaemonSet.DeepCopy()
			nw.PodSpec = nw.DaemonSet.Spec.Template.Spec
		}
		nw.Images = map[string]string{}
		for k, v := range w.Images {
			nw.Images[k] = v
		}
		nw.Pods = append([]PodInfo{}, w.Pods...)
		c.Workloads[i] = &nw
	}
	c.Secrets = make([]*SecretInfo, len(s.Secrets))
	for i, si := range s.Secrets {
		n := *si
		n.Keys = map[string]int{}
		for k, v := range si.Keys {
			n.Keys[k] = v
		}
		n.values = map[string][]byte{}
		for k, v := range si.values {
			n.values[k] = v
		}
		c.Secrets[i] = &n
	}
	c.Refs = append([]Ref{}, s.Refs...)
	c.Annotated = append([]Annotated{}, s.Annotated...)
	c.Namespaces = append([]string{}, s.Namespaces...)
	c.Errors = append([]string{}, s.Errors...)
	return &c
}

// PodSpecRef returns a pointer to the workload's live pod spec inside its object, so edits land
// in the object that gets applied.
func (w *Workload) PodSpecRef() *corev1.PodSpec {
	if w.Deployment != nil {
		return &w.Deployment.Spec.Template.Spec
	}
	return &w.DaemonSet.Spec.Template.Spec
}

// TemplateAnnotations returns the pod template annotations map, creating it if needed.
func (w *Workload) TemplateAnnotations() map[string]string {
	var m *metav1.ObjectMeta
	if w.Deployment != nil {
		m = &w.Deployment.Spec.Template.ObjectMeta
	} else {
		m = &w.DaemonSet.Spec.Template.ObjectMeta
	}
	if m.Annotations == nil {
		m.Annotations = map[string]string{}
	}
	return m.Annotations
}

// RefreshRefs re-derives Refs and Images after pod specs were edited.
func (s *Snapshot) RefreshRefs() {
	s.Refs = nil
	for _, w := range s.Workloads {
		w.PodSpec = *w.PodSpecRef()
		w.Images = map[string]string{}
		for _, c := range w.PodSpec.Containers {
			w.Images[c.Name] = c.Image
		}
		s.Refs = append(s.Refs, refsOf(w)...)
	}
}

// SetSecretValue records a proposed secret value (for validating a change before apply).
func (si *SecretInfo) SetSecretValue(key string, v []byte) {
	if si.values == nil {
		si.values = map[string][]byte{}
	}
	si.values[key] = v
	si.Keys[key] = len(v)
	si.Exists = true
}

// NewSecretInfo builds a SecretInfo with values, for tests and offline (file) snapshots.
func NewSecretInfo(name string, data map[string][]byte) *SecretInfo {
	si := &SecretInfo{Name: name, Exists: true, Keys: map[string]int{}, values: map[string][]byte{}}
	for k, v := range data {
		si.Keys[k] = len(v)
		si.values[k] = v
	}
	return si
}
