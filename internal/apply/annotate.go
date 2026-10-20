package apply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/opswhisperer/eh-k8s-console/internal/config"
	"github.com/opswhisperer/eh-k8s-console/internal/discovery"
)

// Annotation edit modes.
const (
	// ModeNow annotates running pods (and nodes) directly: effective immediately, no restart, but
	// lost when a pod is replaced.
	ModeNow = "now"
	// ModePersist annotates the owning workload's pod template: lasting, but rolls its pods.
	ModePersist = "persist"
	// ModeBoth does both: effective now and kept for replacement pods (still rolls the workload).
	ModeBoth = "both"
)

type Target struct {
	Kind      string `json:"kind"` // Pod | Node | Deployment | StatefulSet | DaemonSet
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

type AnnotateRequest struct {
	Targets []Target `json:"targets,omitempty"`
	// Namespace + Selector pick pods by label selector.
	Namespace string `json:"namespace,omitempty"`
	Selector  string `json:"selector,omitempty"`
	// Rule is mirror, skip, or "" to remove the annotation.
	Rule   string `json:"rule"`
	Mode   string `json:"mode"`
	DryRun bool   `json:"dryRun"`
}

type AnnotateResult struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Action    string `json:"action"`
	// Rolls: the edit changes a pod template, so the workload's pods are replaced.
	Rolls bool   `json:"rolls,omitempty"`
	Error string `json:"error,omitempty"`
}

func patchFor(rule string, template bool) []byte {
	var v any = rule
	if rule == "" {
		v = nil // JSON null removes the key in a merge patch
	}
	ann := map[string]any{"annotations": map[string]any{discovery.MirrorAnnotation: v}}
	var body any = map[string]any{"metadata": ann}
	if template {
		body = map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": ann}}}
	}
	b, _ := json.Marshal(body)
	return b
}

// Annotate sets or removes extrahop.com/traffic-mirror-rule. The coordinator notices annotation
// changes on running pods and nodes without a restart.
func (e *Engine) Annotate(ctx context.Context, req AnnotateRequest, scope config.Annotations, who string) ([]AnnotateResult, error) {
	if !scope.Enabled {
		return nil, errors.New("annotation editing is disabled (integration.annotations.enabled)")
	}
	if req.Rule != "" && req.Rule != "mirror" && req.Rule != "skip" {
		return nil, fmt.Errorf("rule must be mirror, skip or empty (remove), not %q", req.Rule)
	}
	switch req.Mode {
	case "":
		req.Mode = ModeNow
	case ModeNow, ModePersist, ModeBoth:
	default:
		return nil, fmt.Errorf("unknown mode %q", req.Mode)
	}
	targets := append([]Target{}, req.Targets...)
	if req.Selector != "" || req.Namespace != "" && len(req.Targets) == 0 {
		if req.Namespace == "" {
			return nil, errors.New("a namespace is required with a selector")
		}
		pods, err := e.Kube.CoreV1().Pods(req.Namespace).List(ctx, metav1.ListOptions{LabelSelector: req.Selector})
		if err != nil {
			return nil, err
		}
		for _, p := range pods.Items {
			targets = append(targets, Target{Kind: "Pod", Namespace: p.Namespace, Name: p.Name})
		}
	}
	if len(targets) == 0 {
		return nil, errors.New("no targets matched")
	}
	if scope.MaxTargets > 0 && len(targets) > scope.MaxTargets {
		return nil, fmt.Errorf("%d targets exceeds the limit of %d; narrow the selector", len(targets), scope.MaxTargets)
	}

	var out []AnnotateResult
	templates := map[Target]bool{}
	action := "set " + discovery.MirrorAnnotation + "=" + req.Rule
	if req.Rule == "" {
		action = "removed " + discovery.MirrorAnnotation
	}
	dry := metav1.PatchOptions{FieldManager: FieldManager}
	if req.DryRun {
		dry.DryRun = []string{metav1.DryRunAll}
	}
	for _, t := range targets {
		res := AnnotateResult{Kind: t.Kind, Namespace: t.Namespace, Name: t.Name}
		if t.Kind != "Node" && !scope.Editable(t.Namespace) {
			res.Error = "namespace " + t.Namespace + " is not editable here (integration.annotations allow/exclude lists)"
			out = append(out, res)
			continue
		}
		switch t.Kind {
		case "Node":
			_, err := e.Kube.CoreV1().Nodes().Patch(ctx, t.Name, types.MergePatchType, patchFor(req.Rule, false), dry)
			res.Action, res.Error = action, errStr(err)
			out = append(out, res)
		case "Pod":
			if req.Mode == ModeNow || req.Mode == ModeBoth {
				_, err := e.Kube.CoreV1().Pods(t.Namespace).Patch(ctx, t.Name, types.MergePatchType, patchFor(req.Rule, false), dry)
				res.Action, res.Error = action, errStr(err)
				out = append(out, res)
			}
			if req.Mode == ModePersist || req.Mode == ModeBoth {
				owner, err := e.ownerWorkload(ctx, t)
				if err != nil {
					out = append(out, AnnotateResult{Kind: t.Kind, Namespace: t.Namespace, Name: t.Name, Error: "cannot persist: " + err.Error()})
					continue
				}
				templates[owner] = true
			}
		case "Deployment", "StatefulSet", "DaemonSet":
			templates[t] = true
		default:
			res.Error = "unsupported kind " + t.Kind + " (the integration reads annotations on pods and nodes)"
			out = append(out, res)
		}
	}
	keys := make([]Target, 0, len(templates))
	for t := range templates {
		keys = append(keys, t)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Namespace+keys[i].Name < keys[j].Namespace+keys[j].Name })
	for _, t := range keys {
		res := AnnotateResult{Kind: t.Kind, Namespace: t.Namespace, Name: t.Name, Action: action + " on the pod template", Rolls: true}
		var err error
		p := patchFor(req.Rule, true)
		switch t.Kind {
		case "Deployment":
			_, err = e.Kube.AppsV1().Deployments(t.Namespace).Patch(ctx, t.Name, types.StrategicMergePatchType, p, dry)
		case "StatefulSet":
			_, err = e.Kube.AppsV1().StatefulSets(t.Namespace).Patch(ctx, t.Name, types.StrategicMergePatchType, p, dry)
		case "DaemonSet":
			_, err = e.Kube.AppsV1().DaemonSets(t.Namespace).Patch(ctx, t.Name, types.StrategicMergePatchType, p, dry)
		}
		res.Error = errStr(err)
		out = append(out, res)
	}
	if !req.DryRun {
		e.log().Info("annotations changed", "user", who, "rule", req.Rule, "mode", req.Mode, "results", out)
	}
	return out, nil
}

func errStr(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

// ownerWorkload follows Pod → ReplicaSet → Deployment, or Pod → StatefulSet/DaemonSet.
func (e *Engine) ownerWorkload(ctx context.Context, t Target) (Target, error) {
	pod, err := e.Kube.CoreV1().Pods(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
	if err != nil {
		return Target{}, err
	}
	for _, o := range pod.OwnerReferences {
		if o.Controller == nil || !*o.Controller {
			continue
		}
		switch o.Kind {
		case "StatefulSet", "DaemonSet":
			return Target{Kind: o.Kind, Namespace: t.Namespace, Name: o.Name}, nil
		case "ReplicaSet":
			rs, err := e.Kube.AppsV1().ReplicaSets(t.Namespace).Get(ctx, o.Name, metav1.GetOptions{})
			if err != nil {
				return Target{}, err
			}
			for _, ro := range rs.OwnerReferences {
				if ro.Controller != nil && *ro.Controller && ro.Kind == "Deployment" {
					return Target{Kind: "Deployment", Namespace: t.Namespace, Name: ro.Name}, nil
				}
			}
			return Target{}, fmt.Errorf("ReplicaSet %s has no Deployment", o.Name)
		default:
			return Target{}, fmt.Errorf("owner %s/%s is not a Deployment, StatefulSet or DaemonSet", o.Kind, o.Name)
		}
	}
	return Target{}, errors.New("the pod has no controller; annotate it directly instead")
}
