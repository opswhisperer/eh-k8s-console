// Package policy previews the integration's traffic filtering so the UI can show what gets
// mirrored and why, before a change is applied.
//
// The console does not assume an evaluation order: the steps come from the config
// (policy.order), so the preview matches the traffic-forwarder version you run. With no order
// configured the preview is off; the console still edits the settings and annotations.
package policy

import (
	"fmt"
	"strings"

	"github.com/opswhisperer/eh-k8s-console/internal/model"
)

type Kind string

const (
	Pod      Kind = "pod"
	Node     Kind = "node"
	External Kind = "external"
)

// Step is one rule in the evaluation order. A step matches when any Kubernetes peer of the
// conversation matches it; the first matching step decides.
type Step string

const (
	AnnotationSkip   Step = "annotation:skip"       // a peer annotated skip -> skip
	AnnotationMirror Step = "annotation:mirror"     // a peer annotated mirror -> mirror
	SkipList         Step = "namespace:skip-list"   // a pod peer in Skip namespaces -> skip
	MirrorList       Step = "namespace:mirror-list" // a pod peer in Mirror namespaces -> mirror
	NamespacedRule   Step = "namespace:rule"        // a pod peer -> kubernetesNamespacedTrafficRule
	BaseRule         Step = "cluster:rule"          // any Kubernetes peer -> kubernetesBaseTrafficRule
)

// Steps lists every known step, for validation and docs.
var Steps = []Step{AnnotationSkip, AnnotationMirror, SkipList, MirrorList, NamespacedRule, BaseRule}

// ParseOrder validates a configured order.
func ParseOrder(order []string) ([]Step, error) {
	known := map[Step]bool{}
	for _, s := range Steps {
		known[s] = true
	}
	seen := map[Step]bool{}
	var out []Step
	for _, o := range order {
		s := Step(strings.TrimSpace(o))
		if !known[s] {
			names := make([]string, len(Steps))
			for i, k := range Steps {
				names[i] = string(k)
			}
			return nil, fmt.Errorf("unknown policy step %q (known: %s)", o, strings.Join(names, ", "))
		}
		if seen[s] {
			return nil, fmt.Errorf("policy step %q is listed twice", o)
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}

// Endpoint is one side of a conversation.
type Endpoint struct {
	Kind       Kind   `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name,omitempty"`
	Annotation string `json:"annotation,omitempty"` // "", mirror, skip
}

func (e Endpoint) String() string {
	switch e.Kind {
	case Pod:
		if e.Name == "" {
			return "a pod in " + e.Namespace
		}
		return "pod " + e.Namespace + "/" + e.Name
	case Node:
		if e.Name == "" {
			return "a node"
		}
		return "node " + e.Name
	}
	if e.Name != "" {
		return e.Name
	}
	return "an address outside the cluster"
}

// Policy is the filtering configuration.
type Policy struct {
	Base       string   `json:"base"`
	Namespaced string   `json:"namespaced"`
	Mirror     []string `json:"mirrorNamespaces"`
	Skip       []string `json:"skipNamespaces"`
}

// FromConfig reads a Policy from ConfigMap data, applying the documented defaults (mirror).
func FromConfig(d map[string]string) Policy {
	p := Policy{Base: d["kubernetesBaseTrafficRule"], Namespaced: d["kubernetesNamespacedTrafficRule"],
		Mirror: model.SplitList(d["mirrorNamespaces"]), Skip: model.SplitList(d["skipNamespaces"])}
	if p.Base == "" {
		p.Base = "mirror"
	}
	if p.Namespaced == "" {
		p.Namespaced = "mirror"
	}
	return p
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Decision explains the outcome.
type Decision struct {
	Mirror bool   `json:"mirror"`
	Rule   int    `json:"rule"` // 1-based position in the order; 0 = no step matched
	Step   Step   `json:"step,omitempty"`
	Reason string `json:"reason"`
}

func verdict(rule string) bool { return rule != "skip" }

// Evaluate decides for one endpoint (its traffic with outside addresses) or a pair of peers.
func Evaluate(order []Step, p Policy, peers ...Endpoint) Decision {
	var k8s []Endpoint
	for _, e := range peers {
		if e.Kind == Pod || e.Kind == Node {
			k8s = append(k8s, e)
		}
	}
	if len(k8s) == 0 {
		return Decision{Mirror: true, Reason: "No Kubernetes peer, so these settings don't apply."}
	}
	for i, step := range order {
		d := Decision{Rule: i + 1, Step: step}
		for _, e := range k8s {
			switch {
			case step == AnnotationSkip && e.Annotation == "skip":
				d.Mirror, d.Reason = false, fmt.Sprintf("%s is annotated skip.", e)
			case step == AnnotationMirror && e.Annotation == "mirror":
				d.Mirror, d.Reason = true, fmt.Sprintf("%s is annotated mirror.", e)
			case step == SkipList && e.Kind == Pod && contains(p.Skip, e.Namespace):
				d.Mirror, d.Reason = false, fmt.Sprintf("Namespace %s is in Skip namespaces.", e.Namespace)
			case step == MirrorList && e.Kind == Pod && contains(p.Mirror, e.Namespace):
				d.Mirror, d.Reason = true, fmt.Sprintf("Namespace %s is in Mirror namespaces.", e.Namespace)
			case step == NamespacedRule && e.Kind == Pod:
				d.Mirror, d.Reason = verdict(p.Namespaced), fmt.Sprintf("%s: the namespace rule (%s) applies.", e, p.Namespaced)
			case step == BaseRule:
				d.Mirror, d.Reason = verdict(p.Base), fmt.Sprintf("The cluster-scoped rule (%s) applies.", p.Base)
			default:
				continue
			}
			return d
		}
	}
	return Decision{Mirror: true, Reason: "No step in policy.order matched."}
}

// NamespaceRow is the default outcome for unannotated pods in one namespace.
type NamespaceRow struct {
	Namespace string   `json:"namespace"`
	Decision  Decision `json:"decision"`
}

// Overview evaluates every namespace (for unannotated pods talking to outside addresses) and
// unannotated nodes. It returns nothing when no order is configured.
func Overview(order []Step, p Policy, namespaces []string) (rows []NamespaceRow, nodes *Decision) {
	if len(order) == 0 {
		return nil, nil
	}
	for _, ns := range namespaces {
		rows = append(rows, NamespaceRow{ns, Evaluate(order, p, Endpoint{Kind: Pod, Namespace: ns})})
	}
	d := Evaluate(order, p, Endpoint{Kind: Node})
	return rows, &d
}

// Mode is a named filtering preset shown in the editor.
type Mode struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

var Modes = []Mode{
	{"all-except", "Mirror everything except…", "Namespace rule mirror, with Skip namespaces and skip annotations for exceptions."},
	{"only-listed", "Mirror only listed namespaces", "Namespace rule skip with Mirror namespaces. Annotate individual workloads to add or remove them."},
	{"only-annotated", "Mirror only annotated workloads", "Namespace rule skip and no namespace lists: only resources annotated mirror are forwarded."},
	{"custom", "Custom", "Set each rule and list yourself."},
}

// DetectMode names the preset a configuration matches.
func DetectMode(p Policy) string {
	switch {
	case p.Namespaced == "mirror" && len(p.Mirror) == 0:
		return "all-except"
	case p.Namespaced == "skip" && len(p.Mirror) > 0 && len(p.Skip) == 0:
		return "only-listed"
	case p.Namespaced == "skip" && len(p.Mirror) == 0 && len(p.Skip) == 0:
		return "only-annotated"
	}
	return "custom"
}

// Notes shown with filtering changes. They describe what the manifests show (the rules reach the
// coordinator as environment variables) and plain Kubernetes behaviour.
const (
	RestartNoteConfig     = "The traffic rules and namespace lists reach the coordinator as environment variables, so changes take effect when it restarts."
	RestartNoteAnnotation = "Annotating running pods doesn't restart them. Putting the annotation on a workload's pod template rolls that workload's pods."
)
