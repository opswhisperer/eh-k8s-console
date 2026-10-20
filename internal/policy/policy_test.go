package policy

import "testing"

var (
	shop  = Endpoint{Kind: Pod, Namespace: "shop"}
	batch = Endpoint{Kind: Pod, Namespace: "batch"}
	quiet = Endpoint{Kind: Pod, Namespace: "shop", Annotation: "skip"}
	loud  = Endpoint{Kind: Pod, Namespace: "batch", Annotation: "mirror"}
	node  = Endpoint{Kind: Node}
	out   = Endpoint{Kind: External}
	pol   = Policy{Base: "mirror", Namespaced: "skip", Mirror: []string{"shop"}, Skip: []string{"batch"}}
)

func TestFirstMatchingStepDecides(t *testing.T) {
	a := []Step{SkipList, MirrorList, NamespacedRule, BaseRule}
	b := []Step{MirrorList, SkipList, NamespacedRule, BaseRule}
	if d := Evaluate(a, pol, shop, batch); d.Mirror || d.Step != SkipList || d.Rule != 1 {
		t.Fatalf("order a: %+v", d)
	}
	if d := Evaluate(b, pol, shop, batch); !d.Mirror || d.Step != MirrorList {
		t.Fatalf("order b: %+v", d)
	}
}

func TestStepsMatchTheirPeers(t *testing.T) {
	all := Steps
	cases := []struct {
		peers  []Endpoint
		mirror bool
		step   Step
	}{
		{[]Endpoint{quiet, out}, false, AnnotationSkip},
		{[]Endpoint{loud, out}, true, AnnotationMirror},
		{[]Endpoint{batch, out}, false, SkipList},
		{[]Endpoint{shop, out}, true, MirrorList},
		{[]Endpoint{{Kind: Pod, Namespace: "misc"}, out}, false, NamespacedRule},
		{[]Endpoint{node, node}, true, BaseRule},
	}
	for _, c := range cases {
		if d := Evaluate(all, pol, c.peers...); d.Mirror != c.mirror || d.Step != c.step {
			t.Errorf("%v: got %+v, want %s mirror=%v", c.peers, d, c.step, c.mirror)
		}
	}
	if d := Evaluate(all, pol, out, out); !d.Mirror || d.Rule != 0 {
		t.Fatalf("no Kubernetes peer: %+v", d)
	}
}

func TestNoOrderMeansNoPreview(t *testing.T) {
	if rows, nodes := Overview(nil, pol, []string{"shop"}); rows != nil || nodes != nil {
		t.Fatal("overview without an order must be empty")
	}
	if _, err := ParseOrder([]string{"annotation:skip", "made-up"}); err == nil {
		t.Fatal("unknown steps must be refused")
	}
	if _, err := ParseOrder([]string{"cluster:rule", "cluster:rule"}); err == nil {
		t.Fatal("duplicates must be refused")
	}
}

func TestDefaultsAndModes(t *testing.T) {
	p := FromConfig(map[string]string{})
	if p.Base != "mirror" || p.Namespaced != "mirror" || DetectMode(p) != "all-except" {
		t.Fatalf("defaults = %+v mode %s", p, DetectMode(p))
	}
	if DetectMode(FromConfig(map[string]string{"kubernetesNamespacedTrafficRule": "skip"})) != "only-annotated" {
		t.Fatal("skip with no lists is annotation-only")
	}
	p = FromConfig(map[string]string{"kubernetesNamespacedTrafficRule": "skip", "mirrorNamespaces": "a b"})
	if DetectMode(p) != "only-listed" || len(p.Mirror) != 2 {
		t.Fatalf("got %+v", p)
	}
}
