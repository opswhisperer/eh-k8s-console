package ignore

import (
	"context"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

const sig = "SensorClient: SendDeviceProperties returned Bad Request [all_updates_invalid, device_not_found]"

func TestSuggestMatchesExactlyItsSignature(t *testing.T) {
	re, err := Validate(Suggest(sig))
	if err != nil {
		t.Fatal(err)
	}
	if !re.MatchString(sig) || re.MatchString(sig+" more") || re.MatchString("x"+sig) {
		t.Fatalf("suggested pattern %q is not exact", Suggest(sig))
	}
}

func TestValidateRefusesCatchAll(t *testing.T) {
	for _, p := range []string{"", ".*", "a|", "(", "x*"} {
		if _, err := Validate(p); err == nil {
			t.Errorf("%q should be refused", p)
		}
	}
}

func TestAddRemovePersistAndSources(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewSimpleClientset()
	s := NewStore(kube, "extrahop", "eh-k8s-console-ignore", []string{`packet poll failed$`}, false)
	if _, ok := s.Match("stopped reading packets on cali<id>: packet poll failed"); !ok {
		t.Fatal("config rule should match")
	}
	r, err := s.Add(ctx, Suggest(sig), "pods already gone", "rob")
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != SourceConsole || r.CreatedBy != "rob" {
		t.Fatalf("rule = %+v", r)
	}
	if _, err := s.Add(ctx, Suggest(sig), "", "rob"); err == nil {
		t.Fatal("duplicates must be refused")
	}
	// A second store (another replica / a restart) sees it after Load.
	s2 := NewStore(kube, "extrahop", "eh-k8s-console-ignore", nil, false)
	if err := s2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if got, ok := s2.Match(sig); !ok || got.Note != "pods already gone" {
		t.Fatalf("persisted rule not loaded: %+v %v", got, ok)
	}
	if err := s.Remove(ctx, `packet poll failed$`); err == nil {
		t.Fatal("config rules must not be removable from the console")
	}
	if err := s.Remove(ctx, Suggest(sig)); err != nil {
		t.Fatal(err)
	}
	s2.Load(ctx)
	if _, ok := s2.Match(sig); ok {
		t.Fatal("removed rule still matches")
	}
	ro := NewStore(kube, "extrahop", "eh-k8s-console-ignore", nil, true)
	if _, err := ro.Add(ctx, Suggest(sig), "", "rob"); err == nil {
		t.Fatal("read-only store must refuse")
	}
	var nilStore *Store
	if _, ok := nilStore.Match(sig); ok {
		t.Fatal("nil store matches nothing")
	}
}

func TestValidateRefusesBroadPatterns(t *testing.T) {
	for _, p := range []string{".", "^.+$", "[a-z]", `\w`, "<n>", ".{1,}"} {
		if _, err := Validate(p); err == nil {
			t.Errorf("%q should be refused as too broad", p)
		}
	}
	for _, p := range []string{Suggest(sig), `device_not_found\]$`, "^stopped reading packets on cali<id>: packet poll failed$", "connection refused"} {
		if _, err := Validate(p); err != nil {
			t.Errorf("%q should be allowed: %v", p, err)
		}
	}
}
