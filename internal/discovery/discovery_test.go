package discovery_test

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"

	"github.com/opswhisperer/eh-k8s-console/internal/discovery"
	"github.com/opswhisperer/eh-k8s-console/internal/testfix"
)

func opts() discovery.Options {
	return discovery.Options{Namespace: testfix.NS, Prefix: testfix.Prefix, ConfigMap: testfix.CM, Annotations: true}
}

func TestDiscoverSensorGeneratedLayout(t *testing.T) {
	cs := testfix.Clientset(t, testfix.Options{Extra: []k8sruntime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "media", Annotations: map[string]string{discovery.MirrorAnnotation: "skip"}}},
	}})
	s, err := discovery.Discover(context.Background(), discovery.Clients{Kube: cs}, opts())
	if err != nil {
		t.Fatal(err)
	}
	if !s.ConfigMapFound || len(s.Workloads) != 4 {
		t.Fatalf("found cm=%v workloads=%d", s.ConfigMapFound, len(s.Workloads))
	}
	comps := map[string]bool{}
	for _, w := range s.Workloads {
		comps[w.Component] = true
	}
	for _, c := range []string{"metadata-forwarder", "exkpkt-coordinator", "exkpkt-forwarder", "session-key-forwarder"} {
		if !comps[c] {
			t.Errorf("component %s not discovered (have %v)", c, comps)
		}
	}

	// The consumer graph is derived from the manifests.
	certUsers := discovery.WorkloadsUsing(s.Consumers("sensorCert"))
	if len(certUsers) != 2 {
		t.Fatalf("sensorCert consumers = %v, want metadata-forwarder and session-key-forwarder", certUsers)
	}
	if got := discovery.WorkloadsUsing(s.Consumers("mgmtTarget")); len(got) != 1 || got[0] != testfix.Prefix+"metadata-forwarder" {
		t.Fatalf("mgmtTarget consumers = %v", got)
	}
	skf := s.ArgRefs("-server")
	if len(skf) != 1 || skf[0].Value != "192.0.2.10" || skf[0].Workload != testfix.Prefix+"session-key-forwarder" {
		t.Fatalf("-server arg refs = %+v", skf)
	}
	if len(s.Secrets) != 3 {
		t.Fatalf("secrets = %d, want 3", len(s.Secrets))
	}
	for _, si := range s.Secrets {
		if !si.Exists || len(si.Keys) != 1 {
			t.Errorf("secret %s: %+v", si.Name, si)
		}
	}
	if len(s.Annotated) != 1 || s.Annotated[0].Name != "media" || s.Annotated[0].Rule != "skip" {
		t.Fatalf("annotated = %+v", s.Annotated)
	}
	if s.Helm != nil {
		t.Fatalf("the fixture is raw manifests, not Helm: %+v", s.Helm)
	}
	if s.ArgoCD != nil {
		t.Fatalf("the fixture has no Argo CD tracking: %+v", s.ArgoCD)
	}
}

func TestDiscoverArgoCDTracking(t *testing.T) {
	cs := testfix.Clientset(t, testfix.Options{})
	cm, err := cs.CoreV1().ConfigMaps(opts().Namespace).Get(context.Background(), opts().ConfigMap, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cm.Annotations = map[string]string{discovery.ArgoCDTrackingAnnotation: "eh-integration:/ConfigMap:" + cm.Namespace + "/" + cm.Name}
	if _, err := cs.CoreV1().ConfigMaps(cm.Namespace).Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	s, err := discovery.Discover(context.Background(), discovery.Clients{Kube: cs}, opts())
	if err != nil {
		t.Fatal(err)
	}
	if s.ArgoCD == nil || s.ArgoCD.Application != "eh-integration" {
		t.Fatalf("argocd = %+v", s.ArgoCD)
	}
}

func TestParseArgs(t *testing.T) {
	got := discovery.ParseArgs([]string{"-server", "a", "-docker-enable=false", "-containerd-enable", "-cert", "/c", "-wait-for-children"})
	want := []discovery.Arg{
		{Index: 0, Flag: "-server", Value: "a", HasValue: true},
		{Index: 2, Flag: "-docker-enable", Value: "false", Inline: true, HasValue: true},
		{Index: 3, Flag: "-containerd-enable"},
		{Index: 4, Flag: "-cert", Value: "/c", HasValue: true},
		{Index: 6, Flag: "-wait-for-children"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("arg %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestCloneIsIndependent(t *testing.T) {
	s, err := discovery.Discover(context.Background(), discovery.Clients{Kube: testfix.Clientset(t, testfix.Options{})}, opts())
	if err != nil {
		t.Fatal(err)
	}
	c := s.Clone()
	c.ConfigData["mgmtTarget"] = "changed"
	c.Workloads[0].PodSpecRef().Containers[0].Image = "changed"
	c.RefreshRefs()
	if s.ConfigData["mgmtTarget"] == "changed" || s.Workloads[0].PodSpec.Containers[0].Image == "changed" {
		t.Fatal("clone shares state with the original")
	}
	if c.Workloads[0].Images[c.Workloads[0].PodSpec.Containers[0].Name] != "changed" {
		t.Fatal("RefreshRefs did not pick up the edited image")
	}
}
