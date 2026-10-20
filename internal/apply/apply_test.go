package apply

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"

	"github.com/opswhisperer/eh-k8s-console/internal/config"
	"github.com/opswhisperer/eh-k8s-console/internal/discovery"
	"github.com/opswhisperer/eh-k8s-console/internal/testfix"
	"github.com/opswhisperer/eh-k8s-console/internal/validate"
)

const (
	coord = testfix.Prefix + "exkpkt-coordinator"
	md    = testfix.Prefix + "metadata-forwarder"
	skf   = testfix.Prefix + "session-key-forwarder"
	fwd   = testfix.Prefix + "exkpkt-forwarder"
)

func setup(t *testing.T, o testfix.Options) (*Engine, kubernetes.Interface, func() *discovery.Snapshot) {
	t.Helper()
	cs := testfix.Clientset(t, o)
	e := &Engine{Kube: cs, Namespace: testfix.NS, Prefix: testfix.Prefix, ValidateOpts: validate.Options{Prefix: testfix.Prefix, ListSep: ","},
		HistoryKeep: 3, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC) }}
	snap := func() *discovery.Snapshot {
		s, err := discovery.Discover(context.Background(), discovery.Clients{Kube: cs},
			discovery.Options{Namespace: testfix.NS, Prefix: testfix.Prefix, ConfigMap: testfix.CM})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	return e, cs, snap
}

func restartNames(p *Plan) map[string]Restart {
	out := map[string]Restart{}
	for _, r := range p.Restarts {
		out[r.Name] = r
	}
	return out
}

func TestSensorAddressChangeUpdatesLinkedArgsAndRestartsConsumers(t *testing.T) {
	e, cs, snap := setup(t, testfix.Options{})
	ctx := context.Background()
	p, err := e.Plan(snap(), Change{Config: map[string]string{"mgmtTarget": "192.0.2.20"}, Reason: "new sensor"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Blocked || p.Empty {
		t.Fatalf("plan blocked=%v (%s) empty=%v", p.Blocked, p.BlockReason, p.Empty)
	}
	rs := restartNames(p)
	if r, ok := rs[md]; !ok || r.Rolls {
		t.Fatalf("metadata-forwarder must restart via annotation: %+v", rs)
	}
	if r, ok := rs[skf]; !ok || !r.Rolls {
		t.Fatalf("session-key-forwarder args change must roll it: %+v", rs)
	}
	if _, ok := rs[coord]; ok {
		t.Fatal("coordinator does not read mgmtTarget and must not restart")
	}
	for _, f := range p.Introduced {
		if f.Code == "arg_drift" {
			t.Fatal("args were not kept in sync")
		}
	}
	if len(p.Diffs) != 2 || !strings.Contains(p.Diffs[0].Diff+p.Diffs[1].Diff, "+mgmtTarget: 192.0.2.20") {
		t.Fatalf("diffs = %+v", p.Diffs)
	}

	res, err := e.Apply(ctx, p, "rob", "apply")
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision != 1 {
		t.Fatalf("revision = %d", res.Revision)
	}
	cm, _ := cs.CoreV1().ConfigMaps(testfix.NS).Get(ctx, testfix.CM, metav1.GetOptions{})
	if cm.Data["mgmtTarget"] != "192.0.2.20" {
		t.Fatalf("ConfigMap not updated: %s", cm.Data["mgmtTarget"])
	}
	ds, _ := cs.AppsV1().DaemonSets(testfix.NS).Get(ctx, skf, metav1.GetOptions{})
	if !strings.Contains(strings.Join(ds.Spec.Template.Spec.Containers[0].Args, " "), "-server 192.0.2.20") {
		t.Fatalf("args not updated: %v", ds.Spec.Template.Spec.Containers[0].Args)
	}
	dep, _ := cs.AppsV1().Deployments(testfix.NS).Get(ctx, md, metav1.GetOptions{})
	if dep.Spec.Template.Annotations[RestartAnnotation] == "" {
		t.Fatal("metadata-forwarder was not restarted")
	}
	c, _ := cs.AppsV1().Deployments(testfix.NS).Get(ctx, coord, metav1.GetOptions{})
	if c.Spec.Template.Annotations[RestartAnnotation] != "" {
		t.Fatal("coordinator was restarted needlessly")
	}

	// Roll back to the state before revision 1.
	hist, _ := e.History(ctx)
	if len(hist) != 1 || hist[0].User != "rob" || hist[0].Reason != "new sensor" {
		t.Fatalf("history = %+v", hist)
	}
	rev, err := e.Revision(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := e.Plan(snap(), RollbackChange(snap(), rev))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, rp, "rob", "rollback"); err != nil {
		t.Fatal(err)
	}
	cm, _ = cs.CoreV1().ConfigMaps(testfix.NS).Get(ctx, testfix.CM, metav1.GetOptions{})
	ds, _ = cs.AppsV1().DaemonSets(testfix.NS).Get(ctx, skf, metav1.GetOptions{})
	if cm.Data["mgmtTarget"] != "192.0.2.10" || !strings.Contains(strings.Join(ds.Spec.Template.Spec.Containers[0].Args, " "), "-server 192.0.2.10") {
		t.Fatal("rollback did not restore the ConfigMap and args")
	}
}

func TestFilteringChangeRestartsOnlyCoordinator(t *testing.T) {
	e, _, snap := setup(t, testfix.Options{})
	p, err := e.Plan(snap(), Change{Config: map[string]string{"kubernetesNamespacedTrafficRule": "skip", "mirrorNamespaces": "apps default"}})
	if err != nil {
		t.Fatal(err)
	}
	rs := restartNames(p)
	if len(rs) != 1 || rs[coord].Name == "" {
		t.Fatalf("restarts = %+v, want only the coordinator", rs)
	}
	if got := p.Proposed().ConfigData["mirrorNamespaces"]; got != "apps,default" {
		t.Fatalf("list not normalized to the configured separator: %q", got)
	}
	if len(p.Notes) == 0 || !strings.Contains(p.Notes[0], "coordinator") {
		t.Fatalf("notes = %v", p.Notes)
	}
}

func TestCriticalProblemsBlockUnlessForced(t *testing.T) {
	e, _, snap := setup(t, testfix.Options{})
	p, _ := e.Plan(snap(), Change{Config: map[string]string{"mirrorTarget": "no-port"}})
	if !p.Blocked {
		t.Fatal("an invalid mirror target must block the change")
	}
	if _, err := e.Apply(context.Background(), p, "rob", "apply"); err == nil {
		t.Fatal("apply of a blocked plan must fail")
	}
	p, _ = e.Plan(snap(), Change{Config: map[string]string{"mirrorTarget": "no-port"}, Force: true})
	if p.Blocked {
		t.Fatal("force should unblock")
	}
	if _, err := e.Plan(snap(), Change{Config: map[string]string{"made-up": "x"}}); err == nil {
		t.Fatal("unknown settings must be refused")
	}
}

func TestSecretRotationNeverEchoesValue(t *testing.T) {
	e, cs, snap := setup(t, testfix.Options{})
	ctx := context.Background()
	p, err := e.Plan(snap(), Change{Secrets: []SecretChange{{Name: testfix.Prefix + "sensor-api-credentials", Key: "apiKey", Value: "new-api-key-value"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range p.Changes {
		if strings.Contains(c.Old+c.New, "new-api-key") || strings.Contains(c.Old+c.New, "test-api-key") {
			t.Fatalf("secret value leaked into the plan: %+v", c)
		}
	}
	if _, ok := restartNames(p)[md]; !ok {
		t.Fatal("metadata-forwarder reads the API key and must restart")
	}
	if _, err := e.Apply(ctx, p, "rob", "apply"); err != nil {
		t.Fatal(err)
	}
	s, _ := cs.CoreV1().Secrets(testfix.NS).Get(ctx, testfix.Prefix+"sensor-api-credentials", metav1.GetOptions{})
	if string(s.Data["apiKey"]) != "new-api-key-value" {
		t.Fatal("secret not updated")
	}
	rev, _ := e.Revision(ctx, 1)
	for k, v := range rev.ConfigData {
		if strings.Contains(v, "new-api-key") {
			t.Fatalf("secret stored in history key %s", k)
		}
	}
}

func TestHistoryIsPruned(t *testing.T) {
	e, _, snap := setup(t, testfix.Options{})
	ctx := context.Background()
	for i, v := range []string{"a", "b", "c", "d", "e"} {
		p, _ := e.Plan(snap(), Change{Config: map[string]string{"clusterName": v}})
		if _, err := e.Apply(ctx, p, "rob", "apply"); err != nil {
			t.Fatalf("apply %d: %v", i, err)
		}
	}
	h, _ := e.History(ctx)
	if len(h) != 3 || h[0].N != 5 {
		t.Fatalf("history = %+v, want newest 3", h)
	}
}

func TestHelmManagedIsBlocked(t *testing.T) {
	e, _, snap := setup(t, testfix.Options{})
	s := snap()
	s.Helm = &discovery.HelmInfo{Release: "eh"}
	p, _ := e.Plan(s, Change{Config: map[string]string{"clusterName": "x"}})
	if !p.Blocked || !strings.Contains(p.BlockReason, "Helm") {
		t.Fatalf("blocked=%v reason=%s", p.Blocked, p.BlockReason)
	}
	if out := HelmValues(s, testfix.Prefix, false); !strings.Contains(out, "mgmtTarget: 192.0.2.10") || !strings.Contains(out, "Not supported by chart") || strings.Contains(out, "test-api-key") {
		t.Fatalf("helm values:\n%s", out)
	}
}

func TestAnnotatePodsNowAndPersist(t *testing.T) {
	ctrl := true
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "apps"}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "web-abc", Namespace: "apps",
		OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "web", Controller: &ctrl}}}}
	pod := func(name string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "apps", Labels: map[string]string{"app": "web"},
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "web-abc", Controller: &ctrl}}}}
	}
	sys := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "dns", Namespace: "kube-system"}}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}
	e, cs, _ := setup(t, testfix.Options{Extra: []k8sruntime.Object{dep, rs, pod("web-1"), pod("web-2"), sys, node}})
	ctx := context.Background()
	scope := config.Default().Integration.Annotations
	scope.Enabled = true

	res, err := e.Annotate(ctx, AnnotateRequest{Namespace: "apps", Selector: "app=web", Rule: "mirror", Mode: ModeBoth}, scope, "rob")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 { // two pods now + the Deployment template once
		t.Fatalf("results = %+v", res)
	}
	p, _ := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{})
	d, _ := cs.AppsV1().Deployments("apps").Get(ctx, "web", metav1.GetOptions{})
	if p.Annotations[discovery.MirrorAnnotation] != "mirror" || d.Spec.Template.Annotations[discovery.MirrorAnnotation] != "mirror" {
		t.Fatalf("pod=%v template=%v", p.Annotations, d.Spec.Template.Annotations)
	}

	if _, err := e.Annotate(ctx, AnnotateRequest{Targets: []Target{{Kind: "Node", Name: "n1"}}, Rule: "skip"}, scope, "rob"); err != nil {
		t.Fatal(err)
	}
	n, _ := cs.CoreV1().Nodes().Get(ctx, "n1", metav1.GetOptions{})
	if n.Annotations[discovery.MirrorAnnotation] != "skip" {
		t.Fatal("node not annotated")
	}

	// Removal.
	e.Annotate(ctx, AnnotateRequest{Targets: []Target{{Kind: "Pod", Namespace: "apps", Name: "web-1"}}, Rule: ""}, scope, "rob")
	p, _ = cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{})
	if _, ok := p.Annotations[discovery.MirrorAnnotation]; ok {
		t.Fatal("annotation not removed")
	}

	// Scope: kube-system is excluded by default, and the target cap applies.
	res, _ = e.Annotate(ctx, AnnotateRequest{Targets: []Target{{Kind: "Pod", Namespace: "kube-system", Name: "dns"}}, Rule: "skip"}, scope, "rob")
	if len(res) != 1 || res[0].Error == "" {
		t.Fatalf("kube-system edit must be refused: %+v", res)
	}
	scope.MaxTargets = 1
	if _, err := e.Annotate(ctx, AnnotateRequest{Namespace: "apps", Selector: "app=web", Rule: "skip"}, scope, "rob"); err == nil {
		t.Fatal("target cap not enforced")
	}
	scope.Enabled = false
	if _, err := e.Annotate(ctx, AnnotateRequest{Targets: []Target{{Kind: "Node", Name: "n1"}}, Rule: "skip"}, scope, "rob"); err == nil {
		t.Fatal("disabled feature must refuse")
	}
}

func TestUnifiedDiff(t *testing.T) {
	d := UnifiedDiff("x", "a\nb\nc\n", "a\nB\nc\n")
	if !strings.Contains(d, "-b\n+B\n") || !strings.Contains(d, "@@ -1,3 +1,3 @@") {
		t.Fatalf("diff:\n%s", d)
	}
	if UnifiedDiff("x", "same", "same") != "" {
		t.Fatal("identical inputs must give no diff")
	}
}

func TestKeyPairsAreReadOnly(t *testing.T) {
	e, _, snap := setup(t, testfix.Options{})
	_, otherPub := testfix.KeyPair(t)
	if _, err := e.Plan(snap(), Change{Config: map[string]string{"exkpktForwarderPublic": otherPub}}); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("public key change must be refused, got %v", err)
	}
	if _, err := e.Plan(snap(), Change{Secrets: []SecretChange{{Name: testfix.Prefix + "exkpkt-coordinator", Key: "secret", Value: strings.Repeat("ab", 32)}}}); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("private key change must be refused, got %v", err)
	}
	if _, err := e.Plan(snap(), Change{Remove: []string{"exkpktCoordinatorPublic"}}); err == nil {
		t.Fatal("removing a public key must be refused")
	}
	// Sending the current value (e.g. a form that posts every field) is not a change.
	s := snap()
	p, err := e.Plan(s, Change{Config: map[string]string{"exkpktForwarderPublic": s.ConfigData["exkpktForwarderPublic"], "clusterName": "x"}})
	if err != nil || len(p.Changes) != 1 {
		t.Fatalf("unchanged read-only value should be ignored: %v %+v", err, p)
	}
	// Rollback leaves key pairs alone.
	rev := &Revision{N: 1, ConfigData: map[string]string{}}
	for k, v := range s.ConfigData {
		rev.ConfigData[k] = v
	}
	rev.ConfigData["exkpktForwarderPublic"] = otherPub
	if ch := RollbackChange(s, rev); ch.Config["exkpktForwarderPublic"] != "" {
		t.Fatal("rollback must not restore a public key without its private key")
	}
}
