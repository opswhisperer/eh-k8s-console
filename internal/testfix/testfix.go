// Package testfix loads sanitized manifests from a real sensor-generated install (testdata/integration.json)
// into a fake clientset so tests run against the real layout.
package testfix

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	NS     = "extrahop"
	Prefix = "extrahop-kubernetes-integration-"
	CM     = Prefix + "cm"
)

// Objects returns the fixture's objects (Deployments, DaemonSets, Service, ConfigMap).
func Objects(t testing.TB) []k8sruntime.Object {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "testdata", "integration.json"))
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatal(err)
	}
	var out []k8sruntime.Object
	for _, raw := range list.Items {
		var meta metav1.TypeMeta
		_ = json.Unmarshal(raw, &meta)
		var obj k8sruntime.Object
		switch meta.Kind {
		case "Deployment":
			obj = &appsv1.Deployment{}
		case "DaemonSet":
			obj = &appsv1.DaemonSet{}
		case "Service":
			obj = &corev1.Service{}
		case "ConfigMap":
			obj = &corev1.ConfigMap{}
		default:
			continue
		}
		if err := json.Unmarshal(raw, obj); err != nil {
			t.Fatal(err)
		}
		out = append(out, obj)
	}
	return out
}

// KeyPair returns an X25519 key pair as hex (private, public).
func KeyPair(t testing.TB) (string, string) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(k.Bytes()), hex.EncodeToString(k.PublicKey().Bytes())
}

// Options tweaks the fixture before it is loaded.
type Options struct {
	// MutateCM edits the ConfigMap data.
	MutateCM func(map[string]string)
	// SkipSecrets leaves out the integration Secrets.
	SkipSecrets bool
	// Namespaces to create (default: extrahop, default, apps, kube-system).
	Namespaces []string
	Extra      []k8sruntime.Object
}

// Clientset builds a fake clientset with matching key pairs, Secrets and namespaces, and marks
// every workload ready.
func Clientset(t testing.TB, o Options) *fake.Clientset {
	t.Helper()
	objs := Objects(t)
	cPriv, cPub := KeyPair(t)
	fPriv, fPub := KeyPair(t)
	for _, obj := range objs {
		switch v := obj.(type) {
		case *corev1.ConfigMap:
			v.Data["exkpktCoordinatorPublic"] = cPub
			v.Data["exkpktForwarderPublic"] = fPub
			if o.MutateCM != nil {
				o.MutateCM(v.Data)
			}
		case *appsv1.Deployment:
			v.Generation, v.Status.ObservedGeneration = 1, 1
			v.Status.Replicas, v.Status.ReadyReplicas, v.Status.UpdatedReplicas, v.Status.AvailableReplicas = 1, 1, 1, 1
		case *appsv1.DaemonSet:
			v.Generation, v.Status.ObservedGeneration = 1, 1
			v.Status.DesiredNumberScheduled, v.Status.NumberReady, v.Status.UpdatedNumberScheduled, v.Status.NumberAvailable = 2, 2, 2, 2
		}
	}
	if !o.SkipSecrets {
		sec := func(name string, data map[string]string) *corev1.Secret {
			s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: NS}, Data: map[string][]byte{}}
			for k, v := range data {
				s.Data[k] = []byte(v)
			}
			return s
		}
		objs = append(objs,
			sec(Prefix+"sensor-api-credentials", map[string]string{"apiKey": "test-api-key"}),
			sec(Prefix+"exkpkt-coordinator", map[string]string{"secret": cPriv}),
			sec(Prefix+"exkpkt-forwarder", map[string]string{"secret": fPriv}),
		)
	}
	nss := o.Namespaces
	if nss == nil {
		nss = []string{NS, "default", "apps", "kube-system"}
	}
	for _, n := range nss {
		objs = append(objs, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
	}
	objs = append(objs, o.Extra...)
	return fake.NewSimpleClientset(objs...)
}
