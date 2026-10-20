package validate_test

import (
	"context"
	"testing"
	"time"

	"github.com/opswhisperer/eh-k8s-console/internal/discovery"
	"github.com/opswhisperer/eh-k8s-console/internal/finding"
	"github.com/opswhisperer/eh-k8s-console/internal/testfix"
	"github.com/opswhisperer/eh-k8s-console/internal/validate"
)

var vopts = validate.Options{Prefix: testfix.Prefix, ListSep: ","}

func snap(t *testing.T, o testfix.Options) *discovery.Snapshot {
	t.Helper()
	s, err := discovery.Discover(context.Background(), discovery.Clients{Kube: testfix.Clientset(t, o)},
		discovery.Options{Namespace: testfix.NS, Prefix: testfix.Prefix, ConfigMap: testfix.CM, Annotations: true})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func codes(fs []finding.Finding) map[string]finding.Finding {
	out := map[string]finding.Finding{}
	for _, f := range fs {
		out[f.Code+"/"+f.Setting] = f
	}
	return out
}

func TestBaselineIsClean(t *testing.T) {
	fs := validate.Config(snap(t, testfix.Options{}), vopts)
	for _, f := range fs {
		if f.Severity != finding.Info {
			t.Errorf("unexpected %s %s: %s", f.Severity, f.Code, f.Message)
		}
	}
	if _, ok := codes(fs)["args_not_from_configmap/mgmtTarget"]; !ok {
		t.Error("want the info finding about session-key-forwarder args")
	}
}

func TestProposedChangesAreChecked(t *testing.T) {
	s := snap(t, testfix.Options{})
	p := s.Clone()
	p.ConfigData["mgmtTarget"] = "192.0.2.99"   // args not updated -> drift
	p.ConfigData["mirrorTarget"] = "192.0.2.10" // no port
	p.ConfigData["kubernetesNamespacedTrafficRule"] = "mirror"
	p.ConfigData["mirrorNamespaces"] = "apps"    // ignored under mirror
	p.ConfigData["skipNamespaces"] = "nope apps" // unknown + overlap + wrong separator
	p.ConfigData["kubernetesBaseTrafficRule"] = "maybe"
	c := codes(validate.Config(p, vopts))
	for key, sev := range map[string]finding.Severity{
		"arg_drift/mgmtTarget":                    finding.Warning,
		"invalid_value/mirrorTarget":              finding.Critical,
		"ignored_list/mirrorNamespaces":           finding.Warning,
		"unknown_namespace/skipNamespaces":        finding.Warning,
		"namespace_overlap/skipNamespaces":        finding.Warning,
		"invalid_value/kubernetesBaseTrafficRule": finding.Warning,
	} {
		if got, ok := c[key]; !ok || got.Severity != sev {
			t.Errorf("%s: got %+v, want %s", key, got, sev)
		}
	}
}

func TestAnnotationOnlyMode(t *testing.T) {
	p := snap(t, testfix.Options{}).Clone()
	p.ConfigData["kubernetesNamespacedTrafficRule"] = "skip"
	p.ConfigData["mirrorNamespaces"] = ""
	c := codes(validate.Config(p, vopts))
	if f, ok := c["nothing_mirrored/mirrorNamespaces"]; !ok || f.Severity != finding.Warning {
		t.Fatalf("want nothing_mirrored warning, got %v", c)
	}
	p.Annotated = []discovery.Annotated{{Kind: "Pod", Namespace: "apps", Name: "web", Rule: "mirror"}}
	c = codes(validate.Config(p, vopts))
	if _, ok := c["annotation_only/mirrorNamespaces"]; !ok {
		t.Fatalf("want annotation_only info, got %v", c)
	}
}

func TestKeyPairMismatchAndMissingSecret(t *testing.T) {
	_, otherPub := testfix.KeyPair(t)
	s := snap(t, testfix.Options{MutateCM: func(d map[string]string) { d["exkpktForwarderPublic"] = otherPub }})
	c := codes(validate.Config(s, vopts))
	if f, ok := c["keypair_mismatch/exkpktForwarderPublic"]; !ok || f.Severity != finding.Critical {
		t.Fatalf("want keypair_mismatch, got %v", c)
	}
	if _, ok := c["keypair_mismatch/exkpktCoordinatorPublic"]; ok {
		t.Fatal("coordinator pair matches and must not be flagged")
	}
	s = snap(t, testfix.Options{SkipSecrets: true})
	if f, ok := codes(validate.Config(s, vopts))["secret_missing/"+testfix.Prefix+"sensor-api-credentials"]; !ok || f.Severity != finding.Critical {
		t.Fatal("want secret_missing")
	}
}

func TestCertPathAndImageChecks(t *testing.T) {
	p := snap(t, testfix.Options{}).Clone()
	for _, w := range p.Workloads {
		spec := w.PodSpecRef()
		for i := range spec.Containers {
			if w.Component == "session-key-forwarder" {
				for j, a := range spec.Containers[i].Args {
					if a == "/certs/sensor.crt" {
						spec.Containers[i].Args[j] = "/certs/wrong.crt"
					}
				}
			}
			if w.Component == "exkpkt-forwarder" {
				spec.Containers[i].Image = "public.ecr.aws/extrahop/kubernetes-traffic-forwarder:latest"
			}
		}
	}
	p.RefreshRefs()
	c := codes(validate.Config(p, vopts))
	if f, ok := c["cert_path_unmounted/sensorCert"]; !ok || f.Severity != finding.Critical {
		t.Fatalf("want cert_path_unmounted, got %v", c)
	}
	if _, ok := c["floating_image_tag/"]; !ok {
		t.Fatal("want floating_image_tag")
	}
	if _, ok := c["image_version_skew/"]; !ok {
		t.Fatal("want image_version_skew between coordinator and forwarder")
	}
}

func TestRuntimeAndLogs(t *testing.T) {
	s := snap(t, testfix.Options{})
	s.Workloads[0].Ready = 0
	if f := validate.Runtime(s); len(f) != 1 || f[0].Code != "workload_down" {
		t.Fatalf("runtime = %+v", f)
	}
	fs := validate.Logs([]validate.LogStat{{Component: "metadata-forwarder", Signature: "SendDeviceProperties 400 device_not_found", Count: 200, Window: time.Hour}}, 30)
	if len(fs) != 1 || fs[0].Severity != finding.Warning {
		t.Fatalf("logs = %+v", fs)
	}
}

func TestAnnotationKinds(t *testing.T) {
	s := snap(t, testfix.Options{})
	s.Annotated = []discovery.Annotated{
		{Kind: "Namespace", Name: "media", Rule: "skip"},
		{Kind: "Pod", Namespace: "apps", Name: "web", Rule: "mirror"},
		{Kind: "Deployment", Namespace: "apps", Name: "api", Rule: "mirror", OnTemplate: true},
	}
	if _, ok := codes(validate.Config(s, vopts))["annotation_not_honored/"]; ok {
		t.Fatal("no kinds configured: nothing should be flagged")
	}
	o := vopts
	o.AnnotationKinds = []string{"Pod", "Node"}
	n := 0
	for _, f := range validate.Config(s, o) {
		if f.Code == "annotation_not_honored" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("only the Namespace annotation should be flagged, got %d", n)
	}
}
