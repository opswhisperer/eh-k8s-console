// Command demo runs eh-k8s-console against an in-memory, entirely synthetic cluster: the sanitized
// fixture in testdata/integration.json plus made-up namespaces, nodes and pods, a fake TLS sensor
// (sensor.example.com) whose certificate was recently renewed, and generated logs. Nothing touches a
// real cluster. It's used for screenshots and for trying the UI.
//
//	go run ./hack/demo                # UI on http://127.0.0.1:8090, metrics on 127.0.0.1:9095
package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/opswhisperer/eh-k8s-console/internal/alerts"
	"github.com/opswhisperer/eh-k8s-console/internal/apply"
	"github.com/opswhisperer/eh-k8s-console/internal/auth"
	"github.com/opswhisperer/eh-k8s-console/internal/certs"
	"github.com/opswhisperer/eh-k8s-console/internal/config"
	"github.com/opswhisperer/eh-k8s-console/internal/discovery"
	"github.com/opswhisperer/eh-k8s-console/internal/ignore"
	"github.com/opswhisperer/eh-k8s-console/internal/logs"
	"github.com/opswhisperer/eh-k8s-console/internal/server"
	"github.com/opswhisperer/eh-k8s-console/web"
)

const (
	ns     = "extrahop"
	prefix = "extrahop-kubernetes-integration-"
	sni    = "sensor.example.com"
)

var nodes = []string{"node-a", "node-b", "node-c", "node-d"}

func main() {
	listen := flag.String("listen", "127.0.0.1:8090", "UI address")
	metricsListen := flag.String("metrics-listen", "127.0.0.1:9095", "metrics address")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx := context.Background()

	pki := newPKI()
	kube := fake.NewSimpleClientset(objects(pki)...)
	sensorAddr := pki.serve()

	cfg := config.Default()
	cfg.Listen = *listen
	cfg.Auth.Modes = []string{"none"}
	cfg.Integration.Annotations.Enabled = true
	cfg.Alerts.Events = true
	cfg.ScanInterval.Duration = 20 * time.Second
	cfg.Policy.Order = []string{"annotation:skip", "annotation:mirror", "namespace:mirror-list", "namespace:skip-list", "namespace:rule", "cluster:rule"}
	cfg.Policy.AnnotationKinds = []string{"Pod"}
	cfg.Logs.Ignore = []string{`^stopped reading packets on cali<id>: packet poll failed$`}
	if err := cfg.Validate(); err != nil {
		panic(err)
	}

	rules := ignore.NewStore(kube, ns, "eh-k8s-console-ignore", cfg.Logs.Ignore, false)
	if _, err := rules.Add(ctx, `^server: failed to deliver update: endpoint subscription closed by peer$`, "Forwarders reconnect after node drains; expected during maintenance.", "alice"); err != nil {
		panic(err)
	}
	eng := &apply.Engine{Kube: kube, Namespace: ns, Prefix: prefix, HistoryKeep: 20,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	eng.ValidateOpts.Prefix, eng.ValidateOpts.ListSep, eng.ValidateOpts.AnnotationKinds = prefix, ",", cfg.Policy.AnnotationKinds
	lr := &logs.Reader{Kube: kube, Namespace: ns, Ignore: rules, Source: logSource}
	col := alerts.NewCollector()
	d := &net.Dialer{}
	sc := &server.Scanner{Cfg: cfg, Clients: discovery.Clients{Kube: kube}, Logs: lr, Engine: eng, Collector: col, Log: log,
		Roots: pki.roots, SkipNetwork: true, Ignore: rules,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, sensorAddr)
		}}
	sc.Notifier = &alerts.Notifier{Cluster: "demo", Log: log, Events: &alerts.EventRecorder{Kube: kube, Namespace: ns, ConfigMap: prefix + "cm"},
		Store: &alerts.ConfigMapStore{Kube: kube, Namespace: ns, Name: "eh-k8s-console-alerts"}}
	seedHistory(ctx, sc, eng)
	go sc.Run(ctx)
	go churn(ctx, kube)

	a, err := auth.New(cfg, log)
	if err != nil {
		panic(err)
	}
	srv := &server.Server{Cfg: cfg, Auth: a, Scanner: sc, Engine: eng, Logs: lr, Notifier: sc.Notifier, Static: web.Static(), Log: log, Version: "demo"}
	reg := prometheus.NewRegistry()
	reg.MustRegister(col)
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		_ = http.ListenAndServe(*metricsListen, mux)
	}()
	fmt.Printf("eh-k8s-console demo: http://%s  (metrics http://%s/metrics)\n", *listen, *metricsListen)
	if err := http.ListenAndServe(*listen, srv.Handler()); err != nil {
		panic(err)
	}
}

// seedHistory records two changes so the History page has content.
func seedHistory(ctx context.Context, sc *server.Scanner, eng *apply.Engine) {
	for _, step := range []struct {
		who string
		ch  apply.Change
	}{
		{"alice", apply.Change{Config: map[string]string{"skipNamespaces": "batch-jobs"}, Reason: "Quiet the nightly batch namespace"}},
		{"bob", apply.Change{Restart: []string{prefix + "metadata-forwarder"}, Reason: "Pick up the rotated sensor API key"}},
	} {
		snap, err := sc.FreshSnapshot(ctx)
		if err != nil {
			panic(err)
		}
		p, err := eng.Plan(snap, step.ch)
		if err != nil {
			panic(err)
		}
		if _, err := eng.Apply(ctx, p, step.who, "apply"); err != nil {
			panic(err)
		}
	}
}

// churn makes the demo look alive: a forwarder pod restarts now and then, and briefly isn't ready.
func churn(ctx context.Context, kube *fake.Clientset) {
	t := time.NewTicker(75 * time.Second)
	defer t.Stop()
	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		dsName := prefix + "exkpkt-forwarder"
		ds, err := kube.AppsV1().DaemonSets(ns).Get(ctx, dsName, metav1.GetOptions{})
		if err != nil {
			continue
		}
		ready := int32(4)
		if i%3 == 0 {
			ready = 3
			pod, err := kube.CoreV1().Pods(ns).Get(ctx, dsName+"-"+nodes[i%4][5:]+"x7k2", metav1.GetOptions{})
			if err == nil && len(pod.Status.ContainerStatuses) > 0 {
				pod.Status.ContainerStatuses[0].RestartCount++
				_, _ = kube.CoreV1().Pods(ns).UpdateStatus(ctx, pod, metav1.UpdateOptions{})
			}
		}
		ds.Status.NumberReady, ds.Status.NumberAvailable = ready, ready
		_, _ = kube.AppsV1().DaemonSets(ns).UpdateStatus(ctx, ds, metav1.UpdateOptions{})
	}
}

// ---------- objects ----------

func fixture() []k8sruntime.Object {
	_, file, _, _ := runtime.Caller(0)
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "testdata", "integration.json"))
	if err != nil {
		panic(err)
	}
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		panic(err)
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
			panic(err)
		}
		out = append(out, obj)
	}
	return out
}

func keyPair() (string, string) {
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	return hex.EncodeToString(k.Bytes()), hex.EncodeToString(k.PublicKey().Bytes())
}

func objects(p *pki) []k8sruntime.Object {
	objs := fixture()
	cPriv, cPub := keyPair()
	fPriv, fPub := keyPair()
	ctrl := true
	var extra []k8sruntime.Object
	for _, o := range objs {
		switch v := o.(type) {
		case *corev1.ConfigMap:
			v.Data["clusterName"] = "demo"
			v.Data["exkpktCoordinatorPublic"], v.Data["exkpktForwarderPublic"] = cPub, fPub
			v.Data["sensorCert"] = p.bundle
		case *appsv1.Deployment:
			v.Generation, v.Status.ObservedGeneration = 1, 1
			v.Status.Replicas, v.Status.ReadyReplicas, v.Status.UpdatedReplicas, v.Status.AvailableReplicas = 1, 1, 1, 1
			extra = append(extra, pod(v.Name, v.Spec.Template, nodes[len(extra)%4], "6f9c7d", &metav1.OwnerReference{Kind: "ReplicaSet", Name: v.Name + "-6f9c7d", Controller: &ctrl}, 0))
		case *appsv1.DaemonSet:
			v.Generation, v.Status.ObservedGeneration = 1, 1
			v.Status.DesiredNumberScheduled, v.Status.NumberReady, v.Status.UpdatedNumberScheduled, v.Status.NumberAvailable = 4, 4, 4, 4
			for i, n := range nodes {
				extra = append(extra, pod(v.Name, v.Spec.Template, n, n[5:]+"x7k2", &metav1.OwnerReference{Kind: "DaemonSet", Name: v.Name, Controller: &ctrl}, int32(i%2)))
			}
		}
	}
	secret := func(name, key, val string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}, Data: map[string][]byte{key: []byte(val)}}
	}
	extra = append(extra,
		secret(prefix+"sensor-api-credentials", "apiKey", "demo-api-key-not-real-0123456789abcdef"),
		secret(prefix+"exkpkt-coordinator", "secret", cPriv),
		secret(prefix+"exkpkt-forwarder", "secret", fPriv))
	for _, n := range []string{ns, "default", "kube-system", "kube-public", "monitoring", "ingress-nginx", "payments", "checkout", "catalog", "batch-jobs", "auth"} {
		extra = append(extra, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
	}
	for _, n := range nodes {
		extra = append(extra, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: n}})
	}
	// Application workloads, a few carrying the mirror annotation.
	app := func(nsName, name, rule string) {
		tmpl := corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: name, Image: "registry.example.com/" + name + ":2.4.1"}}}}
		dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: nsName},
			Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}}, Template: tmpl}}
		extra = append(extra, dep)
		for i, n := range nodes[:2] {
			p := pod(name, tmpl, n, fmt.Sprintf("7c9f8b%d", i), &metav1.OwnerReference{Kind: "ReplicaSet", Name: name + "-7c9f8b", Controller: &ctrl}, 0)
			p.Namespace = nsName
			if rule != "" {
				p.Annotations = map[string]string{discovery.MirrorAnnotation: rule}
			}
			extra = append(extra, p)
		}
	}
	app("payments", "ledger", "")
	app("payments", "fraud-scoring", "mirror")
	app("checkout", "cart", "")
	app("checkout", "health-probe", "skip")
	app("catalog", "search", "")
	return append(objs, extra...)
}

func pod(owner string, tmpl corev1.PodTemplateSpec, node, suffix string, ref *metav1.OwnerReference, restarts int32) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: owner + "-" + suffix, Namespace: ns, Labels: tmpl.Labels, OwnerReferences: []metav1.OwnerReference{*ref}},
		Spec:       corev1.PodSpec{NodeName: node, Containers: tmpl.Spec.Containers},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: fmt.Sprintf("10.244.%d.%d", mrand.Intn(4), 10+mrand.Intn(200)),
			StartTime:  &metav1.Time{Time: time.Now().Add(-time.Duration(30+mrand.Intn(200)) * time.Hour)},
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	for _, c := range tmpl.Spec.Containers {
		p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, corev1.ContainerStatus{Name: c.Name, Ready: true, RestartCount: restarts,
			State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}})
	}
	return p
}

// ---------- sensor PKI ----------

type pki struct {
	roots  *x509.CertPool
	bundle string
	leaf   tls.Certificate
}

func newPKI() *pki {
	mk := func(cn string, parent *x509.Certificate, pkey *ecdsa.PrivateKey, ca bool, life time.Duration, dns ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn, Organization: []string{"Example Trust Services"}},
			NotBefore: time.Now().Add(-60 * 24 * time.Hour), NotAfter: time.Now().Add(life), IsCA: ca, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: dns}
		if !ca {
			tmpl.Subject.Organization = nil
		}
		signer, sk := tmpl, k
		if parent != nil {
			signer, sk = parent, pkey
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &k.PublicKey, sk)
		if err != nil {
			panic(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, k
	}
	day := 24 * time.Hour
	root, rk := mk("Example Root CA R1", nil, nil, true, 4000*day)
	inter, ik := mk("Example TLS Issuing CA 2", root, rk, true, 3000*day)
	old, _ := mk(sni, inter, ik, false, 19*day, sni)
	renewed, lk := mk(sni, inter, ik, false, 84*day, sni)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &pki{roots: pool, bundle: certs.EncodeBundle([]*x509.Certificate{old, inter, root}),
		leaf: tls.Certificate{Certificate: [][]byte{renewed.Raw, inter.Raw}, PrivateKey: lk}}
}

func (p *pki) serve() string {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{p.leaf}})
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = c.(*tls.Conn).Handshake(); c.Close() }(c)
		}
	}()
	return ln.Addr().String()
}

// ---------- logs ----------

type genFn func(r *mrand.Rand, t time.Time) string

func hexs(r *mrand.Rand, n int) string {
	b := make([]byte, n/2)
	r.Read(b)
	return hex.EncodeToString(b)
}

var generators = map[string]genFn{
	"metadata-forwarder": func(r *mrand.Rand, t time.Time) string {
		ts := t.UTC().Format(time.RFC3339Nano)
		switch n := r.Intn(10); {
		case n < 2:
			return fmt.Sprintf(`{"time":%q,"level":"ERROR","msg":"SensorClient: SendDeviceProperties returned Bad Request","host":"192.0.2.10","status":400,"count":%d,"body":"{\"error\": \"all_updates_invalid\", \"warnings\": [{\"index\": 0, \"key\": \"device_id\", \"value\": \"k8s-%s\", \"warnings\": [{\"type\": \"device_not_found\"}]}]}"}`, ts, 1+r.Intn(3), hexs(r, 32))
		case n < 3:
			return fmt.Sprintf(`{"time":%q,"level":"WARN","msg":"SensorClient: slow response from sensor","host":"192.0.2.10","elapsed_ms":%d}`, ts, 900+r.Intn(1500))
		default:
			return fmt.Sprintf(`{"time":%q,"level":"INFO","msg":"Agent: sent device properties","host":"192.0.2.10","devices":%d}`, ts, 5+r.Intn(40))
		}
	},
	"exkpkt-coordinator": func(r *mrand.Rand, t time.Time) string {
		ts := t.Format("2006/01/02 15:04:05")
		pods := []string{"payments/ledger-7c9f8b0", "payments/fraud-scoring-7c9f8b1", "checkout/cart-7c9f8b0", "catalog/search-7c9f8b1"}
		switch n := r.Intn(10); {
		case n < 1:
			return ts + " server: failed to deliver update: endpoint subscription closed by peer"
		case n < 5:
			return fmt.Sprintf("%s update Pod: %s @ %s-%s -> 10.244.%d.%d (mirror-low)", ts, pods[r.Intn(len(pods))], hexs(r, 8), hexs(r, 4), r.Intn(4), 10+r.Intn(200))
		default:
			return fmt.Sprintf("%s server: received endpoint subscription from 10.244.%d.%d:33089 for 10.244.%d.%d", ts, r.Intn(4), 10+r.Intn(200), r.Intn(4), 10+r.Intn(200))
		}
	},
	"exkpkt-forwarder": func(r *mrand.Rand, t time.Time) string {
		ts := t.Format("2006/01/02 15:04:05")
		switch n := r.Intn(12); {
		case n < 1:
			return fmt.Sprintf("%s stopped reading packets on cali%s: packet poll failed", ts, hexs(r, 10))
		case n < 3:
			return fmt.Sprintf("%s interface added: cali%s", ts, hexs(r, 10))
		default:
			return fmt.Sprintf("%s eth0: %d packets, %d bytes, 0 missed packets, %d queue freezes", ts, 200000+r.Intn(900000), 90000000+r.Intn(900000000), r.Intn(4))
		}
	},
	"session-key-forwarder": func(r *mrand.Rand, t time.Time) string {
		ts := t.Format("2006/01/02 15:04:05")
		if r.Intn(15) == 0 {
			return fmt.Sprintf("%s go: could not read build info from /proc/%d/exe: not a Go binary", ts, 1000+r.Intn(30000))
		}
		return fmt.Sprintf("%s containerd: new container %s", ts, hexs(r, 64))
	},
}

func logSource(ctx context.Context, t logs.Target, opts *corev1.PodLogOptions) (io.ReadCloser, error) {
	gen := generators[t.Component]
	if gen == nil {
		gen = generators["session-key-forwarder"]
	}
	seed := int64(0)
	for _, c := range t.Pod {
		seed = seed*31 + int64(c)
	}
	r := mrand.New(mrand.NewSource(seed))
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		w := bufio.NewWriter(pw)
		line := func(at time.Time) bool {
			_, err := fmt.Fprintf(w, "%s %s\n", at.UTC().Format(time.RFC3339Nano), gen(r, at))
			return err == nil
		}
		// Backlog: one line every ~20s over the requested window (or the tail count).
		back := 300
		if opts.TailLines != nil {
			back = int(*opts.TailLines)
		}
		if opts.SinceSeconds != nil {
			back = int(*opts.SinceSeconds / 20)
		}
		now := time.Now()
		for i := back; i > 0; i-- {
			if !line(now.Add(-time.Duration(i)*20*time.Second + time.Duration(r.Intn(15000))*time.Millisecond)) {
				return
			}
		}
		w.Flush()
		if !opts.Follow {
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(1500+r.Intn(4000)) * time.Millisecond):
				if !line(time.Now()) || w.Flush() != nil {
					return
				}
			}
		}
	}()
	return struct {
		io.Reader
		io.Closer
	}{pr, closerFunc(func() error { return pr.Close() })}, nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }
