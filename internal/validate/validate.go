// Package validate checks an integration state (live or proposed) and returns findings.
package validate

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"fmt"
	"net"
	"path"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/opswhisperer/eh-k8s-console/internal/certs"
	"github.com/opswhisperer/eh-k8s-console/internal/discovery"
	"github.com/opswhisperer/eh-k8s-console/internal/finding"
	"github.com/opswhisperer/eh-k8s-console/internal/model"
)

// LogStat is a recurring log error, counted over a window.
type LogStat struct {
	Component string        `json:"component"`
	Level     string        `json:"level"`
	Signature string        `json:"signature"`
	Count     int           `json:"count"`
	Window    time.Duration `json:"window"`
	Example   string        `json:"example"`
	// IgnoredBy is set when an ignore rule hides this signature.
	IgnoredBy string `json:"ignoredBy,omitempty"`
}

// Options carry install-specific conventions.
type Options struct {
	Prefix string
	// ListSep is the namespace-list separator the traffic forwarder expects ("," or " ").
	ListSep string
	// AnnotationKinds are the kinds whose mirror annotation the integration reads; annotations
	// on other kinds are flagged. Empty: no check.
	AnnotationKinds []string
}

type Input struct {
	Snap  *discovery.Snapshot
	Opts  Options
	Certs *certs.Assessment
	// Net is the result of CheckNetwork, nil to skip.
	Net []finding.Finding
	// Logs are recurring error signatures, nil to skip.
	Logs []LogStat
	// LogErrorsPerHour above this raise a warning (0 means 30).
	LogErrorsPerHour int
}

// Run returns every finding, most severe first.
func Run(in Input) []finding.Finding {
	var out []finding.Finding
	out = append(out, Config(in.Snap, in.Opts)...)
	out = append(out, Runtime(in.Snap)...)
	if in.Certs != nil {
		out = append(out, in.Certs.Findings...)
	}
	out = append(out, in.Net...)
	out = append(out, Logs(in.Logs, in.LogErrorsPerHour)...)
	Sort(out)
	return out
}

// Sort orders findings by severity (critical first), then source and code.
func Sort(fs []finding.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if finding.Rank(a.Severity) != finding.Rank(b.Severity) {
			return finding.Rank(a.Severity) > finding.Rank(b.Severity)
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.Code+a.Setting < b.Code+b.Setting
	})
}

func f(sev finding.Severity, source, code, setting, msg, fix string) finding.Finding {
	return finding.Finding{Severity: sev, Source: source, Code: code, Setting: setting, Message: msg, Fix: fix}
}

// Config checks the ConfigMap, Secrets and workload wiring.
func Config(s *discovery.Snapshot, o Options) []finding.Finding {
	prefix := o.Prefix
	var out []finding.Finding
	add := func(sev finding.Severity, code, setting, msg, fix string) {
		out = append(out, f(sev, "config", code, setting, msg, fix))
	}
	if len(s.Workloads) == 0 {
		add(finding.Critical, "no_workloads", "", fmt.Sprintf("No integration workloads found in namespace %s (names starting %q or labelled part-of=%s).", s.Namespace, prefix, discovery.PartOf),
			"Install the integration, or set integration.namespace / integration.prefix to match it.")
	}
	if !s.ConfigMapFound {
		add(finding.Critical, "configmap_missing", "", fmt.Sprintf("ConfigMap %s/%s not found.", s.Namespace, s.ConfigMapName),
			"Install the integration or set integration.configMap.")
		return out
	}
	if s.Helm != nil {
		add(finding.Info, "helm_managed", "", fmt.Sprintf("The integration is managed by Helm release %q (%s). Live edits are overwritten by the next helm upgrade.", s.Helm.Release, s.Helm.Chart),
			"Use Export → Helm values and upgrade the release instead of applying live.")
	}

	data := s.ConfigData
	for i := range model.Settings {
		st := &model.Settings[i]
		v, present := data[st.Key]
		consumed := len(s.Consumers(st.Key)) > 0
		if !present {
			if consumed {
				add(finding.Critical, "missing_key", st.Key, fmt.Sprintf("%s (%s) is read by %s but missing from the ConfigMap; those pods cannot start.",
					st.Label, st.Key, strings.Join(discovery.WorkloadsUsing(s.Consumers(st.Key)), ", ")), "Set a value.")
			}
			continue
		}
		if err := st.Check(v); err != nil {
			sev := finding.Warning
			if st.Required || st.Type == model.TypeHex64 || st.Type == model.TypeHostPort || st.Type == model.TypeHost {
				sev = finding.Critical
			}
			add(sev, "invalid_value", st.Key, fmt.Sprintf("%s: %v", st.Label, err), st.Doc)
		}
	}
	// Keys consumed by workloads but unknown to the model are still checked for presence.
	for _, r := range s.Refs {
		if r.Source == "configmap" && r.Object == s.ConfigMapName && r.Key != "*" && model.Lookup(r.Key) == nil {
			if _, ok := data[r.Key]; !ok {
				add(finding.Critical, "missing_key", r.Key, fmt.Sprintf("%s reads ConfigMap key %s, which does not exist.", r.Workload, r.Key), "Add the key.")
			}
		}
	}
	for k := range data {
		if model.Lookup(k) == nil && len(s.Consumers(k)) == 0 {
			add(finding.Info, "unused_key", k, fmt.Sprintf("ConfigMap key %s is not used by any integration workload.", k), "Remove it if it is left over.")
		}
	}

	out = append(out, filtering(s, o.ListSep, o.AnnotationKinds)...)
	out = append(out, linkedArgs(s)...)
	out = append(out, certPaths(s)...)
	out = append(out, secrets(s, prefix)...)
	out = append(out, images(s)...)
	return out
}

func filtering(s *discovery.Snapshot, sep string, annotationKinds []string) []finding.Finding {
	var out []finding.Finding
	add := func(sev finding.Severity, code, setting, msg, fix string) {
		out = append(out, f(sev, "config", code, setting, msg, fix))
	}
	if sep == "" {
		sep = ","
	}
	for _, key := range []string{"mirrorNamespaces", "skipNamespaces"} {
		v := strings.TrimSpace(s.ConfigData[key])
		if len(model.SplitList(v)) < 2 {
			continue
		}
		want := model.JoinList(model.SplitList(v), sep)
		if v != want {
			name := map[string]string{",": "comma", " ": "space"}[sep]
			add(finding.Warning, "list_separator", key, fmt.Sprintf("%s is %q; this install expects a %s-separated list (%q). The traffic forwarder may read it as one namespace.", key, v, name, want),
				"Save the setting in this app to rewrite it, or change integration.listSeparator if your traffic forwarder expects the other form.")
		}
	}
	rule := s.ConfigData["kubernetesNamespacedTrafficRule"]
	if rule == "" {
		rule = "mirror"
	}
	mirror := model.SplitList(s.ConfigData["mirrorNamespaces"])
	skip := model.SplitList(s.ConfigData["skipNamespaces"])
	if rule == "mirror" && len(mirror) > 0 {
		add(finding.Warning, "ignored_list", "mirrorNamespaces", "Mirror namespaces has no effect while the namespace rule is mirror (those namespaces are mirrored anyway).",
			"Clear it, or switch the namespace rule to skip to mirror only these namespaces.")
	}
	if rule == "skip" && len(skip) > 0 {
		add(finding.Warning, "ignored_list", "skipNamespaces", "Skip namespaces has no effect while the namespace rule is skip (unlisted namespaces are skipped anyway).",
			"Clear it, or switch the namespace rule to mirror.")
	}
	if rule == "skip" && len(mirror) == 0 {
		annotated := 0
		for _, a := range s.Annotated {
			if a.Rule == "mirror" {
				annotated++
			}
		}
		msg := "The namespace rule is skip and no Mirror namespaces are set, so only resources annotated extrahop.com/traffic-mirror-rule=mirror are forwarded"
		if annotated == 0 && s.Annotated != nil {
			add(finding.Warning, "nothing_mirrored", "mirrorNamespaces", msg+", and none are annotated: no namespaced traffic is forwarded.",
				"Add Mirror namespaces or annotate the resources to forward.")
		} else {
			add(finding.Info, "annotation_only", "mirrorNamespaces", msg+".", "")
		}
	}
	known := map[string]bool{}
	for _, n := range s.Namespaces {
		known[n] = true
	}
	inMirror := map[string]bool{}
	for _, n := range mirror {
		inMirror[n] = true
	}
	for key, list := range map[string][]string{"mirrorNamespaces": mirror, "skipNamespaces": skip} {
		for _, n := range list {
			if len(known) > 0 && !known[n] {
				add(finding.Warning, "unknown_namespace", key, fmt.Sprintf("Namespace %q in %s does not exist.", n, key), "Check the spelling, or remove it.")
			}
			if key == "skipNamespaces" && inMirror[n] {
				add(finding.Warning, "namespace_overlap", key, fmt.Sprintf("Namespace %q is in both Mirror and Skip namespaces.", n), "Keep it in one list.")
			}
		}
	}
	honoured := map[string]bool{}
	for _, k := range annotationKinds {
		honoured[strings.ToLower(k)] = true
	}
	for _, a := range s.Annotated {
		kind := a.Kind
		if a.OnTemplate {
			kind = "Pod" // a workload template annotation ends up on its pods
		}
		if len(honoured) > 0 && !honoured[strings.ToLower(kind)] {
			add(finding.Warning, "annotation_not_honored", "", fmt.Sprintf("%s %s has %s=%s, but this integration reads the annotation on %s only (policy.annotationKinds).",
				a.Kind, qual(a.Namespace, a.Name), discovery.MirrorAnnotation, a.Rule, strings.Join(annotationKinds, ", ")),
				"Use Mirror namespaces / Skip namespaces for whole namespaces, or annotate the pods.")
			continue
		}
		if a.Rule != "mirror" && a.Rule != "skip" {
			add(finding.Warning, "invalid_annotation", "", fmt.Sprintf("%s %s has %s=%q; only mirror or skip are valid.", a.Kind, qual(a.Namespace, a.Name), discovery.MirrorAnnotation, a.Rule),
				"Set mirror or skip, or remove the annotation.")
		}
	}
	return out
}

func qual(ns, name string) string {
	if ns == "" {
		return name
	}
	return ns + "/" + name
}

func linkedArgs(s *discovery.Snapshot) []finding.Finding {
	var out []finding.Finding
	for _, la := range model.LinkedArgs {
		want := s.ConfigData[la.Setting]
		for _, r := range s.ArgRefs(la.Flag) {
			if r.Value != want {
				out = append(out, f(finding.Warning, "config", "arg_drift", la.Setting,
					fmt.Sprintf("%s passes %s %q but the ConfigMap's %s is %q. The two settings disagree.", r.Workload, la.Flag, r.Value, la.Setting, want),
					"Save the setting in this app: it updates the ConfigMap and the args together."))
			}
		}
	}
	if refs := s.ArgRefs("-server"); len(refs) > 0 {
		out = append(out, f(finding.Info, "config", "args_not_from_configmap", "mgmtTarget",
			fmt.Sprintf("%s takes the sensor address and TLS name as command-line args, not from the ConfigMap. This app keeps them in sync when you edit those settings; edits made by hand must change both.", strings.Join(discovery.WorkloadsUsing(refs), ", ")), ""))
	}
	return out
}

// certPaths checks that every cert path a container is told to read is actually mounted from
// sensorCert.
func certPaths(s *discovery.Snapshot) []finding.Finding {
	var out []finding.Finding
	for _, w := range s.Workloads {
		for _, c := range w.PodSpec.Containers {
			var paths []string
			for _, e := range c.Env {
				if e.Name == "CERT_FILENAME" && e.ValueFrom == nil {
					paths = append(paths, e.Value)
				}
			}
			for _, a := range discovery.ParseArgs(append(append([]string{}, c.Command...), c.Args...)) {
				if a.Flag == "-cert" || a.Flag == "--cert" {
					paths = append(paths, a.Value)
				}
			}
			for _, p := range paths {
				if !mountedFromSensorCert(s, w, c.VolumeMounts, p) {
					out = append(out, f(finding.Critical, "config", "cert_path_unmounted", "sensorCert",
						fmt.Sprintf("%s/%s reads the sensor certificate from %s, but that path is not mounted from the ConfigMap's sensorCert.", w.Name, c.Name, p),
						"Mount sensorCert at that path (volume item key sensorCert)."))
				}
			}
		}
	}
	return out
}

func mountedFromSensorCert(s *discovery.Snapshot, w *discovery.Workload, mounts []corev1.VolumeMount, file string) bool {
	for _, m := range mounts {
		for _, v := range w.PodSpec.Volumes {
			if v.Name != m.Name || v.ConfigMap == nil || v.ConfigMap.Name != s.ConfigMapName {
				continue
			}
			if m.SubPath != "" {
				if path.Clean(m.MountPath) == path.Clean(file) && m.SubPath == "sensorCert" {
					return true
				}
				continue
			}
			if len(v.ConfigMap.Items) == 0 && path.Clean(path.Join(m.MountPath, "sensorCert")) == path.Clean(file) {
				return true
			}
			for _, it := range v.ConfigMap.Items {
				if it.Key == "sensorCert" && path.Clean(path.Join(m.MountPath, it.Path)) == path.Clean(file) {
					return true
				}
			}
		}
	}
	return false
}

func secrets(s *discovery.Snapshot, prefix string) []finding.Finding {
	var out []finding.Finding
	add := func(sev finding.Severity, code, setting, msg, fix string) {
		out = append(out, f(sev, "config", code, setting, msg, fix))
	}
	for _, si := range s.Secrets {
		users := strings.Join(discovery.WorkloadsUsing(s.SecretConsumers(si.Name, "*")), ", ")
		if !si.Exists {
			add(finding.Critical, "secret_missing", si.Name, fmt.Sprintf("Secret %s is referenced by %s but does not exist.", si.Name, users), "Create it, or set it in this app.")
			continue
		}
		for _, r := range s.Refs {
			if r.Source != "secret" || r.Object != si.Name || r.Key == "*" {
				continue
			}
			n, ok := si.Keys[r.Key]
			switch {
			case !ok:
				add(finding.Critical, "secret_key_missing", si.Name, fmt.Sprintf("%s reads key %s from Secret %s, which has no such key.", r.Workload, r.Key, si.Name), "Add the key.")
			case n == 0:
				add(finding.Critical, "secret_key_empty", si.Name, fmt.Sprintf("Secret %s key %s is empty.", si.Name, r.Key), "Set a value.")
			}
		}
		if es := si.ExternalSecret; es != nil && !es.Ready {
			add(finding.Warning, "externalsecret_not_ready", si.Name, fmt.Sprintf("ExternalSecret %s (store %s) is not Ready: %s %s", es.Name, es.Store, es.Reason, es.Message),
				"Check the secret store and the remote key.")
		}
	}
	seen := map[string]bool{}
	for _, ss := range model.Secrets {
		if ss.PublicKey == "" {
			continue
		}
		name := ss.SecretName(prefix)
		si := s.Secret(name)
		if si == nil || !si.Exists || seen[name] {
			continue
		}
		seen[name] = true
		pub, err := model.DecodeKey(s.ConfigData[ss.PublicKey])
		if err != nil {
			continue // reported as invalid_value
		}
		switch KeyPairMatches(si.Value(ss.Key), pub) {
		case PairMismatch:
			add(finding.Critical, "keypair_mismatch", ss.PublicKey, fmt.Sprintf("%s in Secret %s does not match %s in the ConfigMap; the coordinator and forwarders cannot talk.", ss.Label, name, ss.PublicKey),
				"Regenerate the key pair on the sensor's Kubernetes Integration page, or rotate it here.")
		case PairUnknownFormat:
			add(finding.Info, "keypair_unchecked", ss.PublicKey, fmt.Sprintf("%s is not a 64-hex-character key, so it could not be checked against %s.", ss.Label, ss.PublicKey), "")
		}
	}
	return out
}

type PairResult int

const (
	PairMatch PairResult = iota
	PairMismatch
	PairUnknownFormat
)

// KeyPairMatches checks a private key against a public key. The integration's key format is not
// documented, so both X25519 and Ed25519 derivations are tried.
func KeyPairMatches(private, public []byte) PairResult {
	priv, err := model.DecodeKey(string(bytes.TrimSpace(private)))
	if err != nil {
		return PairUnknownFormat
	}
	if k, err := ecdh.X25519().NewPrivateKey(priv); err == nil && bytes.Equal(k.PublicKey().Bytes(), public) {
		return PairMatch
	}
	if bytes.Equal(ed25519.NewKeyFromSeed(priv).Public().(ed25519.PublicKey), public) {
		return PairMatch
	}
	return PairMismatch
}

func images(s *discovery.Snapshot) []finding.Finding {
	var out []finding.Finding
	byImage := map[string]map[string]string{} // repo -> tag -> workload
	for _, w := range s.Workloads {
		for c, img := range w.Images {
			repo, tag := splitImage(img)
			if tag == "latest" || tag == "" {
				out = append(out, f(finding.Warning, "config", "floating_image_tag", "",
					fmt.Sprintf("%s/%s uses %s; pods on different nodes can run different versions.", w.Name, c, img), "Pin a release tag."))
			}
			if byImage[repo] == nil {
				byImage[repo] = map[string]string{}
			}
			byImage[repo][tag] = w.Name
		}
	}
	for repo, tags := range byImage {
		if len(tags) > 1 {
			var list []string
			for t, w := range tags {
				list = append(list, w+"="+t)
			}
			sort.Strings(list)
			out = append(out, f(finding.Warning, "config", "image_version_skew", "",
				fmt.Sprintf("%s runs different tags: %s.", repo, strings.Join(list, ", ")), "Use one tag for every workload of this image."))
		}
	}
	return out
}

func splitImage(img string) (repo, tag string) {
	if i := strings.Index(img, "@"); i >= 0 {
		return img[:i], img[i+1:]
	}
	slash := strings.LastIndex(img, "/")
	if i := strings.LastIndex(img, ":"); i > slash {
		return img[:i], img[i+1:]
	}
	return img, ""
}

// Runtime checks pods and rollouts.
func Runtime(s *discovery.Snapshot) []finding.Finding {
	var out []finding.Finding
	for _, w := range s.Workloads {
		switch {
		case w.Desired > 0 && w.Ready == 0:
			out = append(out, f(finding.Critical, "runtime", "workload_down", w.Name, fmt.Sprintf("%s %s has no ready pods (0/%d).", w.Kind, w.Name, w.Desired), "Check its logs and events."))
		case !w.Healthy():
			out = append(out, f(finding.Warning, "runtime", "workload_degraded", w.Name,
				fmt.Sprintf("%s %s: %d/%d ready, %d updated.", w.Kind, w.Name, w.Ready, w.Desired, w.Updated), "A rollout may be in progress or stuck."))
		}
		for _, p := range w.Pods {
			if p.Waiting == "CrashLoopBackOff" || p.Waiting == "ImagePullBackOff" || p.Waiting == "ErrImagePull" || p.Waiting == "CreateContainerConfigError" {
				out = append(out, f(finding.Critical, "runtime", "pod_failing", w.Name, fmt.Sprintf("Pod %s on %s is %s.", p.Name, p.Node, p.Waiting),
					"Open its logs; CreateContainerConfigError usually means a missing ConfigMap or Secret key."))
			}
		}
	}
	return out
}

// Logs turns recurring error signatures into findings.
func Logs(stats []LogStat, perHour int) []finding.Finding {
	if perHour <= 0 {
		perHour = 30
	}
	var out []finding.Finding
	infos, hidden := 0, 0
	for _, st := range stats {
		hours := st.Window.Hours()
		if hours <= 0 {
			hours = 1
		}
		rate := float64(st.Count) / hours
		sev := finding.Info
		if rate >= float64(perHour) {
			sev = finding.Warning
		} else if infos++; infos > 5 {
			hidden++
			continue
		}
		out = append(out, f(sev, "logs", "log_errors", st.Component+": "+st.Signature,
			fmt.Sprintf("%s logged %q %d times in the last %s (%.0f/h).", st.Component, st.Signature, st.Count, st.Window.Round(time.Minute), rate),
			"Open the log viewer filtered to this message."))
	}
	if hidden > 0 {
		out = append(out, f(finding.Info, "logs", "log_errors_more", "", fmt.Sprintf("%d more occasional error messages; see the log viewer's error summary.", hidden), ""))
	}
	return out
}

// Resolver and dialer are replaceable for tests.
type Network struct {
	Resolver *net.Resolver
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	Timeout  time.Duration
}

// CheckNetwork tests what this app can reach. The forwarders mostly use the host network, so a
// failure here is a strong hint, not proof.
func CheckNetwork(ctx context.Context, n Network, s *discovery.Snapshot, probePort int) []finding.Finding {
	var out []finding.Finding
	if n.Resolver == nil {
		n.Resolver = net.DefaultResolver
	}
	if n.Timeout == 0 {
		n.Timeout = 5 * time.Second
	}
	if n.Dial == nil {
		d := &net.Dialer{Timeout: n.Timeout}
		n.Dial = d.DialContext
	}
	resolve := func(key, host string) bool {
		if net.ParseIP(host) != nil {
			return true
		}
		ctx, cancel := context.WithTimeout(ctx, n.Timeout)
		defer cancel()
		if _, err := n.Resolver.LookupHost(ctx, host); err != nil {
			out = append(out, f(finding.Critical, "network", "dns_failed", key, fmt.Sprintf("%s %q does not resolve: %v", key, host, err), "Fix DNS or use an IP address."))
			return false
		}
		return true
	}
	if mt := s.ConfigData["mgmtTarget"]; mt != "" && resolve("mgmtTarget", mt) {
		addr := net.JoinHostPort(mt, fmt.Sprint(probePort))
		ctx, cancel := context.WithTimeout(ctx, n.Timeout)
		c, err := n.Dial(ctx, "tcp", addr)
		cancel()
		if err != nil {
			out = append(out, f(finding.Warning, "network", "sensor_unreachable", "mgmtTarget", fmt.Sprintf("Cannot connect to %s from this app: %v", addr, err),
				"Check firewall rules: the cluster must reach the sensor on 443 (and 4873 for session keys, UDP 6081 for traffic)."))
		} else {
			c.Close()
		}
	}
	if mt := s.ConfigData["mirrorTarget"]; mt != "" {
		if h, _, err := net.SplitHostPort(mt); err == nil {
			resolve("mirrorTarget", h)
		}
	}
	return out
}
