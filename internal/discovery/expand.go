package discovery

import (
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// ArgExpansion is an arg value after the kubelet's $(VAR) expansion, as far as the snapshot
// can tell.
type ArgExpansion struct {
	// Value is the expanded value. References that cannot be resolved are left as written.
	Value string `json:"value"`
	// HasRefs: the value as written contains at least one $(VAR) reference.
	HasRefs bool `json:"hasRefs,omitempty"`
	// Resolved: every reference was resolved (no Secret, fieldRef, other ConfigMap or undefined var).
	Resolved bool `json:"resolved"`
	// ConfigKeys lists the integration ConfigMap keys the value is read from.
	ConfigKeys []string `json:"configKeys,omitempty"`
	// Tracks: the value is exactly one $(VAR) reference to integration ConfigMap key Tracks.
	// Such an arg follows the ConfigMap by itself and must never be rewritten.
	Tracks string `json:"tracks,omitempty"`
}

// envVal is what the snapshot knows about one container env var.
type envVal struct {
	value  string
	cmKeys []string
	known  bool
	// tracks: the var is exactly integration ConfigMap key tracks (directly or via another var).
	tracks string
}

// ExpandArg resolves $(VAR) references in an arg ref's value through its container's env, the
// way the kubelet does at container start: env literals, and configMapKeyRef / envFrom into the
// integration ConfigMap (read from s.ConfigData, so a proposed snapshot expands with the
// proposed values).
func (s *Snapshot) ExpandArg(r Ref) ArgExpansion {
	return expandVars(r.Value, s.containerEnv(r.Workload, r.Container))
}

func (s *Snapshot) containerEnv(workload, container string) map[string]envVal {
	env := map[string]envVal{}
	w := s.Workload(workload)
	if w == nil {
		return env
	}
	var c *corev1.Container
	for _, list := range [][]corev1.Container{w.PodSpec.InitContainers, w.PodSpec.Containers} {
		for i := range list {
			if list[i].Name == container {
				c = &list[i]
			}
		}
	}
	if c == nil {
		return env
	}
	// envFrom first; env entries override it (kubelet order).
	for _, ef := range c.EnvFrom {
		if ef.ConfigMapRef == nil || ef.ConfigMapRef.Name != s.ConfigMapName {
			continue // a Secret or another ConfigMap: names unknown, so leave them undefined
		}
		for k, v := range s.ConfigData {
			env[ef.Prefix+k] = envVal{value: v, cmKeys: []string{k}, known: true, tracks: k}
		}
	}
	for _, e := range c.Env {
		switch {
		case e.ValueFrom == nil:
			// Env values may reference earlier vars too.
			x := expandVars(e.Value, env)
			env[e.Name] = envVal{value: x.Value, cmKeys: x.ConfigKeys, known: x.Resolved, tracks: x.Tracks}
		case e.ValueFrom.ConfigMapKeyRef != nil && e.ValueFrom.ConfigMapKeyRef.Name == s.ConfigMapName:
			k := e.ValueFrom.ConfigMapKeyRef.Key
			v, ok := s.ConfigData[k]
			env[e.Name] = envVal{value: v, cmKeys: []string{k}, known: ok, tracks: k}
		default:
			env[e.Name] = envVal{known: false}
		}
	}
	return env
}

// expandVars implements Kubernetes $(VAR) expansion: $$ is a literal $, $(NAME) is replaced
// when NAME is defined, and anything else is kept as written.
func expandVars(in string, env map[string]envVal) ArgExpansion {
	out := ArgExpansion{Resolved: true}
	keys := map[string]bool{}
	var b strings.Builder
	for i := 0; i < len(in); i++ {
		if in[i] != '$' || i+1 >= len(in) {
			b.WriteByte(in[i])
			continue
		}
		switch in[i+1] {
		case '$':
			b.WriteByte('$')
			i++
			continue
		case '(':
			end := strings.IndexByte(in[i+2:], ')')
			if end < 0 {
				b.WriteString(in[i:])
				i = len(in)
				continue
			}
			name := in[i+2 : i+2+end]
			raw := in[i : i+3+end]
			i += 2 + end
			out.HasRefs = true
			v, ok := env[name]
			if !ok || !v.known {
				out.Resolved = false
				b.WriteString(raw)
				continue
			}
			b.WriteString(v.value)
			for _, k := range v.cmKeys {
				keys[k] = true
			}
			if raw == in {
				out.Tracks = v.tracks
			}
		default:
			b.WriteByte(in[i])
		}
	}
	out.Value = b.String()
	for k := range keys {
		out.ConfigKeys = append(out.ConfigKeys, k)
	}
	sort.Strings(out.ConfigKeys)
	return out
}
