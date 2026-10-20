package apply

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/opswhisperer/eh-k8s-console/internal/discovery"
	"github.com/opswhisperer/eh-k8s-console/internal/model"
)

const (
	historyLabel  = "eh-k8s-console.opswhisperer.io/history"
	historyPrefix = "eh-k8s-console-rev-"
)

// Revision records the state *before* a change plus what the change did, so "undo change N"
// restores Revision N. Secret values are never stored.
type Revision struct {
	N          int                        `json:"n"`
	Time       string                     `json:"time"`
	User       string                     `json:"user"`
	Kind       string                     `json:"kind"` // apply | rollback | cert-refresh | cert-auto-sync | annotate
	Reason     string                     `json:"reason,omitempty"`
	Changes    []FieldChange              `json:"changes"`
	ConfigData map[string]string          `json:"configData"`
	Containers map[string][]containerView `json:"containers"`
}

// Summary is a Revision without the bulky state, for listings.
type Summary struct {
	N       int           `json:"n"`
	Time    string        `json:"time"`
	User    string        `json:"user"`
	Kind    string        `json:"kind"`
	Reason  string        `json:"reason,omitempty"`
	Changes []FieldChange `json:"changes"`
}

func (e *Engine) listHistory(ctx context.Context) ([]corev1.ConfigMap, error) {
	l, err := e.Kube.CoreV1().ConfigMaps(e.Namespace).List(ctx, metav1.ListOptions{LabelSelector: historyLabel + "=true"})
	if err != nil {
		return nil, err
	}
	items := l.Items
	sort.Slice(items, func(i, j int) bool { return revNum(items[i].Name) > revNum(items[j].Name) })
	return items, nil
}

func revNum(name string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(name, historyPrefix))
	return n
}

// SaveRevision stores the live state and the plan's changes, pruning old revisions.
func (e *Engine) SaveRevision(ctx context.Context, live *discovery.Snapshot, p *Plan, who, kind string) (int, error) {
	items, err := e.listHistory(ctx)
	if err != nil {
		return 0, err
	}
	n := 1
	if len(items) > 0 {
		n = revNum(items[0].Name) + 1
	}
	rev := Revision{N: n, Time: e.now().UTC().Format("2006-01-02T15:04:05Z"), User: who, Kind: kind, ConfigData: live.ConfigData, Containers: map[string][]containerView{}}
	if p != nil {
		rev.Reason, rev.Changes = p.Reason, p.Changes
	}
	for _, w := range live.Workloads {
		var cs []containerView
		for _, c := range w.PodSpec.Containers {
			cs = append(cs, containerView{c.Name, c.Image, c.Command, c.Args})
		}
		rev.Containers[w.Name] = cs
	}
	b, err := json.Marshal(rev)
	if err != nil {
		return 0, err
	}
	sum, _ := json.Marshal(Summary{N: n, Time: rev.Time, User: who, Kind: kind, Reason: rev.Reason, Changes: rev.Changes})
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s%05d", historyPrefix, n), Namespace: e.Namespace,
			Labels: map[string]string{historyLabel: "true", "app.kubernetes.io/managed-by": "eh-k8s-console"}},
		Data: map[string]string{"revision.json": string(b), "summary.json": string(sum)},
	}
	if _, err := e.Kube.CoreV1().ConfigMaps(e.Namespace).Create(ctx, cm, metav1.CreateOptions{FieldManager: FieldManager}); err != nil {
		return 0, err
	}
	keep := e.HistoryKeep
	if keep <= 0 {
		keep = 20
	}
	for i, it := range items {
		if i+1 >= keep { // +1 for the one just created
			_ = e.Kube.CoreV1().ConfigMaps(e.Namespace).Delete(ctx, it.Name, metav1.DeleteOptions{})
		}
	}
	return n, nil
}

// History lists revisions, newest first.
func (e *Engine) History(ctx context.Context) ([]Summary, error) {
	items, err := e.listHistory(ctx)
	if err != nil {
		return nil, err
	}
	var out []Summary
	for _, it := range items {
		var s Summary
		if json.Unmarshal([]byte(it.Data["summary.json"]), &s) == nil {
			out = append(out, s)
		}
	}
	return out, nil
}

// Revision loads one revision.
func (e *Engine) Revision(ctx context.Context, n int) (*Revision, error) {
	cm, err := e.Kube.CoreV1().ConfigMaps(e.Namespace).Get(ctx, fmt.Sprintf("%s%05d", historyPrefix, n), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	var r Revision
	if err := json.Unmarshal([]byte(cm.Data["revision.json"]), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// RollbackChange builds a Change that restores revision r's state (ConfigMap data, container
// images and args). Secrets are not restored: their values were never recorded. Read-only
// settings (the key pairs) are left as they are, because their private halves can't be restored.
func RollbackChange(live *discovery.Snapshot, r *Revision) Change {
	ch := Change{Config: map[string]string{}, Images: map[string]string{}, Args: map[string][]string{},
		Reason: fmt.Sprintf("roll back to the state before revision %d", r.N)}
	for k, v := range r.ConfigData {
		if st := model.Lookup(k); st != nil && st.ReadOnly {
			continue
		}
		if live.ConfigData[k] != v {
			ch.Config[k] = v
		}
	}
	for k := range live.ConfigData {
		if st := model.Lookup(k); st != nil && st.ReadOnly {
			continue
		}
		if _, ok := r.ConfigData[k]; !ok {
			ch.Remove = append(ch.Remove, k)
		}
	}
	for wn, cs := range r.Containers {
		w := live.Workload(wn)
		if w == nil {
			continue
		}
		for _, c := range cs {
			lc := container(&w.PodSpec, c.Name)
			if lc == nil {
				continue
			}
			if lc.Image != c.Image {
				ch.Images[wn+"/"+c.Name] = c.Image
			}
			if strings.Join(lc.Args, "\x00") != strings.Join(c.Args, "\x00") {
				ch.Args[wn+"/"+c.Name] = c.Args
			}
		}
	}
	return ch
}
