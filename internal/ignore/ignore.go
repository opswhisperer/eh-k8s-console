// Package ignore holds the rules that hide known-harmless log errors from findings, metrics and
// alerts. Rules come from two places: the config file (logs.ignore, read-only here) and the
// console itself (added from a log line, kept in a ConfigMap the console owns).
package ignore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	SourceConfig  = "config"
	SourceConsole = "console"
	// MaxRules bounds the console-managed list.
	MaxRules = 100
)

type Rule struct {
	Pattern   string    `json:"pattern"`
	Note      string    `json:"note,omitempty"`
	Source    string    `json:"source"`
	CreatedBy string    `json:"createdBy,omitempty"`
	CreatedAt time.Time `json:"createdAt,omitempty"`

	re *regexp.Regexp
}

// Store merges config rules with console rules persisted in a ConfigMap.
type Store struct {
	Kube      kubernetes.Interface
	Namespace string
	Name      string
	ReadOnly  bool

	mu      sync.RWMutex
	config  []Rule
	console []Rule
}

// NewStore compiles the config rules (already validated by config.Validate).
func NewStore(kube kubernetes.Interface, namespace, name string, configPatterns []string, readOnly bool) *Store {
	s := &Store{Kube: kube, Namespace: namespace, Name: name, ReadOnly: readOnly}
	for _, p := range configPatterns {
		if re, err := regexp.Compile(p); err == nil {
			s.config = append(s.config, Rule{Pattern: p, Source: SourceConfig, re: re})
		}
	}
	return s
}

// Load re-reads console rules from the ConfigMap (called every scan, so replicas agree).
func (s *Store) Load(ctx context.Context) error {
	if s.Kube == nil {
		return nil
	}
	cm, err := s.Kube.CoreV1().ConfigMaps(s.Namespace).Get(ctx, s.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		s.mu.Lock()
		s.console = nil
		s.mu.Unlock()
		return nil
	}
	if err != nil {
		return err
	}
	var rules []Rule
	if raw := cm.Data["rules.json"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &rules); err != nil {
			return fmt.Errorf("%s/%s rules.json: %w", s.Namespace, s.Name, err)
		}
	}
	var ok []Rule
	for _, r := range rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			continue
		}
		r.re, r.Source = re, SourceConsole
		ok = append(ok, r)
	}
	s.mu.Lock()
	s.console = ok
	s.mu.Unlock()
	return nil
}

// Rules returns config rules first, then console rules.
func (s *Store) Rules() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append(append([]Rule{}, s.config...), s.console...)
}

// Match returns the first rule matching a signature.
func (s *Store) Match(sig string) (Rule, bool) {
	if s == nil || sig == "" {
		return Rule{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, list := range [][]Rule{s.config, s.console} {
		for _, r := range list {
			if r.re.MatchString(sig) {
				return r, true
			}
		}
	}
	return Rule{}, false
}

// Validate checks a proposed pattern.
func Validate(pattern string) (*regexp.Regexp, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, errors.New("the pattern is empty")
	}
	if len(pattern) > 500 {
		return nil, errors.New("the pattern is longer than 500 characters")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("not a valid regular expression: %w", err)
	}
	if re.MatchString("") {
		return nil, errors.New("the pattern matches everything (it matches an empty string); anchor it to a message")
	}
	return re, nil
}

// Suggest builds an exact, anchored pattern for a signature.
func Suggest(sig string) string { return "^" + regexp.QuoteMeta(sig) + "$" }

// Add stores a console rule.
func (s *Store) Add(ctx context.Context, pattern, note, who string) (Rule, error) {
	if s.ReadOnly {
		return Rule{}, errors.New("this console is read-only")
	}
	pattern = strings.TrimSpace(pattern)
	re, err := Validate(pattern)
	if err != nil {
		return Rule{}, err
	}
	if err := s.Load(ctx); err != nil {
		return Rule{}, err
	}
	for _, r := range s.Rules() {
		if r.Pattern == pattern {
			return Rule{}, fmt.Errorf("that rule already exists (%s)", r.Source)
		}
	}
	s.mu.RLock()
	n := len(s.console)
	s.mu.RUnlock()
	if n >= MaxRules {
		return Rule{}, fmt.Errorf("there are already %d console rules; remove some first", MaxRules)
	}
	r := Rule{Pattern: pattern, Note: strings.TrimSpace(note), Source: SourceConsole, CreatedBy: who, CreatedAt: time.Now().UTC(), re: re}
	s.mu.Lock()
	next := append(append([]Rule{}, s.console...), r)
	s.mu.Unlock()
	if err := s.save(ctx, next); err != nil {
		return Rule{}, err
	}
	s.mu.Lock()
	s.console = next
	s.mu.Unlock()
	return r, nil
}

// Remove deletes a console rule (config rules can only be removed from the config file).
func (s *Store) Remove(ctx context.Context, pattern string) error {
	if s.ReadOnly {
		return errors.New("this console is read-only")
	}
	if err := s.Load(ctx); err != nil {
		return err
	}
	for _, r := range s.config {
		if r.Pattern == pattern {
			return errors.New("this rule comes from the config file (logs.ignore); remove it there")
		}
	}
	s.mu.RLock()
	var next []Rule
	found := false
	for _, r := range s.console {
		if r.Pattern == pattern {
			found = true
			continue
		}
		next = append(next, r)
	}
	s.mu.RUnlock()
	if !found {
		return errors.New("no such rule")
	}
	if err := s.save(ctx, next); err != nil {
		return err
	}
	s.mu.Lock()
	s.console = next
	s.mu.Unlock()
	return nil
}

func (s *Store) save(ctx context.Context, rules []Rule) error {
	if rules == nil {
		rules = []Rule{}
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].CreatedAt.Before(rules[j].CreatedAt) })
	b, _ := json.MarshalIndent(rules, "", "  ")
	data := map[string]string{"rules.json": string(b)}
	cms := s.Kube.CoreV1().ConfigMaps(s.Namespace)
	cm, err := cms.Get(ctx, s.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cms.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: s.Name, Namespace: s.Namespace,
			Labels: map[string]string{"app.kubernetes.io/managed-by": "eh-k8s-console"}}, Data: data},
			metav1.CreateOptions{FieldManager: "eh-k8s-console"})
		return err
	}
	if err != nil {
		return err
	}
	cm.Data = data
	_, err = cms.Update(ctx, cm, metav1.UpdateOptions{FieldManager: "eh-k8s-console"})
	return err
}
