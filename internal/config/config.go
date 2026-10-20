// Package config loads eh-k8s-console's YAML configuration.
//
// Secret values never live in the config file itself: every credential is read from a file
// (a mounted Secret, ExternalSecret target or CSI volume) or an environment variable that the
// config names, so the same config works whichever way the secret is delivered.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/opswhisperer/eh-k8s-console/internal/policy"
)

// Duration is a time.Duration that reads "30s"/"5m" from YAML.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		var n float64
		if err2 := json.Unmarshal(b, &n); err2 != nil {
			return err
		}
		d.Duration = time.Duration(n * float64(time.Second))
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// SecretRef names where a secret value comes from: a file (preferred) or an env var.
type SecretRef struct {
	File string `json:"file,omitempty"`
	Env  string `json:"env,omitempty"`
}

// Read returns the trimmed secret value, or "" when neither source is set.
func (r SecretRef) Read() (string, error) {
	if r.File != "" {
		b, err := os.ReadFile(r.File)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", r.File, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if r.Env != "" {
		return strings.TrimSpace(os.Getenv(r.Env)), nil
	}
	return "", nil
}

func (r SecretRef) Set() bool { return r.File != "" || r.Env != "" }

type Config struct {
	Listen   string `json:"listen"`
	BaseURL  string `json:"baseURL"`
	ReadOnly bool   `json:"readOnly"`

	Kube struct {
		Kubeconfig string `json:"kubeconfig"`
		Context    string `json:"context"`
	} `json:"kube"`

	Integration Integration `json:"integration"`
	Auth        Auth        `json:"auth"`
	Certs       Certs       `json:"certs"`
	Alerts      Alerts      `json:"alerts"`
	History     History     `json:"history"`
	Logs        Logs        `json:"logs"`
	Policy      Policy      `json:"policy"`

	// ScanInterval is how often the background loop rediscovers, validates and probes.
	ScanInterval Duration `json:"scanInterval"`
}

type Integration struct {
	Namespace string `json:"namespace"`
	// Prefix is the object-name prefix the official manifests and chart use.
	Prefix      string      `json:"prefix"`
	ConfigMap   string      `json:"configMap"`
	Annotations Annotations `json:"annotations"`
	// ListSeparator is how mirrorNamespaces/skipNamespaces are written: "," (the documented
	// form) or " " if your traffic-forwarder build expects spaces. Default ",".
	ListSeparator string `json:"listSeparator"`
}

// Annotations controls listing and editing the extrahop.com/traffic-mirror-rule annotation on
// pods, workload pod templates, services and namespaces anywhere in the cluster. It is off by
// default because it needs the optional cluster-wide RBAC (deploy/components/annotations).
type Annotations struct {
	Enabled bool `json:"enabled"`
	// AllowNamespaces limits edits to these namespaces (empty means all not excluded).
	AllowNamespaces []string `json:"allowNamespaces"`
	// ExcludeNamespaces are never edited.
	ExcludeNamespaces []string `json:"excludeNamespaces"`
	// MaxTargets caps how many objects one selector-based edit may touch.
	MaxTargets int `json:"maxTargets"`
}

// Editable reports whether annotation edits are allowed in namespace ns.
func (a Annotations) Editable(ns string) bool {
	if !a.Enabled {
		return false
	}
	for _, x := range a.ExcludeNamespaces {
		if x == ns {
			return false
		}
	}
	if len(a.AllowNamespaces) == 0 {
		return true
	}
	for _, x := range a.AllowNamespaces {
		if x == ns {
			return true
		}
	}
	return false
}

// Policy describes how your traffic-forwarder version evaluates filtering, for the preview.
type Policy struct {
	// Order lists the evaluation steps, first match wins (see internal/policy for the step
	// names). Empty turns the "what gets mirrored" preview off.
	Order []string `json:"order"`
	// AnnotationKinds are the kinds whose extrahop.com/traffic-mirror-rule annotation the
	// integration reads (e.g. Pod, Node). Annotations on other kinds are flagged. Empty: no check.
	AnnotationKinds []string `json:"annotationKinds"`
}

type Auth struct {
	// Modes enabled, any of: oidc, local, apikey, proxy, none.
	Modes         []string  `json:"modes"`
	SessionSecret SecretRef `json:"sessionSecret"`
	SessionTTL    Duration  `json:"sessionTTL"`
	OIDC          OIDC      `json:"oidc"`
	Local         Local     `json:"local"`
	APIKeys       APIKeys   `json:"apiKeys"`
	Proxy         Proxy     `json:"proxy"`
	// DefaultRole is given to an authenticated user who matches no role mapping.
	// Empty means such users are refused.
	DefaultRole string `json:"defaultRole"`
}

type OIDC struct {
	Issuer       string    `json:"issuer"`
	ClientID     string    `json:"clientID"`
	ClientSecret SecretRef `json:"clientSecret"`
	Scopes       []string  `json:"scopes"`
	GroupsClaim  string    `json:"groupsClaim"`
	// Roles maps an IdP group to a role (viewer, operator, admin).
	Roles map[string]string `json:"roles"`
	// DisplayName is shown on the sign-in button.
	DisplayName string `json:"displayName"`
}

type Local struct {
	// UsersFile is a YAML/JSON list of {username, passwordHash (bcrypt), role}.
	UsersFile string `json:"usersFile"`
}

type APIKeys struct {
	// File is a YAML/JSON list of {name, hash (sha256 hex of the key), role}.
	File string `json:"file"`
}

type Proxy struct {
	UserHeader   string   `json:"userHeader"`
	GroupsHeader string   `json:"groupsHeader"`
	EmailHeader  string   `json:"emailHeader"`
	TrustedCIDRs []string `json:"trustedCIDRs"`
	// Roles maps a group from GroupsHeader to a role.
	Roles map[string]string `json:"roles"`
}

type Certs struct {
	ProbePort        int      `json:"probePort"`
	SessionKeyPort   int      `json:"sessionKeyPort"`
	ProbeTimeout     Duration `json:"probeTimeout"`
	LeafWarnDays     int      `json:"leafWarnDays"`
	LeafCriticalDays int      `json:"leafCriticalDays"`
	AnchorWarnDays   int      `json:"anchorWarnDays"`
	// AutoSync lets the scan loop replace sensorCert when the sensor's chain changed but is
	// still verifiable (never for self-signed certs).
	AutoSync bool `json:"autoSync"`
	// Source optionally names a Secret/ConfigMap key holding the PEM bundle to keep sensorCert
	// in sync with (for example a trust-manager Bundle or cert-manager ca.crt).
	Source *CertSource `json:"source,omitempty"`
}

type CertSource struct {
	Kind      string `json:"kind"` // Secret or ConfigMap
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Key       string `json:"key"`
}

type Alerts struct {
	Events   bool      `json:"events"`
	Webhooks []Webhook `json:"webhooks"`
}

type Webhook struct {
	Name string `json:"name"`
	// URL is the endpoint. A URL that embeds a token can come from URLFrom (file/env) instead.
	URL     string    `json:"url"`
	URLFrom SecretRef `json:"urlFrom"`
	Format  string    `json:"format"` // apprise | json | slack
	// MinSeverity is the lowest severity sent: info, warning, critical.
	MinSeverity string `json:"minSeverity"`
	// Tag is passed to Apprise as the notification tag.
	Tag string `json:"tag"`
}

type History struct {
	Keep int `json:"keep"`
}

type Logs struct {
	TailLines int64 `json:"tailLines"`
	// SignatureWindow is how far back error signatures are counted.
	SignatureWindow Duration `json:"signatureWindow"`
	// WarnPerHour: a recurring error at or above this rate becomes a warning (default 30).
	WarnPerHour int `json:"warnPerHour"`
	// Ignore lists regular expressions; matching signatures are not reported (they still show
	// in the log viewer).
	Ignore []string `json:"ignore"`
}

// Default returns a config with every default applied.
func Default() *Config {
	c := &Config{}
	c.applyDefaults()
	return c
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.Integration.Namespace == "" {
		c.Integration.Namespace = "extrahop"
	}
	if c.Integration.Prefix == "" {
		c.Integration.Prefix = "extrahop-kubernetes-integration-"
	}
	if c.Integration.ConfigMap == "" {
		c.Integration.ConfigMap = c.Integration.Prefix + "cm"
	}
	if c.Integration.ListSeparator == "" {
		c.Integration.ListSeparator = ","
	}
	if c.Integration.Annotations.ExcludeNamespaces == nil {
		c.Integration.Annotations.ExcludeNamespaces = []string{"kube-system", "kube-public", "kube-node-lease"}
	}
	if c.Integration.Annotations.MaxTargets == 0 {
		c.Integration.Annotations.MaxTargets = 200
	}
	if c.Auth.SessionTTL.Duration == 0 {
		c.Auth.SessionTTL.Duration = 12 * time.Hour
	}
	if len(c.Auth.OIDC.Scopes) == 0 {
		c.Auth.OIDC.Scopes = []string{"openid", "profile", "email", "groups"}
	}
	if c.Auth.OIDC.GroupsClaim == "" {
		c.Auth.OIDC.GroupsClaim = "groups"
	}
	if c.Auth.OIDC.DisplayName == "" {
		c.Auth.OIDC.DisplayName = "single sign-on"
	}
	if c.Auth.Proxy.UserHeader == "" {
		c.Auth.Proxy.UserHeader = "X-Forwarded-User"
	}
	if c.Auth.Proxy.GroupsHeader == "" {
		c.Auth.Proxy.GroupsHeader = "X-Forwarded-Groups"
	}
	if c.Auth.Proxy.EmailHeader == "" {
		c.Auth.Proxy.EmailHeader = "X-Forwarded-Email"
	}
	if c.Certs.ProbePort == 0 {
		c.Certs.ProbePort = 443
	}
	if c.Certs.SessionKeyPort == 0 {
		c.Certs.SessionKeyPort = 4873
	}
	if c.Certs.ProbeTimeout.Duration == 0 {
		c.Certs.ProbeTimeout.Duration = 5 * time.Second
	}
	if c.Certs.LeafWarnDays == 0 {
		c.Certs.LeafWarnDays = 21
	}
	if c.Certs.LeafCriticalDays == 0 {
		c.Certs.LeafCriticalDays = 7
	}
	if c.Certs.AnchorWarnDays == 0 {
		c.Certs.AnchorWarnDays = 30
	}
	if c.History.Keep == 0 {
		c.History.Keep = 20
	}
	if c.Logs.TailLines == 0 {
		c.Logs.TailLines = 500
	}
	if c.Logs.SignatureWindow.Duration == 0 {
		c.Logs.SignatureWindow.Duration = time.Hour
	}
	if c.Logs.WarnPerHour == 0 {
		c.Logs.WarnPerHour = 30
	}
	if c.ScanInterval.Duration == 0 {
		c.ScanInterval.Duration = 5 * time.Minute
	}
	for i := range c.Alerts.Webhooks {
		if c.Alerts.Webhooks[i].Format == "" {
			c.Alerts.Webhooks[i].Format = "json"
		}
		if c.Alerts.Webhooks[i].MinSeverity == "" {
			c.Alerts.Webhooks[i].MinSeverity = "warning"
		}
	}
}

// Load reads path (empty means defaults only) and validates the result.
func Load(path string) (*Config, error) {
	c := &Config{}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := yaml.UnmarshalStrict(b, c); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	c.applyDefaults()
	return c, c.Validate()
}

var knownModes = map[string]bool{"oidc": true, "local": true, "apikey": true, "proxy": true, "none": true}

// Validate reports config mistakes that would otherwise surface as confusing runtime errors.
func (c *Config) Validate() error {
	var errs []error
	for _, m := range c.Auth.Modes {
		if !knownModes[m] {
			errs = append(errs, fmt.Errorf("auth.modes: unknown mode %q", m))
		}
	}
	if c.HasMode("none") && len(c.Auth.Modes) > 1 {
		errs = append(errs, errors.New("auth.modes: \"none\" cannot be combined with other modes"))
	}
	if c.HasMode("oidc") {
		o := c.Auth.OIDC
		if o.Issuer == "" || o.ClientID == "" || !o.ClientSecret.Set() {
			errs = append(errs, errors.New("auth.oidc: issuer, clientID and clientSecret are required"))
		}
		if c.BaseURL == "" {
			errs = append(errs, errors.New("baseURL is required for OIDC (it builds the redirect URL)"))
		}
	}
	if c.HasMode("local") && c.Auth.Local.UsersFile == "" {
		errs = append(errs, errors.New("auth.local.usersFile is required"))
	}
	if c.HasMode("apikey") && c.Auth.APIKeys.File == "" {
		errs = append(errs, errors.New("auth.apiKeys.file is required"))
	}
	if c.HasMode("proxy") && len(c.Auth.Proxy.TrustedCIDRs) == 0 {
		errs = append(errs, errors.New("auth.proxy.trustedCIDRs is required: never trust identity headers from everyone"))
	}
	if _, err := policy.ParseOrder(c.Policy.Order); err != nil {
		errs = append(errs, fmt.Errorf("policy.order: %w", err))
	}
	for _, re := range c.Logs.Ignore {
		if _, err := regexp.Compile(re); err != nil {
			errs = append(errs, fmt.Errorf("logs.ignore %q: %w", re, err))
		}
	}
	if sep := c.Integration.ListSeparator; sep != "," && sep != " " {
		errs = append(errs, fmt.Errorf("integration.listSeparator must be \",\" or \" \", not %q", sep))
	}
	if r := c.Auth.DefaultRole; r != "" && r != "viewer" && r != "operator" && r != "admin" {
		errs = append(errs, fmt.Errorf("auth.defaultRole: unknown role %q", r))
	}
	if s := c.Certs.Source; s != nil {
		if (s.Kind != "Secret" && s.Kind != "ConfigMap") || s.Name == "" || s.Key == "" {
			errs = append(errs, errors.New("certs.source: kind (Secret|ConfigMap), name and key are required"))
		}
		if s.Namespace == "" {
			s.Namespace = c.Integration.Namespace
		}
	}
	for _, w := range c.Alerts.Webhooks {
		if w.URL == "" && !w.URLFrom.Set() {
			errs = append(errs, fmt.Errorf("alerts.webhooks[%s]: url or urlFrom is required", w.Name))
		}
		switch w.Format {
		case "apprise", "json", "slack":
		default:
			errs = append(errs, fmt.Errorf("alerts.webhooks[%s]: unknown format %q", w.Name, w.Format))
		}
	}
	return errors.Join(errs...)
}

func (c *Config) HasMode(m string) bool {
	for _, x := range c.Auth.Modes {
		if x == m {
			return true
		}
	}
	return false
}
