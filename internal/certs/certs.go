// Package certs inspects the sensor certificate bundle that the integration's forwarders trust
// (ConfigMap key sensorCert, mounted at /certs/sensor.crt) and compares it with what the sensor
// actually presents.
//
// The forwarders load that file as their set of trusted roots and verify the sensor against
// serverNameOverride. So any certificate in the bundle can anchor trust: with a public-CA sensor
// certificate the bundle's CA certificates keep verifying a renewed leaf, and a stale leaf left in
// the bundle is harmless. With a self-signed sensor certificate the leaf is the only anchor, so a
// regenerated certificate breaks every forwarder until the bundle is updated.
package certs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/opswhisperer/eh-k8s-console/internal/finding"
)

// Info describes one certificate for display, metrics and alerts.
type Info struct {
	Role       string    `json:"role"` // leaf | intermediate | root | self-signed
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	SANs       []string  `json:"sans,omitempty"`
	NotBefore  time.Time `json:"notBefore"`
	NotAfter   time.Time `json:"notAfter"`
	DaysLeft   int       `json:"daysLeft"`
	Expired    bool      `json:"expired"`
	SHA256     string    `json:"sha256"`
	IsCA       bool      `json:"isCA"`
	SelfSigned bool      `json:"selfSigned"`
	PEM        string    `json:"pem"`
}

// Fingerprint returns the colon-separated upper-case SHA-256 fingerprint openssl prints.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// ShortFP is the first two bytes of the fingerprint, as people quote them ("42:15…").
func ShortFP(fp string) string {
	if len(fp) >= 5 {
		return fp[:5] + "…"
	}
	return fp
}

func selfSigned(c *x509.Certificate) bool {
	// CheckSignatureFrom would refuse a non-CA parent, and sensor self-signed certs often are not CAs.
	return bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func role(c *x509.Certificate) string {
	switch {
	case selfSigned(c) && c.IsCA:
		return "root"
	case selfSigned(c):
		return "self-signed"
	case c.IsCA:
		return "intermediate"
	default:
		return "leaf"
	}
}

func Describe(c *x509.Certificate, now time.Time) Info {
	sans := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	left := c.NotAfter.Sub(now)
	return Info{
		Role:       role(c),
		Subject:    c.Subject.String(),
		Issuer:     c.Issuer.String(),
		SANs:       sans,
		NotBefore:  c.NotBefore,
		NotAfter:   c.NotAfter,
		DaysLeft:   int(left.Hours() / 24),
		Expired:    now.After(c.NotAfter),
		SHA256:     Fingerprint(c),
		IsCA:       c.IsCA,
		SelfSigned: selfSigned(c),
		PEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})),
	}
}

func DescribeAll(cs []*x509.Certificate, now time.Time) []Info {
	out := make([]Info, len(cs))
	for i, c := range cs {
		out[i] = Describe(c, now)
	}
	return out
}

// ParseBundle parses every CERTIFICATE block. Non-certificate blocks and junk are reported, not
// silently dropped, because a forwarder given a private key or a truncated block fails to start.
func ParseBundle(data string) ([]*x509.Certificate, []string) {
	var certs []*x509.Certificate
	var problems []string
	rest := []byte(strings.TrimSpace(data))
	for len(bytes.TrimSpace(rest)) > 0 {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			problems = append(problems, "trailing data that is not PEM")
			break
		}
		if b.Type != "CERTIFICATE" {
			problems = append(problems, fmt.Sprintf("unexpected PEM block %q (only certificates belong in sensorCert)", b.Type))
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			problems = append(problems, fmt.Sprintf("certificate %d: %v", len(certs)+1, err))
			continue
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 && len(problems) == 0 {
		problems = append(problems, "no certificates")
	}
	return certs, problems
}

// EncodeBundle writes certificates as one PEM bundle, skipping duplicates.
func EncodeBundle(cs []*x509.Certificate) string {
	var buf bytes.Buffer
	seen := map[string]bool{}
	for _, c := range cs {
		fp := Fingerprint(c)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return buf.String()
}

// Probe is the result of connecting to the sensor and reading the chain it presents.
type Probe struct {
	Addr       string    `json:"addr"`
	ServerName string    `json:"serverName"`
	At         time.Time `json:"at"`
	Error      string    `json:"error,omitempty"`
	Chain      []Info    `json:"chain,omitempty"`

	certs []*x509.Certificate
}

// Certificates returns the presented chain, leaf first.
func (p *Probe) Certificates() []*x509.Certificate { return p.certs }

// Dialer lets tests replace the network.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// ProbeTLS connects to addr with SNI serverName and records the presented chain. It does not
// verify during the handshake (that is what Assess does, against the bundle and system roots);
// it only captures what is presented.
func ProbeTLS(ctx context.Context, dial Dialer, addr, serverName string, timeout time.Duration) *Probe {
	p := &Probe{Addr: addr, ServerName: serverName, At: time.Now()}
	if dial == nil {
		d := &net.Dialer{Timeout: timeout}
		dial = d.DialContext
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := dial(ctx, "tcp", addr)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // capture only; verification happens in Assess
		MinVersion:         tls.VersionTLS12,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		p.Error = "TLS handshake: " + err.Error()
		return p
	}
	p.certs = conn.ConnectionState().PeerCertificates
	p.Chain = DescribeAll(p.certs, p.At)
	if len(p.certs) == 0 {
		p.Error = "sensor presented no certificate"
	}
	return p
}

// NewProbeFromCerts builds a Probe from known certificates (tests, CLI file input).
func NewProbeFromCerts(addr, serverName string, cs []*x509.Certificate, at time.Time) *Probe {
	return &Probe{Addr: addr, ServerName: serverName, At: at, certs: cs, Chain: DescribeAll(cs, at)}
}

// State is the overall verdict on the sensor certificate.
type State string

const (
	StateOK             State = "OK"
	StateRotatedTrusted State = "ROTATED_TRUSTED"
	StateBroken         State = "BROKEN"
	StateSNIMismatch    State = "SNI_MISMATCH"
	StateUnreachable    State = "UNREACHABLE"
	StateInvalidBundle  State = "INVALID_BUNDLE"
)

// AllStates lists every state, for metrics that export one series per state.
var AllStates = []State{StateOK, StateRotatedTrusted, StateBroken, StateSNIMismatch, StateUnreachable, StateInvalidBundle}

// Thresholds are expiry warning levels in days.
type Thresholds struct {
	LeafWarnDays     int
	LeafCriticalDays int
	AnchorWarnDays   int
}

// Assessment is the full certificate verdict.
type Assessment struct {
	State    State             `json:"state"`
	Severity finding.Severity  `json:"severity"`
	Summary  string            `json:"summary"`
	Findings []finding.Finding `json:"findings"`

	Bundle         []Info   `json:"bundle"`
	BundleProblems []string `json:"bundleProblems,omitempty"`
	Probe          *Probe   `json:"probe,omitempty"`

	// TrustedByBundle: the live chain verifies with the bundle as roots and serverNameOverride as
	// hostname — exactly what the forwarders check.
	TrustedByBundle bool   `json:"trustedByBundle"`
	BundleError     string `json:"bundleError,omitempty"`
	// Anchor is the bundle certificate the live chain ends at.
	Anchor *Info `json:"anchor,omitempty"`
	// PublicCA: the live chain also verifies against the system roots, so storing only the CA
	// chain keeps working across leaf renewals.
	PublicCA    bool   `json:"publicCA"`
	SystemError string `json:"systemError,omitempty"`
	SNIMatches  bool   `json:"sniMatches"`
	LeafChanged bool   `json:"leafChanged"`
	// Recommended is the bundle mode to store on refresh: "ca-chain" or "full-chain".
	Recommended string `json:"recommended,omitempty"`

	systemChain []*x509.Certificate
}

func hasFP(infos []Info, fp string) bool {
	for _, i := range infos {
		if i.SHA256 == fp {
			return true
		}
	}
	return false
}

// Assess compares the configured bundle with a probe. systemRoots nil means the host's roots.
func Assess(bundlePEM string, probe *Probe, serverName string, systemRoots *x509.CertPool, th Thresholds, now time.Time) *Assessment {
	a := &Assessment{Probe: probe}
	bundle, problems := ParseBundle(bundlePEM)
	a.Bundle = DescribeAll(bundle, now)
	a.BundleProblems = problems
	add := func(sev finding.Severity, code, msg, fix string) {
		a.Findings = append(a.Findings, finding.Finding{Severity: sev, Code: code, Message: msg, Fix: fix, Setting: "sensorCert", Source: "certs"})
	}

	if len(bundle) == 0 {
		a.State = StateInvalidBundle
		add(finding.Critical, "bundle_empty", "sensorCert has no usable certificate: forwarders cannot verify the sensor.",
			"Refresh from the sensor or paste the sensor's certificate chain.")
	} else if len(problems) > 0 {
		add(finding.Warning, "bundle_problems", "sensorCert has content that is not a certificate: "+strings.Join(problems, "; "),
			"Remove the extra blocks; only CERTIFICATE PEM blocks belong in sensorCert.")
	}

	if probe == nil || probe.Error != "" || len(probe.certs) == 0 {
		if a.State == "" {
			a.State = StateUnreachable
		}
		msg := "the sensor was not probed"
		if probe != nil && probe.Error != "" {
			msg = "could not read the sensor's certificate: " + probe.Error
		}
		add(finding.Warning, "probe_failed", msg+". Drift cannot be checked.",
			"Check that this app can reach the sensor's management interface on the probe port.")
		a.inventoryExpiry(bundle, th, now, add)
		a.finish()
		return a
	}

	live := probe.certs
	leaf := live[0]
	inter := x509.NewCertPool()
	for _, c := range live[1:] {
		inter.AddCert(c)
	}

	// SNI check on its own, so a mismatch is not misreported as an untrusted chain.
	a.SNIMatches = leaf.VerifyHostname(serverName) == nil

	if len(bundle) > 0 {
		roots := x509.NewCertPool()
		for _, c := range bundle {
			roots.AddCert(c)
		}
		chains, err := leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: inter, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			a.BundleError = err.Error()
		} else {
			a.TrustedByBundle = true
			anchor := chains[0][len(chains[0])-1]
			for _, ch := range chains[1:] { // prefer the anchor with the longest remaining life
				if c := ch[len(ch)-1]; c.NotAfter.After(anchor.NotAfter) {
					anchor = c
				}
			}
			info := Describe(anchor, now)
			a.Anchor = &info
		}
	}

	sysChains, err := leaf.Verify(x509.VerifyOptions{
		Roots: systemRoots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err == nil {
		a.PublicCA = true
		a.systemChain = sysChains[0]
	} else {
		a.SystemError = err.Error()
	}

	liveFP := Fingerprint(leaf)
	// "Changed" only makes sense when the bundle pins a leaf: a CA-only bundle never holds the
	// sensor's leaf, and that's the recommended state, not drift.
	a.LeafChanged = a.bundleHasLeaf() && !hasFP(a.Bundle, liveFP)
	if a.PublicCA {
		a.Recommended = "ca-chain"
	} else {
		a.Recommended = "full-chain"
	}

	switch {
	case a.State == StateInvalidBundle:
	case !a.SNIMatches:
		a.State = StateSNIMismatch
		add(finding.Critical, "sni_mismatch", fmt.Sprintf("serverNameOverride %q is not in the sensor certificate's names (%s): forwarders reject the sensor.",
			serverName, strings.Join(Describe(leaf, now).SANs, ", ")),
			"Set serverNameOverride (and the session-key-forwarder -server-name-override arg) to a name on the certificate.")
	case !a.TrustedByBundle:
		a.State = StateBroken
		why := "the sensor's certificate does not verify against sensorCert"
		if selfSigned(leaf) {
			why = "the sensor now presents a different self-signed certificate"
		}
		add(finding.Critical, "chain_untrusted", why+": forwarders cannot connect ("+a.BundleError+").",
			"Refresh sensorCert from the sensor after confirming the new fingerprint "+ShortFP(liveFP)+" on the sensor's admin UI.")
	case a.LeafChanged:
		a.State = StateRotatedTrusted
		add(finding.Info, "leaf_rotated", fmt.Sprintf("The sensor renewed its certificate (now %s, expires %s). sensorCert still verifies it through %s, so nothing is broken.",
			ShortFP(liveFP), leaf.NotAfter.Format("2006-01-02"), a.Anchor.Subject),
			"Optional: refresh sensorCert to record the current chain.")
	default:
		a.State = StateOK
	}

	if selfSigned(leaf) {
		add(finding.Info, "self_signed", "The sensor uses a self-signed certificate: every time it is regenerated, the forwarders break until sensorCert is updated. Auto-sync never applies to self-signed certificates.",
			"Consider a certificate from a public or internal CA on the sensor, then store only the CA chain.")
	} else if a.PublicCA && a.bundleHasLeaf() {
		add(finding.Info, "bundle_pins_leaf", "sensorCert includes the sensor's leaf certificate. Its CA certificates already carry the trust, so the leaf only adds noise that goes stale on every renewal.",
			"Refresh with \"CA chain only\" to make the bundle renewal-proof.")
	}

	// Live leaf expiry: for a public CA this means the sensor's renewal is failing.
	days := int(leaf.NotAfter.Sub(now).Hours() / 24)
	switch {
	case days < 0:
		add(finding.Critical, "leaf_expired", fmt.Sprintf("The sensor's certificate expired on %s.", leaf.NotAfter.Format("2006-01-02")),
			"Renew the certificate on the sensor.")
	case days < th.LeafCriticalDays:
		add(finding.Critical, "leaf_expiring", fmt.Sprintf("The sensor's certificate expires in %d days (%s).", days, leaf.NotAfter.Format("2006-01-02")),
			"Renew the certificate on the sensor; if it renews automatically, its renewal is failing.")
	case days < th.LeafWarnDays:
		add(finding.Warning, "leaf_expiring", fmt.Sprintf("The sensor's certificate expires in %d days (%s).", days, leaf.NotAfter.Format("2006-01-02")),
			"Check the sensor's certificate renewal.")
	}

	if a.Anchor != nil && a.Anchor.IsCA { // a self-signed leaf anchor is covered by the leaf checks
		if a.Anchor.DaysLeft < th.AnchorWarnDays {
			add(finding.Warning, "anchor_expiring", fmt.Sprintf("The bundle certificate that anchors trust (%s) expires in %d days.", a.Anchor.Subject, a.Anchor.DaysLeft),
				"Refresh sensorCert so it carries the CA the sensor's chain currently uses.")
		}
	}
	for _, b := range a.Bundle {
		if b.Expired && (a.Anchor == nil || b.SHA256 != a.Anchor.SHA256) && a.TrustedByBundle {
			add(finding.Info, "stale_bundle_cert", fmt.Sprintf("sensorCert contains an expired certificate (%s, %s, expired %s). It is not used for trust, so this is harmless.",
				b.Role, b.Subject, b.NotAfter.Format("2006-01-02")), "Refresh sensorCert to tidy it.")
		}
	}
	a.finish()
	return a
}

// bundleHasLeaf reports whether the bundle pins an end-entity certificate (a leaf, or a
// self-signed certificate that isn't a CA).
func (a *Assessment) bundleHasLeaf() bool {
	for _, b := range a.Bundle {
		if b.Role == "leaf" || b.Role == "self-signed" {
			return true
		}
	}
	return false
}

// inventoryExpiry reports expiry from the bundle alone when the sensor could not be probed.
func (a *Assessment) inventoryExpiry(bundle []*x509.Certificate, th Thresholds, now time.Time, add func(finding.Severity, string, string, string)) {
	for _, c := range bundle {
		d := int(c.NotAfter.Sub(now).Hours() / 24)
		if c.IsCA && d < th.AnchorWarnDays {
			add(finding.Warning, "bundle_ca_expiring", fmt.Sprintf("Bundle CA %s expires in %d days.", c.Subject, d), "Refresh sensorCert.")
		}
	}
}

func (a *Assessment) finish() {
	a.Severity = finding.Max(a.Findings)
	switch a.State {
	case StateOK:
		if a.bundleHasLeaf() {
			a.Summary = "sensorCert matches the sensor's certificate."
		} else {
			a.Summary = "sensorCert trusts the sensor's certificate through its CA chain."
		}
	case StateRotatedTrusted:
		a.Summary = "The sensor renewed its certificate; sensorCert still trusts it."
	case StateBroken:
		a.Summary = "sensorCert does not trust the sensor's current certificate."
	case StateSNIMismatch:
		a.Summary = "serverNameOverride does not match the sensor's certificate."
	case StateUnreachable:
		a.Summary = "The sensor could not be probed."
	case StateInvalidBundle:
		a.Summary = "sensorCert is empty or invalid."
	}
}

// Bundle modes for BuildBundle.
const (
	ModeCAChain   = "ca-chain"
	ModeFullChain = "full-chain"
)

// BuildBundle returns the PEM to store in sensorCert from a probe.
//
// ca-chain stores the CA certificates the sensor presents plus the root the system verified,
// which survives leaf renewals; it requires a chain that verifies against system roots.
// full-chain stores everything the sensor presents (required for self-signed certificates).
func BuildBundle(a *Assessment, mode string) (string, error) {
	if a.Probe == nil || len(a.Probe.certs) == 0 {
		return "", errors.New("no probe result to build a bundle from")
	}
	live := a.Probe.certs
	switch mode {
	case ModeCAChain:
		if !a.PublicCA {
			return "", errors.New("the sensor's chain does not verify against public roots, so a CA-only bundle would not trust it; use full-chain")
		}
		var cs []*x509.Certificate
		cs = append(cs, live[1:]...)
		if len(a.systemChain) > 1 {
			cs = append(cs, a.systemChain[1:]...)
		}
		return EncodeBundle(cs), nil
	case ModeFullChain:
		cs := append([]*x509.Certificate{}, live...)
		if len(a.systemChain) > 1 {
			cs = append(cs, a.systemChain[len(a.systemChain)-1])
		}
		return EncodeBundle(cs), nil
	}
	return "", fmt.Errorf("unknown bundle mode %q", mode)
}

// VerifyCandidate checks that a proposed bundle would trust the sensor's live chain, so a pasted
// or fetched bundle cannot be saved if it would break the forwarders.
func VerifyCandidate(bundlePEM string, probe *Probe, serverName string, now time.Time) error {
	certs, problems := ParseBundle(bundlePEM)
	if len(certs) == 0 {
		return fmt.Errorf("bundle has no certificates (%s)", strings.Join(problems, "; "))
	}
	if len(problems) > 0 {
		return fmt.Errorf("bundle has problems: %s", strings.Join(problems, "; "))
	}
	if probe == nil || len(probe.certs) == 0 {
		return nil // nothing live to check against; caller decides whether that is acceptable
	}
	roots := x509.NewCertPool()
	for _, c := range certs {
		roots.AddCert(c)
	}
	inter := x509.NewCertPool()
	for _, c := range probe.certs[1:] {
		inter.AddCert(c)
	}
	_, err := probe.certs[0].Verify(x509.VerifyOptions{
		DNSName: serverName, Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("this bundle would not trust the sensor's current certificate: %w", err)
	}
	return nil
}

// AutoSyncAllowed decides whether the scan loop may replace sensorCert without a person.
// Only a chain that verifies against public roots with a matching name qualifies, and only when
// the stored bundle differs from what a refresh would produce.
func AutoSyncAllowed(a *Assessment, currentPEM string) (string, bool, string) {
	if a.Probe == nil || len(a.Probe.certs) == 0 {
		return "", false, "no probe result"
	}
	if selfSigned(a.Probe.certs[0]) || !a.PublicCA {
		return "", false, "the sensor's certificate is not from a public CA; a person must confirm the new fingerprint"
	}
	if !a.SNIMatches {
		return "", false, "serverNameOverride does not match the certificate"
	}
	if a.State == StateOK && !a.bundleHasLeaf() {
		return "", false, "already up to date"
	}
	if a.State != StateBroken && a.State != StateRotatedTrusted && a.State != StateOK {
		return "", false, "nothing to sync"
	}
	pemOut, err := BuildBundle(a, ModeCAChain)
	if err != nil {
		return "", false, err.Error()
	}
	if sameCerts(pemOut, currentPEM) {
		return "", false, "already up to date"
	}
	return pemOut, true, ""
}

func sameCerts(a, b string) bool {
	ca, _ := ParseBundle(a)
	cb, _ := ParseBundle(b)
	if len(ca) != len(cb) {
		return false
	}
	set := map[string]bool{}
	for _, c := range ca {
		set[Fingerprint(c)] = true
	}
	for _, c := range cb {
		if !set[Fingerprint(c)] {
			return false
		}
	}
	return true
}
