package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/opswhisperer/eh-k8s-console/internal/finding"
)

var now = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

type kp struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial int64

func mk(t *testing.T, cn string, parent *kp, ca bool, notAfter time.Time, dns ...string) *kp {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-30 * 24 * time.Hour),
		NotAfter:              notAfter,
		DNSNames:              dns,
		IsCA:                  ca,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &kp{c, key}
}

func days(n int) time.Time { return now.Add(time.Duration(n) * 24 * time.Hour) }

var th = Thresholds{LeafWarnDays: 21, LeafCriticalDays: 7, AnchorWarnDays: 30}

const sni = "sensor.example.com"

type pki struct{ root, inter *kp }

func newPKI(t *testing.T) pki {
	root := mk(t, "Test Root", nil, true, days(3000))
	return pki{root, mk(t, "Test Issuing CA", root, true, days(2000))}
}

func (p pki) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.root.cert)
	return pool
}

func hasCode(a *Assessment, code string) *finding.Finding {
	for i := range a.Findings {
		if a.Findings[i].Code == code {
			return &a.Findings[i]
		}
	}
	return nil
}

// The common case: public-CA leaf renewed on the sensor, bundle still holds the old leaf + CAs.
func TestPublicCALeafRotationIsTrusted(t *testing.T) {
	p := newPKI(t)
	oldLeaf := mk(t, sni, p.inter, false, days(20), sni)
	newLeaf := mk(t, sni, p.inter, false, days(80), sni)
	bundle := EncodeBundle([]*x509.Certificate{oldLeaf.cert, p.inter.cert, p.root.cert})
	probe := NewProbeFromCerts("192.0.2.10:443", sni, []*x509.Certificate{newLeaf.cert, p.inter.cert}, now)

	a := Assess(bundle, probe, sni, p.pool(), th, now)
	if a.State != StateRotatedTrusted {
		t.Fatalf("state = %s, want ROTATED_TRUSTED; findings %+v", a.State, a.Findings)
	}
	if !a.TrustedByBundle || !a.PublicCA || !a.LeafChanged || a.Recommended != ModeCAChain {
		t.Fatalf("unexpected assessment %+v", a)
	}
	if a.Severity != finding.Info {
		t.Fatalf("severity = %s, want info (nothing is broken)", a.Severity)
	}
	if hasCode(a, "bundle_pins_leaf") == nil {
		t.Error("want bundle_pins_leaf advice")
	}

	out, err := BuildBundle(a, ModeCAChain)
	if err != nil {
		t.Fatal(err)
	}
	certs, _ := ParseBundle(out)
	for _, c := range certs {
		if !c.IsCA {
			t.Fatalf("ca-chain bundle contains a leaf: %s", c.Subject)
		}
	}
	if len(certs) != 2 {
		t.Fatalf("ca-chain bundle has %d certs, want intermediate + root", len(certs))
	}
	if err := VerifyCandidate(out, probe, sni, now); err != nil {
		t.Fatal(err)
	}
	// The CA-only bundle keeps trusting the next renewal too.
	next := mk(t, sni, p.inter, false, days(170), sni)
	if err := VerifyCandidate(out, NewProbeFromCerts("", sni, []*x509.Certificate{next.cert, p.inter.cert}, now), sni, now); err != nil {
		t.Fatalf("CA-only bundle should survive renewal: %v", err)
	}

	pemOut, ok, why := AutoSyncAllowed(a, bundle)
	if !ok || pemOut == "" {
		t.Fatalf("auto-sync should be allowed for a public CA: %s", why)
	}
}

func TestSelfSignedRegenerationIsBroken(t *testing.T) {
	old := mk(t, sni, nil, false, days(300), sni)
	regenerated := mk(t, sni, nil, false, days(365), sni)
	probe := NewProbeFromCerts("", sni, []*x509.Certificate{regenerated.cert}, now)

	a := Assess(EncodeBundle([]*x509.Certificate{old.cert}), probe, sni, x509.NewCertPool(), th, now)
	if a.State != StateBroken || a.Severity != finding.Critical {
		t.Fatalf("state = %s/%s, want BROKEN/critical", a.State, a.Severity)
	}
	if a.Recommended != ModeFullChain || a.PublicCA {
		t.Fatalf("self-signed must recommend full-chain: %+v", a)
	}
	if !strings.Contains(hasCode(a, "chain_untrusted").Message, "self-signed") {
		t.Error("message should explain the self-signed regeneration")
	}
	if _, ok, _ := AutoSyncAllowed(a, ""); ok {
		t.Fatal("auto-sync must never accept a self-signed certificate")
	}
	if _, err := BuildBundle(a, ModeCAChain); err == nil {
		t.Fatal("ca-chain must be refused for a self-signed certificate")
	}
	full, err := BuildBundle(a, ModeFullChain)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCandidate(full, probe, sni, now); err != nil {
		t.Fatal(err)
	}
	// Unchanged self-signed cert is simply OK.
	ok := Assess(EncodeBundle([]*x509.Certificate{regenerated.cert}), probe, sni, x509.NewCertPool(), th, now)
	if ok.State != StateOK {
		t.Fatalf("state = %s, want OK", ok.State)
	}
}

func TestSNIMismatch(t *testing.T) {
	p := newPKI(t)
	leaf := mk(t, "other.example.com", p.inter, false, days(80), "other.example.com")
	probe := NewProbeFromCerts("", sni, []*x509.Certificate{leaf.cert, p.inter.cert}, now)
	a := Assess(EncodeBundle([]*x509.Certificate{p.inter.cert}), probe, sni, p.pool(), th, now)
	if a.State != StateSNIMismatch || a.Severity != finding.Critical {
		t.Fatalf("state = %s, want SNI_MISMATCH", a.State)
	}
	if err := VerifyCandidate(EncodeBundle([]*x509.Certificate{p.inter.cert}), probe, sni, now); err == nil {
		t.Fatal("candidate must fail the hostname check")
	}
	if _, ok, _ := AutoSyncAllowed(a, ""); ok {
		t.Fatal("no auto-sync on name mismatch")
	}
}

func TestExpiringLeafAndStaleBundleLeaf(t *testing.T) {
	p := newPKI(t)
	expiredOld := mk(t, sni, p.inter, false, days(-3), sni)
	soon := mk(t, sni, p.inter, false, days(5), sni)
	bundle := EncodeBundle([]*x509.Certificate{expiredOld.cert, p.inter.cert})
	a := Assess(bundle, NewProbeFromCerts("", sni, []*x509.Certificate{soon.cert, p.inter.cert}, now), sni, p.pool(), th, now)
	if a.State != StateRotatedTrusted {
		t.Fatalf("state = %s, want ROTATED_TRUSTED (expired leaf in bundle is harmless)", a.State)
	}
	if f := hasCode(a, "leaf_expiring"); f == nil || f.Severity != finding.Critical {
		t.Fatalf("want critical leaf_expiring, got %+v", a.Findings)
	}
	if f := hasCode(a, "stale_bundle_cert"); f == nil || f.Severity != finding.Info {
		t.Fatalf("want info stale_bundle_cert, got %+v", a.Findings)
	}
}

func TestExpiringAnchorWarns(t *testing.T) {
	root := mk(t, "Old Root", nil, true, days(10))
	inter := mk(t, "Issuing", root, true, days(9))
	leaf := mk(t, sni, inter, false, days(8), sni)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	a := Assess(EncodeBundle([]*x509.Certificate{inter.cert}), NewProbeFromCerts("", sni, []*x509.Certificate{leaf.cert, inter.cert}, now), sni, pool, th, now)
	if hasCode(a, "anchor_expiring") == nil {
		t.Fatalf("want anchor_expiring, got %+v", a.Findings)
	}
}

func TestUnreachableAndInvalidBundle(t *testing.T) {
	a := Assess("", &Probe{Error: "connection refused"}, sni, nil, th, now)
	if a.State != StateInvalidBundle || a.Severity != finding.Critical {
		t.Fatalf("state = %s/%s", a.State, a.Severity)
	}
	p := newPKI(t)
	a = Assess(EncodeBundle([]*x509.Certificate{p.inter.cert}), &Probe{Error: "timeout"}, sni, nil, th, now)
	if a.State != StateUnreachable || a.Severity != finding.Warning {
		t.Fatalf("state = %s/%s", a.State, a.Severity)
	}
}

func TestParseBundleReportsJunk(t *testing.T) {
	p := newPKI(t)
	in := EncodeBundle([]*x509.Certificate{p.inter.cert}) + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	certs, problems := ParseBundle(in)
	if len(certs) != 1 || len(problems) != 1 || !strings.Contains(problems[0], "PRIVATE KEY") {
		t.Fatalf("certs=%d problems=%v", len(certs), problems)
	}
}

func TestProbeTLSCapturesChain(t *testing.T) {
	p := newPKI(t)
	leaf := mk(t, sni, p.inter, false, days(60), sni)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{leaf.cert.Raw, p.inter.cert.Raw}, PrivateKey: leaf.key,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = c.(*tls.Conn).Handshake(); c.Close() }(c)
		}
	}()
	probe := ProbeTLS(context.Background(), nil, ln.Addr().String(), sni, 3*time.Second)
	if probe.Error != "" {
		t.Fatal(probe.Error)
	}
	if len(probe.Chain) != 2 || probe.Chain[0].SHA256 != Fingerprint(leaf.cert) || probe.Chain[0].Role != "leaf" || probe.Chain[1].Role != "intermediate" {
		t.Fatalf("chain = %+v", probe.Chain)
	}
}
