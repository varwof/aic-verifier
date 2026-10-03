// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// RFC 7555 §2.1 case-insensitivity tests, ported verbatim from
// varwof/gateway-core spiffe_test.go. Parity of the implementation without
// parity of the tests is how a fix gets reverted unnoticed; see
// docs/parity-gateway-core.md §8.

package aicverifier

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"
	"time"
)

func spiffeTestCert(uri string) *x509.Certificate {
	cert := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "spiffe-test"},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}
	if uri != "" {
		u, _ := url.Parse(uri)
		cert.URIs = []*url.URL{u}
	}
	return cert
}

func TestParseSPIFFEID_TrustDomainLowercase(t *testing.T) {
	cases := []struct{ in, td, path string }{
		{"spiffe://VARWOF.com/agent/svc", "varwof.com", "/agent/svc"},
		{"spiffe://Prod.US-East-1.Example.com/ns/Svc", "prod.us-east-1.example.com", "/ns/Svc"},
		{"spiffe://EXAMPLE.COM", "example.com", "/"},
	}
	for _, tc := range cases {
		s, err := ParseSPIFFEID(tc.in)
		if err != nil {
			t.Fatalf("ParseSPIFFEID(%q): %v", tc.in, err)
		}
		if s.TrustDomain != tc.td {
			t.Fatalf("ParseSPIFFEID(%q) TrustDomain=%q, want %q", tc.in, s.TrustDomain, tc.td)
		}
		// Path segments are case-sensitive and preserved verbatim.
		if s.Path != tc.path {
			t.Fatalf("ParseSPIFFEID(%q) Path=%q, want %q", tc.in, s.Path, tc.path)
		}
	}
}

func TestValidTrustDomainCharset(t *testing.T) {
	valid := []string{"example.com", "a-b.com", "a_b.example.org", "x.y.z"}
	for _, td := range valid {
		if !validTrustDomainCharset(td) {
			t.Fatalf("validTrustDomainCharset(%q) = false, want true", td)
		}
	}
	invalid := []string{"VARWOF.com", "exa!mple.com", "exa~mple.com", "exa/mple.com", "exa mple.com", "exa:port.com"}
	for _, td := range invalid {
		if validTrustDomainCharset(td) {
			t.Fatalf("validTrustDomainCharset(%q) = true, want false", td)
		}
	}
}

func TestCanonicalSPIFFEID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"spiffe://VARWOF.com/agent/svc", "spiffe://varwof.com/agent/svc"},
		{"spiffe://VARWOF.com", "spiffe://varwof.com"},
		{"spiffe://Varwof.COM/agent/Svc-A", "spiffe://varwof.com/agent/Svc-A"},
		{"spiffe://varwof.com/agent/svc", "spiffe://varwof.com/agent/svc"},
		{"https://VARWOF.com/x", "https://VARWOF.com/x"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := canonicalSPIFFEID(tc.in); got != tc.want {
			t.Fatalf("canonicalSPIFFEID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestVerifySPIFFESAN_CaseInsensitiveTrustDomain(t *testing.T) {
	cert := spiffeTestCert("spiffe://VARWOF.com/agent/svc-a")
	if !VerifySPIFFESAN(cert, "spiffe://varwof.com/agent/svc-a") {
		t.Fatal("expected case-variant of the SAN to verify against the canonical ID")
	}
	if VerifySPIFFESAN(cert, "spiffe://varwof.com/agent/other") {
		t.Fatal("path mismatch must not verify")
	}
	if VerifySPIFFESAN(cert, "spiffe://evil.com/agent/svc-a") {
		t.Fatal("different trust domain must not verify")
	}
	if VerifySPIFFESAN(cert, "") {
		t.Fatal("empty expected ID must not verify")
	}
}

func TestPipelineSPIFFETrustDomainCaseVariant(t *testing.T) {
	// The certificate carries an uppercase variant of a trust domain that is
	// configured lowercase: RFC 7555 case-insensitivity must admit it.
	cfg := &PipelineConfig{SPIFFETrustDomain: "varwof.com"}
	allowed := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://VARWOF.COM/agent/x")}, cfg)
	if !allowed.Granted {
		t.Fatalf("expected case-variant trust domain to be admitted, got: %s", allowed.DenyReason)
	}

	// Uppercase configured trust domain vs lowercase certificate.
	cfgUp := &PipelineConfig{SPIFFETrustDomain: "VARWOF.COM"}
	allowedUp := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://varwof.com/agent/x")}, cfgUp)
	if !allowedUp.Granted {
		t.Fatalf("expected lowercase cert vs uppercase config to be admitted, got: %s", allowedUp.DenyReason)
	}

	// A genuinely different domain in either case must still be denied.
	denied := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://Evil.com/agent/x")}, cfg)
	if denied.Granted {
		t.Fatal("expected denial for a different trust domain")
	}
}

func TestPipelineSPIFFEAllowedListCaseInsensitive(t *testing.T) {
	cfg := &PipelineConfig{AllowedSPIFFEIDs: []string{"spiffe://varwof.com/agent/known-a"}}

	// Uppercase trust-domain variant of an allowlisted ID must be admitted.
	allowed := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://VARWOF.com/agent/known-a")}, cfg)
	if !allowed.Granted {
		t.Fatalf("expected case-variant allowlist match, got: %s", allowed.DenyReason)
	}

	// Allowlist entries written in a case variant must also match lowercase SANs.
	cfgUp := &PipelineConfig{AllowedSPIFFEIDs: []string{"spiffe://VARWOF.com/agent/known-a"}}
	allowedUp := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://varwof.com/agent/known-a")}, cfgUp)
	if !allowedUp.Granted {
		t.Fatalf("expected lowercase SAN vs uppercase allowlist entry, got: %s", allowedUp.DenyReason)
	}

	// Paths stay case-sensitive: a path case-variant must be denied.
	deniedPath := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://varwof.com/Agent/Known-A")}, cfg)
	if deniedPath.Granted {
		t.Fatal("expected denial for a path case-variant (paths are case-sensitive)")
	}

	// A real different path and a different trust domain must both be denied.
	deniedOther := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://varwof.com/agent/other")}, cfg)
	if deniedOther.Granted {
		t.Fatal("expected denial when ID is not allowlisted")
	}
	deniedDomain := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://evil.com/agent/known-a")}, cfg)
	if deniedDomain.Granted {
		t.Fatal("expected denial when trust domain is not allowlisted")
	}
}
