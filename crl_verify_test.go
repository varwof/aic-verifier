// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// CRLCache verification paths: Start periodic loop, IsRevoked/IsRevokedCert
// lookup (incl. expired + not-covered semantics), robust issuer matching
// (raw bytes then structural RDN comparison), and the RDN canonicalization
// helpers behind finding 13.

package aicverifier

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// rdnDER marshals an RDN sequence from the given sets, preserving set order
// (Go's asn1 sorts attributes *within* a SET, so distinct byte encodings must
// differ by set ordering, exactly the ambiguity finding 13 tolerates).
func rdnDER(t *testing.T, sets ...pkix.RelativeDistinguishedNameSET) []byte {
	t.Helper()
	der, err := asn1.Marshal(pkix.RDNSequence(sets))
	if err != nil {
		t.Fatalf("marshal RDN sequence: %v", err)
	}
	return der
}

// TestCRLCacheStart drives the periodic Start loop: it must refresh immediately,
// keep serving refreshes on the ticker, and exit on stop.
func TestCRLCacheStart(t *testing.T) {
	now := time.Now()
	ca, crlPEM := testCRLFixture(t, now)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlPEM)
	}))
	defer ts.Close()

	cache := NewCRLCache(ca, ts.URL, 1, nil, "en")
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		cache.Start(stop)
		close(done)
	}()
	defer func() {
		close(stop)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Start did not return after stop was signalled")
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if cache.LastRefresh().IsZero() {
			if time.Now().After(deadline) {
				t.Fatal("Start never completed its initial refresh")
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		break
	}
	revoked, err := cache.IsRevoked(ca.Subject.String(), big.NewInt(42))
	if err != nil {
		t.Fatalf("IsRevoked after Start: %v", err)
	}
	if !revoked {
		t.Error("serial 42 not revoked after Start ran the refresh")
	}
}

// TestIsRevokedExpired pins the fail-closed expired branch: once nextUpdate
// passes, every lookup errors instead of silently succeeding.
func TestIsRevokedExpired(t *testing.T) {
	now := time.Now()
	ca, crlPEM := testCRLFixture(t, now)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlPEM)
	}))
	defer ts.Close()

	cache := NewCRLCache(ca, ts.URL, 0, nil, "en")
	if err := cache.ForceRefresh(); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}
	cache.mu.Lock()
	cache.nextUpdate = time.Now().Add(-time.Minute)
	cache.mu.Unlock()

	if _, err := cache.IsRevoked(ca.Subject.String(), big.NewInt(42)); err == nil || !strings.Contains(err.Error(), "CRL expired") {
		t.Fatalf("IsRevoked on expired cache: err = %v, want CRL expired", err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), RawIssuer: ca.RawSubject}
	if _, err := cache.IsRevokedCert(leaf); err == nil || !strings.Contains(err.Error(), "CRL expired") {
		t.Fatalf("IsRevokedCert on expired cache: err = %v, want CRL expired", err)
	}
}

// TestIsRevokedCertLookup covers serial lookup, foreign-CA coverage, and nil.
func TestIsRevokedCertLookup(t *testing.T) {
	now := time.Now()
	ca, crlPEM := testCRLFixture(t, now)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlPEM)
	}))
	defer ts.Close()

	cache := NewCRLCache(ca, ts.URL, 0, nil, "en")
	if err := cache.ForceRefresh(); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}
	// A certificate issued by the CA (RawIssuer == RawSubject) with serial 42.
	revokedLeaf := &x509.Certificate{SerialNumber: big.NewInt(42), RawIssuer: ca.RawSubject}
	revoked, err := cache.IsRevokedCert(revokedLeaf)
	if err != nil {
		t.Fatalf("IsRevokedCert(42): %v", err)
	}
	if !revoked {
		t.Error("leaf serial 42 not revoked")
	}
	okLeaf := &x509.Certificate{SerialNumber: big.NewInt(1), RawIssuer: ca.RawSubject}
	covered, err := cache.IsRevokedCert(okLeaf)
	if err != nil {
		t.Fatalf("IsRevokedCert(1): %v", err)
	}
	if covered {
		t.Error("leaf serial 1 revoked, want false")
	}
	foreign := &x509.Certificate{SerialNumber: big.NewInt(42), RawIssuer: rdnDER(t, pkix.RelativeDistinguishedNameSET{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Foreign CA"}})}
	notCovered, err := cache.IsRevokedCert(foreign)
	if err != nil {
		t.Fatalf("IsRevokedCert(foreign): %v", err)
	}
	if notCovered {
		t.Error("foreign CA cert reported revoked — cache must only answer for its own CA")
	}
	if _, err := cache.IsRevokedCert(nil); err == nil || !strings.Contains(err.Error(), "nil certificate") {
		t.Fatalf("IsRevokedCert(nil): err = %v, want nil certificate", err)
	}
}

// TestIssuerMatchesCARobustRDNOrder pins finding 13: two semantically identical
// issuer names whose RDN attribute ordering differs (so RawIssuer bytes differ)
// must still be matched structurally, and a genuinely different name rejected.
func TestIssuerMatchesCARobustRDNOrder(t *testing.T) {
	cn := asn1.ObjectIdentifier{2, 5, 4, 3}
	org := asn1.ObjectIdentifier{2, 5, 4, 10}
	derAB := rdnDER(t,
		pkix.RelativeDistinguishedNameSET{{Type: cn, Value: "Match CA"}},
		pkix.RelativeDistinguishedNameSET{{Type: org, Value: "Ops"}},
	)
	derBA := rdnDER(t,
		pkix.RelativeDistinguishedNameSET{{Type: org, Value: "Ops"}},
		pkix.RelativeDistinguishedNameSET{{Type: cn, Value: "Match CA"}},
	)
	derOther := rdnDER(t, pkix.RelativeDistinguishedNameSET{{Type: cn, Value: "Different CA"}})
	if string(derAB) == string(derBA) {
		t.Fatal("fixture RDN orderings encoded identically — cannot test structural matching")
	}

	ca := &x509.Certificate{RawSubject: derAB}
	cache := &CRLCache{caCert: ca}

	// Raw-bytes path: identical encoding.
	if !cache.issuerMatchesCA(&x509.Certificate{RawIssuer: derAB}) {
		t.Error("raw issuer match failed")
	}
	// Structural path: reordered attributes, different bytes, same name.
	if !cache.issuerMatchesCA(&x509.Certificate{RawIssuer: derBA}) {
		t.Error("issuerMatchesCA failed on reordered-but-equal RDNs — finding 13 regression")
	}
	// Different name.
	if cache.issuerMatchesCA(&x509.Certificate{RawIssuer: derOther}) {
		t.Error("foreign issuer matched")
	}
	// Nil CA cert.
	none := &CRLCache{}
	if none.issuerMatchesCA(&x509.Certificate{RawIssuer: derAB}) {
		t.Error("issuerMatchesCA with nil caCert matched")
	}
}

// TestRDNSequenceEqualAndCanonical pins the structural comparison helpers.
func TestRDNSequenceEqualAndCanonical(t *testing.T) {
	cn := asn1.ObjectIdentifier{2, 5, 4, 3}
	org := asn1.ObjectIdentifier{2, 5, 4, 10}
	a := rdnDER(t,
		pkix.RelativeDistinguishedNameSET{{Type: cn, Value: "C"}},
		pkix.RelativeDistinguishedNameSET{{Type: org, Value: "A"}},
	)
	b := rdnDER(t,
		pkix.RelativeDistinguishedNameSET{{Type: org, Value: "A"}},
		pkix.RelativeDistinguishedNameSET{{Type: cn, Value: "C"}},
	)
	if !rdnSequenceEqual(a, b) {
		t.Error("rdnSequenceEqual false for reordered RDNs")
	}
	if !rdnSequenceEqual(a, a) {
		t.Error("rdnSequenceEqual false for identical bytes")
	}
	if rdnSequenceEqual(a, []byte{0x30, 0x02, 0x01, 0x01}) {
		t.Error("rdnSequenceEqual true for a malformed input")
	}
	if rdnSequenceEqual([]byte("nope"), []byte("nope too")) {
		t.Error("rdnSequenceEqual true for non-DER inputs")
	}

	var ra, rb pkix.RDNSequence
	if _, err := asn1.Unmarshal(a, &ra); err != nil {
		t.Fatal(err)
	}
	if _, err := asn1.Unmarshal(b, &rb); err != nil {
		t.Fatal(err)
	}
	if canonicalRDNs(ra) == "" || canonicalRDNs(ra) != canonicalRDNs(rb) {
		t.Errorf("canonicalRDNs mismatch: %q vs %q", canonicalRDNs(ra), canonicalRDNs(rb))
	}
}
