// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// CRLCache.refresh path coverage: a real CA-signed CRL served over a mock
// distribution point, exercising fetch, PEM decode, issuer match,
// signature verify, thisUpdate replay detection, and revocation lookup.

package aicverifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// testCRLFixture builds a self-signed CA and a signed CRL revoking serial 42.
func testCRLFixture(t *testing.T, now time.Time) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Varwof CRL Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	revoked := []pkix.RevokedCertificate{
		{SerialNumber: big.NewInt(42), RevocationTime: now.Add(-time.Hour)},
	}
	crlDER, err := ca.CreateCRL(rand.Reader, key, revoked, now.Add(-time.Minute), now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	return ca, crlPEM
}

// TestCRLRefreshServesRevokedSerial drives the full refresh pipeline: fetch
// over HTTP, PEM decode, issuer match, signature verification, and the
// revoked/not-revoked lookup. Guards against the refresh() path silently
// failing and leaving revocation checks permanently open.
func TestCRLRefreshServesRevokedSerial(t *testing.T) {
	now := time.Now()
	ca, crlPEM := testCRLFixture(t, now)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlPEM)
	}))
	defer ts.Close()

	cache := NewCRLCache(ca, ts.URL, 0, nil, "en")
	if lr := cache.LastRefresh(); !lr.IsZero() {
		t.Fatalf("LastRefresh before any refresh = %v, want zero", lr)
	}
	if err := cache.ForceRefresh(); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}
	if lr := cache.LastRefresh(); lr.IsZero() {
		t.Fatal("LastRefresh stayed zero after a successful refresh")
	}

	revoked, err := cache.IsRevoked(ca.Issuer.String(), big.NewInt(42))
	if err != nil {
		t.Fatalf("IsRevoked(42): %v", err)
	}
	if !revoked {
		t.Error("serial 42 not revoked — the CRL fixture revokes it; refresh() must load the list")
	}
	ok, err := cache.IsRevoked(ca.Issuer.String(), big.NewInt(1))
	if err != nil {
		t.Fatalf("IsRevoked(1): %v", err)
	}
	if ok {
		t.Error("serial 1 reported revoked — CRL only revokes serial 42")
	}
	// Unmatched CA DN must not be covered by this cache.
	otherDN := "CN=Different CA"
	covered, err := cache.IsRevoked(otherDN, big.NewInt(42))
	if err != nil {
		t.Fatalf("IsRevoked(otherDN): %v", err)
	}
	if covered {
		t.Errorf("serial 42 reported revoked under foreign CA DN %q", otherDN)
	}

	count, thisU, nextU := cache.Stats()
	if count != 1 {
		t.Errorf("Stats revoked count = %d, want 1", count)
	}
	if thisU.IsZero() || nextU.IsZero() {
		t.Errorf("Stats thisUpdate/nextUpdate not set after refresh: this=%v next=%v", thisU, nextU)
	}
}

// TestCRLRefreshRejectsReplayedList pins the replay guard: a second refresh
// serving the same (already applied) thisUpdate must fail, so a captured and
// re-served CRL cannot roll the cache backwards.
func TestCRLRefreshRejectsReplayedList(t *testing.T) {
	now := time.Now()
	ca, crlPEM := testCRLFixture(t, now)

	var mu sync.Mutex
	serves := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		serves++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlPEM)
	}))
	defer ts.Close()

	cache := NewCRLCache(ca, ts.URL, 0, nil, "en")
	if err := cache.ForceRefresh(); err != nil {
		t.Fatalf("first ForceRefresh: %v", err)
	}
	err := cache.ForceRefresh()
	if err == nil {
		t.Fatal("second refresh with identical thisUpdate succeeded — replay guard must reject it")
	}
	mu.Lock()
	defer mu.Unlock()
	if serves != 2 {
		t.Errorf("CRL served %d times, want 2 (one per ForceRefresh)", serves)
	}
}

// TestCRLRefreshFailsClosedOnServerError ensures a failed fetch (5xx / no
// body) surfaces as an error and does not silently leave the cache in an
// "everything is valid" state.
func TestCRLRefreshFailsClosedOnServerError(t *testing.T) {
	now := time.Now()
	ca, _ := testCRLFixture(t, now)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	cache := NewCRLCache(ca, ts.URL, 0, nil, "en")
	if err := cache.ForceRefresh(); err == nil {
		t.Fatal("ForceRefresh succeeded against a 503 server — must fail")
	}
	if lr := cache.LastRefresh(); !lr.IsZero() {
		t.Fatalf("LastRefresh set after a failed refresh: %v", lr)
	}
}
