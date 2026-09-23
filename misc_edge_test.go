// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Coverage for small utility paths: error-code mapping, nil-safe view logging,
// server contains/trust pool construction, nonce cleanup, placeholder + time
// window constraint evaluators, and CRL/OCSP revocation wiring in checkRevocation.

package aicverifier

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseErrorCodeAllMappings(t *testing.T) {
	for in, wantCode := range map[string]ErrorCode{
		"no_credential":         ErrNoCredential,
		"access_denied":         ErrDenied,
		"bearer_not_configured": ErrNoVerifier,
		"bearer_tls_required":   ErrBearerNeedsTLS,
		"invalid_bearer":        ErrInvalidBearer,
		"chain_invalid":         ErrChainInvalid,
		"config_error":          ErrConfig,
	} {
		got, err := ParseErrorCode(in)
		if err != nil {
			t.Errorf("ParseErrorCode(%q) unexpected error: %v", in, err)
		}
		if got != wantCode {
			t.Errorf("ParseErrorCode(%q) = %v, want %v", in, got, wantCode)
		}
	}
	if _, err := ParseErrorCode("bogus"); err == nil || !strings.Contains(err.Error(), "unknown error code") {
		t.Errorf("ParseErrorCode(bogus) err = %v, want unknown error code", err)
	}
}

func TestRequestPathOfNilSafe(t *testing.T) {
	if got := requestPathOf(nil); got != "" {
		t.Errorf("requestPathOf(nil) = %q, want empty", got)
	}
	if got := requestPathOf(&RequestView{Path: "/evidences"}); got != "/evidences" {
		t.Errorf("requestPathOf = %q, want /evidences", got)
	}
}

func TestContainsHelper(t *testing.T) {
	if !contains([]string{"a", "b", "c"}, "b") {
		t.Error("contains missed present element")
	}
	if contains([]string{"a", "b", "c"}, "z") {
		t.Error("contains found absent element")
	}
	if contains(nil, "x") {
		t.Error("contains(nil, x) = true")
	}
}

func TestBackendRootPool(t *testing.T) {
	if pool, err := backendRootPool(""); err != nil {
		t.Fatalf("backendRootPool empty spec: %v", err)
	} else if pool == nil {
		t.Fatal("nil pool for empty spec")
	}
	if _, err := backendRootPool("/nonexistent/ca.pem"); err == nil {
		t.Error("backendRootPool accepted a missing file")
	}

	ca, _ := testCRLFixture(t, time.Now())
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, block, 0o600); err != nil {
		t.Fatal(err)
	}
	if pool, err := backendRootPool(p + ", " + p); err != nil {
		t.Fatalf("backendRootPool valid PEM: %v", err)
	} else if pool == nil {
		t.Fatal("nil pool for valid PEM")
	}

	junk := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junk, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := backendRootPool(junk); err == nil {
		t.Error("backendRootPool accepted a PEM with no certificates")
	}
}

func TestNonceCacheCleanup(t *testing.T) {
	cache := NewNonceCache()
	cache.m.Store("stale", &nonceEntry{scope: "a", seen: time.Now().Add(-48 * time.Hour)})
	cache.m.Store("fresh", &nonceEntry{scope: "a", seen: time.Now()})
	cache.m.Store("other", "not-a-nonce-entry")
	cache.cleanup()
	if cache.Len() != 2 {
		t.Errorf("Len after cleanup = %d, want 2 (fresh + non-entry)", cache.Len())
	}
	if _, stale := cache.m.Load("stale"); stale {
		t.Error("stale nonce survived cleanup")
	}
}

func TestSkipEvaluator(t *testing.T) {
	ev := skipEvaluator{capabilityId: "not-a-constraint"}
	if ev.CapabilityId() != "not-a-constraint" {
		t.Errorf("skipEvaluator CapabilityId = %q", ev.CapabilityId())
	}
	if err := ev.Evaluate(&Capability{}, &ConstraintContext{}); err != nil {
		t.Errorf("skipEvaluator Evaluate = %v, want nil", err)
	}
}

func TestTimeWindowEvaluator(t *testing.T) {
	ev := timeWindowEvaluator{}
	if ev.CapabilityId() != ConstraintTimeWindowKey {
		t.Fatalf("CapabilityId = %q", ev.CapabilityId())
	}
	mk := func(params string) *Capability {
		return &Capability{SchemeId: "varwof/constraint-v1", CapabilityId: ConstraintTimeWindowKey, Parameters: []byte(params)}
	}
	ctx := &ConstraintContext{Now: time.Date(2026, 9, 16, 10, 30, 0, 0, time.UTC)}

	if err := ev.Evaluate(mk(`{"start":"09:00","end":"18:00"}`), ctx); err != nil {
		t.Errorf("in-window rejected: %v", err)
	}
	cross := &ConstraintContext{Now: time.Date(2026, 9, 16, 23, 30, 0, 0, time.UTC)}
	if err := ev.Evaluate(mk(`{"start":"18:00","end":"09:00"}`), cross); err != nil {
		t.Errorf("cross-midnight in-window rejected: %v", err)
	}
	if err := ev.Evaluate(mk(`{"start":"11:00","end":"12:00"}`), ctx); err == nil {
		t.Error("out-of-window accepted")
	}
	if err := ev.Evaluate(mk(`{"start":"09:00","end":"12:00","tz":"Asia/Shanghai"}`), ctx); err == nil {
		t.Error("window shifted by tz accepted in UTC-10:30 — expected rejection")
	}
	if err := ev.Evaluate(mk(`{"start":"","end":"18:00"}`), ctx); err == nil {
		t.Error("missing start accepted")
	}
	if err := ev.Evaluate(mk(`{"start":"25:00","end":"18:00"}`), ctx); err == nil {
		t.Error("invalid time format accepted")
	}
	if err := ev.Evaluate(mk(`{"start":"09:00","end":"18:00","tz":"Mars/Olympus"}`), ctx); err == nil {
		t.Error("invalid tz accepted")
	}
	if err := ev.Evaluate(mk(`not json`), ctx); err == nil {
		t.Error("invalid JSON accepted")
	}
	// ctx.Now zero must fall back to the real clock; a window spanning a whole
	// day must always contain the current time.
	if err := ev.Evaluate(mk(`{"start":"00:00","end":"23:59"}`), &ConstraintContext{}); err != nil {
		t.Errorf("zero-Now default evaluation rejected: %v", err)
	}
}

func TestCheckAuthorizationConstraintsAt(t *testing.T) {
	if err := CheckAuthorizationConstraintsAt([]Capability{}, "10.0.0.1", ""); err != nil {
		t.Errorf("empty constraints rejected: %v", err)
	}
	if err := CheckAuthorizationConstraintsAt(nil, "", "10:00"); err != nil {
		t.Errorf("nil constraints with time rejected: %v", err)
	}
	if err := CheckAuthorizationConstraintsAt(nil, "", "25:99"); err == nil || !strings.Contains(err.Error(), "invalid --time") {
		t.Errorf("invalid --time: err = %v, want invalid --time", err)
	}
	tw := Capability{SchemeId: "varwof/constraint-v1", CapabilityId: ConstraintTimeWindowKey, Parameters: []byte(`{"start":"09:00","end":"18:00"}`)}
	if err := CheckAuthorizationConstraintsAt([]Capability{tw}, "10.0.0.1", "12:00"); err != nil {
		t.Errorf("in-window admission rejected: %v", err)
	}
	if err := CheckAuthorizationConstraintsAt([]Capability{tw}, "10.0.0.1", "20:00"); err == nil {
		t.Error("out-of-window admission accepted")
	}
}

func TestCheckRevocationWiring(t *testing.T) {
	now := time.Now()
	ca, crlPEM := testCRLFixture(t, now)

	if err := checkRevocation(nil, nil, &PipelineConfig{}); err != nil {
		t.Errorf("empty revocation config: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlPEM)
	}))
	defer ts.Close()

	cache := NewCRLCache(ca, ts.URL, 0, nil, "en")
	if err := cache.ForceRefresh(); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}
	revokedLeaf := &x509.Certificate{SerialNumber: big.NewInt(42), RawIssuer: ca.RawSubject}
	err := checkRevocation(revokedLeaf, ca, &PipelineConfig{CRLCache: cache})
	if err == nil || !strings.Contains(err.Error(), "revoked (CRL)") {
		t.Errorf("revoked cert: err = %v, want revoked (CRL)", err)
	}

	cache.mu.Lock()
	cache.nextUpdate = now.Add(-time.Minute)
	cache.mu.Unlock()
	err = checkRevocation(&x509.Certificate{SerialNumber: big.NewInt(1), RawIssuer: ca.RawSubject}, ca, &PipelineConfig{CRLCache: cache})
	if err == nil || !strings.Contains(err.Error(), "crl check error") {
		t.Errorf("stale CRL: err = %v, want crl check error", err)
	}

	ocsp := NewOCSPCache(0, "crl", nil, "")
	err = checkRevocation(&x509.Certificate{SerialNumber: big.NewInt(1), RawIssuer: ca.RawSubject}, ca, &PipelineConfig{OCSPCache: ocsp})
	if err == nil || !strings.Contains(err.Error(), "ocsp check error") {
		t.Errorf("unconfigured OCSP crl fallback: err = %v, want ocsp check error", err)
	}
}
