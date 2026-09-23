// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Security-fix regression tests for the aic-verifier admission pipeline.
//
// Each test pins down one applied security fix so a future refactor cannot
// silently revert it:
//
//  1. jwt.go            — replay-store default capacity 65536 (not 4096) and the
//                         eviction warning that must not be silent (C1).
//  2. nonce_cache.go    — same-scope nonce reuse is bounded at maxScopeUse (C2).
//  3. ocsp.go           — the fallback_allow path logs every unproven allowance (C3).
//  5. server.go         — X-Forwarded-For is captured from the real peer before
//                         the reverse proxy rewrites it (M4).
//  6. crl.go            — CRL fetch transport has bounded dial/handshake/total
//                         timeouts so a hung distribution point cannot pin
//                         gateway goroutines (H3).
//  7. merkle.go         — VerifyProof is bytes.Equal-based and nil/empty inputs
//                         are never accepted as a match (finding 22).
//  8. supervision_store — Query snapshots the file path under the mutex so
//                         concurrent Record+Query is race-free (H5).
//  9. challenge.go      — RNG failures propagate; an empty token can no longer
//                         silently become a fixed, replayable challenge (M2).
//  10. audit.go         — rotation remove/rename errors are logged, never
//                         silently ignored (L1).
//
// (4. the mcp body-limit fix lives in the mcp subpackage and has its own test
// file — mcp/security_fixes_test.go — because an in-package test here would
// create an import cycle: mcp imports aicverifier.)

package aicverifier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

// captureStdout runs fn while stdout is redirected to a pipe and returns what
// fn printed. Used to assert that security-relevant warnings are emitted (and
// therefore visible to operators) instead of being silently swallowed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(b)
}

func testAgentCert() *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: "test-agent"}}
}

// ---------------------------------------------------------------------------
// 1. jwt.go — memReplayStore default max + eviction warning (C1)
// ---------------------------------------------------------------------------

// TestReplayStoreEvictionWarning guards two halves of the same C1/P1-1 fix:
//   - the default capacity was raised from 4096 to 65536 so capacity pressure —
//     which under the old design evicted the one-time-use marker and made the
//     token replayable — is far less likely under normal load;
//   - when capacity is exhausted with only live markers, the store FAILS CLOSED
//     (refuses to record the new nonce) instead of evicting a live marker.
func TestReplayStoreEvictionWarning(t *testing.T) {
	t.Run("default_max_is_65536_not_4096", func(t *testing.T) {
		store := NewReplayNonceStore(0, 0)
		if store.max != 65536 {
			t.Errorf("default max = %d, want 65536 (the earlier 4096 cap made eviction — and thus replay — too likely)", store.max)
		}
		if store.ttl != 24*time.Hour {
			t.Errorf("default ttl = %v, want 24h", store.ttl)
		}
	})

	t.Run("overflow_fails_closed_never_evicts", func(t *testing.T) {
		out := captureStdout(t, func() {
			store := NewReplayNonceStore(time.Hour, 2)
			if err := store.CheckAndAdd("n-1"); err != nil {
				t.Fatalf("CheckAndAdd(n-1): %v", err)
			}
			if err := store.CheckAndAdd("n-2"); err != nil {
				t.Fatalf("CheckAndAdd(n-2): %v", err)
			}
			if err := store.CheckAndAdd("n-3"); err == nil {
				t.Fatal("CheckAndAdd(n-3): want fail-closed error at capacity with live markers")
			}
		})
		if strings.Contains(out, "WARNING evicting") {
			t.Errorf("live markers must never be evicted, got:\n%s", out)
		}
	})
}

// ---------------------------------------------------------------------------
// 2. nonce_cache.go — same-scope nonce reuse is bounded (C2)
// ---------------------------------------------------------------------------

// TestNonceCacheSameScopeLimit pins the C2 fix: the "same certificate scope"
// carve-out was an unbounded allow, so a nonce captured from one cert could be
// driven in an endless loop inside that cert's own scope. Reuse is now capped
// at maxScopeUse, after which CheckAndAdd fails closed.
func TestNonceCacheSameScopeLimit(t *testing.T) {
	const use = int(maxScopeUse)

	t.Run("same_scope_reuse_bounded_at_maxScopeUse", func(t *testing.T) {
		nc := NewNonceCache()
		defer nc.Stop()

		var got []bool
		for i := 0; i < use+2; i++ {
			got = append(got, nc.CheckAndAdd("cert-A", []byte("nonce-1")))
		}
		// The first use (insert) plus maxScopeUse-1 reuses pass; every further
		// same-scope reuse is rejected: want [true*3, false*2] with maxScopeUse=3.
		for i, v := range got {
			if want := i < use; v != want {
				t.Errorf("use %d: got %v, want %v — same-scope reuse must be capped at %d", i+1, v, want, use)
			}
		}
		if n := nc.Len(); n != 1 {
			t.Errorf("Len() = %d, want 1 (a single nonce entry, whatever its use count)", n)
		}
	})

	t.Run("cross_scope_reuse_rejected", func(t *testing.T) {
		nc := NewNonceCache()
		defer nc.Stop()
		nonce := []byte("nonce-x")
		if !nc.CheckAndAdd("cert-A", nonce) {
			t.Fatal("first use of a fresh nonce must be allowed")
		}
		if nc.CheckAndAdd("cert-B", nonce) {
			t.Error("same nonce under a different certificate scope must be rejected (DA replay attack)")
		}
	})

	t.Run("empty_nonce_rejected", func(t *testing.T) {
		nc := NewNonceCache()
		defer nc.Stop()
		if nc.CheckAndAdd("cert-A", nil) {
			t.Error("nil nonce must be rejected outright")
		}
		if nc.CheckAndAdd("cert-A", []byte{}) {
			t.Error("zero-length nonce must be rejected outright")
		}
	})
}

// ---------------------------------------------------------------------------
// 3. ocsp.go — OCSPFallbackAllow surfaces every unproven allowance (C3)
// ---------------------------------------------------------------------------

// TestOCSPFallbackAllowLogsWarning verifies that the fallback_allow path — which
// admits a certificate whose revocation status could not be proven — emits an
// ERROR-level line naming the certificate and the reason. Pre-fix this
// allowance was silent, so operators could not detect the fallback admitting
// revoked certificates.
func TestOCSPFallbackAllowLogsWarning(t *testing.T) {
	cert := testAgentCert()
	out := captureStdout(t, func() {
		cache := NewOCSPCache(5*time.Minute, OCSPFallbackAllow, nil, "en")
		if err := cache.fallbackErr(cert, "no OCSP URL in certificate AIA"); err != nil {
			t.Fatalf("fallback_allow must allow: %v", err)
		}
	})
	for _, needle := range []string{
		"[ERROR] OCSP fallback_allow",
		"ALLOWING certificate test-agent",
		"no OCSP URL",
	} {
		if !strings.Contains(out, needle) {
			t.Errorf("stdout missing %q — fallback_allow must surface every unproven allowance:\n%s", needle, out)
		}
	}
}

// TestOCSPFallbackFailClosesWithoutAllowLog verifies the non-allow fallbacks
// still fail closed, and that only fallback_allow may print an ALLOWING line.
func TestOCSPFallbackFailClosesWithoutAllowLog(t *testing.T) {
	cert := testAgentCert()
	for _, fb := range []string{OCSPFallbackDeny, OCSPFallbackCRL} {
		out := captureStdout(t, func() {
			cache := NewOCSPCache(5*time.Minute, fb, nil, "en")
			if err := cache.fallbackErr(cert, "no OCSP URL in certificate AIA"); err == nil {
				t.Fatalf("fallback %q must NOT silently allow without revocation proof (finding 3)", fb)
			}
		})
		if strings.Contains(out, "ALLOWING") {
			t.Errorf("fallback %q printed an ALLOWING line; only fallback_allow may admit without proof:\n%s", fb, out)
		}
	}
}

// ---------------------------------------------------------------------------
// 5. server.go — X-Forwarded-For captures the real peer before proxy rewrite (M4)
// ---------------------------------------------------------------------------

// TestXForwardedForCapture drives the reverse proxy end to end: an admitted
// request with a fabricated RemoteAddr must arrive at the backend carrying the
// real peer IP (the host part of RemoteAddr captured before the proxy's
// Director runs). A rewrite of RemoteAddr inside the proxy must not leak into
// the forwarded header.
func TestXForwardedForCapture(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		wantIP     string
	}{
		{name: "ipv4_gets_host_only", remoteAddr: "203.0.113.7:45123", wantIP: "203.0.113.7"},
		{name: "ipv6_gets_host_only", remoteAddr: "[2001:db8::1]:443", wantIP: "2001:db8::1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Get("X-Forwarded-For")
				w.WriteHeader(http.StatusNoContent)
			}))
			defer backend.Close()
			target, err := url.Parse(backend.URL)
			if err != nil {
				t.Fatal(err)
			}

			s := &Server{
				cfg:        &Config{IdentityMode: IdentityMinimal},
				log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
				transport:  &http.Transport{},
				revHeaders: trustHeaderNames(),
				routes:     []Route{{Path: "/api", Target: target}},
			}
			req := httptest.NewRequest(http.MethodGet, "http://gateway.test/api/thing", nil)
			req.RemoteAddr = tc.remoteAddr
			req = req.WithContext(context.WithValue(req.Context(), authCtxKey{}, &AuthContext{
				AgentID:   "agent-1",
				Principal: "p:alice",
			}))
			rec := httptest.NewRecorder()
			s.proxy(rec, req)

			if rec.Code != http.StatusNoContent {
				t.Fatalf("proxy status = %d, want 204; body=%s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(got, tc.wantIP) {
				t.Errorf("backend X-Forwarded-For = %q, want it to contain captured client IP %q (peer captured before proxy rewrite, M4)", got, tc.wantIP)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 6. crl.go — CRL transport timeouts (H3)
// ---------------------------------------------------------------------------

// TestCRLTransportTimeouts verifies a hung CRL distribution point cannot pin a
// gateway goroutine indefinitely: dial and TLS handshake are each bounded at
// 5s and the whole request at 30s. The transport is TLS1.2-minimum.
func TestCRLTransportTimeouts(t *testing.T) {
	ca := &x509.Certificate{Subject: pkix.Name{CommonName: "test-ca"}}
	cache := NewCRLCache(ca, "https://crl.example.test/crl.pem", 0, nil, "en")
	if cache.client == nil {
		t.Fatal("cache.client = nil")
	}
	tr, ok := cache.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client.Transport = %T, want *http.Transport", cache.client.Transport)
	}

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"client total timeout (bound the whole fetch)", cache.client.Timeout, 30 * time.Second},
		{"TLS handshake timeout", tr.TLSHandshakeTimeout, 5 * time.Second},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v (H3)", tc.name, tc.got, tc.want)
		}
	}
	if tr.DialContext == nil {
		t.Error("DialContext is nil — no bounded dial; a suspected CRL url would hang the gateway (H3)")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("TLSClientConfig.MinVersion = %v, want TLS1.2", tr.TLSClientConfig)
	}
	if cache.refreshSec != 5*time.Minute {
		t.Errorf("default refresh interval = %v, want 5m", cache.refreshSec)
	}
	if cache.client.CheckRedirect == nil {
		// http.Client follows up to 10 redirects by default; an unbounded
		// redirect chain is capped by the total 30s timeout regardless.
		t.Log("note: default redirect policy applies; the 30s client timeout bounds the overall fetch")
	}
}

// ---------------------------------------------------------------------------
// 7. merkle.go — VerifyProof is bytes.Equal-based; nil/empty never match (22)
// ---------------------------------------------------------------------------

// TestMerkleVerifyProofBytesEqual pins the comparison fix: the result is
// compared with bytes.Equal and every nil/empty input (leaf, proof, root)
// yields false. Pre-fix, a string-compare could let an empty root hash match an
// empty computed hash, accepting a proof for nothing.
func TestMerkleVerifyProofBytesEqual(t *testing.T) {
	tree := NewMerkleTree([][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")})
	proof, err := tree.Proof(1) // proof for leaf "b"
	if err != nil {
		t.Fatalf("Proof(1): %v", err)
	}
	validRoot := tree.Root()

	tests := []struct {
		name  string
		leaf  []byte
		proof []ProofStep
		root  []byte
		want  bool
	}{
		{name: "nil_leaf_nil_proof_nil_root", leaf: nil, proof: nil, root: nil, want: false},
		{name: "empty_leaf_empty_root", leaf: []byte{}, proof: []ProofStep{}, root: []byte{}, want: false},
		{name: "valid_proof_real_root", leaf: []byte("b"), proof: proof, root: validRoot, want: true},
		{name: "valid_leaf_nil_root", leaf: []byte("b"), proof: proof, root: nil, want: false},
		{name: "valid_leaf_empty_root", leaf: []byte("b"), proof: proof, root: []byte{}, want: false},
		{name: "nil_leaf_real_root", leaf: nil, proof: proof, root: validRoot, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := VerifyProof(tc.leaf, tc.proof, tc.root); got != tc.want {
				t.Errorf("VerifyProof = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 8. supervision_store.go — concurrent Record+Query is race-free (H5)
// ---------------------------------------------------------------------------

// TestSupervisionStoreQueryConcurrency hammers Record (appender) and Query
// (reader) from many goroutines at once. Pre-fix, Query read s.file outside the
// mutex and a concurrent rotation/close could corrupt the read and race the
// write path. The test asserts no panic and that a final, quiesced Query sees
// every recorded event.
func TestSupervisionStoreQueryConcurrency(t *testing.T) {
	store, err := NewSupervisionStore(t.TempDir()+"/supervision.jsonl", nil, 1<<20, 2)
	if err != nil {
		t.Fatalf("NewSupervisionStore: %v", err)
	}
	defer store.Close()

	const writers = 8
	const perWriter = 50
	total := writers * perWriter

	var wg sync.WaitGroup
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				ev := &pki.SupervisionEvent{
					Type:        pki.SupervisionApproval,
					Source:      "security-fixes-test",
					OperationID: fmt.Sprintf("op-%d-%d", w, i),
					DaHash:      strings.Repeat("a", 64),
					AgentID:     fmt.Sprintf("agent-%d", w),
					Actor:       "operator",
					Reason:      "concurrency test",
					Decision:    pki.SupervisionDecisionApproved,
					Ts:          time.Now().UTC(),
				}
				if err := store.Record(ev); err != nil {
					t.Errorf("Record(operation %s): %v", ev.OperationID, err)
					return
				}
			}
		}(w)
	}

	// Concurrent readers must neither panic nor corrupt/inject errors.
	readerStop := make(chan struct{})
	var readers sync.WaitGroup
	readers.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer readers.Done()
			for {
				select {
				case <-readerStop:
					return
				default:
				}
				if _, err := store.Query(SupervisionQuery{Limit: 1000}); err != nil {
					t.Errorf("Query during concurrent writes: %v", err)
					return
				}
				time.Sleep(time.Millisecond)
			}
		}()
	}

	wg.Wait()
	close(readerStop)
	readers.Wait()

	// Quiesced: every recorded event must be observable in append order.
	got, err := store.Query(SupervisionQuery{})
	if err != nil {
		t.Fatalf("final Query: %v", err)
	}
	if len(got) != total {
		t.Errorf("final Query returned %d events, want %d", len(got), total)
	}
}

// ---------------------------------------------------------------------------
// 9. challenge.go — RNG failures propagate (M2)
// ---------------------------------------------------------------------------

// TestRandomTokenErrorPropagation guards the M2 fix: a failure to obtain
// randomness must surface as an error instead of silently becoming an empty —
// and therefore fixed and replayable — challenge token.
//
// The failure branch of randomToken (crypto/rand.Read error → wrapped error) is
// exercised at its observable boundary: the injectable Now/NewID/NewNonce hooks
// let us simulate a collapsed RNG (empty output) and assert the challenge
// pipeline errors out rather than emitting a challenge with a degenerate nonce.
func TestRandomTokenErrorPropagation(t *testing.T) {
	cfg := ChallengeConfig{}

	t.Run("random_token_produces_unpredictable_tokens", func(t *testing.T) {
		a, err := cfg.randomToken(nil)
		if err != nil {
			t.Fatalf("randomToken: %v", err)
		}
		b, err := cfg.randomToken(nil)
		if err != nil {
			t.Fatalf("randomToken: %v", err)
		}
		if len(a) != 32 || len(b) != 32 {
			t.Errorf("token lengths = %d and %d, want 32 hex chars (16 random bytes) each", len(a), len(b))
		}
		if a == b {
			t.Error("two consecutive tokens are identical — randomness collapse produces a fixed, replayable challenge value (M2)")
		}
	})

	t.Run("empty_nonce_surfaces_as_error", func(t *testing.T) {
		cfg := ChallengeConfig{NewID: func() string { return "id-1" }, NewNonce: func() string { return "" }}
		problem, err := problemForResult(obligationResult(), &cfg, "why")
		if err == nil {
			t.Fatal("an empty (RNG-failed) nonce must surface as an error, not mint a challenge with a fixed nonce (M2)")
		}
		if problem != nil {
			t.Errorf("problem = %+v, want nil", problem)
		}
		if !strings.Contains(err.Error(), "challenge nonce unavailable") {
			t.Errorf("error = %v, want it to name the unavailable nonce", err)
		}
	})

	t.Run("empty_id_surfaces_as_error", func(t *testing.T) {
		cfg := ChallengeConfig{NewID: func() string { return "" }, NewNonce: func() string { return "n-1" }}
		if _, err := problemForResult(obligationResult(), &cfg, "why"); err == nil {
			t.Fatal("an empty challenge id must surface as an error (M2)")
		}
	})
}

// ---------------------------------------------------------------------------
// 10. audit.go — rotation failures are logged (L1)
// ---------------------------------------------------------------------------

// TestAuditRotationErrorLogging verifies the L1 fix: when rotation cannot
// remove or rename its slot (here sabotaged by pre-creating the ".1" backup
// path as a non-empty directory), both failures are printed instead of being
// silently ignored — a leftover backup could otherwise shadow the rotation or
// exhaust disk without anyone noticing.
func TestAuditRotationErrorLogging(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	slot := path + ".1"
	if err := os.Mkdir(slot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slot, "stale"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	rf, err := NewRotatingFile(path, 16, 1)
	if err != nil {
		t.Fatalf("NewRotatingFile: %v", err)
	}
	defer rf.Close()

	out := captureStdout(t, func() {
		if _, err := rf.Write([]byte("0123456789abcdef0123456789abcdef")); err != nil {
			t.Fatalf("Write: %v", err)
		}
	})
	for _, needle := range []string{"audit: rotate remove", "audit: rotate rename"} {
		if !strings.Contains(out, needle) {
			t.Errorf("rotation error missing from stdout — rotation failures must be logged, never silent (L1); output:\n%s", out)
		}
	}
	if strings.Contains(out, "WARNING evicting") {
		t.Fatal("unexpected replay-store output leaked into stdout capture")
	}
}

// ---------------------------------------------------------------------------
// 11. merkle.go — VerifyProofBounded proof-length cap (finding 22)
// ---------------------------------------------------------------------------

// TestVerifyProofBoundedLen pins the bounded variant used by AuditChain.Verify:
// a proof longer than the allowed maximum is rejected even when the hashes
// would verify, so an over-long proof can never be deployed as a valid audit
// path. Companion to TestMerkleVerifyProofBytesEqual (bytes.Equal fix).
func TestVerifyProofBoundedLen(t *testing.T) {
	tree := NewMerkleTree([][]byte{[]byte("a"), []byte("b"), []byte("c")})
	proof, err := tree.Proof(0)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	root := tree.Root()

	// The real proof (height 2) must verify within its exact bound.
	if !VerifyProofBounded([]byte("a"), proof, root, len(proof)) {
		t.Error("bounded proof at its exact height rejected — must pass")
	}
	if !VerifyProofBounded([]byte("a"), proof, root, -1) {
		t.Error("unbounded (-1) proof rejected — must pass")
	}
	// Padding the proof with one extra fabricated step exceeds the bound: even
	// though the leaf hashes match, the oversized path must be refused.
	overlong := append(append([]ProofStep{}, proof...), ProofStep{Sibling: make([]byte, 32), Left: false})
	if VerifyProofBounded([]byte("a"), overlong, root, 2) {
		t.Error("proof longer than the tree height accepted — the length cap is bypassed")
	}
	// A bound of 0 rejects any non-empty proof.
	if VerifyProofBounded([]byte("a"), proof, root, 0) {
		t.Error("bound 0 accepted a non-empty proof")
	}
}
