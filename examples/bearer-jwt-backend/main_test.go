// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/aic-verifier"
	"github.com/varwof/aic-verifier/examples/supervision-demo"
	"github.com/varwof/types/aicjwt"
)

// testCA is a self-signed JWT issuing CA: the certificate written to ca.pem
// and the key that signs bearer tokens (kid = CA SPKI hash).
type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bearer-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &testCA{key: key, cert: cert}
}

func (ca *testCA) writeCAPEM(t *testing.T, path string) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// signToken mints a fresh bearer AIC-JWT (unique jti per call) carrying the
// given capability ids, matching the issuer/audience the example config pins.
func (ca *testCA) signToken(t *testing.T, sub string, caps []string) string {
	t.Helper()
	now := time.Now()
	kid, err := aicjwt.SPKIHash(ca.cert, "sha-256")
	if err != nil {
		t.Fatalf("SPKIHash: %v", err)
	}
	principalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("principal key: %v", err)
	}
	keyHash, err := aicjwt.KeyHashOf(&principalKey.PublicKey, "sha-256")
	if err != nil {
		t.Fatalf("KeyHashOf: %v", err)
	}
	jwk, err := aicjwt.PublicKeyToJWK(&principalKey.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyToJWK: %v", err)
	}
	jkt, err := aicjwt.JWKThumbprint(jwk)
	if err != nil {
		t.Fatalf("JWKThumbprint: %v", err)
	}
	aicCaps := make([]aicjwt.Capability, 0, len(caps))
	for _, c := range caps {
		aicCaps = append(aicCaps, aicjwt.Capability{Scheme: "demo", ID: c})
	}
	outer := aicjwt.OuterClaims{
		Iss: "aic-verifier-example",
		Sub: sub,
		Aud: aicjwt.Audience{"myapi"},
		Iat: now.Unix(),
		Exp: now.Add(time.Hour).Unix(),
		Jti: fmt.Sprintf("t-%d", now.UnixNano()),
		Cnf: &aicjwt.Cnf{Jkt: jkt},
		Aic: &aicjwt.AICClaims{
			Ver:            1,
			Principal:      aicjwt.Principal{Realm: "example", ID: sub, KeyHash: keyHash, HashAlg: "sha-256"},
			DelegationMode: aicjwt.ModeAuthorized,
			Capabilities:   aicCaps,
		},
	}
	headerJSON, _ := json.Marshal(aicjwt.Header{Alg: "ES256", Typ: aicjwt.TypOuter, Kid: kid})
	payloadJSON, _ := json.Marshal(outer)
	tok, err := aicjwt.SignCompact(headerJSON, payloadJSON, "ES256", ca.key)
	if err != nil {
		t.Fatalf("SignCompact: %v", err)
	}
	return tok
}

func runArgs(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func startBusyListener(t *testing.T) *os.File {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("busy listener: %v", err)
	}
	f, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatalf("busy listener file: %v", err)
	}
	ln.Close()
	return f
}

// TestRunFlagParseError covers the flag parse failure return path.
func TestRunFlagParseError(t *testing.T) {
	code, _, stderr := runArgs(t, "-no-such-flag")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "no-such-flag") {
		t.Errorf("stderr %q should name the unknown flag", stderr)
	}
}

// TestRunBadBackendURL covers the url.Parse error return path.
func TestRunBadBackendURL(t *testing.T) {
	code, _, stderr := runArgs(t, "-backend", "://bad")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "bad backend") {
		t.Errorf("stderr %q should report the bad backend", stderr)
	}
}

// TestRunWireError covers the supervision.demo Wire error return path (an
// audit file whose directory does not exist fails to open during Wire).
func TestRunWireError(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "missing", "audit.jsonl")
	code, _, stderr := runArgs(t, "-audit-file", bad, "-serve-backend=false")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "supervision demo") {
		t.Errorf("stderr %q should report the supervision demo failure", stderr)
	}
}

// TestRunEnsureServerTLSError covers the ensureServerTLS error return path:
// a symlink loop on server-cert.pem makes both the stat and the create fail.
func TestRunEnsureServerTLSError(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	if err := os.Symlink("server-cert.pem", "loop"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loop", "server-cert.pem"); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runArgs(t, "-serve-backend=false")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "tls:") {
		t.Errorf("stderr %q should report the TLS setup failure", stderr)
	}
}

// TestRunBuildServerMissingCA covers the buildServer error return path: the
// JWT CA (ca.pem) is missing, so building the server's handler chain fails.
func TestRunBuildServerMissingCA(t *testing.T) {
	chdir(t, t.TempDir())
	code, _, stderr := runArgs(t, "-serve-backend=false")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "aic-verifier server") {
		t.Errorf("stderr %q should report the server build failure", stderr)
	}
}

// TestRunListenFailsBusyPort walks the entire happy path of run (flags, config
// build, Wire, ensureServerTLS, go startBackend, buildServer) and covers the
// ListenAndServe error return path with a port that is already bound.
func TestRunListenFailsBusyPort(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	ca := newTestCA(t)
	ca.writeCAPEM(t, "ca.pem")
	busy := startBusyListener(t)
	defer busy.Close()

	code, _, stderr := runArgs(t,
		"-addr", "127.0.0.1:"+portOf(t, busy), "-serve-backend=true", "-backend", "http://127.0.0.1:9080")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1, stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "already in use") {
		t.Errorf("stderr %q should report the bind conflict", stderr)
	}
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	t.Chdir(dir)
}

func portOf(t *testing.T, f *os.File) string {
	t.Helper()
	// Recover the bound address from the duplicated socket file descriptor.
	ln, err := net.FileListener(f)
	if err != nil {
		t.Fatalf("FileListener: %v", err)
	}
	defer ln.Close()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// TestEnsureServerTLS covers the certificate generation happy path, the
// already-present early return, and the error path (non-existent directory).
func TestEnsureServerTLS(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "server-cert.pem")
	key := filepath.Join(dir, "server-key.pem")
	if err := ensureServerTLS(cert, key); err != nil {
		t.Fatalf("ensureServerTLS: %v", err)
	}
	for _, f := range []string{cert, key} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("expected %s to be written: %v", f, err)
		}
	}
	if err := ensureServerTLS(cert, key); err != nil {
		t.Fatalf("second ensureServerTLS (files present): %v", err)
	}
	if err := ensureServerTLS(filepath.Join(dir, "no", "dir", "c.pem"), filepath.Join(dir, "no", "dir", "k.pem")); err == nil {
		t.Fatal("expected ensureServerTLS to fail on a non-existent directory")
	}
}

// TestWritePEMFileBadPath covers the writePEMFile error return path.
func TestWritePEMFileBadPath(t *testing.T) {
	if err := writePEMFile(filepath.Join(t.TempDir(), "no", "dir", "x.pem"), "CERTIFICATE", []byte{1}); err == nil {
		t.Fatal("expected writePEMFile to fail on a non-existent directory")
	}
}

// TestStartBackendBindError covers startBackend's ListenAndServe error branch
// (the sample port is already bound, so the backend reports and returns).
func TestStartBackendBindError(t *testing.T) {
	busy := startBusyListener(t)
	defer busy.Close()
	startBackend("127.0.0.1:"+portOf(t, busy), nil)
}

type stubExporter struct {
	bundle *aicverifier.EvidenceBundle
	err    error
}

func (s stubExporter) Export(ctx context.Context, q aicverifier.EvidenceQuery) (*aicverifier.EvidenceBundle, error) {
	return s.bundle, s.err
}

// TestBackendMux exercises the sample backend mux: identity echo on /api, the
// /api/transfer route, the /evidence handler with and without an exporter, and
// the missing-route 404 when no exporter is installed.
func TestBackendMux(t *testing.T) {
	const (
		apiOK    = `"backend":"real-api"`
		transfer = `"route":"/api/transfer"`
	)

	t.Run("nil_exporter", func(t *testing.T) {
		h := backendMux(nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api", nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), apiOK) {
			t.Fatalf("/api = %d %s", rec.Code, rec.Body.String())
		}
		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/api/transfer", nil))
		if rec2.Code != http.StatusOK || !strings.Contains(rec2.Body.String(), transfer) {
			t.Fatalf("/api/transfer = %d %s", rec2.Code, rec2.Body.String())
		}
		rec3 := httptest.NewRecorder()
		h.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/evidence?operation_id=op-x", nil))
		if rec3.Code != http.StatusNotFound {
			t.Fatalf("/evidence with nil exporter = %d, want 404", rec3.Code)
		}
	})

	okExporter := stubExporter{bundle: &aicverifier.EvidenceBundle{
		Manifest: aicverifier.EvidenceManifest{Schema: "evidence-test"},
	}}
	errExporter := stubExporter{err: fmt.Errorf("boom")}

	t.Run("evidence_success", func(t *testing.T) {
		h := backendMux(okExporter)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/evidence?operation_id=op-abc", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("/evidence = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "evidence-test") {
			t.Errorf("body %q should contain the exported bundle", rec.Body.String())
		}
	})

	t.Run("evidence_error", func(t *testing.T) {
		h := backendMux(errExporter)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/evidence?operation_id=op-xyz", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("/evidence = %d, want 500: %s", rec.Code, rec.Body.String())
		}
	})
}

// TestProxyBearerHandler drives the full assembled reverse proxy (buildServer +
// server.Handler) over TLS: admission by bearer token, route capability
// enforcement, supervisor approval on /api/transfer and the deny-risk path.
func TestProxyBearerHandler(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	ca := newTestCA(t)
	ca.writeCAPEM(t, "ca.pem")

	backendTS := httptest.NewServer(backendMux(okExporterBundle()))
	defer backendTS.Close()
	target, err := url.Parse(backendTS.URL)
	if err != nil {
		t.Fatal(err)
	}

	conf := demoConfig()
	if err := superv.Wire(conf, superv.Options{}); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	s, err := buildServer(conf, target)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	proxyTS := httptest.NewTLSServer(s.Handler())
	defer proxyTS.Close()

	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	do := func(path, tok string) (int, string) {
		req, err := http.NewRequest(http.MethodGet, proxyTS.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	readTok := func() string { return ca.signToken(t, "agent-001", []string{"api:read"}) }
	fullTok := func() string { return ca.signToken(t, "agent-001", []string{"api:read", superv.TransferCapability}) }

	t.Run("admitted_api", func(t *testing.T) {
		code, body := do("/api", readTok())
		if code != http.StatusOK {
			t.Fatalf("/api = %d, want 200: %s", code, body)
		}
		// Bearer mode carries no client certificate, so the proxy only asserts
		// the request is admitted and forwards it; check the backend answered.
		if !strings.Contains(body, `"backend":"real-api"`) {
			t.Errorf("backend did not answer: %s", body)
		}
	})

	t.Run("transfer_approved", func(t *testing.T) {
		code, body := do("/api/transfer", fullTok())
		if code != http.StatusOK {
			t.Fatalf("/api/transfer = %d, want 200: %s", code, body)
		}
		if !strings.Contains(body, `"status":"transferred"`) {
			t.Errorf("body %q should report the transfer", body)
		}
	})

	t.Run("transfer_missing_capability_denied", func(t *testing.T) {
		code, body := do("/api/transfer", readTok())
		if code != http.StatusForbidden {
			t.Fatalf("/api/transfer without %s = %d, want 403: %s", superv.TransferCapability, code, body)
		}
	})

	t.Run("no_route", func(t *testing.T) {
		code, _ := do("/nope", readTok())
		if code != http.StatusNotFound {
			t.Fatalf("/nope = %d, want 404", code)
		}
	})

	t.Run("no_token_rejected", func(t *testing.T) {
		code, _ := do("/api", "")
		if code != http.StatusUnauthorized {
			t.Fatalf("/api without token = %d, want 401", code)
		}
	})

	t.Run("deny_risk_denies_transfer", func(t *testing.T) {
		conf := demoConfig()
		if err := superv.Wire(conf, superv.Options{DenyRisk: true}); err != nil {
			t.Fatalf("Wire(deny): %v", err)
		}
		s, err := buildServer(conf, target)
		if err != nil {
			t.Fatalf("buildServer(deny): %v", err)
		}
		denyTS := httptest.NewTLSServer(s.Handler())
		defer denyTS.Close()
		req, _ := http.NewRequest(http.MethodGet, denyTS.URL+"/api/transfer", nil)
		req.Header.Set("Authorization", "Bearer "+fullTok())
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("deny transfer request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("deny-risk transfer = %d, want 403", resp.StatusCode)
		}
	})
}

func demoConfig() *aicverifier.Config {
	conf := &aicverifier.Config{
		JWTCAFile:              "ca.pem",
		JWTIssuer:              "aic-verifier-example",
		JWTAudience:            []string{"myapi"},
		AuthMode:               aicverifier.BearerOnly,
		RequireAIC:             true,
		RequiredCapabilities:   []string{"api:read"},
		DisallowRepresentative: true,
		EnforceConstraints:     true,
		TLSCertFile:            "server-cert.pem",
		TLSKeyFile:             "server-key.pem",
	}
	return conf
}

func okExporterBundle() stubExporter {
	return stubExporter{bundle: &aicverifier.EvidenceBundle{
		Manifest: aicverifier.EvidenceManifest{Schema: "evidence-test"},
	}}
}
