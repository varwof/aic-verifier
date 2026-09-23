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
	"encoding/asn1"
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
	pki "github.com/varwof/types"
)

// mtlsCA is the demo mTLS CA: the cert and key minted into the certs
// directory, plus a writer for AIC client certificates.
type mtlsCA struct {
	key   *ecdsa.PrivateKey
	cert  *x509.Certificate
	certP string
}

// makeCertDir mints ca-cert.pem and a localhost server keypair into dir,
// mirroring gen-cert so run() can load them.
func makeCertDir(t *testing.T, dir string) *mtlsCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mtls-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ca parse: %v", err)
	}
	ca := &mtlsCA{key: key, cert: cert, certP: filepath.Join(dir, "ca-cert.pem")}
	writePEMFile(t, ca.certP, "CERTIFICATE", der)

	// Server keypair: needed by run()'s ListensAndServe path.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, cert, &serverKey.PublicKey, key)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	writePEMFile(t, filepath.Join(dir, "server-cert.pem"), "CERTIFICATE", serverDER)
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatalf("server key DER: %v", err)
	}
	writePEMFile(t, filepath.Join(dir, "server-key.pem"), "EC PRIVATE KEY", serverKeyDER)
	return ca
}

func writePEMFile(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// issue mints an AIC client certificate signed by the CA and carrying the
// given capabilities (gen-cert / root-package mint style).
func (ca *mtlsCA) issue(t *testing.T, cn string, caps []pki.Capability) tls.Certificate {
	t.Helper()
	aic := pki.AIC{
		Version: 1,
		AgentId: cn,
		PrincipalUid: pki.PrincipalUid{
			Version:    1,
			Realm:      "example",
			Identifier: cn,
			KeyHash:    make([]byte, 32),
			HashAlgo:   pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
		},
		Capabilities: caps,
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "TEST", Description: "mtls example"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			Timestamp:          time.Now().UTC(),
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     []byte{0x01},
		},
	}
	aicDER, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatalf("marshal AIC: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: pki.OIDAIC, Critical: false, Value: aicDER},
		},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, ca.cert.Raw}, PrivateKey: leafKey}
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

func portOf(t *testing.T, f *os.File) string {
	t.Helper()
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

// TestRunWireError covers the supervision.demo Wire error return path.
func TestRunWireError(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "missing", "audit.jsonl")
	code, _, stderr := runArgs(t, "-audit-file", bad)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "supervision demo") {
		t.Errorf("stderr %q should report the supervision demo failure", stderr)
	}
}

// TestRunBuildServerCertsMissing covers the buildServer error return path: the
// configured certs directory does not exist, so the mTLS CA cannot be loaded.
func TestRunBuildServerCertsMissing(t *testing.T) {
	code, _, stderr := runArgs(t, "-certs", filepath.Join(t.TempDir(), "nodir"))
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "aic-verifier server") {
		t.Errorf("stderr %q should report the server build failure", stderr)
	}
}

// TestRunListenFailsBusyPort walks the entire happy path of run (flags, config
// build, Wire, buildServer, go startBackend) and covers the ListenAndServe
// error return path with a port that is already bound.
func TestRunListenFailsBusyPort(t *testing.T) {
	dir := t.TempDir()
	makeCertDir(t, dir)
	busy := startBusyListener(t)
	defer busy.Close()

	code, _, stderr := runArgs(t,
		"-certs", dir, "-addr", "127.0.0.1:"+portOf(t, busy), "-backend", "http://127.0.0.1:9081")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1, stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "already in use") {
		t.Errorf("stderr %q should report the bind conflict", stderr)
	}
}

// TestStartBackendBindError covers startBackend's ListenAndServe error branch.
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

// TestBackendMux exercises the sample backend mux (mtls flavor): identity echo,
// /api/transfer, and the /evidence handler with/without an exporter.
func TestBackendMux(t *testing.T) {
	const (
		apiOK    = `"backend":"real-api-mtls"`
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

	t.Run("evidence_success", func(t *testing.T) {
		h := backendMux(stubExporter{bundle: &aicverifier.EvidenceBundle{
			Manifest: aicverifier.EvidenceManifest{Schema: "evidence-test"},
		}})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/evidence?operation_id=op-abc", nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "evidence-test") {
			t.Fatalf("/evidence = %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("evidence_error", func(t *testing.T) {
		h := backendMux(stubExporter{err: fmt.Errorf("boom")})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/evidence?operation_id=op-xyz", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("/evidence = %d, want 500", rec.Code)
		}
	})
}

// TestProxyMTLSHandler drives the full assembled reverse proxy (buildServer +
// server.Handler) over a real mTLS connection: client certificate admission,
// route capability enforcement, and supervisor approval on /api/transfer.
func TestProxyMTLSHandler(t *testing.T) {
	dir := t.TempDir()
	ca := makeCertDir(t, dir)

	backendTS := httptest.NewServer(backendMux(okExporterBundle()))
	defer backendTS.Close()
	target, err := url.Parse(backendTS.URL)
	if err != nil {
		t.Fatal(err)
	}

	conf := &aicverifier.Config{
		CACertFile:             filepath.Join(dir, "ca-cert.pem"),
		TLSCertFile:            filepath.Join(dir, "server-cert.pem"),
		TLSKeyFile:             filepath.Join(dir, "server-key.pem"),
		AuthMode:               aicverifier.MTLSOnly,
		RequireAIC:             true,
		RequiredCapabilities:   []string{"api:read"},
		DisallowRepresentative: true,
		EnforceConstraints:     true,
		IdentityMode:           aicverifier.IdentityForwardClientCert,
	}
	if err := superv.Wire(conf, superv.Options{}); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	s, err := buildServer(conf, target)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srv := httptest.NewUnstartedServer(s.Handler())
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientCAs:  pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	srv.StartTLS()
	defer srv.Close()

	httpClient := &http.Client{Transport: &http.Transport{
		DisableKeepAlives: true, // each request must handshake with its own certificate
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}}
	do := func(path string, cert tls.Certificate) (int, string) {
		httpClient.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{cert}
		req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	readOnly := ca.issue(t, "agent-ro", []pki.Capability{{SchemeId: "demo/example-v1", CapabilityId: "api:read"}})
	full := ca.issue(t, "agent-full", []pki.Capability{
		{SchemeId: "demo/example-v1", CapabilityId: "api:read"},
		{SchemeId: "demo/example-v1", CapabilityId: superv.TransferCapability},
	})

	t.Run("admitted_api", func(t *testing.T) {
		code, body := do("/api", readOnly)
		if code != http.StatusOK {
			t.Fatalf("/api = %d, want 200: %s", code, body)
		}
		if !strings.Contains(body, `"X-AIC-Agent-Id"`) || !strings.Contains(body, "agent-ro") {
			t.Errorf("backend did not receive the verified identity: %s", body)
		}
	})

	t.Run("transfer_approved", func(t *testing.T) {
		code, body := do("/api/transfer", full)
		if code != http.StatusOK {
			t.Fatalf("/api/transfer = %d, want 200: %s", code, body)
		}
		if !strings.Contains(body, `"status":"transferred"`) {
			t.Errorf("body %q should report the transfer", body)
		}
	})

	t.Run("transfer_missing_capability_denied", func(t *testing.T) {
		code, body := do("/api/transfer", readOnly)
		if code != http.StatusForbidden {
			t.Fatalf("/api/transfer without %s = %d, want 403: %s", superv.TransferCapability, code, body)
		}
	})

	t.Run("no_route", func(t *testing.T) {
		code, _ := do("/nope", full)
		if code != http.StatusNotFound {
			t.Fatalf("/nope = %d, want 404", code)
		}
	})

	t.Run("no_client_cert_rejected", func(t *testing.T) {
		// A fresh transport ensures no previously pooled certificate-auth
		// connection is reused; an mTLS server that requires a client cert
		// fails the handshake for a client that presents none.
		noCertClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}}}
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api", nil)
		if _, err := noCertClient.Do(req); err == nil {
			t.Fatal("expected a TLS error without a client certificate")
		}
	})
}

func okExporterBundle() stubExporter {
	return stubExporter{bundle: &aicverifier.EvidenceBundle{
		Manifest: aicverifier.EvidenceManifest{Schema: "evidence-test"},
	}}
}
