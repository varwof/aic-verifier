// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		t.Fatal(err)
	}
}

// mintCA creates a self-signed CA that signs both the client AIC certificates
// and the server leaf, mirroring the single-PKI layout the demos use.
func mintCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "smoke-verify test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * 365 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func mintClient(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, cn string, caps []pki.Capability, withAIC bool) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var extras []pkix.Extension
	if withAIC {
		subjectKey, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		keyHash := sha256.Sum256(subjectKey)
		aic := pki.AIC{
			Version: 1,
			AgentId: cn,
			PrincipalUid: pki.PrincipalUid{
				Version: 1, Realm: "example", Identifier: cn, KeyHash: keyHash[:],
			},
			Capabilities: caps,
			DelegationAuthorization: pki.DelegationAuthorization{
				Reason:             pki.Reason{ReasonCode: "operator-request", Description: "smoke-verify test"},
				Nonce:              make([]byte, 32),
				RequestedLifetime:  3600,
				SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			},
		}
		aicDER, err := asn1.Marshal(aic)
		if err != nil {
			t.Fatal(err)
		}
		extras = []pkix.Extension{{Id: pki.OIDAIC, Critical: false, Value: aicDER}}
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(time.Now().UnixNano()),
		Subject:         pkix.Name{CommonName: cn},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: extras,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cf := cn + "-cert.pem"
	kf := cn + "-key.pem"
	writePEM(t, cf, "CERTIFICATE", der)
	writePEM(t, kf, "EC PRIVATE KEY", keyDER)
	return cf, kf
}

func mintServer(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "smoke-verify test server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, "server-cert.pem", "CERTIFICATE", der)
	writePEM(t, "server-key.pem", "EC PRIVATE KEY", keyDER)
	return "server-cert.pem", "server-key.pem"
}

// requirePKI mints the whole PKI into the current working directory and returns
// the client credentials to present. The server leaf is written to the names
// buildServer consumes.
func requirePKI(t *testing.T, caps []pki.Capability) (cf, kf string, caPool *x509.CertPool) {
	t.Helper()
	caKey, caCert := mintCA(t)
	writePEM(t, "ca.pem", "CERTIFICATE", caCert.Raw)
	cf, kf = mintClient(t, caKey, caCert, "agent-001", caps, true)
	mintServer(t, caKey, caCert)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return cf, kf, pool
}

func runWith(t *testing.T, args []string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRunFlagAndConfigErrors(t *testing.T) {
	t.Chdir(t.TempDir())

	// Missing required --ca/--cert/--key.
	code, _, errOut := runWith(t, []string{"--ca=a"})
	if code != 1 || !strings.Contains(errOut, "--ca, --cert and --key are required") {
		t.Fatalf("missing flags = %d (%s), want 1", code, errOut)
	}
	// Unknown flag → parse error.
	code, _, _ = runWith(t, []string{"--bogus"})
	if code != 2 {
		t.Fatalf("bad flag = %d, want 2", code)
	}
	// Invalid --op-params JSON.
	code, _, errOut = runWith(t, []string{"--ca=ca.pem", "--cert=c.pem", "--key=k.pem", "--op=smoke:run", "--op-params={notjson"})
	if code != 1 || !strings.Contains(errOut, "--op-params") {
		t.Fatalf("bad op-params = %d (%s), want 1", code, errOut)
	}
	// CA file that exists but is empty → Handler construction must fail.
	os.WriteFile("empty.pem", []byte("not a pem"), 0o600)
	code, _, errOut = runWith(t, []string{"--ca=empty.pem", "--cert=c.pem", "--key=k.pem"})
	if code != 1 {
		t.Fatalf("bad ca = %d (%s), want 1", code, errOut)
	}
}

func TestRunListenFailure(t *testing.T) {
	t.Chdir(t.TempDir())
	caKey, caCert := mintCA(t)
	writePEM(t, "ca.pem", "CERTIFICATE", caCert.Raw)
	mintClient(t, caKey, caCert, "agent-001", []pki.Capability{{SchemeId: "smoke", CapabilityId: "run"}}, true)
	mintServer(t, caKey, caCert)

	// The full run() path executes minting-free startup then fails to bind the
	// final TLS listener (bad port), so the whole serving setup is covered.
	code, _, errOut := runWith(t, []string{"--ca=ca.pem", "--cert=server-cert.pem", "--key=server-key.pem",
		"--cap=smoke:run", "--addr=:99999", "--evidence-dir=ev", "--challenge",
		"--op=mcp:db_query", "--op-params={}", "--evidence-audience=a"})
	if code != 1 {
		t.Fatalf("listen fail = %d (%s), want 1", code, errOut)
	}
}

// mountTLS wraps srv.Handler in a real mTLS test server using srv's client-auth
// configuration plus the CA-signed leaf the operate_smoke demo serves.
func mountTLS(t *testing.T, srv *http.Server) *httptest.Server {
	t.Helper()
	tlsCfg := srv.TLSConfig.Clone()
	cert, err := tls.LoadX509KeyPair("server-cert.pem", "server-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg.Certificates = []tls.Certificate{cert}
	ts := httptest.NewUnstartedServer(srv.Handler)
	ts.TLS = tlsCfg
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func TestAdmissionMTLSEndToEnd(t *testing.T) {
	t.Chdir(t.TempDir())
	caps := []pki.Capability{{SchemeId: "varwof/smoke-v1", CapabilityId: "db_query"}, {SchemeId: "varwof/smoke-v1", CapabilityId: "trade_exec"}}
	cf, kf, caPool := requirePKI(t, caps)

	opts := smokeOptions{
		caFile:      "ca.pem",
		certFile:    "server-cert.pem",
		keyFile:     "server-key.pem",
		capability:  "varwof/smoke-v1:db_query",
		opID:        "varwof/smoke-v1:db_query",
		opParams:    "{}",
		evidenceDir: "evidence",
	}
	srv, err := buildServer(opts)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	ts := mountTLS(t, srv)

	clientCert, err := tls.LoadX509KeyPair(cf, kf)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
	}}}

	resp, err := client.Get(ts.URL + "/whoami")
	if err != nil {
		t.Fatalf("admitted request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (%s), want 200", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "agent=agent-001") {
		t.Fatalf("whoami body = %s", body)
	}

	// A TLS client presenting NO client certificate fails the handshake (the
	// server demands RequireAndVerifyClientCert), so the request never starts.
	noCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    caPool,
	}}}
	if _, err := noCert.Get(ts.URL + "/whoami"); err == nil {
		t.Fatal("expected client-certificate handshake failure")
	}
}

func TestAdmissionRefusesMissingCapability(t *testing.T) {
	t.Chdir(t.TempDir())
	caKey, caCert := mintCA(t)
	writePEM(t, "ca.pem", "CERTIFICATE", caCert.Raw)
	mintClient(t, caKey, caCert, "agent-001", []pki.Capability{{SchemeId: "mcp", CapabilityId: "db_query"}}, true)
	mintServer(t, caKey, caCert)

	// auditor: same CA, but mcp:trade_exec is not granted and db_query-only
	// grants do not cover the required scope either; keep it plainly lacking it.
	audCert, audKey := mintClient(t, caKey, caCert, "auditor", []pki.Capability{{SchemeId: "mcp", CapabilityId: "db_query"}}, true)

	opts := smokeOptions{
		caFile:     "ca.pem",
		certFile:   "server-cert.pem",
		keyFile:    "server-key.pem",
		capability: "varwof/smoke-v1:trade_exec",
	}
	srv, err := buildServer(opts)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	ts := mountTLS(t, srv)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	clientCert, err := tls.LoadX509KeyPair(audCert, audKey)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      pool,
		Certificates: []tls.Certificate{clientCert},
	}}}
	resp, err := client.Get(ts.URL + "/whoami")
	if err != nil {
		t.Fatalf("refused request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}
