// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ── shared TLS / OCSP helpers ------------------------------------------------

// fixedTranslator is a no-op Translator used to exercise OCSP/TLS paths that
// take a translator without formatting anything.
type fixedTranslator struct{}

func (fixedTranslator) T(lang, key string, args ...any) string { return key }

// testRootCA mints a self-signed root CA and writes its PEM to a temp file.
type testRootCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pem  string
}

func newTestRootCA(t *testing.T) *testRootCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "varwof-test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return &testRootCA{key: key, cert: cert, pem: p}
}

// mintTLSServerCert mints a leaf for server-side TLS (ServerAuth EKU) under ca.
func mintTLSServerCert(t *testing.T, ca *testRootCA) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "server.example"},
		DNSNames:              []string{"server.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func keyPairPEM(t *testing.T, name string, key *ecdsa.PrivateKey, cert *x509.Certificate) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	certFile = filepath.Join(dir, name+"-cert.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyFile = filepath.Join(dir, name+"-key.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func leafTLS(cert *x509.Certificate, key *ecdsa.PrivateKey) *tls.Certificate {
	return &tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}
}

// aiaExtension builds the DER for the Authority Information Access extension
// carrying an OCSP responder URL, matching ExtractOCSPURL's expected shape.
func aiaExtension(t *testing.T, responderURL string) pkix.Extension {
	t.Helper()
	descs := []accessDescription{{
		Method:   OCSPOID,
		Location: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(responderURL)},
	}}
	der, err := asn1.Marshal(descs)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: AIAOID, Value: der}
}

// ocspResponder serves a mutable OCSP response body over httptest.
type ocspResponder struct {
	mu   sync.Mutex
	body []byte
	hit  int
}

func (o *ocspResponder) set(body []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.body = body
	o.hit = 0
}

func (o *ocspResponder) countHits() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.hit
}

func (o *ocspResponder) handler(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.hit++
	w.Header().Set("Content-Type", "application/ocsp-response")
	_, _ = w.Write(o.body)
}

func newOCSPResponder(t *testing.T) (*httptest.Server, *ocspResponder) {
	t.Helper()
	o := &ocspResponder{}
	srv := httptest.NewServer(http.HandlerFunc(o.handler))
	t.Cleanup(srv.Close)
	return srv, o
}

func ocspResponseDER(t *testing.T, ca *testRootCA, leaf *x509.Certificate, tmpl ocsp.Response) []byte {
	t.Helper()
	tmpl.IssuerHash = crypto.SHA256
	der, err := ocsp.CreateResponse(ca.cert, ca.cert, tmpl, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// ── tls.go ───────────────────────────────────────────────────────────────────

func TestBuildCipherSuites(t *testing.T) {
	if got := BuildCipherSuites(nil); !reflect.DeepEqual(got, SecureCipherSuites) {
		t.Fatalf("empty input must return the hardened default list, got %v", got)
	}
	if len(SecureCipherSuites) == 0 {
		t.Fatal("SecureCipherSuites must be non-empty")
	}
	got := BuildCipherSuites([]string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "not-a-suite"})
	if !reflect.DeepEqual(got, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}) {
		t.Fatalf("recognized names must filter to their ids, got %v", got)
	}
	if got := BuildCipherSuites([]string{"bogus1", "bogus2"}); !reflect.DeepEqual(got, SecureCipherSuites) {
		t.Fatalf("unrecognized-only input must fall back to defaults, got %v", got)
	}
}

func TestTLSVersionFromString(t *testing.T) {
	cases := map[string]uint16{
		"1.2":     uint16(tls.VersionTLS12),
		"1.3":     uint16(tls.VersionTLS13),
		"":        uint16(tls.VersionTLS12),
		"garbage": uint16(tls.VersionTLS12),
	}
	for in, want := range cases {
		if got := TLSVersionFromString(in); got != want {
			t.Errorf("TLSVersionFromString(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestBaseTLSConfig(t *testing.T) {
	cfg := BaseTLSConfig(nil, "")
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS 1.2 default", cfg.MinVersion)
	}
	if !reflect.DeepEqual(cfg.CipherSuites, SecureCipherSuites) {
		t.Errorf("default cipher suites must be the hardened list")
	}
	cfg = BaseTLSConfig([]string{"TLS_AES_128_GCM_SHA256"}, "1.3")
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want TLS 1.3", cfg.MinVersion)
	}
	if !reflect.DeepEqual(cfg.CipherSuites, []uint16{tls.TLS_AES_128_GCM_SHA256}) {
		t.Errorf("CipherSuites = %v, want the requested suite", cfg.CipherSuites)
	}
}

func TestLoadCertBadPath(t *testing.T) {
	if _, err := LoadCert("/nonexistent-cert.pem", "/nonexistent-key.pem"); err == nil {
		t.Fatal("LoadCert must error on a missing keypair")
	}
}

func TestLoadCertFromTempPEM(t *testing.T) {
	ca := newTestRootCA(t)
	key, cert := mintTLSServerCert(t, ca)
	certFile, keyFile := keyPairPEM(t, "srv", key, cert)
	lc, err := LoadCert(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadCert: %v", err)
	}
	if lc == nil || len(lc.Certificate) == 0 {
		t.Fatal("LoadCert returned an empty certificate")
	}
	if _, err := LoadCert(certFile, "/nonexistent-key.pem"); err == nil {
		t.Fatal("LoadCert must error when the key file is missing")
	}
}

func TestLoadCA(t *testing.T) {
	ca := newTestRootCA(t)
	pool, err := LoadCA(ca.pem)
	if err != nil {
		t.Fatalf("LoadCA root bundle: %v", err)
	}
	if pool == nil {
		t.Fatal("LoadCA returned nil pool")
	}

	// A leaf cert (IsCA=false) in the bundle must be rejected.
	key, leaf := mintTLSServerCert(t, ca)
	leafFile, _ := keyPairPEM(t, "leaf", key, leaf)
	if _, err := LoadCA(leafFile); err == nil {
		t.Fatal("LoadCA must reject a non-CA certificate in the bundle")
	}

	if _, err := LoadCA("/nonexistent-ca.pem"); err == nil {
		t.Fatal("LoadCA must error on a bad path")
	}

	p := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(p, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(p); err == nil {
		t.Fatal("LoadCA must error on a file with no valid CA cert")
	}
}

func TestLoadCACert(t *testing.T) {
	ca := newTestRootCA(t)
	cert, err := LoadCACert(ca.pem)
	if err != nil {
		t.Fatalf("LoadCACert: %v", err)
	}
	if cert.Subject.CommonName != "varwof-test-root" {
		t.Errorf("CN = %q, want varwof-test-root", cert.Subject.CommonName)
	}
	if _, err := LoadCACert("/nonexistent-ca.pem"); err == nil {
		t.Fatal("LoadCACert must error on a bad path")
	}
}

func TestClientTLSConfig(t *testing.T) {
	ca := newTestRootCA(t)
	cliKey, cliCert := mintCert(t, ca.cert, ca.key, "mtls-client", big.NewInt(7), nil, nil, nil)
	certFile, keyFile := keyPairPEM(t, "client", cliKey, cliCert)

	cfg, err := ClientTLSConfig(ca.pem, "", "", nil, "")
	if err != nil {
		t.Fatalf("ClientTLSConfig without client cert: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs must be populated from the CA file")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS 1.2", cfg.MinVersion)
	}

	cfg, err = ClientTLSConfig(ca.pem, certFile, keyFile, nil, "")
	if err != nil {
		t.Fatalf("ClientTLSConfig with client cert: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("Certificates = %d, want 1", len(cfg.Certificates))
	}

	if _, err := ClientTLSConfig("/nonexistent-ca.pem", "", "", nil, ""); err == nil {
		t.Fatal("ClientTLSConfig must error on a bad CA path")
	}
}

// TestServerTLSConfigHandshake drives a real TLS handshake against a listener
// built from ServerTLSConfig and a client from ClientTLSConfig.
func TestServerTLSConfigHandshake(t *testing.T) {
	ca := newTestRootCA(t)
	srvKey, srvCert := mintTLSServerCert(t, ca)
	srvCfg := ServerTLSConfig(leafTLS(srvCert, srvKey), nil, "")
	if len(srvCfg.Certificates) != 1 {
		t.Fatalf("server Certificates = %d, want 1", len(srvCfg.Certificates))
	}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pong"))
	}))
	ts.TLS = srvCfg
	ts.StartTLS()
	defer ts.Close()

	cli, err := ClientTLSConfig(ca.pem, "", "", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	cli.ServerName = "server.example"
	resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: cli}}).Get(ts.URL)
	if err != nil {
		t.Fatalf("plain TLS handshake: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestMTLSHandshake verifies a real mutual-TLS handshake: a client presenting
// a valid client cert is admitted, a client without a cert is rejected.
func TestMTLSHandshake(t *testing.T) {
	ca := newTestRootCA(t)
	srvKey, srvCert := mintTLSServerCert(t, ca)
	cliKey, cliCert := mintCert(t, ca.cert, ca.key, "mtls-client", big.NewInt(7), nil, nil, nil)
	certFile, keyFile := keyPairPEM(t, "client", cliKey, cliCert)

	mtlsCfg, err := MTLSServerConfig(ca.pem, leafTLS(srvCert, srvKey), nil, "")
	if err != nil {
		t.Fatalf("MTLSServerConfig: %v", err)
	}
	if mtlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", mtlsCfg.ClientAuth)
	}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pong"))
	}))
	ts.TLS = mtlsCfg
	ts.StartTLS()
	defer ts.Close()

	t.Run("with_client_cert", func(t *testing.T) {
		withCert, err := ClientTLSConfig(ca.pem, certFile, keyFile, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		withCert.ServerName = "server.example"
		resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: withCert}}).Get(ts.URL)
		if err != nil {
			t.Fatalf("mTLS handshake with client cert: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("without_client_cert", func(t *testing.T) {
		noCert, err := ClientTLSConfig(ca.pem, "", "", nil, "")
		if err != nil {
			t.Fatal(err)
		}
		noCert.ServerName = "server.example"
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: noCert}}
		resp, err := client.Get(ts.URL)
		if err == nil {
			resp.Body.Close()
			t.Fatal("mTLS server must reject a client without a certificate")
		}
	})
}

// ── ocsp.go ──────────────────────────────────────────────────────────────────

func TestExtractOCSPURL(t *testing.T) {
	ca := newTestRootCA(t)

	_, withAIA := mintCert(t, ca.cert, ca.key, "leaf-aia", big.NewInt(11), nil, nil,
		[]pkix.Extension{aiaExtension(t, "http://ocsp.example/responder")})
	if got := ExtractOCSPURL(withAIA); got != "http://ocsp.example/responder" {
		t.Fatalf("ExtractOCSPURL = %q, want the OCSP responder URL", got)
	}

	_, plain := mintCert(t, ca.cert, ca.key, "leaf-plain", big.NewInt(12), nil, nil, nil)
	if got := ExtractOCSPURL(plain); got != "" {
		t.Fatalf("ExtractOCSPURL on a cert without AIA = %q, want empty", got)
	}

	// AIA extension present but no OCSP method (only caIssuers).
	caIssuers := []accessDescription{{
		Method:   asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2},
		Location: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte("http://ca.example/ca.crt")},
	}}
	der, err := asn1.Marshal(caIssuers)
	if err != nil {
		t.Fatal(err)
	}
	_, noOCSP := mintCert(t, ca.cert, ca.key, "leaf-caissuers", big.NewInt(13), nil, nil,
		[]pkix.Extension{{Id: AIAOID, Value: der}})
	if got := ExtractOCSPURL(noOCSP); got != "" {
		t.Fatalf("ExtractOCSPURL with no OCSP method = %q, want empty", got)
	}

	// Malformed AIA value cannot be embedded via x509.CreateCertificate (it is
	// validated at parse time), so attach the garbage extension directly to the
	// parsed certificate.
	_, malformedBase := mintCert(t, ca.cert, ca.key, "leaf-malformed", big.NewInt(14), nil, nil, nil)
	malformed := *malformedBase
	malformed.Extensions = append(malformed.Extensions, pkix.Extension{Id: AIAOID, Value: []byte{0xff, 0xff}})
	if got := ExtractOCSPURL(&malformed); got != "" {
		t.Fatalf("ExtractOCSPURL on a malformed AIA = %q, want empty", got)
	}
}

func TestResponseFresh(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name  string
		entry *ocspCacheEntry
		want  bool
	}{
		{"nil entry", nil, false},
		{"fresh window", &ocspCacheEntry{thisUpdate: now.Add(-time.Minute), nextUpdate: now.Add(time.Hour)}, true},
		{"stale next_update", &ocspCacheEntry{thisUpdate: now.Add(-2 * time.Hour), nextUpdate: now.Add(-time.Hour)}, false},
		{"future this_update", &ocspCacheEntry{thisUpdate: now.Add(time.Minute), nextUpdate: now.Add(time.Hour)}, false},
		{"no next_update within ttl", &ocspCacheEntry{thisUpdate: now.Add(-time.Minute), cachedAt: now.Add(-time.Minute), ttl: 5 * time.Minute}, true},
		{"no next_update past ttl", &ocspCacheEntry{thisUpdate: now.Add(-7 * time.Minute), cachedAt: now.Add(-6 * time.Minute), ttl: 5 * time.Minute}, false},
		{"no timestamps within ttl", &ocspCacheEntry{cachedAt: now, ttl: 5 * time.Minute}, true},
	}
	for _, tc := range cases {
		if got := responseFresh(tc.entry, now); got != tc.want {
			t.Errorf("%s: responseFresh = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestOCSPStatsAndFlush(t *testing.T) {
	c := NewOCSPCache(5*time.Minute, OCSPFallbackDeny, nil, "en")
	if g, r := c.Stats(); g != 0 || r != 0 {
		t.Fatalf("fresh cache Stats = (%d,%d), want (0,0)", g, r)
	}
	c.entries["good"] = &ocspCacheEntry{status: ocsp.Good}
	c.entries["revoked"] = &ocspCacheEntry{status: ocsp.Revoked}
	c.entries["unknown"] = &ocspCacheEntry{status: ocsp.Unknown}
	g, r := c.Stats()
	if g != 1 || r != 1 {
		t.Fatalf("Stats = (%d,%d), want (1,1) — only good/revoked count", g, r)
	}
	c.Flush()
	if g, r := c.Stats(); g != 0 || r != 0 {
		t.Fatalf("after Flush Stats = (%d,%d), want (0,0)", g, r)
	}
}

func TestOCSPCheckGoodAndCacheHit(t *testing.T) {
	ca := newTestRootCA(t)
	srv, resp := newOCSPResponder(t)

	_, leaf := mintCert(t, ca.cert, ca.key, "ocsp-leaf", big.NewInt(21), nil, nil,
		[]pkix.Extension{aiaExtension(t, srv.URL)})
	resp.set(ocspResponseDER(t, ca, leaf, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
	}))

	c := NewOCSPCache(5*time.Minute, OCSPFallbackDeny, nil, "en")
	if err := c.Check(leaf, ca.cert); err != nil {
		t.Fatalf("Check good response: %v", err)
	}
	if err := c.Check(leaf, ca.cert); err != nil {
		t.Fatalf("Check on cached entry: %v", err)
	}
	if got := resp.countHits(); got != 1 {
		t.Errorf("responder received %d requests, want 1 (second Check must be a cache hit)", got)
	}
	if g, r := c.Stats(); g != 1 || r != 0 {
		t.Errorf("Stats = (%d,%d), want (1,0)", g, r)
	}
}

func TestOCSPCheckStatuses(t *testing.T) {
	ca := newTestRootCA(t)
	goodSrv, goodResp := newOCSPResponder(t)

	statuses := []struct {
		name   string
		status int
		want   string
	}{
		{"revoked", ocsp.Revoked, "revoked"},
		{"unknown", ocsp.Unknown, "unknown"},
	}
	for _, st := range statuses {
		t.Run(st.name, func(t *testing.T) {
			_, leaf := mintCert(t, ca.cert, ca.key, st.name, big.NewInt(22), nil, nil,
				[]pkix.Extension{aiaExtension(t, goodSrv.URL)})
			var der []byte
			if st.status == ocsp.Revoked {
				der = ocspResponseDER(t, ca, leaf, ocsp.Response{
					Status:           ocsp.Revoked,
					SerialNumber:     leaf.SerialNumber,
					ThisUpdate:       time.Now().Add(-time.Minute),
					NextUpdate:       time.Now().Add(time.Hour),
					RevokedAt:        time.Now().Add(-5 * time.Minute),
					RevocationReason: 1,
				})
			} else {
				der = ocspResponseDER(t, ca, leaf, ocsp.Response{
					Status:       ocsp.Unknown,
					SerialNumber: leaf.SerialNumber,
					ThisUpdate:   time.Now().Add(-time.Minute),
					NextUpdate:   time.Now().Add(time.Hour),
				})
			}
			goodResp.set(der)
			c := NewOCSPCache(5*time.Minute, OCSPFallbackDeny, nil, "en")
			err := c.Check(leaf, ca.cert)
			if err == nil {
				t.Fatalf("expected an error for status %q", st.name)
			}
			if !strings.Contains(err.Error(), st.want) {
				t.Errorf("error = %q, want it to mention %q", err, st.want)
			}
		})
	}
}

func TestOCSPCheckUnreachableAndMissingIssuer(t *testing.T) {
	ca := newTestRootCA(t)

	// Unreachable responder.
	deadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := deadSrv.URL
	deadSrv.Close()
	_, unreachable := mintCert(t, ca.cert, ca.key, "ocsp-unreachable", big.NewInt(23), nil, nil,
		[]pkix.Extension{aiaExtension(t, deadURL)})
	c := NewOCSPCache(5*time.Minute, OCSPFallbackDeny, nil, "en")
	if err := c.Check(unreachable, ca.cert); err == nil {
		t.Fatal("Check must fail closed against an unreachable responder")
	}

	// Missing issuer (single-cert chain) must not panic; fails closed.
	liveSrv, resp := newOCSPResponder(t)
	_, leaf := mintCert(t, ca.cert, ca.key, "ocsp-no-issuer", big.NewInt(24), nil, nil,
		[]pkix.Extension{aiaExtension(t, liveSrv.URL)})
	resp.set(ocspResponseDER(t, ca, leaf, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
	}))
	if err := c.Check(leaf, nil); err == nil {
		t.Fatal("Check with a nil issuer must fail closed")
	}
}

func TestOCSPCRLFallback(t *testing.T) {
	ca := newTestRootCA(t)
	_, leaf := mintCert(t, ca.cert, ca.key, "crl-leaf", big.NewInt(31), nil, nil, nil) // no AIA

	c := NewOCSPCache(5*time.Minute, OCSPFallbackCRL, nil, "en")
	err := c.Check(leaf, ca.cert)
	if err == nil {
		t.Fatal("crl fallback with no checker must fail closed")
	}
	if !strings.Contains(err.Error(), "unconfigured") {
		t.Errorf("error = %q, want unconfigured-checker mention", err)
	}

	c.SetCRLChecker(func(caDN string, serial *big.Int) (bool, error) { return false, nil })
	if err := c.Check(leaf, ca.cert); err != nil {
		t.Fatalf("crl fallback with not-revoked CRL must admit: %v", err)
	}

	c.SetCRLChecker(func(caDN string, serial *big.Int) (bool, error) { return true, nil })
	if err := c.Check(leaf, ca.cert); err == nil || !strings.Contains(err.Error(), "revoked per CRL") {
		t.Fatalf("crl fallback must fail closed on revoked serial, got %v", err)
	}

	c.SetCRLChecker(func(caDN string, serial *big.Int) (bool, error) { return false, errors.New("crl db down") })
	if err := c.Check(leaf, ca.cert); err == nil || !strings.Contains(err.Error(), "failing closed") {
		t.Fatalf("crl fallback with CRL error must fail closed, got %v", err)
	}

	var nilCache *OCSPCache
	nilCache.SetCRLChecker(nil) // must not panic
}

func TestFetchOCSPResponseRaw(t *testing.T) {
	ca := newTestRootCA(t)
	srv, resp := newOCSPResponder(t)

	_, leaf := mintCert(t, ca.cert, ca.key, "ocsp-raw", big.NewInt(41), nil, nil,
		[]pkix.Extension{aiaExtension(t, srv.URL)})
	resp.set(ocspResponseDER(t, ca, leaf, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
	}))

	raw, err := FetchOCSPResponseRaw(leaf, ca.cert, srv.URL)
	if err != nil {
		t.Fatalf("FetchOCSPResponseRaw: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("raw OCSP response must be non-empty")
	}
	if got := resp.countHits(); got != 1 {
		t.Fatalf("handler hit count: %d, want 1", got)
	}

	deadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := deadSrv.URL
	deadSrv.Close()
	if _, err := FetchOCSPResponseRaw(leaf, ca.cert, deadURL); err == nil {
		t.Fatal("FetchOCSPResponseRaw must error on an unreachable responder")
	}
}

func TestStartOCSPStapling(t *testing.T) {
	ca := newTestRootCA(t)
	srv, resp := newOCSPResponder(t)

	leafKey, leaf := mintCert(t, ca.cert, ca.key, "stapled", big.NewInt(42), nil, nil,
		[]pkix.Extension{aiaExtension(t, srv.URL)})
	resp.set(ocspResponseDER(t, ca, leaf, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
	}))

	tlsCert := &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: leafKey, Leaf: leaf}
	cfg := &tls.Config{}
	stopCh := make(chan struct{})

	StartOCSPStapling(tlsCert, cfg, ca.pem, stopCh, fixedTranslator{}, "en")
	if cfg.GetCertificate == nil {
		t.Fatal("StartOCSPStapling must install the GetCertificate hook")
	}
	got, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if len(got.OCSPStaple) == 0 {
		t.Fatal("server certificate must carry the stapled OCSP response")
	}
	close(stopCh)

	// Early-return guards.
	StartOCSPStapling(nil, cfg, ca.pem, stopCh, nil, "")
	StartOCSPStapling(tlsCert, nil, ca.pem, stopCh, nil, "")
	StartOCSPStapling(&tls.Certificate{}, cfg, ca.pem, stopCh, nil, "")

	// No AIA on the leaf → disabled form.
	_, plainLeaf := mintCert(t, ca.cert, ca.key, "plain", big.NewInt(43), nil, nil, nil)
	plainTLS := &tls.Certificate{Certificate: [][]byte{plainLeaf.Raw}, PrivateKey: leafKey, Leaf: plainLeaf}
	plainCfg := &tls.Config{}
	StartOCSPStapling(plainTLS, plainCfg, ca.pem, stopCh, fixedTranslator{}, "en")
	if plainCfg.GetCertificate != nil {
		t.Fatal("a leaf without an OCSP URL must not install the stapling hook")
	}

	// Bad CA cert path → disabled form.
	badCACfg := &tls.Config{}
	StartOCSPStapling(tlsCert, badCACfg, "/nonexistent-ca.pem", stopCh, fixedTranslator{}, "en")
	if badCACfg.GetCertificate != nil {
		t.Fatal("an unreadable CA cert must disable stapling")
	}
}
