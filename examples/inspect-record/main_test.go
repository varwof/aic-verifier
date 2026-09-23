// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aicverifier "github.com/varwof/aic-verifier"
	"github.com/varwof/types/aicjwt"
)

// ── record production, mirroring examples/showcase: a Bearer AIC-JWT grant ──

const (
	testIssuer   = "https://issuer.inspect.example"
	testAudience = "https://data-api.inspect.example"
	testRealm    = "realm/demo"
	testScheme   = "std/database-v1"
	testOp       = testScheme + ":query:SELECT"
)

// testGrant mints a self-signed AIC-JWT issuing CA (the certificate whose SPKI
// hash becomes the token kid) and a fresh bearer token for the given grant.
func mintTestToken(t *testing.T, capID, grantParams string) (string, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano() % 1e9),
		Subject:               pkix.Name{CommonName: "inspect-record test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	kid, err := aicjwt.SPKIHash(cert, "sha-256")
	if err != nil {
		t.Fatalf("SPKIHash: %v", err)
	}
	jwk, err := aicjwt.PublicKeyToJWK(&key.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyToJWK: %v", err)
	}
	jkt, err := aicjwt.JWKThumbprint(jwk)
	if err != nil {
		t.Fatalf("JWKThumbprint: %v", err)
	}
	outer := &aicjwt.OuterClaims{
		Iss: testIssuer,
		Sub: testRealm + ":agent",
		Aud: aicjwt.Audience{testAudience},
		Iat: now.Unix(),
		Exp: now.Add(time.Hour).Unix(),
		Jti: fmt.Sprintf("t-%d", now.UnixNano()),
		Cnf: &aicjwt.Cnf{Jkt: jkt},
		Aic: &aicjwt.AICClaims{
			Ver:            1,
			Principal:      aicjwt.Principal{Realm: testRealm, ID: "agent", KeyHash: jkt, HashAlg: "sha-256"},
			DelegationMode: aicjwt.ModeAuthorized,
			Capabilities: []aicjwt.Capability{
				{Scheme: testScheme, ID: capID, Params: json.RawMessage(grantParams)},
			},
		},
	}
	hb, _ := json.Marshal(aicjwt.Header{Alg: "ES256", Typ: aicjwt.TypOuter, Kid: kid})
	pb, _ := json.Marshal(outer)
	tok, err := aicjwt.SignCompact(hb, pb, "ES256", key)
	if err != nil {
		t.Fatalf("SignCompact: %v", err)
	}
	return tok, key, cert
}

// emitDecisionRecord runs one admitted request through the SDK with an evidence
// sink and returns the path of the decision record file it wrote.
func emitDecisionRecord(t *testing.T, token string, jwtCA *x509.Certificate) string {
	t.Helper()
	dir := t.TempDir()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: jwtCA.Raw})
	caPath := filepath.Join(dir, "jwt-ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	evDir := filepath.Join(dir, "evidence")
	gateway := &aicverifier.Config{
		AuthMode:           aicverifier.BearerOnly,
		JWTCAFile:          caPath,
		JWTIssuer:          testIssuer,
		JWTAudience:        []string{testAudience},
		RequireAIC:         true,
		RequiredOperations: []aicverifier.Operation{{ID: testOp, Params: map[string]any{"limit": 5, "db": "*"}}},
		Evidence: &aicverifier.EvidenceConfig{
			Sink:       &aicverifier.FileSink{Dir: evDir, RecorderID: "inspect-record"},
			RecorderID: "inspect-record",
			TTL:        5 * time.Minute,
			Audience:   testAudience,
		},
	}
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac := aicverifier.FromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		if ac != nil {
			fmt.Fprintf(w, `{"served_to":%q}`, ac.AgentID)
		} else {
			fmt.Fprint(w, `{"served_to":"?"}`)
		}
	})
	handler, err := gateway.Handler(backend)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	// The pipeline requires a TLS transport for bearer tokens, so drive the
	// handler through a real TLS server.
	srv := httptest.NewTLSServer(handler)
	defer srv.Close()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/query", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	entries, err := os.ReadDir(evDir)
	if err != nil {
		t.Fatalf("evidence dir unreadable: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			return filepath.Join(evDir, e.Name())
		}
	}
	t.Fatalf("no decision record written in %s", evDir)
	return ""
}

func runWith(t *testing.T, args []string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRunRecord(t *testing.T) {
	tok, _, ca := mintTestToken(t, "query:SELECT", `{"limit":10,"db":"*"}`)
	path := emitDecisionRecord(t, tok, ca)

	code, out, errOut := runWith(t, []string{path})
	if code != 0 {
		t.Fatalf("run = %d, stderr=%s", code, errOut)
	}
	for _, want := range []string{"language", "operation", "verdict", "inputs", "recomputed"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRunRefusedRecordCarriesReason(t *testing.T) {
	// A grant that does not cover the required bounds is refused; the record
	// then carries a reason, exercising the reason-printing branch.
	tok, _, ca := mintTestToken(t, "query:SELECT", `{"limit":3,"db":"*"}`)
	path := emitDecisionRecord(t, tok, ca)

	code, out, errOut := runWith(t, []string{path})
	if code != 0 {
		t.Fatalf("run = %d, stderr=%s", code, errOut)
	}
	if !strings.Contains(out, "verdict") {
		t.Fatalf("no verdict printed:\n%s", out)
	}
}

func TestRunUsage(t *testing.T) {
	code, _, errOut := runWith(t, nil)
	if code != 2 || !strings.Contains(errOut, "usage: inspect-record") {
		t.Fatalf("no-arg run = %d (%s), want 2 + usage", code, errOut)
	}
	code, _, _ = runWith(t, []string{"a", "b"})
	if code != 2 {
		t.Fatalf("two-arg run = %d, want 2", code)
	}
}

func TestRunUnreadable(t *testing.T) {
	code, _, errOut := runWith(t, []string{filepath.Join(t.TempDir(), "missing.json")})
	if code != 1 || !strings.Contains(errOut, "inspect-record:") {
		t.Fatalf("missing file = %d (%s), want 1", code, errOut)
	}

	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = runWith(t, []string{bad})
	if code != 1 {
		t.Fatalf("malformed file = %d (%s), want 1", code, errOut)
	}

	// A structurally valid envelope whose verdict does not follow from its
	// inputs must also be rejected (that is the point of the re-load check).
	if err := os.WriteFile(bad, []byte(`{"payload":"AAAA","payloadType":"application/vnd.in-toto+json","signatures":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, _ = runWith(t, []string{bad})
	if code != 1 {
		t.Fatalf("unverifiable envelope = %d, want 1", code)
	}
}
