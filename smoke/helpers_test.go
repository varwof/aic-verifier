// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

//go:build smoke

// Package smoke is the aic-verifier CLC conformance and AIC admission smoke.
//
// It drives the normative CLC-v1 corpus (register vectors) through
// aic-verifier's exported CLC glue and its admission pipeline, and exercises
// the pipeline over real mTLS HTTP.  Run with:
//
//	go test -tags smoke -v -count=1 ./smoke/
//
// The corpus path defaults to
// ../../capability/data/_vectors/clc-v1/vectors.json and can be overridden
// with CLC_VECTORS.  Tests skip when the corpus is absent.
package smoke

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/register/semantics"
	pki "github.com/varwof/types"
)

// ---- corpus loading ------------------------------------------------------

type vector struct {
	ID          string               `json:"id"`
	Kind        string               `json:"kind"`
	SpecClause  string               `json:"spec_clause"`
	CLCRevision string               `json:"clc_revision"`
	Grant       *semantics.Grant     `json:"grant"`
	Request     *semantics.Operation `json:"request"`
	Others      []semantics.Grant    `json:"others"`
	Multi       bool                 `json:"multi,omitempty"`
	RawParams   string               `json:"raw_params,omitempty"`
	Principal   []string             `json:"principal,omitempty"`
	Requested   []string             `json:"requested,omitempty"`
	Expect      expectation          `json:"expect"`
	Derivation  string               `json:"derivation"`
}

type expectation struct {
	Verdict           string         `json:"verdict"`
	Reason            string         `json:"reason,omitempty"`
	Unresolved        []string       `json:"unresolved,omitempty"`
	ResultParams      map[string]any `json:"result_params,omitempty"`
	ResultConstraints []string       `json:"result_constraints,omitempty"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	path := os.Getenv("CLC_VECTORS")
	if path == "" {
		path = filepath.Join("..", "..", "capability", "data", "_vectors", "clc-v1", "vectors.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("CLC corpus not available at %s: %v", path, err)
	}
	var vectors []vector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse corpus %s: %v", path, err)
	}
	return vectors
}

// ---- CLC helpers ---------------------------------------------------------

// canonicalReason returns the stable reason code: everything before the first
// ':' (CLC-v1 §9.4; ": <detail>" is diagnostic).
func canonicalReason(s string) string {
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i]
	}
	return s
}

// rootReason unwraps a wrapped error to its innermost message and canonicalises
// it.  aic-verifier wraps CLC failures (e.g. `operation "x": <reason>`), so the
// normative code is the deepest layer, not the outermost.
func rootReason(err error) string {
	for {
		u := errors.Unwrap(err)
		if u == nil {
			return canonicalReason(err.Error())
		}
		err = u
	}
}

// capFromFullID splits a CLC full identifier (scheme:capability) at the first
// colon.  An identifier without a colon is kept whole so an invalid id is
// reported instead of silently reshaped.
func capFromFullID(full string) pki.Capability {
	if i := strings.IndexByte(full, ':'); i >= 0 {
		return pki.Capability{SchemeId: full[:i], CapabilityId: full[i+1:]}
	}
	return pki.Capability{CapabilityId: full}
}

// parseConstraintCap converts a CLC constraint string into a capability the
// same way the wire form does: scheme before the first colon, the type plus an
// optional JSON parameter suffix after it.  Constraint types contain colons
// (`time:window`), so the boundary is the JSON suffix, never a colon count.
func parseConstraintCap(s string) pki.Capability {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return pki.Capability{SchemeId: s}
	}
	scheme, rest := s[:i], s[i+1:]
	for j := 0; j < len(rest); j++ {
		if rest[j] != '[' && rest[j] != '{' {
			continue
		}
		if json.Valid([]byte(rest[j:])) {
			return pki.Capability{
				SchemeId:     scheme,
				CapabilityId: strings.TrimSuffix(rest[:j], ":"),
				Parameters:   []byte(rest[j:]),
			}
		}
	}
	return pki.Capability{SchemeId: scheme, CapabilityId: rest}
}

// ---- AIC certificate helpers ---------------------------------------------

type certAuthority struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pem  []byte
	pool *x509.CertPool
}

func newCA(t *testing.T, cn string) *certAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ca parse: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &certAuthority{key: key, cert: cert, pem: pemBytes, pool: pool}
}

// issueAIC mints a client certificate carrying an AIC.  The AIC uses a
// syntactically complete delegation authorization so ValidateAIC passes; the
// smoke does not exercise signature/chain verification (that is the transport's
// job) except where it explicitly configures it.  It returns the parsed leaf
// and a tls.Certificate ready for an mTLS client.
func (ca *certAuthority) issueAIC(t *testing.T, agentID string, caps, constraints []pki.Capability) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	aic := pki.AIC{
		Version: 1,
		AgentId: agentID,
		PrincipalUid: pki.PrincipalUid{
			Version:    1,
			Realm:      "pki",
			Identifier: "smoke@example.com",
			KeyHash:    make([]byte, sha256.Size),
			HashAlgo:   pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
		},
		Capabilities:             caps,
		AuthorizationConstraints: constraints,
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "SMOKE", Description: "CLC smoke"},
			RequestedLifetime:  3600,
			Timestamp:          time.Now().UTC(),
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     []byte{0x01},
		},
	}
	aicDER, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatalf("marshal aic: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: agentID, OrganizationalUnit: []string{"gateway:reader"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: pki.OIDAIC, Value: aicDER}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("leaf parse: %v", err)
	}
	return cert, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// writeTempPEM writes pem bytes to a temp file and returns its path.
func writeTempPEM(t *testing.T, name string, pemBytes []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// startMTLSServer starts an httptest TLS server that requires a client
// certificate trusted by ca and runs handler under mTLS.  It returns the base
// URL and a cleanup that keeps the temp files alive for the test duration.
func startMTLSServer(t *testing.T, ca *certAuthority, handler http.Handler) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  ca.pool,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}
