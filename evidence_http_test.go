// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// P0-2：HTTP 级 e2e。走真 mTLS（httptest.NewUnstartedServer + RequireAndVerifyClientCert）
// 覆盖机条证据路径：
//
//  1. 准入 → 200 → 落盘决策记录 → LoadEvidenceRecord 成功且可复算；
//  2. 语言层拒绝（参数超界）→ 403 → 仍落盘决策记录，verdict 一致；
//  3. 语言层之前的拒绝（RequireAIC 而客户端只有 PA）→ 403 → 落盘 AdmissionRecord，
//     stage/reason 正确、facts 含客户端证书 DER 摘要；
//  4. 证据关闭（Evidence == nil）→ 目录为空。
//
// 这些测试与 smoke 包重复的 CA 脚手架是刻意自带的：它们必须随默认
// `go test ./...` 跑，不能依赖 `-tags smoke`。

package aicverifier

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
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/varwof/register/semantics"
	pki "github.com/varwof/types"
)

// ---- HTTP e2e CA helpers ---------------------------------------------------

// httpCA is a minimal CA used by the HTTP evidence e2e tests.
type httpCA struct {
	cert *x509.Certificate
	pem  []byte
	pool *x509.CertPool
	key  *ecdsa.PrivateKey
}

func newHTTPTestCA(t *testing.T) *httpCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "evidence-e2e CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
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
	return &httpCA{key: key, cert: cert, pem: pemBytes, pool: pool}
}

func (ca *httpCA) writePEM(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, ca.pem, 0o600); err != nil {
		t.Fatalf("write CA PEM: %v", err)
	}
	return path
}

// issueAIC mints a client certificate carrying an AIC, signed by the CA.
func (ca *httpCA) issueAIC(t *testing.T, cn string, caps []pki.Capability) tls.Certificate {
	t.Helper()
	aic := &pki.AIC{
		Version: 1,
		AgentId: cn,
		PrincipalUid: pki.PrincipalUid{
			Version:    1,
			Realm:      "pki",
			Identifier: cn,
			KeyHash:    make([]byte, sha256.Size),
			HashAlgo:   pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
		},
		Capabilities: caps,
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "E2E", Description: "test"},
			RequestedLifetime:  3600,
			Timestamp:          time.Now().UTC(),
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     []byte{0x01},
		},
	}
	return ca.issueCert(t, cn, aic, nil)
}

// issuePAOnly mints a human-like client certificate carrying only a
// PrincipalAuthorization extension (no AIC), signed by the CA.
func (ca *httpCA) issuePAOnly(t *testing.T, cn string, grants []pki.Capability) tls.Certificate {
	t.Helper()
	paDER, err := asn1.Marshal(pki.PrincipalAuthorization{Version: 1, Grants: grants})
	if err != nil {
		t.Fatalf("marshal PA: %v", err)
	}
	return ca.issueCert(t, cn, nil, []pkix.Extension{{Id: pki.OIDPrincipalAuthorization, Value: paDER}})
}

func (ca *httpCA) issueCert(t *testing.T, cn string, aic *pki.AIC, extra []pkix.Extension) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	extras := append([]pkix.Extension{}, extra...)
	if aic != nil {
		aicDER, err := asn1.Marshal(*aic)
		if err != nil {
			t.Fatalf("marshal AIC: %v", err)
		}
		extras = append(extras, pkix.Extension{Id: pki.OIDAIC, Value: aicDER})
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       extras,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startMTLSEvidenceTest runs the handler under an httptest server that requires
// a CA-trusted client certificate, and returns its URL.
func startMTLSEvidenceTest(t *testing.T, ca *httpCA, handler http.Handler) string {
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

// doMTLSEvidenceTest performs a GET with the given client certificate.  The
// client trusts no server CA (the httptest certificate is ephemeral) but still
// presents its client certificate, which the server verifies against the CA.
func doMTLSEvidenceTest(t *testing.T, url string, client tls.Certificate) (*http.Response, string) {
	t.Helper()
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{client},
			MinVersion:         tls.VersionTLS12,
		}},
	}
	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(data)
}

// ---- P0-2 test cases -------------------------------------------------------

const e2eSelectCap = "std/database-v1:query:SELECT"

func okHandler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac := FromContext(r.Context())
		if ac == nil {
			http.Error(w, "no auth context", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agent":   ac.AgentID,
			"verdict": ac.Verdict,
		})
	})
}

// e2eConfig returns a Config reading the CA from caFile, requiring mTLS and an
// AIC, and (when ops is non-empty) running those operations through CLC.
func e2eConfig(caFile string, recDir string, ops []Operation, disabled bool) *Config {
	cfg := &Config{
		CACertFile: caFile,
		AuthMode:   MTLSOnly,
		RequireAIC: true,
	}
	if len(ops) > 0 {
		cfg.RequiredOperations = ops
	}
	if !disabled {
		cfg.Evidence = &EvidenceConfig{Sink: &FileSink{Dir: recDir, RecorderID: "pep-e2e"}, RecorderID: "pep-e2e"}
	}
	return cfg
}

func TestEvidenceHTTPAdmissionPath(t *testing.T) {
	ca := newHTTPTestCA(t)
	allowClient := ca.issueAIC(t, "agent-e2e",
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT", Parameters: []byte(`{"limit":10}`)}})

	recDir := t.TempDir()
	cfg := e2eConfig(ca.writePEM(t), recDir, []Operation{{ID: e2eSelectCap, Params: map[string]any{"limit": 5}}}, false)
	handler, err := cfg.Handler(okHandler(t))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	url := startMTLSEvidenceTest(t, ca, handler)

	resp, body := doMTLSEvidenceTest(t, url, allowClient)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if out["verdict"] != "allow" {
		t.Errorf("verdict = %v, want allow", out["verdict"])
	}

	// A decision record was written and loads back as re-computable.
	decisionPath, err := findRecordFile(t, recDir, false)
	if err != nil {
		t.Fatalf("decision record: %v", err)
	}
	rec, err := LoadEvidenceRecord(decisionPath)
	if err != nil {
		t.Fatalf("LoadEvidenceRecord: %v", err)
	}
	if rec.Verdict != "allow" {
		t.Errorf("record verdict = %q, want allow", rec.Verdict)
	}
}

func TestEvidenceHTTPLanguageDenyPath(t *testing.T) {
	ca := newHTTPTestCA(t)
	client := ca.issueAIC(t, "agent-e2e-deny",
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT", Parameters: []byte(`{"limit":10}`)}})

	recDir := t.TempDir()
	// limit 50 exceeds the grant's boundary of 10 → language-layer deny.
	cfg := e2eConfig(ca.writePEM(t), recDir, []Operation{{ID: e2eSelectCap, Params: map[string]any{"limit": 50}}}, false)
	handler, err := cfg.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	url := startMTLSEvidenceTest(t, ca, handler)

	resp, _ := doMTLSEvidenceTest(t, url, client)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	decisionPath, err := findRecordFile(t, recDir, false)
	if err != nil {
		t.Fatalf("decision record: %v", err)
	}
	rec, err := LoadEvidenceRecord(decisionPath)
	if err != nil {
		t.Fatalf("LoadEvidenceRecord: %v", err)
	}
	if rec.Verdict != "deny" {
		t.Errorf("record verdict = %q, want deny", rec.Verdict)
	}
}

func TestEvidenceHTTPPreLanguageDenyPath(t *testing.T) {
	ca := newHTTPTestCA(t)
	paOnly := ca.issuePAOnly(t, "person-e2e",
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"}})

	recDir := t.TempDir()
	// No RequiredOperations: the pipeline refuses on RequireAIC before CLC.
	cfg := e2eConfig(ca.writePEM(t), recDir, nil, false)
	handler, err := cfg.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	url := startMTLSEvidenceTest(t, ca, handler)

	resp, _ := doMTLSEvidenceTest(t, url, paOnly)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	admissionPath, err := findRecordFile(t, recDir, true)
	if err != nil {
		t.Fatalf("admission record: %v", err)
	}
	rec, err := ParseAdmissionEnvelope(mustEnvelope(t, admissionPath))
	if err != nil {
		t.Fatalf("ParseAdmissionEnvelope: %v", err)
	}
	if rec.Stage != ErrDenied.String() {
		t.Errorf("stage = %q, want %q", rec.Stage, ErrDenied.String())
	}
	if len(rec.Facts) == 0 || rec.Facts[0].Type != "client-cert" {
		t.Fatalf("facts = %+v, want the client certificate digest", rec.Facts)
	}
	want := sha256.Sum256(paOnly.Certificate[0])
	if !bytes.Equal(rec.Facts[0].Digest.Value, want[:]) {
		t.Error("client-cert fact is not the presented leaf digest")
	}
}

func TestEvidenceHTTPDisabledEmitsNothing(t *testing.T) {
	ca := newHTTPTestCA(t)
	allowClient := ca.issueAIC(t, "agent-e2e-off",
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"}})

	recDir := t.TempDir()
	cfg := e2eConfig(ca.writePEM(t), recDir, []Operation{{ID: e2eSelectCap, Params: map[string]any{"limit": 5}}}, true)
	handler, err := cfg.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	url := startMTLSEvidenceTest(t, ca, handler)

	resp, _ := doMTLSEvidenceTest(t, url, allowClient)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	entries, err := os.ReadDir(recDir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("evidence disabled must leave no files, got: %v", entries)
	}
}

// TestEvidenceRefusalMapsRetryBoundToHeaderAndBody: 需求未满足的证据拒绝若配置了
// ChallengeConfig.RetryAfter，挑战的 retry 下限必须同时落到 JSON 的
// retry_timing 与 HTTP 的 Retry-After 头（与残余义务路径一致，执业谱驱动重试节流）。
func TestEvidenceRefusalMapsRetryBoundToHeaderAndBody(t *testing.T) {
	ca := newHTTPTestCA(t)
	client := ca.issueAIC(t, "agent-e2e-retry",
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT", Parameters: []byte(`{"limit":10}`)}})

	var captured *AuthError
	cfg := &Config{
		CACertFile:          ca.writePEM(t),
		AuthMode:            MTLSOnly,
		RequireAIC:          true,
		EvidenceRequirement: wireRequirement(),
		EvidenceFacts:       func(*http.Request, *AuthContext) ([]semantics.EvidenceFact, error) { return nil, nil },
		Challenges: &ChallengeConfig{
			TTL:        5 * time.Minute,
			Audience:   "https://gateway-a.example",
			RetryAfter: 30 * time.Second,
			NewID:      func() string { return "ch_retry" },
			NewNonce:   func() string { return "nonce-0123456789" },
		},
		Hooks: &Hooks{Denied: func(_ *http.Request, ae *AuthError) { captured = ae }},
	}
	handler, err := cfg.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	url := startMTLSEvidenceTest(t, ca, handler)

	resp, body := doMTLSEvidenceTest(t, url, client)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	// HTTP 层：Retry-After 必须是挑战下限的秒数（30s 配置 → 30）。
	retryAfter, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || retryAfter <= 0 || retryAfter > 31 {
		t.Errorf("Retry-After = %q, want 1..31 (mapped from the 30s lower bound)", resp.Header.Get("Retry-After"))
	}
	if !strings.Contains(body, "retry_timing") {
		t.Errorf("problem body must carry retry_timing, got: %s", body)
	}

	// 结构化层：挑战的 Retry 下限为 UTC 的 now+30s。
	if captured == nil || captured.Problem == nil || captured.Problem.Challenge == nil {
		t.Fatal("the refusal must carry a challenge")
	}
	retry := captured.Problem.Challenge.Retry
	if retry == nil {
		t.Fatal("the evidence challenge must carry a retry lower bound")
	}
	if retry.NotBefore.Location() != time.UTC {
		t.Errorf("NotBefore location = %v, want UTC", retry.NotBefore.Location())
	}
	lo := time.Now().UTC().Add(29 * time.Second)
	hi := time.Now().UTC().Add(32 * time.Second)
	if retry.NotBefore.Before(lo) || retry.NotBefore.After(hi) {
		t.Errorf("NotBefore = %s, want now+30s (±2s)", retry.NotBefore.Format(time.RFC3339))
	}

	// 无 RequiredOperations 时，action_digest 必须绑定具体请求而非常量：
	// doMTLSEvidenceTest 发 GET /，挑战摘要应等于 "GET /" 的摘要。
	wantDigest := semantics.DigestOfCanonical([]byte("GET /"))
	if got := captured.Problem.Challenge.ActionDigest; got.Alg != wantDigest.Alg || !bytes.Equal(got.Value, wantDigest.Value) {
		t.Errorf("action_digest = %+v, want the request-bound digest for %q", got, "GET /")
	}
}
func findRecordFile(t *testing.T, dir string, admission bool) (string, error) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		isAdmission := strings.Contains(e.Name(), "admission-")
		if admission == isAdmission {
			return filepath.Join(dir, e.Name()), nil
		}
	}
	return "", os.ErrNotExist
}
