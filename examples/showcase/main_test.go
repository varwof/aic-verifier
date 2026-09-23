// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRun drives the whole end-to-end showcase. run() builds its own httptest
// TLS server and temp dirs, so a nil return already proves every admission,
// rejection, record-verification and forging step worked.
func TestRun(t *testing.T) {
	if err := run(); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestUseCABranches(t *testing.T) {
	tlClient := &http.Client{}
	if err := useCA(tlClient, filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("useCA with a missing file must fail")
	}
	badCA := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(badCA, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := useCA(tlClient, badCA); err == nil {
		t.Fatal("useCA with a non-PEM file must fail")
	}
	if tlClient.Transport != nil {
		t.Fatal("failed useCA must not leave a transport")
	}
}

func TestHelpersSmall(t *testing.T) {
	if got := orNone(""); got != "-" {
		t.Errorf("orNone(\"\") = %q", got)
	}
	if got := orNone("x"); got != "x" {
		t.Errorf("orNone(x) = %q", got)
	}
	if got := short("1234567890"); got != "1234567890" {
		t.Errorf("short(<=16) = %q", got)
	}
	long := strings.Repeat("a", 32)
	if got := short(long); got != long[:16]+"…" {
		t.Errorf("short(long) = %q", got)
	}
	if got := hex([]byte{0xde, 0xad}); got != "dead" {
		t.Errorf("hex = %q", got)
	}
	if got := trim([]byte("short")); got != "short" {
		t.Errorf("trim(short) = %q", got)
	}
	if got := trim([]byte(strings.Repeat("b", 100))); got != strings.Repeat("b", 80)+"…" {
		t.Errorf("trim(long) = %q", got)
	}
	if got, err := randToken(); err != nil || len(got) == 0 {
		t.Errorf("randToken = %q, %v", got, err)
	}
}

// fakeEnvelope builds a DSSE envelope the demo helpers parse.
func fakeEnvelope(t *testing.T, predicate map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(predicate)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.MarshalIndent(map[string]any{
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"payloadType": "application/vnd.in-toto+json",
		"signatures":  []any{},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(env)
}

func TestRecordsErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := records(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("records on a missing dir must fail")
	}
	// A directory whose name ends in .json is skipped, as are files that fail
	// to parse as envelopes or whose payload is not base64.
	if err := os.MkdirAll(filepath.Join(dir, "subdir.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "noise.json"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "badb64.json"), []byte(`{"payload":"%%%","payloadType":"application/vnd.in-toto+json"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "env.json"), []byte(fakeEnvelope(t, map[string]any{"predicateType": "some/other"})), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := records(dir); err == nil || !strings.Contains(err.Error(), "no decision record") {
		t.Fatalf("records(no decisions) err = %v", err)
	}
}

func TestOutcomeRecordErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := outcomeRecord(dir); err == nil || !strings.Contains(err.Error(), "no outcome record") {
		t.Fatalf("outcomeRecord(empty) err = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x.json"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := outcomeRecord(dir); err == nil {
		t.Fatal("outcomeRecord with only garbage must fail")
	}
	// A structurally valid outcome envelope is found.
	outcome := map[string]any{
		"predicateType": "https://varwof.com/aic/v1/outcome-record",
		"predicate":     map[string]any{"decisionDigest": ""},
	}
	if err := os.WriteFile(filepath.Join(dir, "outcome.json"), []byte(fakeEnvelope(t, outcome)), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := outcomeRecord(dir)
	if err != nil || !strings.HasSuffix(got, "outcome.json") {
		t.Fatalf("outcomeRecord = %q, %v", got, err)
	}
}

func TestRelinkOutcomeErrorBranches(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.json")
	dst := filepath.Join(dir, "dst.json")

	if err := relinkOutcome(filepath.Join(dir, "missing"), dst, "deadbeef"); err == nil {
		t.Fatal("missing src must fail")
	}
	if err := os.WriteFile(src, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := relinkOutcome(src, dst, "deadbeef"); err == nil {
		t.Fatal("malformed envelope must fail")
	}
	// payload is not a string.
	if err := os.WriteFile(src, []byte(`{"payload":42}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := relinkOutcome(src, dst, "deadbeef"); err == nil {
		t.Fatal("non-string payload must fail")
	}
	// payload is not base64.
	b64Env := fakeEnvelope(t, map[string]any{"predicate": map[string]any{"decisionDigest": "a"}})
	b64Env = strings.Replace(b64Env, `"`+base64.StdEncoding.EncodeToString(mustMarshal(t, map[string]any{"predicate": map[string]any{"decisionDigest": "a"}}))+`"`, `"%%%"`, 1)
	if err := os.WriteFile(src, []byte(b64Env), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := relinkOutcome(src, dst, "deadbeef"); err == nil {
		t.Fatal("non-base64 payload must fail")
	}
	// payload that is base64 but not JSON.
	if err := os.WriteFile(src, []byte(`{"payload":"`+base64.StdEncoding.EncodeToString([]byte("not json"))+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := relinkOutcome(src, dst, "deadbeef"); err == nil {
		t.Fatal("non-JSON payload must fail")
	}
	// payload without a predicate is refused.
	if err := os.WriteFile(src, []byte(fakeEnvelope(t, map[string]any{"predicate": "not an object"})), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := relinkOutcome(src, dst, "deadbeef"); err == nil || !strings.Contains(err.Error(), "no predicate") {
		t.Fatalf("no-predicate err = %v", err)
	}
	// Happy path rewrites the decisionDigest.
	if err := os.WriteFile(src, []byte(fakeEnvelope(t, map[string]any{"predicate": map[string]any{"decisionDigest": "old"}})), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := relinkOutcome(src, dst, "newdigest"); err != nil {
		t.Fatalf("relink happy path: %v", err)
	}
	out, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	var dec struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(out, &dec); err != nil {
		t.Fatalf("relinked file is not an envelope: %v: %s", err, out)
	}
	payload, err := base64.StdEncoding.DecodeString(dec.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), "newdigest") {
		t.Fatalf("relinked payload missing new digest: %s", payload)
	}
}

func TestForgeVerdictErrorBranches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rec.json")

	if err := forgeVerdict(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file must fail")
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := forgeVerdict(path); err == nil {
		t.Fatal("malformed envelope must fail")
	}
	// payload that is not base64, and payload that is base64 but not JSON.
	if err := os.WriteFile(path, []byte(`{"payload":"%%%","payloadType":"application/vnd.in-toto+json","signatures":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := forgeVerdict(path); err == nil {
		t.Fatal("non-base64 payload must fail")
	}
	if err := os.WriteFile(path, []byte(`{"payload":"`+base64.StdEncoding.EncodeToString([]byte("not json"))+`","payloadType":"application/vnd.in-toto+json","signatures":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := forgeVerdict(path); err == nil {
		t.Fatal("non-JSON payload must fail")
	}
	if err := os.WriteFile(path, []byte(fakeEnvelope(t, map[string]any{"predicate": "not an object"})), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := forgeVerdict(path); err == nil || !strings.Contains(err.Error(), "no predicate") {
		t.Fatalf("no-predicate err = %v", err)
	}
	// Happy path flips the verdict in place.
	if err := os.WriteFile(path, []byte(fakeEnvelope(t, map[string]any{
		"predicateType": "uri://varwof.at/decision",
		"predicate":     map[string]any{"verdict": "allow"},
	})), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := forgeVerdict(path); err != nil {
		t.Fatalf("forge happy path: %v", err)
	}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("forged file is not an envelope: %v: %s", err, out)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"deny"`) {
		t.Fatalf("forged verdict not written: %s", payload)
	}
}

// TestCallErrorBranches drives call() into its error branches: a bad CA file
// fails in useCA, a malformed URL fails in http.NewRequest, and a dead server
// fails on client.Do.
func TestCallErrorBranches(t *testing.T) {
	a, err := newAgent("wide")
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()

	badCA := filepath.Join(tmp, "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := call("https://localhost", badCA, a, `{"limit":10}`); err == nil {
		t.Fatal("call with a non-PEM CA must fail")
	}

	if err := call("http://\x7f bad host", badCA, a, `{"limit":10}`); err == nil {
		t.Fatal("call with a malformed URL must fail")
	}

	// A server whose CA we trust but that is already closed: the TLS dial
	// fails, reaching the client.Do error branch.
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	caFile := filepath.Join(tmp, "server-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	ts.Close()
	if err := call(ts.URL, caFile, a, `{"limit":10}`); err == nil {
		t.Fatal("call against a dead server must fail")
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
