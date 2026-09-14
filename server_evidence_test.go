// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// P1-4 与 P1-5 之外的代理层测试：Server.deny 的后准入拒绝落 AdmissionRecord
// （一次一条、stage 可区分）；EvidenceConfig.EmitOutcome 让代理自动 ReportOutcome
// （200/5xx → observed，传输错误 → indeterminate，decisionDigest 指回裁决记录）；
// 需求未满足的拒绝携带 Satisfaction（P1-5）。

package aicverifier

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varwof/register/semantics"
	pki "github.com/varwof/types"
)

// serverCapClient returns a client certificate holding a capability different
// from the one the routes below demand, so it is admitted by the pipeline but
// refused by route-level capability checks.
func serverCapClient(t *testing.T, ca *httpCA) tls.Certificate {
	t.Helper()
	return ca.issueAIC(t, "agent-route-denied",
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:UPDATE", Parameters: []byte(`{"limit":10}`)}})
}

// TestServerRouteDenialLeavesRecord: 后准入的策略拒绝（无路由 / 缺路由能力）各自
// 落一条 AdmissionRecord，stage 可区分（404→route_denied，403→capability_denied）；
// 且当准入已经落了决策记录时，不再补第二条（一次拒绝一条记录）。
func TestServerRouteDenialLeavesRecord(t *testing.T) {
	ca := newHTTPTestCA(t)
	client := serverCapClient(t, ca)
	recDir := t.TempDir()

	cfg := &Config{
		CACertFile: ca.writePEM(t),
		AuthMode:   MTLSOnly,
		RequireAIC: true,
		Evidence: &EvidenceConfig{
			Sink:       &FileSink{Dir: recDir},
			RecorderID: "pep-rt",
		},
	}
	deadTarget, _ := url.Parse("http://127.0.0.1:1")
	s, err := NewServer(cfg, []Route{{
		Path:                 "/api",
		Target:               deadTarget,
		RequiredCapabilities: []string{"std/database-v1:query:SELECT"},
	}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	url := startMTLSEvidenceTest(t, ca, s.Handler())

	resp, _ := doMTLSEvidenceTest(t, url, client)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("no-route status = %d, want 404", resp.StatusCode)
	}
	resp, _ = doMTLSEvidenceTest(t, url+"/api", client)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing-capability status = %d, want 403", resp.StatusCode)
	}

	records := admissionRecordsOnDisk(t, recDir)
	if len(records) != 2 {
		t.Fatalf("got %d admission records, want 2 (route_denied + capability_denied)", len(records))
	}
	stages := map[string]bool{}
	reasons := map[string]string{}
	for path, rec := range records {
		stages[rec.Stage] = true
		reasons[rec.Stage] = rec.Reason
		if len(rec.Facts) == 0 || rec.Facts[0].Type != "client-cert" {
			t.Errorf("%s: refusal record should bind the client certificate", path)
		}
	}
	if !stages["route_denied"] || !stages["capability_denied"] {
		t.Errorf("stages = %v, want route_denied and capability_denied", stages)
	}
	if !strings.Contains(reasons["route_denied"], "no matching route") {
		t.Errorf("route_denied reason = %q", reasons["route_denied"])
	}
	if !strings.Contains(reasons["capability_denied"], "missing required capabilities") {
		t.Errorf("capability_denied reason = %q", reasons["capability_denied"])
	}
}

// TestServerRouteDenialRespectsSingleRecord: 准入已落决策记录时，随后的路由拒绝
// 只留那批决策记录，不再追加 AdmissionRecord。
func TestServerRouteDenialRespectsSingleRecord(t *testing.T) {
	ca := newHTTPTestCA(t)
	client := ca.issueAIC(t, "agent-route-dup",
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT", Parameters: []byte(`{"limit":10}`)}})
	recDir := t.TempDir()

	cfg := &Config{
		CACertFile: ca.writePEM(t),
		AuthMode:   MTLSOnly,
		RequireAIC: true,
		RequiredOperations: []Operation{
			{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": 5}},
		},
		Evidence: &EvidenceConfig{
			Sink:       &FileSink{Dir: recDir},
			RecorderID: "pep-rt2",
		},
	}
	deadTarget, _ := url.Parse("http://127.0.0.1:1")
	s, err := NewServer(cfg, []Route{{Path: "/api", Target: deadTarget}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	url := startMTLSEvidenceTest(t, ca, s.Handler())

	resp, _ := doMTLSEvidenceTest(t, url+"/nope", client)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}

	// Only decision records (RecorderID-<digest>.json): no "admission-".
	entries, err := os.ReadDir(recDir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var decisions, admissions int
	for _, e := range entries {
		switch {
		case strings.Contains(e.Name(), "admission-"):
			admissions++
		default:
			decisions++
		}
	}
	if decisions == 0 {
		t.Fatalf("expected a decision record, got none in %v", entries)
	}
	if admissions != 0 {
		t.Fatalf("one refusal one record: got %d admission records on top of the decision, files=%v", admissions, entries)
	}
}

// TestProxyEmitsOutcomeRecord: 200 与 5xx 各一条 outcome 记录
// （observed + status），decisionDigest 与准入决策记录一致。
func TestProxyEmitsOutcomeRecord(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/err") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	ca := newHTTPTestCA(t)
	client := ca.issueAIC(t, "agent-outcome",
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT", Parameters: []byte(`{"limit":10}`)}})
	recDir := t.TempDir()

	target, _ := url.Parse(backend.URL)
	cfg := &Config{
		CACertFile: ca.writePEM(t),
		AuthMode:   MTLSOnly,
		RequireAIC: true,
		RequiredOperations: []Operation{
			{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": 5}},
		},
		Evidence: &EvidenceConfig{
			Sink:        &FileSink{Dir: recDir},
			RecorderID:  "pep-out",
			EmitOutcome: true,
		},
	}
	s, err := NewServer(cfg, []Route{{Path: "/*", Target: target}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	url := startMTLSEvidenceTest(t, ca, s.Handler())

	if resp, _ := doMTLSEvidenceTest(t, url+"/ok", client); resp.StatusCode != http.StatusOK {
		t.Fatalf("/ok status = %d, want 200", resp.StatusCode)
	}
	if resp, _ := doMTLSEvidenceTest(t, url+"/err", client); resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("/err status = %d, want 500", resp.StatusCode)
	}

	// The admitted request froze a decision record; both outcomes must point at it.
	decisionDigest := decisionDigests(t, recDir)
	if len(decisionDigest) != 1 {
		t.Fatalf("expected one decision record, got %v", decisionDigest)
	}

	outcomes := outcomeRecordsOnDisk(t, recDir)
	if len(outcomes) != 2 {
		t.Fatalf("got %d outcome records, want 2", len(outcomes))
	}
	statuses := map[int]bool{}
	for path, rec := range outcomes {
		if rec.Outcome != OutcomeObserved {
			t.Errorf("%s: outcome = %q, want observed", path, rec.Outcome)
		}
		statuses[rec.StatusCode] = true
		if rec.DecisionDigest != decisionDigest[0] {
			t.Errorf("%s: decisionDigest %q does not point at the admission record %q", path, rec.DecisionDigest, decisionDigest[0])
		}
	}
	if !statuses[200] || !statuses[500] {
		t.Errorf("statuses = %v, want 200 and 500", statuses)
	}
}

// TestProxyEmitsIndeterminateOnTransportError: 后端连接失败 → outcome 报告
// indeterminate（不冒充 502 是后端的回答）。
func TestProxyEmitsIndeterminateOnTransportError(t *testing.T) {
	// A listener that is gone before the request goes out.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	deadTarget, _ := url.Parse(deadURL)

	ca := newHTTPTestCA(t)
	client := ca.issueAIC(t, "agent-outcome-ind",
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"}})
	recDir := t.TempDir()

	cfg := &Config{
		CACertFile: ca.writePEM(t),
		AuthMode:   MTLSOnly,
		RequireAIC: true,
		Evidence: &EvidenceConfig{
			Sink:        &FileSink{Dir: recDir},
			RecorderID:  "pep-out2",
			EmitOutcome: true,
		},
	}
	s, err := NewServer(cfg, []Route{{Path: "/*", Target: deadTarget}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	url := startMTLSEvidenceTest(t, ca, s.Handler())

	resp, _ := doMTLSEvidenceTest(t, url+"/dead", client)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}

	outcomes := outcomeRecordsOnDisk(t, recDir)
	if len(outcomes) != 1 {
		t.Fatalf("got %d outcome records, want 1", len(outcomes))
	}
	for path, rec := range outcomes {
		if rec.Outcome != OutcomeIndeterminate {
			t.Errorf("%s: outcome = %q, want indeterminate", path, rec.Outcome)
		}
	}
}

// TestRefusalCarriesSatisfaction: 需求未满足的拒绝携带机器可读的 Satisfaction
// （violated + MissingRoles），且与挑战的 required 对准。
func TestRefusalCarriesSatisfaction(t *testing.T) {
	ca := newHTTPTestCA(t)
	client := ca.issueAIC(t, "agent-sat",
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"}})

	var captured *AuthError
	cfg := &Config{
		CACertFile:          ca.writePEM(t),
		AuthMode:            MTLSOnly,
		RequireAIC:          true,
		EvidenceRequirement: wireRequirement(),
		EvidenceFacts: func(*http.Request, *AuthContext) ([]semantics.EvidenceFact, error) {
			return []semantics.EvidenceFact{
				fact("human-authorization", "alice", true),
				fact("human-authorization", "bob", true),
			}, nil
		},
		Challenges: &ChallengeConfig{TTL: 5 * 60_000_000_000, Audience: "https://gateway-a.example",
			NewID: func() string { return "ch_sat" }, NewNonce: func() string { return "nonce-0123456789" }},
		Hooks: &Hooks{Denied: func(_ *http.Request, ae *AuthError) { captured = ae }},
	}
	handler, err := cfg.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	url := startMTLSEvidenceTest(t, ca, handler)

	resp, _ := doMTLSEvidenceTest(t, url+"/", client)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if captured == nil {
		t.Fatal("the Denied hook did not receive the refusal")
	}

	sat := captured.Satisfaction
	if sat == nil {
		t.Fatal("the refusal must carry Satisfaction")
	}
	if sat.Verdict != semantics.EvidenceViolated {
		t.Errorf("Satisfaction.Verdict = %q, want violated", sat.Verdict)
	}
	wantMissing := []string{"policy-permit"}
	if !stringSetsEqual(sat.MissingRoles, wantMissing) {
		t.Errorf("MissingRoles = %v, want %v", sat.MissingRoles, wantMissing)
	}
	if captured.Problem == nil || captured.Problem.Challenge == nil || len(captured.Problem.Challenge.Required) == 0 {
		t.Fatal("the refusal must carry a challenge naming the missing item")
	}
	if captured.Problem.Challenge.Required[0].ID != "policy-permit" {
		t.Errorf("challenge required = %+v, want the missing role aligned with Satisfaction", captured.Problem.Challenge.Required)
	}
}

// TestProfileApplyTurnsOnOutcome: 全链 profile 把 EmitOutcome 置位（P1-4 的数据面开关）。
func TestProfileApplyTurnsOnOutcome(t *testing.T) {
	p, err := LookupEvidenceProfile("clc-decision+admission+outcome@1")
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	ev, err := p.Apply(&EvidenceConfig{})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !ev.EmitOutcome {
		t.Error("clc-decision+admission+outcome@1 must set EmitOutcome")
	}
	if p.Outcome != true {
		t.Error("profile must declare Outcome")
	}
}

// ---- test helpers ----------------------------------------------------------

// decisionDigests lists the input digests (hex) of the decision records on disk.
func decisionDigests(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "admission-") || strings.Contains(e.Name(), "outcome-") {
			continue
		}
		rec, err := LoadEvidenceRecord(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("load decision %s: %v", e.Name(), err)
		}
		out = append(out, hexOf(rec.InputDigest.Value))
	}
	return out
}

// admissionRecordsOnDisk returns the parsed admission records, keyed by file.
func admissionRecordsOnDisk(t *testing.T, dir string) map[string]AdmissionRecord {
	t.Helper()
	out := map[string]AdmissionRecord{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if !strings.Contains(e.Name(), "admission-") {
			continue
		}
		env := mustEnvelope(t, filepath.Join(dir, e.Name()))
		rec, err := ParseAdmissionEnvelope(env)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		out[e.Name()] = rec
	}
	return out
}

// outcomeRecordsOnDisk returns the parsed outcome records, keyed by file.
func outcomeRecordsOnDisk(t *testing.T, dir string) map[string]OutcomeRecord {
	t.Helper()
	out := map[string]OutcomeRecord{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if !strings.Contains(e.Name(), "outcome-") {
			continue
		}
		env := mustEnvelope(t, filepath.Join(dir, e.Name()))
		rec, err := ParseOutcomeEnvelope(env)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		out[e.Name()] = rec
	}
	return out
}

func stringSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		if !set[s] {
			return false
		}
	}
	return true
}
