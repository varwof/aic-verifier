// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

type stubRequester struct {
	result *SupervisionResult
	err    error
	called bool
	risk   RiskAssessment
}

func (s *stubRequester) Request(ctx context.Context, risk RiskAssessment) (*SupervisionResult, error) {
	s.called = true
	s.risk = risk
	return s.result, s.err
}

type stubRecorder struct {
	called bool
}

func (s *stubRecorder) Record(ctx context.Context, risk RiskAssessment, actor, reason string) (*SupervisionResult, error) {
	s.called = true
	return &SupervisionResult{Decision: SupervisionDecisionApproved, Approver: actor, Reason: reason, DecidedAt: time.Now().UTC()}, nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewSupervisionStoreNilForEmptyFile(t *testing.T) {
	s, err := NewSupervisionStore("", nil, 1<<20, 2)
	if err != nil {
		t.Fatalf("NewSupervisionStore: %v", err)
	}
	if s != nil {
		t.Fatalf("expected nil store for empty file, got %+v", s)
	}
}

func TestSupervisionStoreRecordQueryRoundTrip(t *testing.T) {
	store, err := NewSupervisionStore(t.TempDir()+"/events.jsonl", nil, 1<<20, 2)
	if err != nil {
		t.Fatalf("NewSupervisionStore: %v", err)
	}
	defer store.Close()

	ts := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	ev := &pki.SupervisionEvent{
		Type:        pki.SupervisionApproval,
		Source:      "aic-verifier",
		OperationID: "op-abc",
		DaHash:      strings.Repeat("a", 64),
		AgentID:     "agent-1",
		Actor:       "operator-a",
		Reason:      "approved",
		Decision:    pki.SupervisionDecisionApproved,
		Ts:          ts,
	}
	if err := store.Record(ev); err != nil {
		t.Fatalf("Record: %v", err)
	}

	got, err := store.Query(SupervisionQuery{OperationID: "op-abc"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d", len(got))
	}
	if got[0].Type != pki.SupervisionApproval || got[0].Actor != "operator-a" {
		t.Fatalf("unexpected event: %+v", got[0])
	}

	if err := store.Record(&pki.SupervisionEvent{
		Type: pki.SupervisionDenied, Source: "aic-verifier", OperationID: "op-xyz",
		Actor: "operator-b", Reason: "no", Decision: pki.SupervisionDecisionDenied, Ts: ts.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Record denied: %v", err)
	}
	all, err := store.Query(SupervisionQuery{})
	if err != nil {
		t.Fatalf("Query all: %v", err)
	}
	if len(all) != 2 || all[0].OperationID != "op-abc" || all[1].OperationID != "op-xyz" {
		t.Fatalf("unexpected order/results: %+v", all)
	}
	byType, err := store.Query(SupervisionQuery{Type: pki.SupervisionDenied})
	if err != nil {
		t.Fatalf("Query by type: %v", err)
	}
	if len(byType) != 1 || byType[0].OperationID != "op-xyz" {
		t.Fatalf("unexpected type filter: %+v", byType)
	}
	byDa, err := store.Query(SupervisionQuery{DaHash: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatalf("Query by da_hash: %v", err)
	}
	if len(byDa) != 1 || byDa[0].OperationID != "op-abc" {
		t.Fatalf("unexpected da_hash filter: %+v", byDa)
	}
	limited, err := store.Query(SupervisionQuery{Limit: 1})
	if err != nil {
		t.Fatalf("Query limited: %v", err)
	}
	if len(limited) != 1 || limited[0].OperationID != "op-abc" {
		t.Fatalf("unexpected limit result: %+v", limited)
	}
}

func TestSupervisionStoreRejectsInvalidAndNil(t *testing.T) {
	store, err := NewSupervisionStore(t.TempDir()+"/events.jsonl", nil, 1<<20, 2)
	if err != nil {
		t.Fatalf("NewSupervisionStore: %v", err)
	}
	defer store.Close()

	if err := store.Record(&pki.SupervisionEvent{}); err == nil {
		t.Fatal("expected validation error for empty event")
	}
	var nilStore *SupervisionStore
	if err := nilStore.Record(&pki.SupervisionEvent{}); err == nil {
		t.Fatal("expected error recording on nil store")
	}
	if _, err := nilStore.Query(SupervisionQuery{}); err == nil {
		t.Fatal("expected error querying nil store")
	}
}

func TestSupervisionStoreClosesAppendLock(t *testing.T) {
	store, err := NewSupervisionStore(t.TempDir()+"/events.jsonl", nil, 1<<20, 2)
	if err != nil {
		t.Fatalf("NewSupervisionStore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := store.Record(&pki.SupervisionEvent{
		Type: pki.SupervisionApproval, Source: "aic-verifier", Actor: "x",
		Decision: pki.SupervisionDecisionApproved, Ts: time.Now().UTC(),
	}); err == nil {
		t.Fatal("expected error recording on closed store")
	}
}

func TestSupervisionResultApproved(t *testing.T) {
	if !(&SupervisionResult{Decision: SupervisionDecisionApproved}).Approved() {
		t.Fatal("approved result should report approved")
	}
	if (&SupervisionResult{Decision: SupervisionDecisionDenied}).Approved() {
		t.Fatal("denied result must not report approved")
	}
	var nilResult *SupervisionResult
	if nilResult.Approved() {
		t.Fatal("nil result must not report approved")
	}
}

func TestNewSummaryFromBody(t *testing.T) {
	if NewSummaryFromBody(nil) != Summary("") {
		t.Fatal("empty body should yield empty summary")
	}
	s := NewSummaryFromBody([]byte(`{"amount":1000000}`))
	if !strings.HasPrefix(string(s), "sha256:") || !strings.Contains(string(s), "bytes:") {
		t.Fatalf("unexpected summary %q", s)
	}
}

func TestNewOperationIDUnique(t *testing.T) {
	id := newOperationID()
	if !strings.HasPrefix(id, "op-") || len(id) < 5 {
		t.Fatalf("unexpected operation id %q", id)
	}
	if newOperationID() == id {
		t.Fatal("operation ids must be unique")
	}
}

func TestApprovalPathFailClosed(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSupervisionStore(dir+"/events.jsonl", nil, 1<<20, 2)
	if err != nil {
		t.Fatalf("NewSupervisionStore: %v", err)
	}
	defer store.Close()

	mkRequest := func() *http.Request {
		return httptest.NewRequest(http.MethodPost, "/trade", strings.NewReader(`{"amount":999}`))
	}
	ac := &AuthContext{AgentID: "agent-1", Principal: "realm:owner"}

	cfg := &Config{
		SupervisionStore: store,
		RequireApproval:  func(ctx *AuthContext, r *http.Request) bool { return true },
	}
	a := &authenticator{cfg: cfg, log: testLogger()}

	// nil requester → fail closed deny(approval_required) + denied event.
	req := mkRequest()
	err = a.supervise(context.Background(), viewFromHTTP(nil, req), ac, nil)
	var ae *AuthError
	if !errors.As(err, &ae) || ae.Message != "approval_required" {
		t.Fatalf("want approval_required deny, got %v", err)
	}
	if evs := storeEvents(t, store); len(evs) != 1 || evs[0].Type != pki.SupervisionDenied {
		t.Fatalf("want one denied event, got %+v", evs)
	}

	// requester returned denied → fail closed + denied event.
	requester := &stubRequester{result: &SupervisionResult{
		Decision: pki.SupervisionDecisionDenied, Approver: "reviewer", Reason: "too risky", DecidedAt: time.Now().UTC(),
	}}
	cfg.ApprovalRequester = requester
	req = mkRequest()
	err = a.supervise(context.Background(), viewFromHTTP(nil, req), ac, nil)
	if !errors.As(err, &ae) || ae.Message != "approval_required" {
		t.Fatalf("want approval_required deny, got %v", err)
	}
	if !requester.called {
		t.Fatal("requester must be consulted")
	}
	if requester.risk.AgentID != "agent-1" || requester.risk.Operation != "POST /trade" {
		t.Fatalf("unexpected risk: %+v", requester.risk)
	}
	if requester.risk.PrincipalUid != "realm:owner" {
		t.Fatalf("principal not propagated: %+v", requester.risk)
	}
	if evs := storeEvents(t, store); len(evs) != 2 {
		t.Fatalf("want two denied events, got %+v", evs)
	}

	// requester approved → admitted + approval event.
	requester2 := &stubRequester{result: &SupervisionResult{
		Decision: pki.SupervisionDecisionApproved, Approver: "reviewer", Reason: "ok", DecidedAt: time.Now().UTC(),
	}}
	cfg.ApprovalRequester = requester2
	req = mkRequest()
	if err := a.supervise(context.Background(), viewFromHTTP(nil, req), ac, nil); err != nil {
		t.Fatalf("approved request should be admitted, got %v", err)
	}
	evs := storeEvents(t, store)
	if len(evs) != 3 || evs[2].Type != pki.SupervisionApproval || evs[2].Actor != "reviewer" {
		t.Fatalf("want approval event last, got %+v", evs)
	}

	// requester error → fail closed + denied event.
	requester3 := &stubRequester{err: errors.New("gateway down")}
	cfg.ApprovalRequester = requester3
	req = mkRequest()
	err = a.supervise(context.Background(), viewFromHTTP(nil, req), ac, nil)
	if !errors.As(err, &ae) || ae.Message != "approval_required" {
		t.Fatalf("want approval_required deny on error, got %v", err)
	}
	if evs := storeEvents(t, store); len(evs) != 4 {
		t.Fatalf("want four events total, got %+v", evs)
	}

	// RequireApproval==nil → no requester consultation, no events.
	cfg.RequireApproval = nil
	requester3.called = false
	if err := a.supervise(context.Background(), viewFromHTTP(nil, mkRequest()), ac, nil); err != nil {
		t.Fatalf("no hook should admit directly, got %v", err)
	}
	if requester3.called {
		t.Fatal("requester must not run when RequireApproval is nil")
	}
	if evs := storeEvents(t, store); len(evs) != 4 {
		t.Fatalf("no new events expected, got %d", len(evs))
	}
}

func storeEvents(t *testing.T, store *SupervisionStore) []pki.SupervisionEvent {
	t.Helper()
	evs, err := store.Query(SupervisionQuery{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	return evs
}

func TestStartupValidationSupervision(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{
			name: "require_runtime_approval_without_requester",
			cfg: Config{
				SupervisionPolicy: SupervisionPolicy{RequireRuntimeApproval: true},
			},
		},
		{
			name: "allow_break_glass_without_recorder",
			cfg: Config{
				SupervisionPolicy: SupervisionPolicy{AllowBreakGlass: true},
			},
		},
		{
			name: "require_evidence_export_without_exporter",
			cfg: Config{
				SupervisionPolicy: SupervisionPolicy{RequireEvidenceExport: true},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newAuthenticator(&tc.cfg)
			if err == nil {
				t.Fatal("expected startup validation error")
			}
		})
	}

	// Safe combos pass.
	ok, err := newAuthenticator(&Config{
		ApprovalRequester: nil,
		SupervisionPolicy: SupervisionPolicy{RequireRuntimeApproval: false},
	})
	if err != nil {
		t.Fatalf("zero supervision policy should validate: %v", err)
	}
	if ok == nil {
		t.Fatal("expected non-nil authenticator")
	}
}

func TestSupervisionEventJSON(t *testing.T) {
	ev := pki.SupervisionEvent{
		Type: pki.SupervisionConsent, Source: "user-signer", OperationID: "op-1",
		Actor: "owner", Reason: "consent", Decision: pki.SupervisionDecisionApproved,
		Ts: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
	}
	b, err := json.Marshal(&ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, want := range []string{`"type":"consent"`, `"operation_id":"op-1"`, `"decision":"approved"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in %s", want, s)
		}
	}
}
