// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 拒绝路径的 HTTP 载体：403 + application/problem+json + Retry-After，
// 挑战本体由语义层构造（这里只做搬运与写出）。

package aicverifier

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/varwof/register/semantics"
)

const windowObligation = `varwof/constraint-v1:time:window:[{"start":"09:00","end":"18:00"}]`

func obligationResult() *PipelineResult {
	return &PipelineResult{
		Granted:    false,
		DenyReason: "operation std/database-v1:query:SELECT: allow_unresolved (unresolved [varwof/constraint-v1:time:...])",
		OperationDecisions: []OperationDecision{{
			ID:         "std/database-v1:query:SELECT",
			Verdict:    semantics.VerdictAllowUR,
			Unresolved: []string{windowObligation},
		}},
	}
}

func TestBuildChallengeForResult(t *testing.T) {
	cfg := &ChallengeConfig{
		TTL:        5 * time.Minute,
		Audience:   "https://gateway-a.example",
		RetryAfter: 30 * time.Second,
	}

	problem, err := problemForResult(obligationResult(), cfg, "why")
	if err != nil {
		t.Fatalf("problemForResult: %v", err)
	}
	if problem == nil || problem.Challenge == nil {
		t.Fatal("an unresolved-obligation denial must carry a challenge")
	}
	if problem.Type != ProblemTypeEvidenceRequired || problem.Status != http.StatusForbidden {
		t.Errorf("problem envelope = %+v", problem)
	}
	c := problem.Challenge
	if err := c.Validate(); err != nil {
		t.Fatalf("challenge does not validate: %v", err)
	}
	if c.Authorizes() {
		t.Error("a challenge must never authorize")
	}
	if len(c.Required) != 1 || c.Required[0].ID != "varwof/constraint-v1:time" {
		t.Fatalf("required = %+v, want the time obligation identity", c.Required)
	}
	if c.Retry == nil || !c.Retry.NotBefore.After(time.Now()) {
		t.Errorf("retry timing = %+v, want a future lower bound", c.Retry)
	}

	// A hard refusal has nothing to obtain, so it keeps the plain error.
	hard := &PipelineResult{
		Granted:    false,
		DenyReason: "missing capabilities: [std/database-v1:crm:read]",
		OperationDecisions: []OperationDecision{{
			ID:      "std/database-v1:query:SELECT",
			Verdict: semantics.VerdictDeny,
			Reason:  "capability_not_authorized",
		}},
	}
	problem, err = problemForResult(hard, cfg, hard.DenyReason)
	if err != nil {
		t.Fatalf("problemForResult: %v", err)
	}
	if problem != nil {
		t.Errorf("a hard denial must not be dressed up as retryable: %+v", problem)
	}

	// Disabled by default: no carrier config, no challenge.
	if problem, _ := problemForResult(obligationResult(), nil, "why"); problem != nil {
		t.Error("challenges must be opt-in")
	}

	// A released operation has already been confirmed, so there is nothing to ask for.
	released := obligationResult()
	released.OperationDecisions[0].Released = true
	if problem, _ := problemForResult(released, cfg, "why"); problem != nil {
		t.Error("a released operation must not produce a challenge")
	}
}

func TestProblemCarrierResponse(t *testing.T) {
	cfg := &ChallengeConfig{
		TTL:        5 * time.Minute,
		Audience:   "https://gateway-a.example",
		RetryAfter: 30 * time.Second,
		Now:        func() time.Time { return time.Now().UTC() },
		NewID:      func() string { return "ch_test" },
		NewNonce:   func() string { return "nonce-0123456789" },
	}
	problem, err := problemForResult(obligationResult(), cfg, "operation needs a confirmed time window")
	if err != nil {
		t.Fatalf("problemForResult: %v", err)
	}

	rec := httptest.NewRecorder()
	writeAuthError(rec, &AuthError{
		Code:    ErrDenied,
		Status:  http.StatusForbidden,
		Message: "denied",
		Problem: problem,
	}, nil)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != ProblemContentType {
		t.Errorf("content type = %q, want %q", ct, ProblemContentType)
	}
	retryAfter := rec.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("Retry-After missing (the challenge's lower bound must be mapped)")
	}
	if secs, err := strconv.Atoi(retryAfter); err != nil || secs <= 0 || secs > 30 {
		t.Errorf("Retry-After = %q, want 1..30", retryAfter)
	}

	var back ProblemDetails
	if err := json.Unmarshal(rec.Body.Bytes(), &back); err != nil {
		t.Fatalf("body is not problem+json: %v (%s)", err, rec.Body.String())
	}
	if back.Challenge == nil {
		t.Fatal("challenge missing from the problem document")
	}
	if err := back.Challenge.Validate(); err != nil {
		t.Fatalf("carried challenge does not validate: %v", err)
	}
	if back.Type != ProblemTypeEvidenceRequired {
		t.Errorf("problem type = %q", back.Type)
	}
}

// 自定义 carrier：响应形状由部署决定，但 Retry-After 仍由 SDK 设置。
func TestCustomChallengeCarrier(t *testing.T) {
	cfg := &ChallengeConfig{
		TTL:        5 * time.Minute,
		Audience:   "https://gateway-a.example",
		RetryAfter: 30 * time.Second,
		Now:        func() time.Time { return time.Now().UTC() },
		NewID:      func() string { return "ch_carrier" },
		NewNonce:   func() string { return "nonce-custom-0123" },
	}
	problem, err := problemForResult(obligationResult(), cfg, "operation needs a confirmed time window")
	if err != nil {
		t.Fatalf("problemForResult: %v", err)
	}
	carrier := &flipCarrier{}
	rec := httptest.NewRecorder()
	writeAuthError(rec, &AuthError{
		Code:    ErrDenied,
		Status:  http.StatusForbidden,
		Message: "denied",
		Problem: problem,
	}, &Config{ChallengeCarrier: carrier})

	if !carrier.called {
		t.Fatal("custom carrier was never called")
	}
	// Shape is the carrier's own, not application/problem+json.
	if ct := rec.Header().Get("Content-Type"); ct != "text/carrier-v1" {
		t.Errorf("content type = %q, want the carrier's text/carrier-v1", ct)
	}
	if strings.HasPrefix(rec.Body.String(), "{") {
		t.Errorf("custom carrier must not write problem+json, body = %q", rec.Body.String())
	}
	// The challenge's lower bound survives the carrier swap.
	retryAfter := rec.Header().Get("Retry-After")
	if secs, err := strconv.Atoi(retryAfter); err != nil || secs != 30 {
		t.Errorf("Retry-After = %q, want 30 (the carrier must not drop the bound)", retryAfter)
	}
}

// flipCarrier writes the challenge in a deployment-specific text shape.
type flipCarrier struct{ called bool }

func (c *flipCarrier) Write(w http.ResponseWriter, problem *ProblemDetails) error {
	c.called = true
	w.Header().Set("Content-Type", "text/carrier-v1")
	w.WriteHeader(problem.Status)
	_, err := fmt.Fprintf(w, "carrier: evidence required (action=%s)\n", hex.EncodeToString(problem.Challenge.ActionDigest.Value))
	return err
}

// 没有挑战时保持原样：仍是紧凑 JSON error，不改变既有客户端。
func TestPlainDenialKeepsCompactError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeAuthError(rec, &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: "missing capabilities"}, nil)

	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content type = %q", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if body["code"] != ErrDenied.String() || body["message"] != "missing capabilities" {
		t.Errorf("body = %v", body)
	}
	if rec.Header().Get("Retry-After") != "" {
		t.Error("a plain denial must not carry Retry-After")
	}
}
