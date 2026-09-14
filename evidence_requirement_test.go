// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 证据面接口：依赖方需求 + 呈递事实 → 三值评估；未满足即拒绝，并带机器可读挑战。

package aicverifier

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/varwof/register/semantics"
)

func wireRequirement() *semantics.Requirement {
	return &semantics.Requirement{
		Version:     semantics.RequirementVersion,
		ID:          "wire-release-evidence@7",
		Expression:  "human-authorization AND policy-permit",
		Constraints: []semantics.RequirementConstraint{{Role: "human-authorization", Constraint: "varwof/evidence-v1:quorum:distinct:2"}},
	}
}

func fact(role, subject string, verified bool) semantics.EvidenceFact {
	return semantics.EvidenceFact{Type: role, Subject: subject, IssuedAt: time.Now().UTC().Add(-time.Second), Verified: verified}
}

func TestCheckEvidenceRequirementSatisfied(t *testing.T) {
	a := &authenticator{cfg: &Config{
		EvidenceRequirement: wireRequirement(),
		EvidenceFacts: func(*http.Request, *AuthContext) ([]semantics.EvidenceFact, error) {
			return []semantics.EvidenceFact{
				fact("human-authorization", "alice", true),
				fact("human-authorization", "bob", true),
				fact("policy-permit", "policy-1", true),
			}, nil
		},
	}}
	ac := &AuthContext{}
	if err := a.checkEvidenceRequirement(nil, ac, &PipelineResult{}); err != nil {
		t.Fatalf("satisfied requirement must admit: %v", err)
	}
	if ac.Satisfaction == nil || !ac.Satisfaction.Satisfied() {
		t.Fatalf("satisfaction = %+v, want satisfied", ac.Satisfaction)
	}
}

func TestCheckEvidenceRequirementRefusesWithChallenge(t *testing.T) {
	a := &authenticator{cfg: &Config{
		EvidenceRequirement: wireRequirement(),
		EvidenceFacts: func(*http.Request, *AuthContext) ([]semantics.EvidenceFact, error) {
			// Two approvers, no permit → the expression is false.
			return []semantics.EvidenceFact{
				fact("human-authorization", "alice", true),
				fact("human-authorization", "bob", true),
			}, nil
		},
		Challenges: &ChallengeConfig{TTL: 5 * time.Minute, Audience: "https://gateway-a.example",
			NewID: func() string { return "ch_evidence" }, NewNonce: func() string { return "nonce-0123456789" }},
	}}
	ac := &AuthContext{}
	err := a.checkEvidenceRequirement(nil, ac, &PipelineResult{})
	if err == nil {
		t.Fatal("an unsatisfied requirement must refuse")
	}
	ae := asAuthError(err)
	if !strings.Contains(ae.Message, "missing roles") || !strings.Contains(ae.Message, "policy-permit") {
		t.Errorf("message %q should name the missing role", ae.Message)
	}
	if ae.Problem == nil || ae.Problem.Challenge == nil {
		t.Fatal("the refusal must carry a challenge")
	}
	if ae.Problem.Challenge.Authorizes() {
		t.Error("a challenge never authorizes")
	}
	if len(ae.Problem.Challenge.Required) == 0 || ae.Problem.Challenge.Required[0].ID != "policy-permit" {
		t.Errorf("challenge required = %+v, want the missing role", ae.Problem.Challenge.Required)
	}
}

// A constraint the core must not answer leaves the requirement unknown — and
// unknown is not admitted.
func TestCheckEvidenceRequirementUnknownIsFailClosed(t *testing.T) {
	req := wireRequirement()
	req.Expression = "human-authorization"
	req.Constraints = []semantics.RequirementConstraint{{Role: "human-authorization", Constraint: "varwof/evidence-v1:consumption:once"}}
	a := &authenticator{cfg: &Config{
		EvidenceRequirement: req,
		EvidenceFacts: func(*http.Request, *AuthContext) ([]semantics.EvidenceFact, error) {
			return []semantics.EvidenceFact{fact("human-authorization", "alice", true)}, nil
		},
	}}
	ac := &AuthContext{}
	err := a.checkEvidenceRequirement(nil, ac, &PipelineResult{})
	if err == nil {
		t.Fatal("unknown must fail closed")
	}
	if ac.Satisfaction == nil || ac.Satisfaction.Verdict != semantics.EvidenceUnknown {
		t.Errorf("satisfaction = %+v, want unknown", ac.Satisfaction)
	}
}

func TestCheckEvidenceRequirementFactErrorsFailClosed(t *testing.T) {
	a := &authenticator{cfg: &Config{
		EvidenceRequirement: wireRequirement(),
		EvidenceFacts: func(*http.Request, *AuthContext) ([]semantics.EvidenceFact, error) {
			return nil, errors.New("evidence store unreachable")
		},
	}}
	if err := a.checkEvidenceRequirement(nil, &AuthContext{}, &PipelineResult{}); err == nil {
		t.Fatal("a facts error must refuse")
	}
}

// No requirement configured → the evidence face is inactive (default minimum).
func TestCheckEvidenceRequirementDisabled(t *testing.T) {
	a := &authenticator{cfg: &Config{}}
	ac := &AuthContext{}
	if err := a.checkEvidenceRequirement(nil, ac, &PipelineResult{}); err != nil {
		t.Fatalf("no requirement must be a no-op: %v", err)
	}
	if ac.Satisfaction != nil {
		t.Error("no requirement means no satisfaction result")
	}
}

// 记录绑定需求摘要：有需求时记录里出现 requirement_digest。
func TestRecordBindsConfiguredRequirement(t *testing.T) {
	req := wireRequirement()
	cert := testAICCert(t, false)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))

	dir := t.TempDir()
	cfg := &EvidenceConfig{Sink: &FileSink{Dir: dir}, Requirement: req}
	refs, err := EmitDecisionRecords(cfg, EvidenceContext{Outcome: EvidenceAdmitted}, cert, res.AIC, res.PrincipalAuthorization, nil, res.OperationDecisions)
	if err != nil || len(refs) == 0 {
		t.Fatalf("emit: refs=%v err=%v", refs, err)
	}
	rec, err := LoadEvidenceRecord(refs[0].Path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if rec.Inputs.RequirementDigest == nil {
		t.Fatal("the record must bind the requirement digest")
	}
	want, err := req.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if !rec.Inputs.RequirementDigest.Equal(want) {
		t.Error("recorded requirement digest does not match the configured requirement")
	}
}
