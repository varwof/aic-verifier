// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package superv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/varwof/aic-verifier"
)

func TestDemoApproverAllowsByDefault(t *testing.T) {
	a := &DemoApprover{}
	sr, err := a.Request(context.Background(), aicverifier.RiskAssessment{OperationID: "op-demo1"})
	if err != nil {
		t.Fatal(err)
	}
	if sr.Decision != "approved" || sr.Approver != Approver {
		t.Fatalf("default decision = %+v, want approved by %s", sr, Approver)
	}
	if want := "demo-ev-op-demo1"; sr.EvidenceRef != want {
		t.Fatalf("evidence_ref = %q, want %q", sr.EvidenceRef, want)
	}
}

func TestDemoApproverDeniesWhenFlagged(t *testing.T) {
	a := &DemoApprover{DenyRisk: true}
	sr, err := a.Request(context.Background(), aicverifier.RiskAssessment{OperationID: "op-demo2"})
	if err != nil {
		t.Fatal(err)
	}
	if sr.Decision != "denied" {
		t.Fatalf("decision = %q, want denied", sr.Decision)
	}
	if sr.EvidenceRef != "demo-ev-op-demo2" {
		t.Fatalf("evidence_ref = %q", sr.EvidenceRef)
	}
}

func TestWireBuildsComplianceConfig(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.jsonl")
	sup := filepath.Join(dir, "supervision.jsonl")

	conf := &aicverifier.Config{}
	if err := Wire(conf, Options{AuditLogFile: audit, SupervisionLog: sup}); err != nil {
		t.Fatal(err)
	}

	// Policy switches + code-injected interfaces must satisfy the startup
	// validations, so building the handler chain must succeed.
	if conf.ApprovalRequester == nil || conf.EvidenceExporter == nil || conf.SupervisionStore == nil {
		t.Fatalf("Wire left interfaces nil: %+v", conf.SupervisionPolicy)
	}
	if !conf.SupervisionPolicy.RequireRuntimeApproval || !conf.SupervisionPolicy.RequireEvidenceExport {
		t.Fatalf("policy = %+v, want runtime+export on", conf.SupervisionPolicy)
	}
	if _, err := conf.Handler(http.NotFoundHandler()); err != nil {
		t.Fatalf("handler build (startup validation) failed: %v", err)
	}
	if conf.SupervisionStore.File() != sup {
		t.Fatalf("store file = %q, want %q", conf.SupervisionStore.File(), sup)
	}
}

func TestWireRequireApprovalTriggersOnlyOnTransfer(t *testing.T) {
	conf := &aicverifier.Config{}
	if err := Wire(conf, Options{}); err != nil {
		t.Fatal(err)
	}
	ac := &aicverifier.AuthContext{}
	if !conf.RequireApproval(ac, httptest.NewRequest("GET", TransferPath, nil)) {
		t.Fatal("transfer request should require approval")
	}
}

func TestWireRequireApprovalIgnoresOtherPaths(t *testing.T) {
	conf := &aicverifier.Config{}
	if err := Wire(conf, Options{}); err != nil {
		t.Fatal(err)
	}
	ac := &aicverifier.AuthContext{}
	if conf.RequireApproval(ac, httptest.NewRequest("GET", "/api/read", nil)) {
		t.Fatal("non-transfer request must not require approval")
	}
}

func TestWireDenyRiskHooksDenyAuditPath(t *testing.T) {
	dir := t.TempDir()
	conf := &aicverifier.Config{}
	if err := Wire(conf, Options{DenyRisk: true, AuditLogFile: filepath.Join(dir, "audit.jsonl"), SupervisionLog: filepath.Join(dir, "supervision.jsonl")}); err != nil {
		t.Fatal(err)
	}
	sr, err := conf.ApprovalRequester.Request(context.Background(), aicverifier.RiskAssessment{OperationID: "op-risky"})
	if err != nil {
		t.Fatal(err)
	}
	if sr.Decision != "denied" {
		t.Fatalf("decision = %q, want denied under deny-risk", sr.Decision)
	}
}
