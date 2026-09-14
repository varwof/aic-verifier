// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// P2-6：审计与记录互相锚定。决策记一条审计(record_digest=refs[0].Digest)，
// 导出时按摘要从 EvidenceDir 自动取回信封 ApplyRecord；摘要取不回就是缺口，
// 必须报错而不是静默退化成“只有报告”的 bundle。

package aicverifier

import (
	"context"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	semantics "github.com/varwof/register/semantics"
	pki "github.com/varwof/types"
)

func TestAuditEntryCarriesRecordDigest(t *testing.T) {
	ca := newHTTPTestCA(t)
	allowClient := ca.issueAIC(t, "agent-e2e-anchor",
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT", Parameters: []byte(`{"limit":10}`)}})
	denyClient := ca.issueAIC(t, "agent-e2e-anchor-deny",
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT", Parameters: []byte(`{"limit":10}`)}})

	recDir := t.TempDir()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	audit, err := NewAuditLogger(auditPath, nil, 64<<20, 3)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}

	cfg := e2eConfig(ca.writePEM(t), recDir, []Operation{{ID: e2eSelectCap, Params: map[string]any{"limit": 5}}}, false)
	cfg.AuditLogger = audit
	handler, err := cfg.Handler(okHandler(t))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	url := startMTLSEvidenceTest(t, ca, handler)

	// Admitted request.
	resp, body := doMTLSEvidenceTest(t, url, allowClient)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admitted status = %d, body=%s", resp.StatusCode, body)
	}
	// Language-layer deny: limit 50 exceeds the grant boundary of 10.
	cfg2 := e2eConfig(ca.writePEM(t), recDir, []Operation{{ID: e2eSelectCap, Params: map[string]any{"limit": 50}}}, false)
	cfg2.AuditLogger = audit
	handler2, err := cfg2.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("handler2: %v", err)
	}
	url2 := startMTLSEvidenceTest(t, ca, handler2)
	resp2, _ := doMTLSEvidenceTest(t, url2, denyClient)
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("denied status = %d, want 403", resp2.StatusCode)
	}

	// The audit stream is flushed on Close; reuse the path afterwards.
	if err := audit.Close(); err != nil {
		t.Fatalf("audit close: %v", err)
	}

	decisionDigests := map[string]bool{}
	entries, err := os.ReadDir(recDir)
	if err != nil {
		t.Fatalf("read records dir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "admission-") || strings.Contains(e.Name(), "outcome-") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		decisionDigests[strings.TrimPrefix(name, "pep-e2e-")] = true
	}

	auditEntries, err := ReadAuditEntries(auditPath, AuditFilter{})
	if err != nil {
		t.Fatalf("ReadAuditEntries: %v", err)
	}
	if len(auditEntries) != 2 {
		t.Fatalf("audit entries = %d, want 2 (admitted + denied)", len(auditEntries))
	}
	var admitted, denied *AuditEntry
	for i := range auditEntries {
		switch auditEntries[i].Action {
		case string(ActionConnected):
			admitted = &auditEntries[i]
		case string(ActionDenied):
			denied = &auditEntries[i]
		}
	}
	if admitted == nil || denied == nil {
		t.Fatalf("want one connected and one denied entry, got: %+v", auditEntries)
	}
	if admitted.RecordDigest == "" {
		t.Error("admitted entry lacks record_digest")
	}
	if !decisionDigests[admitted.RecordDigest] {
		t.Errorf("admitted record_digest %q does not match any on-disk decision record", admitted.RecordDigest)
	}
	if admitted.Mapping != "GET" || admitted.Target != "/" {
		t.Errorf("admitted entry = %+v, want mapping=GET target=/", *admitted)
	}
	if denied.RecordDigest == "" || denied.DenyReason == "" {
		t.Errorf("denied entry = %+v, want record_digest and deny_reason", *denied)
	}
	if !decisionDigests[denied.RecordDigest] {
		t.Errorf("denied record_digest %q does not match any on-disk decision record", denied.RecordDigest)
	}
	if denied.RecordDigest == admitted.RecordDigest {
		t.Error("admitted and denied decisions must not share a record digest")
	}
}

func TestExporterResolvesRecordByDigest(t *testing.T) {
	ca := newHTTPTestCA(t)
	allowClient := ca.issueAIC(t, "agent-e2e-export",
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT", Parameters: []byte(`{"limit":10}`)}})

	recDir := t.TempDir()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	audit, err := NewAuditLogger(auditPath, nil, 64<<20, 3)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	cfg := e2eConfig(ca.writePEM(t), recDir, []Operation{{ID: e2eSelectCap, Params: map[string]any{"limit": 5}}}, false)
	cfg.AuditLogger = audit
	handler, err := cfg.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	url := startMTLSEvidenceTest(t, ca, handler)
	resp, body := doMTLSEvidenceTest(t, url, allowClient)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if err := audit.Close(); err != nil {
		t.Fatalf("audit close: %v", err)
	}
	decisionPath, err := findRecordFile(t, recDir, false)
	if err != nil {
		t.Fatalf("decision record: %v", err)
	}
	wantRec, err := LoadEvidenceRecord(decisionPath)
	if err != nil {
		t.Fatalf("LoadEvidenceRecord: %v", err)
	}
	wantDigest := hex.EncodeToString(wantRec.InputDigest.Value)

	exporter := &FileEvidenceExporter{AuditFile: auditPath, EvidenceDir: recDir}
	bundle, err := exporter.Export(context.Background(), EvidenceQuery{})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if bundle.Decision.Record == nil {
		t.Fatal("bundle decision carried no record after EvidenceDir resolution")
	}
	if bundle.Decision.RecordDigest != wantDigest {
		t.Errorf("RecordDigest = %q, want %q", bundle.Decision.RecordDigest, wantDigest)
	}
	if !hasSameInputDigest(bundle.Decision.Record, wantRec) {
		t.Error("resolved record is not the on-disk decision record")
	}
	if err := bundle.CheckDecisions(); err != nil {
		t.Errorf("CheckDecisions: %v", err)
	}

	// Negative: the anchor digest exists in the audit but the envelope file is
	// gone — a gap, not a silent report-only export.
	gapDir := t.TempDir()
	gapAF, err := os.Create(filepath.Join(gapDir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("create audit: %v", err)
	}
	writeAuditLine(t, gapAF, AuditEntry{
		Time:         "2026-09-08T10:00:00Z",
		Action:       "proxied",
		SrcIP:        "10.0.0.1",
		Mapping:      "GET",
		Target:       "/db",
		RecordDigest: wantDigest,
	})
	gapAF.Close()
	if _, err := (&FileEvidenceExporter{
		AuditFile:   gapAF.Name(),
		EvidenceDir: t.TempDir(),
	}).Export(context.Background(), EvidenceQuery{}); err == nil ||
		!strings.Contains(err.Error(), "evidence gap") {
		t.Errorf("missing record envelope must fail the export, got: %v", err)
	}

	// Negative: anchored but no EvidenceDir configured — refusing to export a
	// report-only bundle is the non-silent behavior.
	if _, err := (&FileEvidenceExporter{
		AuditFile: gapAF.Name(),
	}).Export(context.Background(), EvidenceQuery{}); err == nil ||
		!strings.Contains(err.Error(), "EvidenceDir") {
		t.Errorf("anchor without EvidenceDir must fail the export, got: %v", err)
	}
}

// hasSameInputDigest reports whether a and b freeze the same decision inputs.
func hasSameInputDigest(a, b *semantics.DecisionRecord) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return hex.EncodeToString(a.InputDigest.Value) == hex.EncodeToString(b.InputDigest.Value)
}

// TestAuditLoggerCloseIdempotent guards the double-close defect: a second
// Close must return nil instead of draining the closed channel forever (which
// spun and hammered the already-closed file).
func TestAuditLoggerCloseIdempotent(t *testing.T) {
	l, err := NewAuditLogger(filepath.Join(t.TempDir(), "audit.jsonl"), nil, 16<<20, 2)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	l.Log(AuditEntry{Action: "connected"})
	l.Log(AuditEntry{Action: string(ActionDenied), Level: "WARN"})
	if err := l.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	entries, err := ReadAuditEntries(l.File(), AuditFilter{})
	if err != nil {
		t.Fatalf("ReadAuditEntries: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("entries = %d, want 2 (drained before close)", len(entries))
	}
	if err := l.Close(); err != nil {
		t.Errorf("second Close must be a no-op, got: %v", err)
	}
}
