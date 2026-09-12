// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

func writeAuditLine(t *testing.T, f *os.File, e AuditEntry) {
	t.Helper()
	b, err := json.Marshal(SignedAuditEntry{Entry: e})
	if err != nil {
		t.Fatalf("marshal audit entry: %v", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		t.Fatalf("write audit line: %v", err)
	}
}

func writeSupervisionLine(t *testing.T, f *os.File, ev pki.SupervisionEvent) {
	t.Helper()
	b, err := json.Marshal(SignedSupervisionEvent{Event: ev})
	if err != nil {
		t.Fatalf("marshal supervision event: %v", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		t.Fatalf("write supervision line: %v", err)
	}
}

func merkleHexOfLines(t *testing.T, lines [][]byte) string {
	t.Helper()
	leaves := make([][]byte, 0, len(lines))
	for _, raw := range lines {
		d := sha256.Sum256(raw)
		leaves = append(leaves, d[:])
	}
	root := NewMerkleTree(leaves).RootHex()
	if root == "" {
		return ""
	}
	return "sha256:" + root
}

func TestEvidenceExportMergesAuditAndSupervision(t *testing.T) {
	dir := t.TempDir()
	auditPath := dir + "/audit.jsonl"
	supPath := dir + "/supervision.jsonl"

	af, err := os.Create(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	ts := func(s string) time.Time {
		tm, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatalf("bad ts %q: %v", s, err)
		}
		return tm
	}

	first := AuditEntry{
		Time: "2026-09-08T10:00:00.000Z", Action: string(ActionConnected),
		SrcIP: "10.0.0.1", ClientCN: "agent-1", ClientSerial: "DEADBEEF",
		AgentId: "agent-1", PrincipalUid: "realm:owner",
		DelegationMode: int(DelegationAuthorized), DaHash: strings.Repeat("b", 64),
		AICFingerprint: strings.Repeat("c", 64), Mapping: "demo", Target: "/trade",
		Capabilities: []string{"api:read"}, Decision: "allow", Level: "INFO",
	}
	second := AuditEntry{
		Time: "2026-09-08T10:00:05.000Z", Action: string(ActionDenied),
		SrcIP: "10.0.0.1", ClientCN: "agent-1", ClientSerial: "DEADBEEF",
		AgentId: "agent-1", PrincipalUid: "realm:owner",
		DelegationMode: int(DelegationAuthorized), DaHash: strings.Repeat("b", 64),
		Mapping: "demo", Target: "/trade", DenyReason: "param-out-of-bound",
		Capabilities: []string{"api:read"}, Decision: "deny", Level: "WARN",
	}
	firstSeed := AuditEntry{Time: "2026-09-08T09:00:00Z", Action: "seed", Mapping: "m", Target: "other"}
	writeAuditLine(t, af, firstSeed)
	writeAuditLine(t, af, first)
	writeAuditLine(t, af, second)
	af.Close()

	sf, err := os.Create(supPath)
	if err != nil {
		t.Fatal(err)
	}
	writeSupervisionLine(t, sf, pki.SupervisionEvent{
		Type: pki.SupervisionApproval, Source: "aic-verifier", OperationID: "op-x", DaHash: strings.Repeat("b", 64),
		AgentID: "agent-1", Actor: "reviewer", Reason: "ok", Decision: pki.SupervisionDecisionApproved,
		Ts: ts("2026-09-08T10:00:06Z"),
	})
	writeSupervisionLine(t, sf, pki.SupervisionEvent{
		Type: pki.SupervisionBreakGlass, Source: "admin-console", OperationID: "op-y",
		AgentID: "agent-1", Actor: "admin", Reason: "break", Decision: pki.SupervisionDecisionApproved,
		Ts: ts("2026-09-08T10:00:07Z"),
	})
	sf.Close()

	exporter := NewFileEvidenceExporter(auditPath, supPath)
	exporter.Now = func() time.Time { return ts("2026-09-08T11:00:00Z") }

	bundle, err := exporter.Export(context.Background(), EvidenceQuery{
		AgentID:            "agent-1",
		IncludeSupervision: true,
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	if bundle.Manifest.Schema != evidenceSchema || bundle.Manifest.Version != evidenceVersion {
		t.Fatalf("unexpected manifest: %+v", bundle.Manifest)
	}
	if bundle.Manifest.BundleID == "" || !strings.HasPrefix(bundle.Manifest.BundleID, "evidence-") {
		t.Fatalf("unexpected bundle id %q", bundle.Manifest.BundleID)
	}
	if bundle.AuditChain.Anchor != "self" {
		t.Fatalf("expected self anchor, got %q", bundle.AuditChain.Anchor)
	}

	// AgentID filter drops the seeded entry, keeps the two agent-1 entries.
	if len(bundle.AuditChain.Entries) != 2 {
		t.Fatalf("want 2 audit entries, got %d", len(bundle.AuditChain.Entries))
	}
	if bundle.Operation.OperationID != "" {
		t.Fatalf("expected empty operation id, got %q", bundle.Operation.OperationID)
	}
	if bundle.Operation.Outcome != "deny" {
		t.Fatalf("final outcome should be deny, got %q", bundle.Operation.Outcome)
	}
	if bundle.Operation.Action != string(ActionConnected) {
		t.Fatalf("unexpected action %q", bundle.Operation.Action)
	}
	if bundle.Subject.AgentID != "agent-1" {
		t.Fatalf("unexpected subject %+v", bundle.Subject)
	}
	if bundle.Subject.KeyBinding != "sha256:"+strings.Repeat("c", 64) {
		t.Fatalf("unexpected keyBinding %q", bundle.Subject.KeyBinding)
	}
	if bundle.Authorization.GrantRef == nil || bundle.Authorization.GrantRef.Digest != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("unexpected grantRef %+v", bundle.Authorization.GrantRef)
	}
	if bundle.Authorization.DelegationMode != "authorized" {
		t.Fatalf("unexpected delegation mode %q", bundle.Authorization.DelegationMode)
	}
	if len(bundle.Authorization.Capabilities) != 1 || bundle.Authorization.Capabilities[0].CapabilityID != "api:read" {
		t.Fatalf("unexpected capabilities %+v", bundle.Authorization.Capabilities)
	}
	if bundle.Decision.Decision != "deny" {
		t.Fatalf("unexpected decision %+v", bundle.Decision)
	}
	if len(bundle.Decision.ReasonCodes) != 1 || bundle.Decision.ReasonCodes[0] != "param-out-of-bound" {
		t.Fatalf("unexpected reason codes %+v", bundle.Decision.ReasonCodes)
	}

	// PrevHash chaining.
	if bundle.AuditChain.Entries[0].PrevHash != "" {
		t.Fatalf("first entry prevHash must be empty, got %q", bundle.AuditChain.Entries[0].PrevHash)
	}
	if bundle.AuditChain.Entries[1].PrevHash != bundle.AuditChain.Entries[0].EntryHash {
		t.Fatalf("prevHash chain broken: %q != %q",
			bundle.AuditChain.Entries[1].PrevHash, bundle.AuditChain.Entries[0].EntryHash)
	}
	if bundle.AuditChain.Entries[0].Seq != 1 || bundle.AuditChain.Entries[1].Seq != 2 {
		t.Fatalf("unexpected seq: %+v", bundle.AuditChain.Entries)
	}

	// Merkle root over exported line digests.
	lines := readFileLines(t, auditPath)
	if len(lines) != 3 {
		t.Fatalf("want 3 audit lines, got %d", len(lines))
	}
	expectedRoot := merkleHexOfLines(t, lines[1:])
	if bundle.AuditChain.MerkleRoot != expectedRoot {
		t.Fatalf("merkle root mismatch: got %q want %q", bundle.AuditChain.MerkleRoot, expectedRoot)
	}

	// Supervision merged: type remapping for step_up/break_glass and the
	// approval entry.
	if len(bundle.Supervision) != 2 {
		t.Fatalf("want 2 supervision events, got %d", len(bundle.Supervision))
	}
	byType := map[string]EvidenceSupervisionEvent{}
	for _, s := range bundle.Supervision {
		byType[s.Type] = s
	}
	if ev, ok := byType["approval"]; !ok || ev.Actor != "reviewer" || ev.DecisionRef != "op-x" {
		t.Fatalf("unexpected approval supervision %+v", byType)
	}
	if ev, ok := byType["breakGlass"]; !ok || ev.Actor != "admin" {
		t.Fatalf("expected breakGlass remap, got %+v", byType)
	}
	if _, ok := byType["stepUp"]; ok {
		t.Fatalf("unexpected stepUp event: %+v", byType)
	}

	// Signatures empty, JSON canonical and deterministic.
	if len(bundle.Signatures) != 0 {
		t.Fatalf("signatures must be empty, got %+v", bundle.Signatures)
	}
	b1, err := bundle.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	b2, err := bundle.JSON()
	if err != nil {
		t.Fatalf("JSON again: %v", err)
	}
	if string(b1) != string(b2) {
		t.Fatal("canonical JSON not deterministic")
	}
	// Canonical output must already be compact (no structural whitespace).
	var compact bytes.Buffer
	if err := json.Compact(&compact, b1); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if compact.String() != string(b1) {
		t.Fatal("canonical JSON must not contain structural whitespace")
	}
	// The supervision array is present even when populated with entries.
	if !strings.Contains(string(b1), `"supervision":`) {
		t.Fatalf("missing supervision key in %s", b1)
	}
	// Re-parse with sorted-map semantics: Go map marshal sorts keys, so a
	// re-marshal of the decoded tree equals the canonical output.
	var tree map[string]any
	if err := json.Unmarshal(b1, &tree); err != nil {
		t.Fatalf("canonical JSON parse: %v", err)
	}
	re, err := CanonicalJSON(tree)
	if err != nil {
		t.Fatalf("re-canonicalize: %v", err)
	}
	re2, err := CanonicalJSON(bundle)
	if err != nil {
		t.Fatalf("re-canonicalize bundle: %v", err)
	}
	if string(re) != string(re2) {
		t.Fatal("canonical JSON not normalized across representations")
	}
}

func TestEvidenceExportWithoutSupervision(t *testing.T) {
	dir := t.TempDir()
	auditPath := dir + "/audit.jsonl"
	af, err := os.Create(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	writeAuditLine(t, af, AuditEntry{
		Time: "2026-09-08T10:00:00Z", Action: string(ActionConnected), SrcIP: "1.2.3.4",
		ClientCN: "agent-2", Mapping: "demo", Target: "/api", Level: "INFO",
	})
	af.Close()

	exporter := NewFileEvidenceExporter(auditPath, dir+"/missing-supervision.jsonl")
	bundle, err := exporter.Export(context.Background(), EvidenceQuery{IncludeSupervision: false})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if bundle.Supervision == nil || len(bundle.Supervision) != 0 {
		t.Fatalf("supervision must be an empty array, got %+v", bundle.Supervision)
	}

	// IncludeSupervision with a missing store file yields an empty array, not an
	// error.
	bundle2, err := exporter.Export(context.Background(), EvidenceQuery{IncludeSupervision: true})
	if err != nil {
		t.Fatalf("Export with IncludeSupervision: %v", err)
	}
	if bundle2.Supervision == nil || len(bundle2.Supervision) != 0 {
		t.Fatalf("missing supervision file should yield empty array, got %+v", bundle2.Supervision)
	}
}

func TestEvidenceExportErrorsOnMissingAudit(t *testing.T) {
	exporter := NewFileEvidenceExporter(t.TempDir()+"/none.jsonl", "")
	if _, err := exporter.Export(context.Background(), EvidenceQuery{}); err == nil {
		t.Fatal("expected error for missing audit file")
	}
}

func TestEvidenceQueryFilterByDaHash(t *testing.T) {
	dir := t.TempDir()
	auditPath := dir + "/audit.jsonl"
	af, err := os.Create(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	writeAuditLine(t, af, AuditEntry{Time: "2026-09-08T10:00:00Z", Action: "connected", SrcIP: "x",
		ClientCN: "agent-2", Mapping: "demo", Target: "/api", DaHash: strings.Repeat("d", 64), Level: "INFO"})
	writeAuditLine(t, af, AuditEntry{Time: "2026-09-08T10:00:01Z", Action: "connected", SrcIP: "x",
		ClientCN: "agent-3", Mapping: "demo", Target: "/other", DaHash: strings.Repeat("e", 64), Level: "INFO"})
	af.Close()

	exporter := NewFileEvidenceExporter(auditPath, "")
	bundle, err := exporter.Export(context.Background(), EvidenceQuery{DaHash: strings.Repeat("e", 64)})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(bundle.AuditChain.Entries) != 1 {
		t.Fatalf("want 1 filtered entry, got %d", len(bundle.AuditChain.Entries))
	}
	if bundle.Subject.AgentID != "agent-3" {
		t.Fatalf("expected agent-3 subject, got %+v", bundle.Subject)
	}
}

func readFileLines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, []byte(line))
	}
	return out
}

func TestCanonicalJSONSortedKeys(t *testing.T) {
	in := map[string]any{
		"z": 1,
		"a": map[string]any{
			"y": []any{3, 2},
			"x": json.RawMessage(`{"b":1,"a":2}`),
		},
	}
	b, err := CanonicalJSON(in)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	// Map keys are sorted by encoding/json. The embedded RawMessage must be
	// canonicalized so "a" sorts before "b" inside it.
	s := string(b)
	// Inner RawMessage keys must be re-sorted ("a" before "b").
	idxA := strings.Index(s, `"a":2`)
	idxB := strings.Index(s, `"b":1`)
	if idxA < 0 || idxB < 0 || idxA > idxB {
		t.Fatalf("inner raw message keys not re-sorted: %s", s)
	}
	if strings.Index(s, `"z"`) < strings.Index(s, `"a"`) {
		t.Fatalf("top-level keys not sorted: %s", s)
	}
}
