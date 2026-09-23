// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// P1/G2：人类可读渲染。三种格式由同一组行派生，且表格/CSV 必须正确转义包含
// 逗号、引号、管道符或换行的值（来自审计行，可能是任意 caller 输入）。

package aicverifier

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func renderFixtureBundle() *EvidenceBundle {
	b := &EvidenceBundle{
		Manifest: EvidenceManifest{
			Schema:     evidenceSchema,
			Version:    evidenceVersion,
			BundleID:   "evidence-abc",
			ExportedAt: time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC),
			Generator:  "aic-verifier v0.2.0",
			HashAlg:    evidenceHashAlg,
		},
		Operation: EvidenceOperation{OperationID: "op-1", Action: "exec", Resource: "git", Outcome: "permit"},
		Subject:   EvidenceSubject{AgentID: "agent-001", KeyBinding: "sha256:aa"},
		Authorization: EvidenceAuthorization{
			Principal:      "alice",
			DelegationMode: "authorized",
			Capabilities:   []EvidenceCapability{{CapabilityID: "varwof/exec-v1:git:*"}},
		},
		Decision: EvidenceDecision{
			Decision:     "allow",
			RecordDigest: "digest-1",
			ReasonCodes:  []string{"ok"},
		},
		Supervision: []EvidenceSupervisionEvent{
			{Type: "approval", OccurredAt: "2026-09-23T09:59:00Z", Actor: "reviewer"},
		},
		AuditChain: EvidenceAuditChain{Anchor: "self", MerkleRoot: "sha256:root"},
		Signatures: map[string]json.RawMessage{"exporter-1": json.RawMessage(`{"keyid":"exporter-1","sig":"AAAA"}`)},
	}
	return b
}

func TestRenderTextIncludesSections(t *testing.T) {
	var buf bytes.Buffer
	if err := renderFixtureBundle().RenderText(&buf); err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Evidence bundle evidence-abc", "[manifest]", "[decision]", "[authorization]", "[auditChain]", "allow", "reviewer"} {
		if !strings.Contains(out, want) {
			t.Fatalf("text rendering missing %q:\n%s", want, out)
		}
	}
}

func TestRenderMarkdownHasTables(t *testing.T) {
	var buf bytes.Buffer
	if err := renderFixtureBundle().Render(&buf, RenderMarkdown); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "# Evidence bundle") {
		t.Fatalf("markdown must start with a heading:\n%s", out)
	}
	if !strings.Contains(out, "| field | value |") || !strings.Contains(out, "| --- | --- |") && !strings.Contains(out, "|---|---|") {
		t.Fatalf("markdown must carry a table header:\n%s", out)
	}
}

// TestRenderMarkdownEscapesPipes checks an audit-sourced value with a pipe does
// not break the table.
func TestRenderMarkdownEscapesPipes(t *testing.T) {
	b := renderFixtureBundle()
	b.Subject.AgentID = "evil|injected\nnewline"
	var buf bytes.Buffer
	if err := b.Render(&buf, RenderMarkdown); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "| evil|injected\nnewline |") {
		t.Fatalf("pipe/newline must be escaped in a markdown cell:\n%s", out)
	}
	if !strings.Contains(out, `evil\|injected newline`) {
		t.Fatalf("expected escaped cell, got:\n%s", out)
	}
}

// TestRenderCSVRoundTripsEmbeddedCommas checks encoding/csv quoting: a value
// with a comma or quote is parseable back to the original.
func TestRenderCSVRoundTripsEmbeddedCommas(t *testing.T) {
	b := renderFixtureBundle()
	b.Authorization.Principal = `Doe, "Jane"`
	var buf bytes.Buffer
	if err := b.RenderCSV(&buf); err != nil {
		t.Fatalf("RenderCSV: %v", err)
	}
	records, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("produced CSV does not parse: %v", err)
	}
	found := false
	for _, rec := range records {
		if len(rec) == 3 && rec[1] == "principal" && rec[2] == `Doe, "Jane"` {
			found = true
		}
	}
	if !found {
		t.Fatalf("principal with comma must round-trip through CSV:\n%s", buf.String())
	}
}

func TestRenderRejectsUnknownFormat(t *testing.T) {
	if err := renderFixtureBundle().Render(&bytes.Buffer{}, "xml"); err == nil {
		t.Fatal("an unknown format must be rejected")
	}
}

func TestWriteRenderedCreatesFile(t *testing.T) {
	path := t.TempDir() + "/bundle.md"
	if err := renderFixtureBundle().WriteRendered(path, RenderMarkdown); err != nil {
		t.Fatalf("WriteRendered: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "evidence-abc") {
		t.Fatalf("rendered file missing content:\n%s", data)
	}
}
