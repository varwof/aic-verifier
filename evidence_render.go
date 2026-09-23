// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 人类可读渲染：把 EvidenceBundle 变成「可直接下载/打印」的成品。
//
// 合规条文关心的是「能不能方便地下载和打印」证据本身（SEC 17a-4(f)(2)(iv) 的
// 可读性要求），而一个规范化的 JSON 包对审计员、法务、临床治理委员会都不是可读
// 材料。这一层提供三种渲染：Markdown（人看）、CSV（表格/取证工具吞）、text（纯文本，
// 便于贴进工单或终端）。三者都由同一组行派生，所以它们永远描述同一份数据。
//
// 渲染只做展示，不改变任何判定：bundle 里的裁决仍以 Decision.Record 为准。

package aicverifier

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
)

// RenderFormat selects a human-readable rendering of an evidence bundle.
type RenderFormat string

const (
	// RenderMarkdown is a sectioned, printable Markdown document.
	RenderMarkdown RenderFormat = "markdown"
	// RenderCSV is a flat section,field,value table for spreadsheets and
	// forensic tooling.
	RenderCSV RenderFormat = "csv"
	// RenderText is a plain-text rendering for tickets and terminals.
	RenderText RenderFormat = "text"
)

// Render writes the bundle in the requested human-readable format (the empty
// format defaults to Markdown).  It is a presentation view: the JSON bundle
// remains the canonical, verifiable artifact.
func (b *EvidenceBundle) Render(w io.Writer, format RenderFormat) error {
	switch format {
	case "", RenderMarkdown:
		return b.RenderMarkdown(w)
	case RenderCSV:
		return b.RenderCSV(w)
	case RenderText:
		return b.RenderText(w)
	default:
		return fmt.Errorf("evidence_bundle: unknown render format %q", format)
	}
}

// WriteRendered renders the bundle to a file, creating it with 0600 (evidence
// is not world-readable).  It is the "download to a path an auditor can open"
// entry point.
func (b *EvidenceBundle) WriteRendered(path string, format RenderFormat) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := b.Render(f, format); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// bundleRow is one section/field/value line, the common shape every renderer
// consumes so the three formats never disagree.
type bundleRow struct {
	section string
	field   string
	value   string
}

// bundleRows flattens the bundle into ordered rows.  Empty optional fields are
// omitted, so a sparse bundle stays readable instead of a wall of blanks.
func bundleRows(b *EvidenceBundle) []bundleRow {
	if b == nil {
		return nil
	}
	var rows []bundleRow
	add := func(section, field, value string) {
		if value == "" {
			return
		}
		rows = append(rows, bundleRow{section: section, field: field, value: value})
	}

	m := b.Manifest
	add("manifest", "schema", m.Schema+" "+m.Version)
	add("manifest", "bundleId", m.BundleID)
	add("manifest", "exportedAt", m.ExportedAt.UTC().Format("2006-01-02T15:04:05Z"))
	add("manifest", "generator", m.Generator)
	add("manifest", "hashAlg", m.HashAlg)
	add("manifest", "policyRef", m.PolicyRef)

	op := b.Operation
	add("operation", "operationId", op.OperationID)
	add("operation", "action", op.Action)
	add("operation", "resource", op.Resource)
	add("operation", "outcome", op.Outcome)
	add("operation", "startedAt", op.StartedAt)
	add("operation", "finishedAt", op.FinishedAt)

	sub := b.Subject
	add("subject", "agentId", sub.AgentID)
	add("subject", "keyBinding", sub.KeyBinding)
	add("subject", "transportIdentity", sub.TransportIdentity)
	add("subject", "presentedCredentialRef", sub.PresentedCredentialRef)

	a := b.Authorization
	add("authorization", "principal", a.Principal)
	add("authorization", "delegationMode", a.DelegationMode)
	if a.GrantRef != nil {
		add("authorization", "grantRef.ref", a.GrantRef.Ref)
		add("authorization", "grantRef.digest", a.GrantRef.Digest)
	}
	if len(a.Capabilities) > 0 {
		caps := make([]string, 0, len(a.Capabilities))
		for _, c := range a.Capabilities {
			caps = append(caps, c.CapabilityID)
		}
		add("authorization", "capabilities", strings.Join(caps, " "))
	}
	add("authorization", "constraints", a.Constraints)
	add("authorization", "ceiling", a.Ceiling)
	add("authorization", "validFrom", a.ValidFrom)
	add("authorization", "expiresAt", a.ExpiresAt)

	d := b.Decision
	add("decision", "decision", d.Decision)
	add("decision", "recordDigest", d.RecordDigest)
	add("decision", "matchedPolicy", d.MatchedPolicy)
	add("decision", "reasonCodes", strings.Join(d.ReasonCodes, " "))
	add("decision", "evaluatedCapabilities", strings.Join(d.EvaluatedCapabilities, " "))
	add("decision", "pdpContext", d.PdpContext)

	for i, s := range b.Supervision {
		add("supervision", fmt.Sprintf("%d.%s", i+1, s.Type),
			strings.TrimSpace(s.OccurredAt+" "+s.Actor))
	}

	add("auditChain", "anchor", b.AuditChain.Anchor)
	add("auditChain", "merkleRoot", b.AuditChain.MerkleRoot)
	add("auditChain", "tsa", b.AuditChain.TSA)
	for _, ent := range b.AuditChain.Entries {
		add("auditChain", fmt.Sprintf("entry[%d]", ent.Seq),
			fmt.Sprintf("%s %s %s %s", ent.Action, ent.Actor, ent.Ts, ent.EntryHash))
	}

	for keyID := range b.Signatures {
		add("signature", "keyID", keyID)
	}
	return rows
}

// RenderCSV writes a flat section,field,value table.  encoding/csv handles
// quoting, so a value with commas, quotes or newlines (actor names, paths) is
// emitted correctly for spreadsheets and forensic importers.
func (b *EvidenceBundle) RenderCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"section", "field", "value"}); err != nil {
		return err
	}
	for _, r := range bundleRows(b) {
		if err := cw.Write([]string{r.section, r.field, r.value}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// RenderText writes a plain-text rendering grouped by section.
func (b *EvidenceBundle) RenderText(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "Evidence bundle %s\n\n", b.Manifest.BundleID); err != nil {
		return err
	}
	section := ""
	for _, r := range bundleRows(b) {
		if r.section != section {
			section = r.section
			if _, err := fmt.Fprintf(w, "[%s]\n", section); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "  %s: %s\n", r.field, r.value); err != nil {
			return err
		}
	}
	return nil
}

// RenderMarkdown writes a sectioned Markdown document with one table per
// section.  Cell values are escaped so an actor name or path containing a pipe
// or newline cannot break — or inject into — the table.
func (b *EvidenceBundle) RenderMarkdown(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "# Evidence bundle `%s`\n\n", mdCell(b.Manifest.BundleID)); err != nil {
		return err
	}
	section := ""
	open := false
	for _, r := range bundleRows(b) {
		if r.section != section {
			if open {
				if err := writeMarkdownClose(w); err != nil {
					return err
				}
			}
			section = r.section
			if _, err := fmt.Fprintf(w, "## %s\n\n| field | value |\n|---|---|\n", mdCell(section)); err != nil {
				return err
			}
			open = true
		}
		if _, err := fmt.Fprintf(w, "| %s | %s |\n", mdCell(r.field), mdCell(r.value)); err != nil {
			return err
		}
	}
	if open {
		if err := writeMarkdownClose(w); err != nil {
			return err
		}
	}
	return nil
}

func writeMarkdownClose(w io.Writer) error {
	_, err := io.WriteString(w, "\n")
	return err
}

// mdCell neutralises table-breaking characters in a Markdown cell: pipes are
// escaped and newlines collapsed to spaces.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "|", `\|`)
	return s
}
