// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 两套证据格式的合并：bundle 的裁决段**引用** CLC 记录并由它派生摘要；
// 摘要与记录相互矛盾时，bundle 不是证据。

package aicverifier

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/register/semantics"
)

func testRecordWithObligation(t *testing.T) semantics.DecisionRecord {
	t.Helper()
	rec, err := semantics.RecordWith(
		[]semantics.Grant{{ID: sqlQueryCap, Constraints: []string{
			`varwof/constraint-v1:time:window:[{"start":"09:00","end":"18:00"}]`}}},
		semantics.Operation{ID: sqlQueryCap},
		semantics.RecordOptions{Context: &semantics.DecisionContext{At: time.Now().UTC().Truncate(time.Second), MaxAgeSec: 60}},
	)
	if err != nil {
		t.Fatalf("RecordWith: %v", err)
	}
	return rec
}

func TestEvidenceDecisionDerivesFromRecord(t *testing.T) {
	rec := testRecordWithObligation(t)
	if rec.Verdict != semantics.VerdictAllowUR {
		t.Fatalf("setup: verdict = %q", rec.Verdict)
	}

	var d EvidenceDecision
	d.Decision = "allow" // a stale summary the audit text might have said
	if err := d.ApplyRecord(&rec); err != nil {
		t.Fatalf("ApplyRecord: %v", err)
	}
	if d.Decision != semantics.VerdictAllowUR {
		t.Errorf("decision = %q, want it derived from the record", d.Decision)
	}
	if d.RecordDigest == "" || d.Record == nil {
		t.Fatal("record and digest must be carried")
	}
	if len(d.ReasonCodes) == 0 || d.ReasonCodes[0] != "unresolved:varwof/constraint-v1:time:window:[{\"start\":\"09:00\",\"end\":\"18:00\"}]" {
		t.Errorf("reason codes = %v, want the residual obligation carried", d.ReasonCodes)
	}

	b := &EvidenceBundle{Decision: d}
	if err := b.CheckDecisions(); err != nil {
		t.Fatalf("consistent bundle: %v", err)
	}

	// A summary that contradicts its record is not evidence.
	bad := *b
	bad.Decision.Decision = "allow"
	if err := bad.CheckDecisions(); err == nil {
		t.Error("a bundle whose decision contradicts its record must be refused")
	}

	// A digest that does not name the record is refused too.
	badDigest := *b
	badDigest.Decision.RecordDigest = "00"
	if err := badDigest.CheckDecisions(); err == nil {
		t.Error("a record digest that does not match the record must be refused")
	}

	// So is a record that does not reproduce.
	tampered := rec
	tampered.Verdict = semantics.VerdictAllow
	badRecord := *b
	badRecord.Decision.Record = &tampered
	if err := badRecord.CheckDecisions(); err == nil {
		t.Error("a record that does not reproduce must be refused")
	}
}

// The bridge from the emission side: a FileSink file loads back as a verified
// record that a bundle can then carry.
func TestLoadEvidenceRecordFromSinkFile(t *testing.T) {
	cert := testAICCert(t, false)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))
	if len(res.OperationDecisions) == 0 {
		t.Fatal("no operation decisions")
	}
	dir := t.TempDir()
	cfg := &EvidenceConfig{Sink: &FileSink{Dir: dir}, TTL: time.Minute}
	if _, err := EmitDecisionRecords(cfg, EvidenceContext{Outcome: EvidenceAdmitted}, cert, res.AIC, res.PrincipalAuthorization, nil, res.OperationDecisions); err != nil {
		t.Fatalf("EmitDecisionRecords: %v", err)
	}
	entries, err := readDirNames(dir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("no evidence files (%v)", err)
	}
	rec, err := LoadEvidenceRecord(entries[0])
	if err != nil {
		t.Fatalf("LoadEvidenceRecord: %v", err)
	}
	if err := rec.Verify(); err != nil {
		t.Fatalf("loaded record does not reproduce: %v", err)
	}

	var d EvidenceDecision
	if err := d.ApplyRecord(rec); err != nil {
		t.Fatalf("ApplyRecord: %v", err)
	}
	b := &EvidenceBundle{Decision: d}
	if err := b.CheckDecisions(); err != nil {
		t.Fatalf("bundle carrying an emitted record: %v", err)
	}
}

// readDirNames returns the full paths of a directory's entries.
func readDirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out, nil
}
