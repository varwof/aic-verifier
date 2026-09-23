// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Test coverage for the Merkle audit chain (merkle.go), the v1.2 audit
// extensions / plugin decision helpers (audit.go), the evidence sinks
// (evidence_sink.go), and the small identity / serial / registry helpers
// (identity.go, serial.go, capregistry.go, evidence.go canonicalReasonCode).
// It reuses the fixture helpers from audit_integrity_test.go,
// residual_test.go, security_fixes_test.go and crl_refresh_test.go.

package aicverifier

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/register/semantics"
	pki "github.com/varwof/types"
)

// ---------------------------------------------------------------------------
// merkle.go — AuditChain
// ---------------------------------------------------------------------------

// TestAuditChainSealAndLatestRoot covers NewAuditChain + Seal: the onSeal
// callback receives the raw root bytes, the latest root is stable between
// seals, and a second seal produces a new batch and a new latest root.
func TestAuditChainSealAndLatestRoot(t *testing.T) {
	var callbackRoot string
	c := NewAuditChain(4, func(root []byte) { callbackRoot = hex.EncodeToString(root) })

	if got := c.LatestRoot(); got != "" {
		t.Fatalf("LatestRoot on empty chain = %q, want empty", got)
	}
	if got := c.LatestRootBytes(); len(got) != 0 {
		t.Fatalf("LatestRootBytes on empty chain = %x, want nil", got)
	}

	st0 := c.Seal([][]byte{[]byte("a"), []byte("b")}, "")
	if callbackRoot != st0.Root {
		t.Errorf("onSeal root = %q, want %q", callbackRoot, st0.Root)
	}
	if got := c.LatestRoot(); got != st0.Root {
		t.Errorf("LatestRoot = %q, want %q", got, st0.Root)
	}
	if got := c.LatestRoot(); got != st0.Root {
		t.Errorf("LatestRoot is not stable across reads: %q != %q", got, st0.Root)
	}
	wantBytes, _ := hex.DecodeString(st0.Root)
	if got := c.LatestRootBytes(); hex.EncodeToString(got) != hex.EncodeToString(wantBytes) {
		t.Errorf("LatestRootBytes = %x, want %x", got, wantBytes)
	}

	st1 := c.Seal([][]byte{[]byte("c")}, st0.Root)
	if st1.BatchNumber != 1 || st1.Previous != st0.Root {
		t.Errorf("second seal = %+v, want batch 1 linked to %q", st1, st0.Root)
	}
	if got := c.LatestRoot(); got != st1.Root {
		t.Errorf("LatestRoot after second seal = %q, want %q", got, st1.Root)
	}
}

// TestAuditChainVerify checks that Verify accepts the exact tuple the chain
// produces (batch, leaf, proof), rejects a modified leaf, bounds proof length
// by the tree height, and errors on an out-of-range batch.
func TestAuditChainVerify(t *testing.T) {
	c := NewAuditChain(4, nil)
	leaves := [][]byte{[]byte("one"), []byte("two"), []byte("three"), []byte("four")}
	c.Seal(leaves, "")
	tree := NewMerkleTree(leaves)
	proof, err := tree.Proof(1)
	if err != nil {
		t.Fatalf("Proof(1): %v", err)
	}

	t.Run("exact tuple verifies", func(t *testing.T) {
		ok, err := c.Verify(0, leaves[1], proof)
		if err != nil || !ok {
			t.Fatalf("Verify(0, leaf, proof) = %v, %v; want true, nil", ok, err)
		}
	})
	t.Run("modified leaf fails", func(t *testing.T) {
		ok, err := c.Verify(0, []byte("tampered"), proof)
		if err != nil || ok {
			t.Fatalf("Verify with modified leaf = %v, %v; want false, nil", ok, err)
		}
	})
	t.Run("out of range batch errors", func(t *testing.T) {
		if _, err := c.Verify(7, leaves[1], proof); err == nil {
			t.Fatal("out-of-range batch must error")
		}
	})
	t.Run("overlong proof rejected", func(t *testing.T) {
		overlong := append(append([]ProofStep{}, proof...), ProofStep{Sibling: make([]byte, 32), Left: false})
		ok, err := c.Verify(0, leaves[1], overlong)
		if err != nil || ok {
			t.Fatalf("overlong proof = %v, %v; want false, nil (bounded by ceil(log2 size))", ok, err)
		}
	})
}

// TestAuditChainBatchCountAndDump covers BatchCount growth and the Dump text
// export on empty and populated chains.
func TestAuditChainBatchCountAndDump(t *testing.T) {
	c := NewAuditChain(3, nil)
	if got := c.BatchCount(); got != 0 {
		t.Fatalf("BatchCount on empty chain = %d, want 0", got)
	}
	if got := c.Dump(); got != "" {
		t.Fatalf("Dump on empty chain = %q, want empty", got)
	}

	c.Seal([][]byte{[]byte("x")}, "")
	c.Seal([][]byte{[]byte("y")}, c.LatestRoot())

	if got := c.BatchCount(); got != 2 {
		t.Fatalf("BatchCount = %d, want 2", got)
	}
	out := c.Dump()
	if out == "" {
		t.Fatal("Dump returned empty for a populated chain")
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("Dump lines = %d, want 2:\n%s", len(lines), out)
	}
	if st := c.GetTree(0); !strings.HasPrefix(lines[0], "0|") || !strings.Contains(lines[0], st.Root) {
		t.Errorf("first dump line = %q, want batch 0 naming root %q", lines[0], st.Root)
	}
	if !strings.HasPrefix(lines[1], "1|") {
		t.Errorf("second dump line = %q, want batch 1", lines[1])
	}
}

// TestGetTreeBounds covers GetTree on empty, valid and out-of-range batches.
func TestGetTreeBounds(t *testing.T) {
	c := NewAuditChain(3, nil)
	if c.GetTree(0) != nil {
		t.Fatal("GetTree on empty chain must be nil")
	}
	st := c.Seal([][]byte{[]byte("a")}, "")
	if got := c.GetTree(0); got == nil || got.Root != st.Root || got.BatchNumber != 0 {
		t.Fatalf("GetTree(0) = %+v, want batch 0 with root %q", got, st.Root)
	}
	if c.GetTree(-1) != nil || c.GetTree(1) != nil {
		t.Fatal("GetTree must return nil for negative and out-of-range batches")
	}
}

// TestSealCheckedLinkage covers the continuity-enforcing seal variant: an
// empty previous_root on a populated chain is refused, a mismatched root is
// refused, and the correct link is accepted.
func TestSealCheckedLinkage(t *testing.T) {
	c := NewAuditChain(4, nil)

	b0, err := c.SealChecked([][]byte{[]byte("a")}, "")
	if err != nil {
		t.Fatalf("first SealChecked on empty chain: %v", err)
	}
	if b0.BatchNumber != 0 {
		t.Fatalf("first batch number = %d, want 0", b0.BatchNumber)
	}

	if _, err := c.SealChecked([][]byte{[]byte("b")}, ""); err == nil {
		t.Fatal("SealChecked with empty previous_root on a populated chain must be refused")
	}
	if _, err := c.SealChecked([][]byte{[]byte("b")}, "deadbeef"); err == nil || !strings.Contains(err.Error(), "continuity broken") {
		t.Fatalf("mismatched previous_root = %v, want continuity broken error", err)
	}

	prev := c.LatestRoot()
	b1, err := c.SealChecked([][]byte{[]byte("b")}, prev)
	if err != nil {
		t.Fatalf("linked SealChecked: %v", err)
	}
	if b1.BatchNumber != 1 || b1.Previous != prev {
		t.Fatalf("linked batch = %+v, want batch 1 linking %q", b1, prev)
	}
}

// TestVerifyContinuityBreaks covers the chain-level continuity check: a
// properly linked chain passes, and a tampered Previous link is detected.
func TestVerifyContinuityBreaks(t *testing.T) {
	c := NewAuditChain(4, nil)
	c.SealChecked([][]byte{[]byte("a")}, "")
	c.SealChecked([][]byte{[]byte("b")}, c.LatestRoot())
	if err := c.VerifyContinuity(); err != nil {
		t.Fatalf("linked chain reported a discontinuity: %v", err)
	}

	c.trees[1].Previous = "decafbad"
	err := c.VerifyContinuity()
	if err == nil || !strings.Contains(err.Error(), "discontinuity at batch 1") {
		t.Fatalf("tampered chain = %v, want discontinuity at batch 1", err)
	}
}

// TestVerifyJSONRoundTrip covers the JSON proof API: the exact tuple the chain
// produces validates, a modified leaf fails, and invalid encodings / batch
// numbers surface as errors.
func TestVerifyJSONRoundTrip(t *testing.T) {
	c := NewAuditChain(4, nil)
	leaves := [][]byte{[]byte("alpha"), []byte("beta")}
	c.Seal(leaves, "")
	tree := NewMerkleTree(leaves)
	proof, err := tree.Proof(0)
	if err != nil {
		t.Fatalf("Proof(0): %v", err)
	}

	req := &VerifyRequest{Batch: 0, Leaf: hex.EncodeToString(leaves[0])}
	for _, s := range proof {
		req.Proof = append(req.Proof, ProofStepJSON{Sibling: hex.EncodeToString(s.Sibling), Left: s.Left})
	}

	if resp := c.VerifyJSON(req); resp.Error != "" || !resp.Valid {
		t.Fatalf("valid request = %+v, want Valid", resp)
	}
	if resp := c.VerifyJSON(&VerifyRequest{Batch: 0, Leaf: hex.EncodeToString([]byte("gamma")), Proof: req.Proof}); resp.Valid {
		t.Fatal("modified leaf reported valid")
	}
	if resp := c.VerifyJSON(&VerifyRequest{Batch: 0, Leaf: "zz!", Proof: req.Proof}); resp.Error == "" {
		t.Fatal("invalid leaf hex must error")
	}
	if resp := c.VerifyJSON(&VerifyRequest{Batch: 9, Leaf: hex.EncodeToString(leaves[0]), Proof: req.Proof}); resp.Error == "" {
		t.Fatal("out-of-range batch must error")
	}
	if resp := c.VerifyJSON(&VerifyRequest{Batch: 0, Leaf: hex.EncodeToString(leaves[0]), Proof: []ProofStepJSON{{Sibling: "not-hex", Left: false}}}); resp.Error == "" {
		t.Fatal("invalid sibling hex must error")
	}
}

// ---------------------------------------------------------------------------
// audit.go — v1.2 fields, fingerprints, duration, plugin decisions
// ---------------------------------------------------------------------------

// TestSetV12Fields asserts the five v1.2 extension fields land on the entry.
func TestSetV12Fields(t *testing.T) {
	e := AuditEntry{}
	e.SetV12Fields("grpc", "gw-9", "trace-abc", "sess-123", "allow")
	if e.Protocol != "grpc" || e.GatewayId != "gw-9" || e.TraceId != "trace-abc" ||
		e.SessionId != "sess-123" || e.Decision != "allow" {
		t.Fatalf("SetV12Fields did not populate the entry: %+v", e)
	}
}

// TestWithEvidenceFingerprints asserts the fingerprint fields are filled from
// an AIC certificate, the entry is returned for chaining, and a nil cert
// leaves both fields empty.
func TestWithEvidenceFingerprints(t *testing.T) {
	cert := testAICCert(t, false)
	entry := AuditEntry{}
	ret := entry.WithEvidenceFingerprints(cert)
	if ret != &entry {
		t.Fatal("WithEvidenceFingerprints must return the same entry")
	}
	if entry.AICFingerprint != AICFingerprint(cert) {
		t.Errorf("AICFingerprint = %q, want %q", entry.AICFingerprint, AICFingerprint(cert))
	}
	if entry.DaHash != DAHash(cert) {
		t.Errorf("DaHash = %q, want %q", entry.DaHash, DAHash(cert))
	}
	if entry.AICFingerprint == "" || entry.DaHash == "" {
		t.Errorf("AIC cert produced empty fingerprints: %+v", entry)
	}

	plain := AuditEntry{}
	plain.WithEvidenceFingerprints(nil)
	if plain.AICFingerprint != "" || plain.DaHash != "" {
		t.Errorf("nil cert must leave fingerprints empty, got %+v", plain)
	}
}

// TestAuditDurationSetsElapsed asserts AuditDuration writes a parseable,
// positive duration string equal to the elapsed time.
func TestAuditDurationSetsElapsed(t *testing.T) {
	start := time.Now().Add(-30 * time.Millisecond)
	var entry AuditEntry
	AuditDuration(start, &entry)
	got, err := time.ParseDuration(entry.Duration)
	if err != nil {
		t.Fatalf("AuditDuration produced unparseable duration %q: %v", entry.Duration, err)
	}
	want, _ := time.ParseDuration(time.Since(start).Round(time.Millisecond).String())
	if d := got - want; d > 3*time.Millisecond || d < -3*time.Millisecond {
		t.Errorf("AuditDuration = %v, want ~%v", got, want)
	}
	if got <= 0 {
		t.Errorf("AuditDuration = %v, want positive", got)
	}
}

// TestLogPluginDecisionWrites drives the plugin-decision audit helper end to
// end: the emitted audit line carries the plugin action and mapped fields, and
// the level is inferred from the decision (deny → WARN, allow → INFO, explicit
// Level preserved). A nil logger must be a no-op.
func TestLogPluginDecisionWrites(t *testing.T) {
	LogPluginDecision(nil, PluginAuditEntry{})

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := NewAuditLogger(path, nil, 1<<20, 1)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	LogPluginDecision(logger, PluginAuditEntry{
		Scheme:        "ssh",
		CapabilityID:  "ca:tunnel",
		Decision:      "deny",
		Reason:        "policy",
		ClientCN:      "alice",
		Principal:     "realm:user-1",
		DaHash:        strings.Repeat("a", 64),
		PolicyVersion: 7,
	})
	LogPluginDecision(logger, PluginAuditEntry{
		Scheme:       "http",
		CapabilityID: "read",
		Decision:     "allow",
		Reason:       "",
		ClientCN:     "bob",
	})
	LogPluginDecision(logger, PluginAuditEntry{
		Scheme:       "http",
		CapabilityID: "write",
		Decision:     "deny",
		Level:        "ERROR", // explicit level must be preserved, not re-inferred
	})
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("wrote %d audit lines, want 3:\n%s", len(lines), data)
	}

	entries := make([]AuditEntry, 0, 3)
	for _, line := range lines {
		var signed SignedAuditEntry
		if err := json.Unmarshal([]byte(line), &signed); err != nil {
			t.Fatalf("unmarshal %q: %v", line, err)
		}
		if signed.Entry.Action != string(ActionPluginDecision) {
			t.Fatalf("action = %q, want %q", signed.Entry.Action, ActionPluginDecision)
		}
		entries = append(entries, signed.Entry)
	}
	found := map[string]AuditEntry{}
	for _, e := range entries {
		seen := false
		for _, id := range []string{"ssh/deny", "allow", "write/ERROR"} {
			if id == "ssh/deny" && e.Mapping == "ssh" && e.Target == "ca:tunnel" {
				found[id], seen = e, true
				break
			}
			if id == "allow" && e.Mapping == "http" && e.Target == "read" {
				found[id], seen = e, true
				break
			}
			if id == "write/ERROR" && e.Mapping == "http" && e.Target == "write" {
				found[id], seen = e, true
				break
			}
		}
		if !seen {
			t.Errorf("unexpected audit entry: %+v", e)
		}
	}
	if deny, ok := found["ssh/deny"]; !ok {
		t.Error("deny entry not written")
	} else {
		if deny.Level != "WARN" || deny.DenyReason != "policy" || deny.TargetID != "deny" ||
			deny.ClientCN != "alice" || deny.PrincipalUid != "realm:user-1" ||
			deny.DaHash != strings.Repeat("a", 64) || deny.PolicyVersion != 7 {
			t.Errorf("deny entry fields wrong: %+v", deny)
		}
	}
	if allow, ok := found["allow"]; !ok {
		t.Error("allow entry not written")
	} else if allow.Level != "INFO" {
		t.Errorf("allow level = %q, want INFO (inferred from decision)", allow.Level)
	}
	if wantErr, ok := found["write/ERROR"]; !ok {
		t.Error("explicit-ERROR entry not written")
	} else if wantErr.Level != "ERROR" {
		t.Errorf("explicit level = %q, want ERROR (must not be re-inferred)", wantErr.Level)
	}
}

// TestDroppedCountsOverflow pins the M6 drop counter: a nil logger reports 0,
// a fresh logger reports 0, and enqueue attempts past a full buffer increment
// the dropped count without blocking.
func TestDroppedCountsOverflow(t *testing.T) {
	var nilLogger *AuditLogger
	if got := nilLogger.Dropped(); got != 0 {
		t.Fatalf("Dropped on nil logger = %d, want 0", got)
	}

	l := &AuditLogger{entries: make(chan AuditEntry, 2)}
	if got := l.Dropped(); got != 0 {
		t.Fatalf("Dropped on fresh logger = %d, want 0", got)
	}
	entry := AuditEntry{Action: string(ActionConnected), SrcIP: "1.2.3.4", Mapping: "m", Target: "t"}
	l.Log(entry)
	l.Log(entry)
	if got := l.Dropped(); got != 0 {
		t.Fatalf("Dropped within capacity = %d, want 0", got)
	}
	l.Log(entry) // buffer full → dropped
	if got := l.Dropped(); got != 1 {
		t.Fatalf("Dropped after overflow = %d, want 1", got)
	}
	l.Log(entry)
	if got := l.Dropped(); got != 2 {
		t.Fatalf("Dropped after second overflow = %d, want 2", got)
	}
}

// TestLogSyncWritesLine asserts the synchronous write path lands a JSON
// SignedAuditEntry line on disk through the RotatingFile backing.
func TestLogSyncWritesLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	rf, err := NewRotatingFile(path, 1<<20, 1)
	if err != nil {
		t.Fatalf("NewRotatingFile: %v", err)
	}
	l := &AuditLogger{w: rf}
	l.logSync(AuditEntry{
		Action:     string(ActionDenied),
		SrcIP:      "10.0.0.9",
		Mapping:    "ssh",
		Target:     "10.0.0.2:22",
		DenyReason: "no route",
		Level:      "WARN",
	})
	if err := rf.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	line := strings.TrimSpace(string(data))
	if line == "" {
		t.Fatal("logSync wrote nothing")
	}
	var signed SignedAuditEntry
	if err := json.Unmarshal([]byte(line), &signed); err != nil {
		t.Fatalf("umarshal %q: %v", line, err)
	}
	if signed.TST != "" {
		t.Errorf("TSA-less logger wrote a TST: %q", signed.TST)
	}
	if signed.Entry.Action != string(ActionDenied) || signed.Entry.SrcIP != "10.0.0.9" ||
		signed.Entry.Mapping != "ssh" || signed.Entry.Target != "10.0.0.2:22" ||
		signed.Entry.DenyReason != "no route" || signed.Entry.Level != "WARN" {
		t.Errorf("written entry = %+v", signed.Entry)
	}
}

// ---------------------------------------------------------------------------
// evidence.go — canonicalReasonCode
// ---------------------------------------------------------------------------

// TestCanonicalReasonCodeMaps pins the reason-code rule: the stable code is
// everything before the first ':' and a string without a colon (or empty)
// passes through unchanged.
func TestCanonicalReasonCodeMaps(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"deny", "deny"},
		{"deny:capability_not_authorized", "deny"},
		{"capability_not_authorized", "capability_not_authorized"},
		{"allow_unresolved:time:window", "allow_unresolved"},
		{"unknown_constraint:foo", "unknown_constraint"},
		{"", ""},
		{"no_colon_here", "no_colon_here"},
	}
	for _, tc := range cases {
		if got := canonicalReasonCode(tc.in); got != tc.want {
			t.Errorf("canonicalReasonCode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// evidence_sink.go — SlogSink and FileSink failure branches
// ---------------------------------------------------------------------------

func testDecisionRecord(t *testing.T) (semantics.DecisionRecord, semantics.Envelope) {
	t.Helper()
	rec, err := semantics.Record(
		[]semantics.Grant{{ID: sqlQueryCap}},
		semantics.Operation{ID: sqlQueryCap},
	)
	if err != nil {
		t.Fatalf("semantics.Record: %v", err)
	}
	env, err := semantics.NewEnvelope(rec)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	return rec, env
}

// TestEvidenceSinkEmitReturnsRef asserts SlogSink.Emit returns a RecordRef
// whose digest is the record's input digest and whose verdict mirrors the
// record.
func TestEvidenceSinkEmitReturnsRef(t *testing.T) {
	rec, env := testDecisionRecord(t)
	ctx := EvidenceContext{
		RecorderID:  "pep-1",
		Outcome:     EvidenceAdmitted,
		OperationID: "op-1",
		Method:      "GET",
		Path:        "/whoami",
		TraceID:     "t-1",
		Principal:   "p:u",
		AgentID:     "a-1",
	}
	ref, err := (SlogSink{}).Emit(ctx, rec, env)
	if err != nil {
		t.Fatalf("SlogSink.Emit: %v", err)
	}
	if want := hex.EncodeToString(rec.InputDigest.Value); ref.Digest != want {
		t.Errorf("ref.Digest = %q, want %q", ref.Digest, want)
	}
	if ref.Verdict != rec.Verdict {
		t.Errorf("ref.Verdict = %q, want %q", ref.Verdict, rec.Verdict)
	}
}

// TestEvidenceSinkEmitAdmissionReturnsRef asserts SlogSink.EmitAdmission
// returns a ref naming the admission record's digest and the refused outcome.
func TestEvidenceSinkEmitAdmissionReturnsRef(t *testing.T) {
	ctx := EvidenceContext{
		RecorderID: "pep-1",
		At:         time.Now().UTC(),
		Principal:  "p",
		AgentID:    "a",
		Serial:     "S",
	}
	ar := NewAdmissionRecord(ctx, &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: "no credential"},
		[]AdmissionFact{{Type: "client_cert", Digest: semantics.Digest{Alg: semantics.DigestAlgSHA256, Value: []byte{1, 2, 3, 4, 5}}}})
	env, err := NewAdmissionEnvelope(ar)
	if err != nil {
		t.Fatalf("NewAdmissionEnvelope: %v", err)
	}
	ref, err := (SlogSink{}).EmitAdmission(ctx, ar, env)
	if err != nil {
		t.Fatalf("SlogSink.EmitAdmission: %v", err)
	}
	want, err := ar.Digest()
	if err != nil {
		t.Fatalf("ar.Digest: %v", err)
	}
	if ref.Digest != hex.EncodeToString(want.Value) {
		t.Errorf("ref.Digest = %q, want %q", ref.Digest, hex.EncodeToString(want.Value))
	}
	if ref.Verdict != string(EvidenceRefused) {
		t.Errorf("ref.Verdict = %q, want %q", ref.Verdict, EvidenceRefused)
	}
}

// TestEvidenceSinkEmitOutcomeReturnsRef asserts the outcome sink returns a ref
// naming the outcome record digest and its outcome token.
func TestEvidenceSinkEmitOutcomeReturnsRef(t *testing.T) {
	or := OutcomeRecord{
		Ver:            OutcomeRecordVersion,
		Outcome:        OutcomeObserved,
		At:             time.Now().UTC(),
		DecisionDigest: "dec-1",
		OperationID:    "op-1",
		RecorderID:     "r-1",
		StatusCode:     200,
	}
	env, err := NewOutcomeEnvelope(or)
	if err != nil {
		t.Fatalf("NewOutcomeEnvelope: %v", err)
	}
	ref, err := (SlogSink{}).EmitOutcome(EvidenceContext{RecorderID: "r-1"}, or, env)
	if err != nil {
		t.Fatalf("SlogSink.EmitOutcome: %v", err)
	}
	want, err := or.Digest()
	if err != nil {
		t.Fatalf("or.Digest: %v", err)
	}
	if ref.Digest != hex.EncodeToString(want.Value) {
		t.Errorf("ref.Digest = %q, want %q", ref.Digest, hex.EncodeToString(want.Value))
	}
	if ref.Verdict != OutcomeObserved {
		t.Errorf("ref.Verdict = %q, want %q", ref.Verdict, OutcomeObserved)
	}
}

// TestEvidenceSinkFailureBranches asserts each FileSink entry point fails
// closed when no directory is configured.
func TestEvidenceSinkFailureBranches(t *testing.T) {
	fs := &FileSink{}
	ctx := EvidenceContext{}
	if _, err := fs.Emit(ctx, semantics.DecisionRecord{}, semantics.Envelope{}); err == nil || !strings.Contains(err.Error(), "needs a directory") {
		t.Fatalf("FileSink.Emit without Dir = %v, want needs-a-directory error", err)
	}
	if _, err := fs.EmitAdmission(ctx, AdmissionRecord{}, semantics.Envelope{}); err == nil || !strings.Contains(err.Error(), "needs a directory") {
		t.Fatalf("FileSink.EmitAdmission without Dir = %v, want needs-a-directory error", err)
	}
	if _, err := fs.EmitOutcome(ctx, OutcomeRecord{}, semantics.Envelope{}); err == nil || !strings.Contains(err.Error(), "needs a directory") {
		t.Fatalf("FileSink.EmitOutcome without Dir = %v, want needs-a-directory error", err)
	}
}

// ---------------------------------------------------------------------------
// serial.go — NormalizeSerial
// ---------------------------------------------------------------------------

// TestNormalizeSerialPads asserts the uppercase, no-prefix, 40-char
// zero-padded hex form of certificate serial numbers.
func TestNormalizeSerialPads(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0x1234abcd, strings.Repeat("0", 32) + "1234ABCD"},
		{123, strings.Repeat("0", 38) + "7B"},
		{0, strings.Repeat("0", 40)},
	}
	for _, tc := range cases {
		if got := NormalizeSerial(big.NewInt(tc.in)); got != tc.want {
			t.Errorf("NormalizeSerial(%d) = %q(len %d), want %q(len %d)", tc.in, got, len(got), tc.want, len(tc.want))
		}
	}
}

// ---------------------------------------------------------------------------
// identity.go — certSPKIHashHex, SetIdentityHeaderMode, identityHeaderModeOf,
// injectIdentityHeaders
// ---------------------------------------------------------------------------

// TestCertSPKIHashHex asserts the SPKI SHA-256 hex hash matches a reference
// computation via crypto/sha256.
func TestCertSPKIHashHex(t *testing.T) {
	cert := newPlainCert(t)
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	want := hex.EncodeToString(sum[:])
	if got := certSPKIHashHex(cert); got != want {
		t.Errorf("certSPKIHashHex = %q, want %q", got, want)
	}
}

// TestIdentityHeaderModeRoundTrip covers SetIdentityHeaderMode writing the
// header and identityHeaderModeOf reading it back, plus the default and the
// IdentityForwardClientCert default-case round trip.
func TestIdentityHeaderModeRoundTrip(t *testing.T) {
	for _, mode := range []IdentityHeaderMode{IdentityMinimal, IdentityXForwarded, IdentityAIC} {
		r := httptest.NewRequest(http.MethodGet, "http://b.test/", nil)
		SetIdentityHeaderMode(r, mode)
		if got := identityHeaderModeOf(r); got != mode {
			t.Errorf("round trip for mode %d = %d", mode, got)
		}
	}

	r := httptest.NewRequest(http.MethodGet, "http://b.test/", nil)
	if got := identityHeaderModeOf(r); got != IdentityForwardClientCert {
		t.Errorf("unset header mode = %d, want IdentityForwardClientCert (%d)", got, IdentityForwardClientCert)
	}

	r2 := httptest.NewRequest(http.MethodGet, "http://b.test/", nil)
	SetIdentityHeaderMode(r2, IdentityForwardClientCert)
	if got := identityHeaderModeOf(r2); got != IdentityForwardClientCert {
		t.Errorf("forward round trip = %d, want IdentityForwardClientCert", got)
	}

	SetIdentityHeaderMode(nil, IdentityMinimal) // must not panic
}

// TestIdentityHeaderInjectionForward asserts the full forward mode: client
// cert DER, SPKI hash, serial, CN and principal headers are set, the AIC
// structured headers are emitted, and the client-supplied header namespace is
// stripped first.
func TestIdentityHeaderInjectionForward(t *testing.T) {
	cert := newPlainCert(t)
	ac := &AuthContext{
		ClientCert: cert,
		Principal:  "realm:owner",
		AgentID:    "agent-1",
		AIC: &AIC{
			AgentId: "agent-1",
			Capabilities: []pki.Capability{
				{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"},
			},
		},
	}
	r := httptest.NewRequest(http.MethodGet, "http://backend.test/", nil)
	r.Header.Set("X-Client-Cert-DER", "tampered")
	r.Header.Set("X-Forwarded-Client-CN", "tampered")
	injectIdentityHeaders(r, ac, IdentityForwardClientCert)

	if got := r.Header.Get("X-Client-Cert-DER"); got != base64.StdEncoding.EncodeToString(cert.Raw) {
		t.Errorf("X-Client-Cert-DER = %q, want %q", got, base64.StdEncoding.EncodeToString(cert.Raw))
	}
	if got := r.Header.Get("X-Client-Cert-SPKI-Hash"); got != certSPKIHashHex(cert) {
		t.Errorf("X-Client-Cert-SPKI-Hash = %q, want %q", got, certSPKIHashHex(cert))
	}
	if got := r.Header.Get("X-Client-Cert-Serial"); got != cert.SerialNumber.Text(16) {
		t.Errorf("X-Client-Cert-Serial = %q, want %q", got, cert.SerialNumber.Text(16))
	}
	if got := r.Header.Get("X-Client-Cert-CN"); got != "client.example" {
		t.Errorf("X-Client-Cert-CN = %q, want client.example", got)
	}
	if got := r.Header.Get("X-Client-Cert-Principal"); got != "realm:owner" {
		t.Errorf("X-Client-Cert-Principal = %q, want realm:owner", got)
	}
	if got := r.Header.Get("X-Client-Cert-Agent-ID"); got != "agent-1" {
		t.Errorf("X-Client-Cert-Agent-ID = %q, want agent-1", got)
	}
	if got := r.Header.Get("X-AIC-Agent-Id"); got != "agent-1" {
		t.Errorf("X-AIC-Agent-Id = %q, want agent-1", got)
	}
	if got := r.Header.Get("X-AIC-Principal-Uid"); got != "realm:owner" {
		t.Errorf("X-AIC-Principal-Uid = %q, want realm:owner", got)
	}
	if got := r.Header.Get("X-AIC-Capabilities"); got != "query:SELECT" {
		t.Errorf("X-AIC-Capabilities = %q, want query:SELECT", got)
	}
	if got := r.Header.Get("X-AIC-Capabilities-Full"); got != "std/database-v1:query:SELECT" {
		t.Errorf("X-AIC-Capabilities-Full = %q, want std/database-v1:query:SELECT", got)
	}
	if got := r.Header.Get("X-Forwarded-Client-CN"); got != "" {
		t.Errorf("X-Forwarded-Client-CN survived injection: %q", got)
	}
}

// TestIdentityHeaderInjectionXForwarded asserts the X-Forwarded mode only sets
// the X-Forwarded-Client-* namespace.
func TestIdentityHeaderInjectionXForwarded(t *testing.T) {
	cert := newPlainCert(t)
	ac := &AuthContext{ClientCert: cert, Principal: "realm:owner"}
	r := httptest.NewRequest(http.MethodGet, "http://backend.test/", nil)
	r.Header.Set("X-Client-Cert-DER", "tampered")
	injectIdentityHeaders(r, ac, IdentityXForwarded)

	if got := r.Header.Get("X-Forwarded-Client-CN"); got != "client.example" {
		t.Errorf("X-Forwarded-Client-CN = %q, want client.example", got)
	}
	if got := r.Header.Get("X-Forwarded-Client-Serial"); got != cert.SerialNumber.Text(16) {
		t.Errorf("X-Forwarded-Client-Serial = %q, want %q", got, cert.SerialNumber.Text(16))
	}
	if got := r.Header.Get("X-Client-Cert-DER"); got != "" {
		t.Errorf("X-Client-Cert-DER set in X-Forwarded mode: %q", got)
	}
	if got := r.Header.Get("X-AIC-Agent-Id"); got != "" {
		t.Errorf("X-AIC-Agent-Id set in X-Forwarded mode: %q", got)
	}
}

// TestIdentityHeaderInjectionMinimalStrips asserts IdentityMinimal sets
// nothing and always strips the trusted header namespace; a nil AuthContext
// still strips (fail closed) without setting anything.
func TestIdentityHeaderInjectionMinimalStrips(t *testing.T) {
	ac := &AuthContext{
		ClientCert: newPlainCert(t),
		Principal:  "realm:owner",
		AgentID:    "agent-1",
		AIC:        &AIC{AgentId: "agent-1", Capabilities: []pki.Capability{{SchemeId: "x", CapabilityId: "y"}}},
	}
	r := httptest.NewRequest(http.MethodGet, "http://backend.test/", nil)
	r.Header.Set("X-AIC-Agent-Id", "client-spoof")
	r.Header.Set("X-Client-Cert-DER", "client-spoof")
	injectIdentityHeaders(r, ac, IdentityMinimal)
	if got := r.Header.Get("X-AIC-Agent-Id"); got != "" {
		t.Errorf("X-AIC-Agent-Id survived IdentityMinimal: %q", got)
	}
	if got := r.Header.Get("X-Client-Cert-DER"); got != "" {
		t.Errorf("X-Client-Cert-DER survived IdentityMinimal: %q", got)
	}

	r2 := httptest.NewRequest(http.MethodGet, "http://backend.test/", nil)
	r2.Header.Set("X-Client-Cert-DER", "client-spoof")
	injectIdentityHeaders(r2, nil, IdentityForwardClientCert)
	if got := r2.Header.Get("X-Client-Cert-DER"); got != "" {
		t.Errorf("nil AuthContext left a spoofed header: %q", got)
	}
}

// ---------------------------------------------------------------------------
// capregistry.go — SetGlobalCapabilityRegistry
// ---------------------------------------------------------------------------

// memCapRegistry is a minimal in-memory CapabilityRegistry for tests.
type memCapRegistry struct {
	registered map[string]bool
	enabled    bool
}

func (m *memCapRegistry) ValidateCapability(formatted string) error {
	if m.registered[formatted] {
		return nil
	}
	return errors.New("capability_not_registered: " + formatted)
}

func (m *memCapRegistry) Enabled() bool { return m.enabled }

// TestSetGlobalCapabilityRegistryInstalls covers install, lookup through the
// installed registry, and the nil-clear path.
func TestSetGlobalCapabilityRegistryInstalls(t *testing.T) {
	defer SetGlobalCapabilityRegistry(nil)

	SetGlobalCapabilityRegistry(nil)
	if got := GetGlobalCapabilityRegistry(); got != nil {
		t.Fatalf("registry after explicit clear = %v, want nil", got)
	}

	reg := &memCapRegistry{registered: map[string]bool{"std/database-v1:query:SELECT": true}, enabled: true}
	SetGlobalCapabilityRegistry(reg)
	got := GetGlobalCapabilityRegistry()
	if got == nil {
		t.Fatal("GetGlobalCapabilityRegistry = nil after install")
	}
	if !got.Enabled() {
		t.Error("installed registry reports not enabled")
	}
	if err := got.ValidateCapability("std/database-v1:query:SELECT"); err != nil {
		t.Errorf("registered capability rejected: %v", err)
	}
	if err := got.ValidateCapability("std/database-v1:query:INSERT"); err == nil {
		t.Error("unregistered capability accepted")
	}

	SetGlobalCapabilityRegistry(nil)
	if got := GetGlobalCapabilityRegistry(); got != nil {
		t.Errorf("registry after nil clear = %v, want nil", got)
	}
}
