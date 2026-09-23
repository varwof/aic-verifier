// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/varwof/register/semantics"
	pki "github.com/varwof/types"
)

// Evidence bundle v0.1 (evidence-bundle-format-v0.1): a single self-contained,
// canonical-serializable JSON package answering the five attribution questions
// — who authorized, what boundary, who executed, whether a human intervened,
// and whether the evidence is tamper-evident.

// EvidenceBundle is the exported evidence package.  Field layout follows the
// v0.1 specification: manifest/operation/subject/authorization/decision/
// supervision/auditChain/signatures.
type EvidenceBundle struct {
	Manifest      EvidenceManifest           `json:"manifest"`
	Operation     EvidenceOperation          `json:"operation"`
	Subject       EvidenceSubject            `json:"subject"`
	Authorization EvidenceAuthorization      `json:"authorization"`
	Decision      EvidenceDecision           `json:"decision"`
	Supervision   []EvidenceSupervisionEvent `json:"supervision"`
	AuditChain    EvidenceAuditChain         `json:"auditChain"`
	Signatures    map[string]json.RawMessage `json:"signatures"`
}

// EvidenceManifest is the bundle's own metadata (v0.1 §3 manifest).
type EvidenceManifest struct {
	Schema     string    `json:"schema"`
	Version    string    `json:"version"`
	BundleID   string    `json:"bundleId"`
	ExportedAt time.Time `json:"exportedAt"`
	Generator  string    `json:"generator"`
	HashAlg    string    `json:"hashAlg"`
	PolicyRef  string    `json:"policyRef,omitempty"`
}

// EvidenceOperation identifies the audited operation and its outcome
// (v0.1 §3 operation).
type EvidenceOperation struct {
	OperationID     string  `json:"operationId,omitempty"`
	StartedAt       string  `json:"startedAt,omitempty"`
	FinishedAt      string  `json:"finishedAt,omitempty"`
	Resource        string  `json:"resource,omitempty"`
	Action          string  `json:"action,omitempty"`
	RequestedParams Summary `json:"requestedParams,omitempty"`
	Outcome         string  `json:"outcome,omitempty"` // permit | deny | error
}

// EvidenceSubject records who executed (v0.1 §3 subject).
type EvidenceSubject struct {
	AgentID                string `json:"agentId,omitempty"`
	KeyBinding             string `json:"keyBinding,omitempty"`
	TransportIdentity      string `json:"transportIdentity,omitempty"`
	PresentedCredentialRef string `json:"presentedCredentialRef,omitempty"`
}

// EvidenceAuthorization records who authorized and the boundary
// (v0.1 §3 authorization).
type EvidenceAuthorization struct {
	DelegationMode string               `json:"delegationMode,omitempty"`
	Principal      string               `json:"principal,omitempty"`
	GrantRef       *EvidenceGrantRef    `json:"grantRef,omitempty"`
	Capabilities   []EvidenceCapability `json:"capabilities,omitempty"`
	Constraints    string               `json:"constraints,omitempty"`
	Ceiling        string               `json:"ceiling,omitempty"`
	ValidFrom      string               `json:"validFrom,omitempty"`
	ExpiresAt      string               `json:"expiresAt,omitempty"`
}

// EvidenceGrantRef is a reference + digest to the governing DA.
type EvidenceGrantRef struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

// EvidenceCapability is a capability sub-set entry with parameter boundary
// summary.
type EvidenceCapability struct {
	Scheme       string `json:"scheme,omitempty"`
	CapabilityID string `json:"capabilityId"`
	Parameters   string `json:"parameters,omitempty"`
}

// EvidenceDecision is the PDP/PEP decision record (v0.1 §3 decision).
type EvidenceDecision struct {
	// Decision mirrors the CLC verdict.  When Record is present this field is
	// derived from it (allow | allow_unresolved | deny) and MUST NOT disagree:
	// a bundle whose summary contradicts its record is not evidence.
	Decision string `json:"decision,omitempty"`
	// RecordDigest is the record's input digest (hex) — the stable identifier
	// of "which decision this bundle is about".
	RecordDigest string `json:"recordDigest,omitempty"`
	// Record is the CLC Decision Record itself: frozen inputs, verdict and
	// residual obligations, independently re-computable by any holder.  The
	// other fields in this section are a reader's summary of it; the record is
	// the authority.
	Record                *semantics.DecisionRecord `json:"record,omitempty"`
	MatchedPolicy         string                    `json:"matchedPolicy,omitempty"`
	ReasonCodes           []string                  `json:"reasonCodes,omitempty"`
	EvaluatedCapabilities []string                  `json:"evaluatedCapabilities,omitempty"`
	PdpContext            string                    `json:"pdpContext,omitempty"`
}

// ApplyRecord attaches a CLC decision record to this section and derives the
// summary fields from it.  Deriving (rather than trusting the audit text) is
// what keeps the bundle from carrying a decision of its own.
func (d *EvidenceDecision) ApplyRecord(rec *semantics.DecisionRecord) error {
	if rec == nil {
		return nil
	}
	if err := rec.Verify(); err != nil {
		return fmt.Errorf("evidence_decision: record does not reproduce: %w", err)
	}
	d.Record = rec
	d.RecordDigest = hex.EncodeToString(rec.InputDigest.Value)
	d.Decision = rec.Verdict
	d.ReasonCodes = nil
	if rec.Reason != "" {
		d.ReasonCodes = append(d.ReasonCodes, canonicalReasonCode(rec.Reason))
	}
	for _, u := range rec.Constraints.Unresolved {
		d.ReasonCodes = append(d.ReasonCodes, "unresolved:"+u)
	}
	return nil
}

// CheckDecisions verifies that the bundle's decision section agrees with the
// record it carries (when it carries one).  A bundle without a record is not
// wrong, but it is a report — not replayable evidence.
func (b *EvidenceBundle) CheckDecisions() error {
	if b == nil {
		return fmt.Errorf("evidence_bundle: nil")
	}
	rec := b.Decision.Record
	if rec == nil {
		return nil
	}
	if err := rec.Verify(); err != nil {
		return fmt.Errorf("evidence_bundle: %w", err)
	}
	if want := hex.EncodeToString(rec.InputDigest.Value); b.Decision.RecordDigest != want {
		return fmt.Errorf("evidence_bundle: record digest %q does not match the record (%s)", b.Decision.RecordDigest, want)
	}
	if b.Decision.Decision != rec.Verdict {
		return fmt.Errorf("evidence_bundle: decision %q contradicts the record verdict %q", b.Decision.Decision, rec.Verdict)
	}
	return nil
}

// canonicalReasonCode mirrors the register runner's rule: the stable code is
// everything before the first ':'.
func canonicalReasonCode(s string) string {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i]
	}
	return s
}

// EvidenceSupervisionEvent is one human-intervention event (v0.1 §3
// supervision).  decisionRef mirrors the shared operation_id correlation key.
type EvidenceSupervisionEvent struct {
	Type        string `json:"type"` // consent | denied | stepUp | approval | breakGlass | override
	OccurredAt  string `json:"occurredAt"`
	Actor       string `json:"actor"`
	DecisionRef string `json:"decisionRef,omitempty"`
	EvidenceRef string `json:"evidenceRef,omitempty"`
}

// EvidenceAuditChain is the tamper-evidence chain (v0.1 §3 auditChain).
type EvidenceAuditChain struct {
	Entries    []EvidenceAuditEntry `json:"entries,omitempty"`
	MerkleRoot string               `json:"merkleRoot,omitempty"`
	Anchor     string               `json:"anchor,omitempty"` // self | tsa | externalLog
	TSA        string               `json:"tsa,omitempty"`
}

// EvidenceAuditEntry is a chained audit line digest.  prevHash of the first
// entry is empty.
type EvidenceAuditEntry struct {
	Seq       int64  `json:"seq"`
	Action    string `json:"action"`
	Actor     string `json:"actor"`
	Ts        string `json:"ts"`
	EntryHash string `json:"entryHash"`
	PrevHash  string `json:"prevHash"`
}

const (
	evidenceSchema   = "varwof/aic-evidence-bundle"
	evidenceVersion  = "0.1"
	evidenceHashAlg  = "SHA-256"
	evidenceAnchor   = "self"
	evidenceSHA256Pf = "sha256:"
)

// FileEvidenceExporter is the built-in minimal exporter: it reads the audit
// chain (SignedAuditEntry JSONL) and optionally the supervision event store,
// filters them by EvidenceQuery, and builds an evidence-bundle v0.1 with a
// Merkle root over the exported line digests.
type FileEvidenceExporter struct {
	// AuditFile is the audit JSON Lines file (SignedAuditEntry stream).
	AuditFile string
	// SupervisionFile is the supervision event JSON Lines file.  Empty means
	// supervision is unavailable; querying with IncludeSupervision then yields
	// no supervision events.
	SupervisionFile string
	// EvidenceDir is the evidence record directory (the FileSink directory).
	// When set and no Record was passed in the query, the exporter resolves the
	// anchor from the audit chain (record_digest), loads the decision record
	// envelope by digest and attaches it to the bundle.  A digest that resolves
	// to nothing is a gap: the export fails instead of silently degrading to a
	// report-only bundle.
	EvidenceDir string
	// Generator is the bundle.generator label; empty defaults to the package
	// version.
	Generator string
	// Signer, when set, key-endorses every exported bundle: the package itself
	// carries a signature over its canonical bytes (sans signatures), so a
	// holder can verify the export was produced by this key, not assembled by
	// hand.  nil leaves the bundle unsigned (a report).
	Signer *RecordSigner
	// Now overrides the export clock (tests).
	Now func() time.Time
}

// NewFileEvidenceExporter builds the built-in exporter over the given audit
// and supervision JSONL files.
func NewFileEvidenceExporter(auditFile, supervisionFile string) *FileEvidenceExporter {
	return &FileEvidenceExporter{AuditFile: auditFile, SupervisionFile: supervisionFile}
}

// Export implements EvidenceExporter.
func (e *FileEvidenceExporter) Export(ctx context.Context, q EvidenceQuery) (*EvidenceBundle, error) {
	now := time.Now().UTC()
	if e.Now != nil {
		now = e.Now().UTC()
	}
	gen := e.Generator
	if gen == "" {
		gen = "aic-verifier v" + Version
	}

	entries, err := readAuditChainLines(e.AuditFile, q)
	if err != nil {
		return nil, err
	}

	bundle := &EvidenceBundle{
		Manifest: EvidenceManifest{
			Schema:     evidenceSchema,
			Version:    evidenceVersion,
			BundleID:   "evidence-" + newOperationID()[3:],
			ExportedAt: now,
			Generator:  gen,
			HashAlg:    evidenceHashAlg,
		},
		Subject:     EvidenceSubject{},
		Supervision: make([]EvidenceSupervisionEvent, 0),
		AuditChain: EvidenceAuditChain{
			Anchor: evidenceAnchor,
		},
		Signatures: make(map[string]json.RawMessage),
	}
	e.fillFromAudit(bundle, entries, q, now)
	if err := bundle.Decision.ApplyRecord(q.Record); err != nil {
		return nil, err
	}
	// Mutual anchoring: when the deployment records evidence and the audit
	// chain pins a record digest but the caller did not hand one over, resolve
	// the record by digest from the evidence directory.  A missing envelope is
	// a gap, not a report-only fallback.
	if q.Record == nil && bundle.Decision.RecordDigest != "" {
		if e.EvidenceDir == "" {
			return nil, fmt.Errorf("evidence_exporter: record %s pinned by audit (%s) but EvidenceDir is not set — cannot resolve it, refusing to export a report-only bundle", bundle.Decision.RecordDigest, e.AuditFile)
		}
		rec, err := e.resolveRecordByDigest(bundle.Decision.RecordDigest)
		if err != nil {
			return nil, err
		}
		if err := bundle.Decision.ApplyRecord(rec); err != nil {
			return nil, err
		}
	}

	if q.IncludeSupervision {
		sup, err := readSupervisionLines(e.SupervisionFile, q)
		if err != nil {
			return nil, err
		}
		bundle.Supervision = sup
	}

	// Merkle root over the exported entry digests.
	if len(bundle.AuditChain.Entries) > 0 {
		leaves := make([][]byte, 0, len(bundle.AuditChain.Entries))
		for _, ent := range bundle.AuditChain.Entries {
			d, err := hex.DecodeString(strings.TrimPrefix(ent.EntryHash, evidenceSHA256Pf))
			if err == nil {
				leaves = append(leaves, d)
			}
		}
		if root := NewMerkleTree(leaves).RootHex(); root != "" {
			bundle.AuditChain.MerkleRoot = evidenceSHA256Pf + root
		}
	}
	if e.Signer != nil {
		if err := bundle.Sign(e.Signer.KeyID(), e.Signer.Sign); err != nil {
			return nil, fmt.Errorf("evidence_exporter: sign bundle: %w", err)
		}
	}
	return bundle, nil
}

// JSON serializes the bundle as canonical JSON (keys sorted lexicographically
// at every level, no extraneous whitespace).  The output is reproducible and
// safe to digest.
func (b *EvidenceBundle) JSON() ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("evidence_bundle: nil")
	}
	return CanonicalJSON(b)
}

// BundlePayloadType domain-separates a bundle signature from the record DSSE
// signatures: the same key never signs two different meanings with the same
// bytes.
const BundlePayloadType = "application/vnd.varwof.aic-evidence-bundle.v0.1+json"

// bundleSignature is one entry in EvidenceBundle.Signatures: a DSSE-style
// (keyid, sig) pair.  KeyID is an unauthenticated hint.
type bundleSignature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   []byte `json:"sig"`
}

// SigningBytes returns the canonical serialization of the bundle with the
// Signatures map emptied — the exact bytes a bundle signature covers.  Emptying
// it first is what lets signatures not have to cover themselves.
func (b *EvidenceBundle) SigningBytes() ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("evidence_bundle: nil")
	}
	clone := *b
	clone.Signatures = map[string]json.RawMessage{}
	return CanonicalJSON(&clone)
}

// Sign appends a signature over PAE(BundlePayloadType, SigningBytes()) — the
// same pre-authentication encoding the record envelopes use, so one verifier
// covers both.  keyID names the signing key (unauthenticated hint); entries are
// keyed by it, so signing twice with the same id replaces rather than stacks.
func (b *EvidenceBundle) Sign(keyID string, sign func(pae []byte) ([]byte, error)) error {
	if b == nil {
		return fmt.Errorf("evidence_bundle: nil")
	}
	if sign == nil {
		return fmt.Errorf("evidence_bundle: nil signer")
	}
	body, err := b.SigningBytes()
	if err != nil {
		return err
	}
	sig, err := sign(semantics.PAE(BundlePayloadType, body))
	if err != nil {
		return err
	}
	raw, err := json.Marshal(bundleSignature{KeyID: keyID, Sig: sig})
	if err != nil {
		return err
	}
	if b.Signatures == nil {
		b.Signatures = map[string]json.RawMessage{}
	}
	b.Signatures[keyID] = raw
	return nil
}

// VerifySignature requires at least one bundle signature to verify over the
// signing bytes (PAE of the bundle without its signatures).  A bundle with no
// signatures, or none that verify, fails — a bundle is evidence of who issued
// it only when key-endorsed.  verify is a RecordSigner.VerifyFn /
// VerifyFnFromKey callback.
func (b *EvidenceBundle) VerifySignature(verify func(keyID string, pae, sig []byte) error) error {
	if b == nil {
		return fmt.Errorf("evidence_bundle: nil")
	}
	if verify == nil {
		return fmt.Errorf("evidence_bundle: nil verifier")
	}
	if len(b.Signatures) == 0 {
		return fmt.Errorf("evidence_bundle: no signatures")
	}
	body, err := b.SigningBytes()
	if err != nil {
		return err
	}
	pae := semantics.PAE(BundlePayloadType, body)
	var firstErr error
	for _, raw := range b.Signatures {
		var s bundleSignature
		if err := json.Unmarshal(raw, &s); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("evidence_bundle: malformed signature: %w", err)
			}
			continue
		}
		if len(s.Sig) == 0 {
			if firstErr == nil {
				firstErr = fmt.Errorf("evidence_bundle: empty signature")
			}
			continue
		}
		if err := verify(s.KeyID, pae, s.Sig); err == nil {
			return nil
		} else if firstErr == nil {
			firstErr = fmt.Errorf("evidence_bundle: signature does not verify: %w", err)
		}
	}
	return firstErr
}

// CanonicalJSON serializes v with keys sorted lexicographically at every level
// (map-key order guaranteed by encoding/json) and no extraneous whitespace.
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tree any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	canon, err := canonicalize(tree)
	if err != nil {
		return nil, err
	}
	return json.Marshal(canon)
}

// canonicalize reorders embedded RawMessage values so their inner keys are
// sorted too.
func canonicalize(v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			cv, err := canonicalize(val)
			if err != nil {
				return nil, err
			}
			out[k] = cv
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			cv, err := canonicalize(val)
			if err != nil {
				return nil, err
			}
			out[i] = cv
		}
		return out, nil
	}
	return v, nil
}

// resolveRecordByDigest loads the CLC decision record envelope whose input
// digest is digest from EvidenceDir.  Files that are not decision-record
// envelopes (admission/outcome records) are skipped.  A digest that matches no
// decision record is an evidence gap and fails the export.
func (e *FileEvidenceExporter) resolveRecordByDigest(digest string) (*semantics.DecisionRecord, error) {
	entries, err := os.ReadDir(e.EvidenceDir)
	if err != nil {
		return nil, fmt.Errorf("evidence_exporter: read evidence dir %s: %w", e.EvidenceDir, err)
	}
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		rec, err := LoadEvidenceRecord(filepath.Join(e.EvidenceDir, de.Name()))
		if err != nil {
			continue
		}
		if hex.EncodeToString(rec.InputDigest.Value) == digest {
			return rec, nil
		}
	}
	return nil, fmt.Errorf("evidence_exporter: decision record %s not found under %s (evidence gap)", digest, e.EvidenceDir)
}

// fillFromAudit derives the operation/subject/authorization/decision and the
// audit chain from the exported audit lines.
func (e *FileEvidenceExporter) fillFromAudit(bundle *EvidenceBundle, entries []auditChainLine, q EvidenceQuery, now time.Time) {
	var first, last *AuditEntry
	var prevHash string
	chain := make([]EvidenceAuditEntry, 0, len(entries))
	var started, finished time.Time

	for i, cl := range entries {
		ent := cl.signed.Entry
		if first == nil {
			first = &ent
			started = entTime(ent)
		}
		last = &ent
		finished = entTime(ent)

		digest := sha256.Sum256(cl.raw)
		entryHash := evidenceSHA256Pf + hex.EncodeToString(digest[:])
		chain = append(chain, EvidenceAuditEntry{
			Seq:       int64(i + 1),
			Action:    ent.Action,
			Actor:     auditActor(ent),
			Ts:        ent.Time,
			EntryHash: entryHash,
			PrevHash:  prevHash,
		})
		prevHash = entryHash
	}
	bundle.AuditChain.Entries = chain

	op := EvidenceOperation{OperationID: q.OperationID, Outcome: "permit"}
	sub := EvidenceSubject{AgentID: q.AgentID}
	authz := EvidenceAuthorization{}
	dec := EvidenceDecision{}

	if first != nil {
		if op.OperationID == "" {
			op.OperationID = first.TraceId
			if op.OperationID == "" {
				op.OperationID = first.TargetID
			}
		}
		op.Resource = first.Target
		op.Action = first.Action
		op.Outcome = outcomeOf(*last)
		op.StartedAt = startEndString(started)
		op.FinishedAt = startEndString(finished)

		if sub.AgentID == "" {
			sub.AgentID = first.AgentId
			if sub.AgentID == "" {
				sub.AgentID = first.ClientCN
			}
		}
		if sub.KeyBinding == "" {
			sub.KeyBinding = digestOf(first.AICFingerprint)
		}
		sub.TransportIdentity = digestOf(first.ClientSerial)
		sub.PresentedCredentialRef = first.Mapping

		authz.DelegationMode = delegationModeString(first.DelegationMode)
		authz.Principal = first.PrincipalUid
		if first.DaHash != "" {
			authz.GrantRef = &EvidenceGrantRef{Ref: "da-jwt", Digest: evidenceSHA256Pf + first.DaHash}
		}
		for _, c := range first.Capabilities {
			authz.Capabilities = append(authz.Capabilities, EvidenceCapability{CapabilityID: c})
		}
		if len(first.Roles) > 0 {
			authz.Constraints = strings.Join(first.Roles, ";")
		}

		dec.Decision = op.Outcome
		if first.RecordDigest != "" {
			dec.RecordDigest = first.RecordDigest
		}
		if dec.Decision == "deny" {
			dec.ReasonCodes = []string{"param-out-of-bound"}
			if first.DenyReason != "" {
				dec.ReasonCodes = []string{first.DenyReason}
			}
		}
		dec.EvaluatedCapabilities = first.Capabilities
	}

	if op.StartedAt == "" {
		if q.TimeRange != nil && !q.TimeRange.Start.IsZero() {
			op.StartedAt = startEndString(q.TimeRange.Start)
		} else {
			op.StartedAt = startEndString(now)
		}
		op.FinishedAt = op.StartedAt
	}

	bundle.Operation = op
	bundle.Subject = sub
	bundle.Authorization = authz
	bundle.Decision = dec
}

func entTime(e AuditEntry) time.Time {
	t, err := time.Parse(time.RFC3339Nano, e.Time)
	if err != nil {
		return time.Time{}
	}
	return t
}

func startEndString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func auditActor(e AuditEntry) string {
	switch {
	case e.ClientCN != "":
		return e.ClientCN
	case e.PrincipalUid != "":
		return e.PrincipalUid
	case e.AgentId != "":
		return e.AgentId
	default:
		return ""
	}
}

func digestOf(hexDigest string) string {
	if hexDigest == "" {
		return ""
	}
	return evidenceSHA256Pf + hexDigest
}

type auditChainLine struct {
	signed SignedAuditEntry
	raw    []byte
}

func readAuditChainLines(file string, q EvidenceQuery) ([]auditChainLine, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []auditChainLine
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var signed SignedAuditEntry
		if err := json.Unmarshal([]byte(line), &signed); err != nil {
			continue
		}
		if !matchesAuditQuery(signed.Entry, q) {
			continue
		}
		out = append(out, auditChainLine{signed: signed, raw: []byte(line)})
	}
	if out == nil {
		out = make([]auditChainLine, 0)
	}
	return out, scanner.Err()
}

func matchesAuditQuery(e AuditEntry, q EvidenceQuery) bool {
	if q.OperationID != "" && e.TraceId != q.OperationID && e.TargetID != q.OperationID {
		return false
	}
	if q.DaHash != "" && e.DaHash != q.DaHash {
		return false
	}
	if q.AgentID != "" && e.AgentId != q.AgentID && e.ClientCN != q.AgentID {
		return false
	}
	if q.TimeRange != nil {
		t, err := time.Parse(time.RFC3339Nano, e.Time)
		if err != nil {
			return false
		}
		if !q.TimeRange.Start.IsZero() && t.Before(q.TimeRange.Start) {
			return false
		}
		if !q.TimeRange.End.IsZero() && t.After(q.TimeRange.End) {
			return false
		}
	}
	return true
}

func readSupervisionLines(file string, q EvidenceQuery) ([]EvidenceSupervisionEvent, error) {
	f, err := os.Open(file)
	if err != nil {
		if os.IsNotExist(err) {
			return make([]EvidenceSupervisionEvent, 0), nil
		}
		return nil, err
	}
	defer f.Close()

	var out []EvidenceSupervisionEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var signed SignedSupervisionEvent
		if err := json.Unmarshal([]byte(line), &signed); err != nil {
			continue
		}
		ev := signed.Event
		if !matchesSupervisionQuery(ev, SupervisionQuery{
			OperationID: q.OperationID,
			DaHash:      q.DaHash,
			AgentID:     q.AgentID,
			TimeRange:   q.TimeRange,
		}) {
			continue
		}
		supType := string(ev.Type)
		if supType == string(pki.SupervisionStepUp) {
			supType = "stepUp"
		}
		if supType == string(pki.SupervisionBreakGlass) {
			supType = "breakGlass"
		}
		out = append(out, EvidenceSupervisionEvent{
			Type:        supType,
			OccurredAt:  ev.Ts.UTC().Format(time.RFC3339Nano),
			Actor:       ev.Actor,
			DecisionRef: ev.OperationID,
			EvidenceRef: ev.EvidenceRef,
		})
	}
	if out == nil {
		out = make([]EvidenceSupervisionEvent, 0)
	}
	return out, scanner.Err()
}

func delegationModeString(mode int) string {
	if mode == int(DelegationRepresentative) {
		return "representative"
	}
	if mode == int(DelegationAuthorized) {
		return "authorized"
	}
	return ""
}

func outcomeOf(e AuditEntry) string {
	if e.DenyReason != "" || e.Action == string(ActionDenied) {
		return "deny"
	}
	return "permit"
}
