// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// P2-7：批量校验与缺口计数。单条 LoadEvidenceRecord 之外补一个目录级的校验入口：
// 按 predicateType 分派三类载荷（decision / admission / outcome），返回每类计数与
// 失败清单。配合 EvidenceConfig.Gaps（缺口计数）让“没留上证据”这件事在证据体系里
// 可见，而不是只在日志里。

package aicverifier

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/varwof/register/semantics"
)

// EvidenceFailure names one file that did not verify and why.
type EvidenceFailure struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// EvidenceVerifyReport is the aggregated result of VerifyEvidenceDir.
type EvidenceVerifyReport struct {
	// Total is the number of record envelopes scanned.
	Total int
	// Decision / Admission / Outcome are the per-kind record counts.  Outcome
	// counts only outcomes whose decisionDigest resolved to a decision record
	// in the same directory: an orphan (unresolved) outcome is counted
	// separately and reported as a gap, never as consent.
	Decision  int
	Admission int
	Outcome   int
	// OrphanOutcome is the number of outcome records whose decisionDigest was
	// empty or did not resolve to a decision record in this directory.  Each
	// orphan is also listed in Failures with the file path, so a linkage gap is
	// as visible as a record that does not verify.
	OrphanOutcome int
	// Failures lists every file that did not verify: malformed JSON, an
	// envelope of an unknown predicate type, a decision that no longer
	// recomputes, an outcome whose decisionDigest does not resolve, or (when
	// verify was supplied) a record with no valid signature.  Empty means the
	// directory verified clean — and every outcome in it is linked.
	Failures []EvidenceFailure
}

// VerifyEvidenceDir scans dir for evidence record envelopes and verifies each
// one, dispatching on its statement's predicate type: a CLC decision must
// re-compute, and an admission / outcome record must parse and be
// shape-invariant (see CheckEvidenceEnvelope).  Outcomes are additionally
// checked for linkage: their decisionDigest must resolve to a decision record
// found in the same directory, or they are counted as orphans and listed in
// Failures — an outcome that cannot be tied to the decision it claims to have
// followed is a gap, not consent.  When verify is non-nil, every envelope must
// also carry at least one signature that verifies over its DSSE PAE (see
// VerifyEvidenceEnvelope).  A deployment that already trusts the emission
// point's key passes VerifyFnFromPublicKey here and the key question is settled
// without writing crypto.
//
// The scan is best-effort per file: a broken or unrecognized file is collected
// in Failures, not returned as an error — an evidence directory with one bad
// record must be auditable, not unreadable.  Only a failure to read the
// directory itself surfaces as (Report{}, err).  A directory without records
// verifies clean (all-zero report).
func VerifyEvidenceDir(dir string, verify func(keyID string, pae, sig []byte) error) (EvidenceVerifyReport, error) {
	var rep EvidenceVerifyReport
	entries, err := os.ReadDir(dir)
	if err != nil {
		return rep, err
	}
	// First pass: classify every envelope and freeze the decision digests the
	// outcomes must point at.  Outcomes are collected and linked in the second
	// pass, once the decision set is complete.
	decisionSet := map[string]bool{}
	var outcomes []struct {
		path string
		env  semantics.Envelope
	}
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, de.Name())
		env, err := loadEvidenceEnvelope(path)
		if err != nil {
			rep.Failures = append(rep.Failures, EvidenceFailure{Path: path, Reason: err.Error()})
			continue
		}
		kind, err := VerifyEvidenceEnvelope(env, verify)
		if err != nil {
			rep.Failures = append(rep.Failures, EvidenceFailure{Path: path, Reason: err.Error()})
			continue
		}
		switch kind {
		case KindDecision:
			rec, err := env.DecisionRecord()
			if err != nil {
				rep.Failures = append(rep.Failures, EvidenceFailure{Path: path, Reason: err.Error()})
				continue
			}
			rep.Decision++
			rep.Total++
			decisionSet[hex.EncodeToString(rec.InputDigest.Value)] = true
		case KindAdmission:
			rep.Admission++
			rep.Total++
		case KindOutcome:
			outcomes = append(outcomes, struct {
				path string
				env  semantics.Envelope
			}{path: path, env: env})
		}
	}
	// Second pass: outcome linkage.  An outcome verifies only when its
	// decisionDigest names a decision record that is present in this set.
	for _, o := range outcomes {
		rep.Total++
		rec, err := ParseOutcomeEnvelope(o.env)
		if err != nil {
			rep.Failures = append(rep.Failures, EvidenceFailure{Path: o.path, Reason: err.Error()})
			continue
		}
		if rec.DecisionDigest == "" || !decisionSet[rec.DecisionDigest] {
			rep.OrphanOutcome++
			rep.Failures = append(rep.Failures, EvidenceFailure{
				Path:   o.path,
				Reason: fmt.Sprintf("outcome decisionDigest %q does not resolve to a decision record in this set", rec.DecisionDigest),
			})
			continue
		}
		rep.Outcome++
	}
	return rep, nil
}

// loadEvidenceEnvelope reads a FileSink envelope as generic DSSE.
func loadEvidenceEnvelope(path string) (semantics.Envelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return semantics.Envelope{}, err
	}
	var env semantics.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return semantics.Envelope{}, fmt.Errorf("parse envelope: %w", err)
	}
	return env, nil
}
