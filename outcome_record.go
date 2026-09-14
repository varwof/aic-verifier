// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 效果侧接口：SDK **只留接口，不定语义**。
//
// CLC 止于"授权裁决"；"动作真的执行了吗、结果是什么、效果是否不可逆"属于执行边界
// （EMILIA AEB §5.6/§5.7 那一段的领地）。这里刻意只做三件事：
//
//	1. 定义**效果记录的形状**（OutcomeRecord）——够小、够诚实，不冒充裁决；
//	2. 提供**发送入口**（ReportOutcome），让部署把效果证据挂到同一条链上；
//	3. 用 `decisionDigest` 把效果**指回它依据的那条裁决记录** —— 这是最有价值的一环：
//	   "这个效果是跟着那条裁决发生的"，而不是两段互不相干的日志。
//
// 我们**不**定义 EXECUTED/FAILED/INDETERMINATE 的判定规则（那是 AEB 的词汇与职责），
// 也不观察副作用：`Outcome` 是部署给定的字符串，SDK 只搬运它。

package aicverifier

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/varwof/register/semantics"
)

// OutcomeRecordPredicateType identifies execution-boundary records.
const OutcomeRecordPredicateType = "https://varwof.com/aic/v1/outcome-record"

// OutcomeRecordVersion is the record revision.
const OutcomeRecordVersion = "AIC-OUTCOME-RECORD-v1"

// Recommended outcome tokens.  The field is a plain string: the vocabulary
// belongs to the execution boundary (AEB), not to this SDK.
const (
	// OutcomeExecuted means the executor established that the effect occurred.
	OutcomeExecuted = "executed"
	// OutcomeFailed means it established the effect did not occur.
	OutcomeFailed = "failed"
	// OutcomeIndeterminate means it could not establish either.
	OutcomeIndeterminate = "indeterminate"
	// OutcomeObserved means a response was observed but the deployment has not
	// classified the effect (the honest default for a proxy that only saw HTTP).
	OutcomeObserved = "observed"
)

// OutcomeRecord says what the execution boundary observed, and which decision it
// followed.  It is evidence about the effect, not about authority.
type OutcomeRecord struct {
	Ver     string    `json:"ver"`
	Outcome string    `json:"outcome"`
	At      time.Time `json:"at"`
	// DecisionDigest points back at the decision record this outcome followed
	// (hex of that record's input digest).  Empty means the linkage was not
	// established — which a consumer should treat as a gap, not as consent.
	DecisionDigest string `json:"decisionDigest,omitempty"`
	// OperationID is the action this outcome is about.
	OperationID string `json:"operationId,omitempty"`
	// RecorderID identifies the execution boundary that reported it.
	RecorderID string `json:"recorderId,omitempty"`
	// StatusCode is the transport-level result when there was one (HTTP).
	StatusCode int `json:"statusCode,omitempty"`
	// Note is a bounded, deployment-supplied description.
	Note string `json:"note,omitempty"`
	// Identity is who executed it, as the boundary established it.
	Identity AdmissionIdentity `json:"identity,omitempty"`
	// Facts are the digests of the material the outcome rests on.
	Facts []AdmissionFact `json:"facts,omitempty"`
}

// OutcomeSink receives execution-boundary records.  A deployment that has no
// execution boundary simply does not configure one.
type OutcomeSink interface {
	EmitOutcome(ctx EvidenceContext, rec OutcomeRecord, env semantics.Envelope) (RecordRef, error)
}

// NewOutcomeEnvelope wraps the record in the same DSSE/in-toto envelope used by
// the decision and admission records; only the predicate type differs.
func NewOutcomeEnvelope(rec OutcomeRecord) (semantics.Envelope, error) {
	subjects := make([]semantics.Subject, 0, len(rec.Facts))
	for _, f := range rec.Facts {
		alg, err := digestKey(f.Digest)
		if err != nil {
			continue
		}
		subjects = append(subjects, semantics.Subject{Name: f.Type, Digest: map[string]string{alg: hexOf(f.Digest.Value)}})
	}
	payload, err := semantics.CanonicalJSON(struct {
		Type          string              `json:"_type"`
		Subject       []semantics.Subject `json:"subject"`
		PredicateType string              `json:"predicateType"`
		Predicate     OutcomeRecord       `json:"predicate"`
	}{
		Type:          semantics.StatementTypeInToto,
		Subject:       subjects,
		PredicateType: OutcomeRecordPredicateType,
		Predicate:     rec,
	})
	if err != nil {
		return semantics.Envelope{}, err
	}
	return semantics.Envelope{Payload: payload, PayloadType: semantics.PayloadTypeInToto, Signatures: []semantics.Signature{}}, nil
}

// ParseOutcomeEnvelope decodes and shape-checks an outcome record.
func ParseOutcomeEnvelope(env semantics.Envelope) (OutcomeRecord, error) {
	rec, err := parsePredicate[OutcomeRecord](env, OutcomeRecordPredicateType)
	if err != nil {
		return OutcomeRecord{}, err
	}
	if rec.Ver != OutcomeRecordVersion || rec.Outcome == "" {
		return OutcomeRecord{}, fmt.Errorf("outcome record: incomplete (%s/%s)", rec.Ver, rec.Outcome)
	}
	return rec, nil
}

// parsePredicate decodes an envelope whose predicate is T, checking the
// statement's predicate type first.  It is shared by the pipeline-level and
// outcome records, which both ride the same envelope but carry different
// payloads.
func parsePredicate[T any](env semantics.Envelope, want string) (T, error) {
	var zero T
	if env.PayloadType != semantics.PayloadTypeInToto {
		return zero, fmt.Errorf("evidence: payload type %q", env.PayloadType)
	}
	var st struct {
		Type          string          `json:"_type"`
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(env.Payload, &st); err != nil {
		return zero, fmt.Errorf("evidence: %w", err)
	}
	if st.Type != semantics.StatementTypeInToto || st.PredicateType != want {
		return zero, fmt.Errorf("evidence: statement %q/%q, want %q", st.Type, st.PredicateType, want)
	}
	var out T
	if err := json.Unmarshal(st.Predicate, &out); err != nil {
		return zero, fmt.Errorf("evidence: %w", err)
	}
	return out, nil
}

// recordDigest identifies the outcome record.
func (r OutcomeRecord) Digest() (semantics.Digest, error) { return semantics.DigestOf(r) }

// ReportOutcome sends an outcome record through the deployment's sink, filling
// in the recorder and timestamp when the caller left them out.
func ReportOutcome(sink OutcomeSink, cfg *EvidenceConfig, ctx EvidenceContext, rec OutcomeRecord) (RecordRef, error) {
	if sink == nil {
		return RecordRef{}, fmt.Errorf("outcome record: no sink configured")
	}
	if rec.Ver == "" {
		rec.Ver = OutcomeRecordVersion
	}
	if rec.At.IsZero() {
		rec.At = ctx.At
	}
	if rec.At.IsZero() {
		if cfg != nil {
			rec.At = cfg.now()
		} else {
			rec.At = time.Now().UTC()
		}
	}
	if rec.RecorderID == "" {
		rec.RecorderID = ctx.RecorderID
	}
	env, err := NewOutcomeEnvelope(rec)
	if err != nil {
		return RecordRef{}, err
	}
	if cfg != nil {
		if env, err = tagEnvelope(env, cfg.Profile, cfg.recorder()); err != nil {
			return RecordRef{}, err
		}
	}
	if env, err = signEnvelope(env, cfg); err != nil {
		return RecordRef{}, err
	}
	ref, err := sink.EmitOutcome(ctx, rec, env)
	if err != nil {
		return RecordRef{}, err
	}
	if ref.Verdict == "" {
		ref.Verdict = rec.Outcome
	}
	return ref, nil
}

// hexOf is a tiny local helper so the envelope builder stays readable.
func hexOf(b []byte) string { return hex.EncodeToString(b) }
