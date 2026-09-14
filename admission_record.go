// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 管线级裁决记录：让**每一次拒绝**都可记录，而不只是语言层的裁决。
//
// CLC 的 DecisionRecord 只能忠实地表达**语言层**的裁决（授权范围、参数、约束）。
// 管线在到达语言层之前就会拒绝很多请求 —— 没有凭据、证书链不可信、被撤销、
// 缺少能力、AIC 解析失败 —— 把这些硬塞进 CLC 记录会**说谎**：一条"空 grant ⇒
// capability_not_authorized"的重算结果会掩盖真正的原因（链不可信 ≠ 无权限）。
//
// 因此管线统一在**一个发射点**记录裁决，但按事实选择**诚实的记录类型**：
//
//	语言层裁决        → CLC DecisionRecord（可复算，predicateType = clc/v1/decision-record）
//	语言层之前的拒绝  → AdmissionRecord（本文件，predicateType = aic/v1/admission-record）
//
// 两者用同一个信封（DSSE/PAE + in-toto Statement）、同一个 sink、同一个 EvidenceContext，
// 所以"一次管线、一个发射点、多种诚实载荷"。AdmissionRecord 的 verdict 只有
// `refused`（它记录的是"未到达语言层的拒绝"），并携带**决定它的那些事实的摘要**。

package aicverifier

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/varwof/register/semantics"
)

// AdmissionRecordPredicateType identifies pipeline-level (pre-language) records.
const AdmissionRecordPredicateType = "https://varwof.com/aic/v1/admission-record"

// AdmissionRecordVersion is the record revision.
const AdmissionRecordVersion = "AIC-ADMISSION-RECORD-v1"

// AdmissionFact is one content-addressed fact that decided the outcome: the
// client certificate, the AIC extension, the requested operations, and so on.
// Only digests travel here — the material stays where it was verified.
type AdmissionFact struct {
	Type   string           `json:"type"`
	Digest semantics.Digest `json:"digest"`
	Note   string           `json:"note,omitempty"`
}

// AdmissionIdentity is who the request claimed to be, as far as the pipeline got.
type AdmissionIdentity struct {
	Principal string `json:"principal,omitempty"`
	AgentID   string `json:"agentId,omitempty"`
	Serial    string `json:"serial,omitempty"`
	SPIFFEID  string `json:"spiffeId,omitempty"`
}

// AdmissionRecord says what the pipeline decided before (or instead of) reaching
// the language layer, and why.  It never claims a CLC verdict.
type AdmissionRecord struct {
	Ver        string            `json:"ver"`
	Stage      string            `json:"stage"`
	Outcome    string            `json:"outcome"` // refused
	Reason     string            `json:"reason,omitempty"`
	RecorderID string            `json:"recorderId,omitempty"`
	At         time.Time         `json:"at"`
	Identity   AdmissionIdentity `json:"identity"`
	Facts      []AdmissionFact   `json:"facts,omitempty"`
}

// NewAdmissionRecord builds a pipeline-level record for a refusal.
func NewAdmissionRecord(ctx EvidenceContext, err *AuthError, facts []AdmissionFact) AdmissionRecord {
	reason := ""
	stage := "authenticate"
	if err != nil {
		reason = err.Message
		stage = err.Stage
		if stage == "" {
			stage = err.Code.String()
		}
	}
	return AdmissionRecord{
		Ver:        AdmissionRecordVersion,
		Stage:      stage,
		Outcome:    string(EvidenceRefused),
		Reason:     reason,
		RecorderID: ctx.RecorderID,
		At:         ctx.At.UTC(),
		Identity: AdmissionIdentity{
			Principal: ctx.Principal,
			AgentID:   ctx.AgentID,
			Serial:    ctx.Serial,
		},
		Facts: facts,
	}
}

// Digest identifies the record (over its canonical JSON).
func (r AdmissionRecord) Digest() (semantics.Digest, error) {
	return semantics.DigestOf(r)
}

// NewAdmissionEnvelope wraps the record in the same DSSE/in-toto envelope the
// CLC records use, with a pipeline-level predicate type.  A consumer that
// already speaks the envelope needs no new transport, only this predicate.
//
// The statement's subjects are the facts the refusal rested on (client
// certificate DER, AIC extension, ...), so the envelope is bound to the same
// material an in-toto consumer would expect — matched purely by digest.
func NewAdmissionEnvelope(rec AdmissionRecord) (semantics.Envelope, error) {
	subjects := make([]semantics.Subject, 0, len(rec.Facts))
	for _, f := range rec.Facts {
		alg, err := digestKey(f.Digest)
		if err != nil {
			continue
		}
		subjects = append(subjects, semantics.Subject{Name: f.Type, Digest: map[string]string{alg: hex.EncodeToString(f.Digest.Value)}})
	}
	payload, err := semantics.CanonicalJSON(struct {
		Type          string              `json:"_type"`
		Subject       []semantics.Subject `json:"subject"`
		PredicateType string              `json:"predicateType"`
		Predicate     AdmissionRecord     `json:"predicate"`
	}{
		Type:          semantics.StatementTypeInToto,
		Subject:       subjects,
		PredicateType: AdmissionRecordPredicateType,
		Predicate:     rec,
	})
	if err != nil {
		return semantics.Envelope{}, err
	}
	return semantics.Envelope{
		Payload:     payload,
		PayloadType: semantics.PayloadTypeInToto,
		Signatures:  []semantics.Signature{},
	}, nil
}

// ParseAdmissionEnvelope decodes and structurally checks a pipeline-level record.
func ParseAdmissionEnvelope(env semantics.Envelope) (AdmissionRecord, error) {
	if env.PayloadType != semantics.PayloadTypeInToto {
		return AdmissionRecord{}, fmt.Errorf("admission record: payload type %q", env.PayloadType)
	}
	var st struct {
		Type          string          `json:"_type"`
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(env.Payload, &st); err != nil {
		return AdmissionRecord{}, fmt.Errorf("admission record: %w", err)
	}
	if st.Type != semantics.StatementTypeInToto || st.PredicateType != AdmissionRecordPredicateType {
		return AdmissionRecord{}, fmt.Errorf("admission record: statement %q/%q", st.Type, st.PredicateType)
	}
	var rec AdmissionRecord
	if err := json.Unmarshal(st.Predicate, &rec); err != nil {
		return AdmissionRecord{}, fmt.Errorf("admission record: %w", err)
	}
	if rec.Ver != AdmissionRecordVersion || rec.Stage == "" || rec.Outcome == "" {
		return AdmissionRecord{}, fmt.Errorf("admission record: incomplete (%s/%s/%s)", rec.Ver, rec.Stage, rec.Outcome)
	}
	return rec, nil
}

// digestKey maps a CLC digest algorithm tag to the in-toto digest map key.
func digestKey(d semantics.Digest) (string, error) {
	switch d.Alg {
	case semantics.DigestAlgSHA256:
		return "sha256", nil
	case "sha-384":
		return "sha384", nil
	}
	return "", fmt.Errorf("admission record: unsupported digest algorithm %q", d.Alg)
}

// admissionRef names the record in the same shape as a CLC record reference.
func admissionRef(rec AdmissionRecord) (RecordRef, error) {
	digest, err := rec.Digest()
	if err != nil {
		return RecordRef{}, err
	}
	return RecordRef{Digest: hex.EncodeToString(digest.Value), Verdict: rec.Outcome}, nil
}

// EvidenceKind names which payload an envelope carries.
type EvidenceKind string

const (
	// KindDecision is a language-layer CLC decision record.
	KindDecision EvidenceKind = "clc-decision"
	// KindAdmission is a pipeline-level admission record.
	KindAdmission EvidenceKind = "aic-admission"
	// KindOutcome is an execution-boundary outcome record.
	KindOutcome EvidenceKind = "aic-outcome"
)

// CheckEvidenceEnvelope validates either payload type through one entry point,
// dispatching on the statement's predicate type.  A CLC record is checked by
// the language (structure, subject binding, re-computation); a pipeline record
// is parsed and shape-checked here.
func CheckEvidenceEnvelope(env semantics.Envelope) (EvidenceKind, error) {
	st, err := env.Statement()
	if err != nil {
		return "", err
	}
	switch st.PredicateType {
	case semantics.PredicateTypeCLCDecision:
		if err := env.Check(); err != nil {
			return KindDecision, err
		}
		return KindDecision, nil
	case AdmissionRecordPredicateType:
		if _, err := ParseAdmissionEnvelope(env); err != nil {
			return KindAdmission, err
		}
		return KindAdmission, nil
	case OutcomeRecordPredicateType:
		if _, err := ParseOutcomeEnvelope(env); err != nil {
			return KindOutcome, err
		}
		return KindOutcome, nil
	default:
		return "", fmt.Errorf("evidence: unknown predicate type %q", st.PredicateType)
	}
}
