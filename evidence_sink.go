// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 执行点留证据（第一版）。
//
// 裁决发生在接入点，证据也应该在接入点产生。  aic-verifier 已经握有构造
// CLC Decision Record 所需的全部输入：
//
//	AuthContext.OperationDecisions  → 每个操作的裁决/原因/残余义务
//	BuildSourceChain  → 字节背书的来源链（证书 DER 摘要）
//	DecisionContext   → RATS §10 新鲜度输入（显式时钟 / nonce / epoch）
//
// 这一层只做三件事：把每个来源的裁决**冻结成记录**、包成 DSSE/in-toto 信封、
// 交给 sink。  它不改任何语言语义，也不替消费方判定 —— 记录里的 verdict 是重跑
// 得来的，不是抄来的。
//
// **第一版的范围（刻意小）**：按来源分别记录（AIC 侧一条、PA 侧一条）。  合并裁决
// （deny-overrides）由 `semantics.Combine` 复算，尚未进入单条记录 —— 记录格式目前
// 只承载单一授权来源，这一点写在 README 里，不假装已覆盖。
//
// 默认关闭；在线只做裁决的部署不产生任何字节。

package aicverifier

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varwof/register/semantics"
)

// EvidenceOutcome says what happened to the request the record belongs to.
type EvidenceOutcome string

const (
	// EvidenceAdmitted means the request was admitted.
	EvidenceAdmitted EvidenceOutcome = "admitted"
	// EvidenceRefused means the request was refused (the record says why).
	EvidenceRefused EvidenceOutcome = "refused"
)

// EvidenceContext is what a sink needs to *use* a record: which request it came
// from, who it was about, and whether that request was admitted or refused.  The
// record itself carries the decision; this carries the correlation.
type EvidenceContext struct {
	// Facts are the content-addressed facts the outcome rested on; pipeline
	// records carry them into the statement's subjects.
	Facts       []AdmissionFact
	RecorderID  string
	OperationID string
	Method      string
	Path        string
	TraceID     string
	Principal   string
	AgentID     string
	Serial      string
	Outcome     EvidenceOutcome
	At          time.Time
}

// RecordRef is where a record ended up, so a caller can point at it (audit
// entry, downstream log, response) without carrying the whole record.
type RecordRef struct {
	Digest  string `json:"digest"`  // hex of the record's input digest
	Verdict string `json:"verdict"` // the CLC verdict recorded
	Path    string `json:"path,omitempty"`
}

// EvidenceSink receives a frozen decision record and its transport envelope,
// and reports where it kept it.  Implementations must be safe for concurrent
// use.
type EvidenceSink interface {
	// Emit receives a language-layer decision record.
	Emit(ctx EvidenceContext, rec semantics.DecisionRecord, env semantics.Envelope) (RecordRef, error)
	// EmitAdmission receives a pipeline-level record: a refusal that happened
	// before the language layer (credential, chain, revocation, missing
	// capability).  It is a separate method because it is a separate payload
	// type — a sink that only understands decisions can still implement it as
	// "store the envelope and move on".
	EmitAdmission(ctx EvidenceContext, rec AdmissionRecord, env semantics.Envelope) (RecordRef, error)
}

// EvidenceConfig turns on record emission at this admission point.
type EvidenceConfig struct {
	// Sink receives every record.  Nil uses SlogSink with the SDK logger.
	Sink EvidenceSink
	// Strict makes an emission failure deny the request (fail-closed).  The
	// default (false) logs and continues: the evidence layer is opt-in, and a
	// broken sink should not silently take a service down — a deployment that
	// needs the record more than the request sets this true.
	Strict bool
	// TTL, when non-zero, pins a RATS §10.1 explicit-clock freshness input on the
	// record (At=now, MaxAgeSec=TTL) in addition to the per-admission nonce that
	// every record carries (RATS §10.2).  Zero pins no clock: the record's context
	// then identifies the admission instance by nonce alone.
	TTL time.Duration
	// Audience names the relying party the evidence is addressed to.
	Audience string
	// RecorderID identifies this admission point when several of them record
	// the same traffic.  It is a deployment property, not a language field.
	RecorderID string
	// Now is injectable for tests.
	Now func() time.Time
	// OnError is called when emission fails, so a deployment can count or page
	// on evidence gaps instead of only finding them in a log.  Nil logs at
	// error level.
	OnError func(ctx EvidenceContext, err error)
	// Gaps, when set, counts every emission that failed to leave a record.  It
	// makes "the evidence layer itself lost evidence" a queryable meter (not a
	// log-scan archaeology problem): gap events call OnError for paging and
	// increment Gaps for reporting.  Nil disables the counter.
	Gaps *GapCounter
	// Sign, when set, appends a DSSE signature over PAE(payloadType, payload) to
	// every emitted envelope — decision, admission and outcome alike.  nil
	// (.default) leaves records unsigned: content-recomputable, but carrying no
	// key that endorses "which admission point issued this".  The signing
	// primitive is caller-supplied (DSSE deliberately does not pick one); KeyID
	// is an unauthenticated hint, never trusted on its own.  A signing failure
	// follows the existing emission rules: OnError is called, and Strict denies
	// the request.
	//
	// Prefer Signer over Sign for new deployments: Signer carries its own key id
	// and public key, so verification needs no separate key exchange.  Sign is
	// kept for callers that already hold a signing closure.
	Sign  func(pae []byte) ([]byte, error)
	KeyID string
	// Signer, when set, key-endorses every emitted envelope and supersedes
	// Sign/KeyID.  Supplying a key is all it takes to sign — there is no
	// separate on-switch, because an unsigned compliance record is exactly the
	// gap this closes.  Load one from a PEM file with LoadRecordSignerFile, or
	// wrap an HSM/KMS with NewRecordSigner.
	Signer *RecordSigner
	// SignKeyFile, when set and Signer is nil, is a PEM private key (PKCS#1 /
	// PKCS#8 / SEC1; RSA, ECDSA or Ed25519) loaded once when the handler is
	// built and used with KeyID.  It is sugar for Signer =
	// LoadRecordSignerFile(SignKeyFile, KeyID).
	SignKeyFile string
	// RequireSignature, when true, refuses to build without a signing key
	// (Signer / Sign / SignKeyFile): a deployment whose evidence is worthless
	// unless key-endorsed fails closed at configuration time, not silently at
	// read time.
	RequireSignature bool
	// EmitOutcome, when true, makes the request path report an outcome record
	// after every admitted request: the reverse proxy observes the backend
	// (a response → observed + status; a transport failure → indeterminate) and
	// the middleware observes the downstream handler (a returned handler →
	// observed + status).  It is an opt-in effect-side channel: classification
	// of executed/failed stays with the deployment.  The decision, admission
	// and standing evidence budget are unaffected.
	EmitOutcome bool
	// Requirement, when set, is bound into each record as its requirement
	// digest: a record then says *which* sufficiency bar was applied, not just
	// what was decided.
	Requirement *semantics.Requirement
	// Profile is the declared evidence shape (EvidenceProfile).  When set, every
	// emitted envelope is tagged with the profile's content-addressed identity,
	// so a consumer can tell which shape it received.
	Profile *EvidenceProfile
	// Recorder, when set, is published as an `evidence-recorder` subject: a
	// consumer holding the descriptor can tell which admission point emitted a
	// record, and one that does not can still tell whether two records came from
	// the same recorder.  RecorderID alone stays a display hint.
	Recorder *RecorderDescriptor
	// profileNoDecision is set by a profile that emits pipeline/outcome records
	// but not language-layer decision records.
	profileNoDecision bool
}

func (c *EvidenceConfig) now() time.Time {
	if c != nil && c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

// gap increments the evidence-gap counter, if one is wired in.  Callers invoke
// it exactly where the failure is reported (OnError / error log), so a gap is
// counted once per failed record.
func (c *EvidenceConfig) gap() {
	if c != nil && c.Gaps != nil {
		c.Gaps.Inc()
	}
}

// newEvidenceNonce mints the per-admission instance identifier that is bound
// into every decision record's context (RATS §10.2 implicit timekeeping).  It
// makes a record's input digest identify one *execution instance*, so an
// outcome record can only ever point back at the exact admission it followed.
// crypto/rand supplies the unpredictable value; the fallback is a monotonic
// timestamp whose collision odds are negligible but must never silently read
// as entropy (hence the distinct prefix).
func newEvidenceNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err == nil {
		return hex.EncodeToString(b)
	}
	return "nonce-" + strconv.FormatInt(time.Now().UnixNano(), 16)
}

// GapCounter is an atomically counted evidence-gap meter: how often an emission
// that was supposed to leave a record failed to do so.  Safe for concurrent
// use from any number of admission points.
type GapCounter struct {
	n atomic.Int64
}

// Inc registers one failed emission.
func (g *GapCounter) Inc() {
	if g == nil {
		return
	}
	g.n.Add(1)
}

// Count returns how many emissions failed to leave a record since the counter
// was created.
func (g *GapCounter) Count() int64 {
	if g == nil {
		return 0
	}
	return g.n.Load()
}

// SlogSink writes a compact summary of each record to a structured logger.
type SlogSink struct {
	Logger *slog.Logger
}

// Emit implements EvidenceSink.
func (s SlogSink) Emit(ctx EvidenceContext, rec semantics.DecisionRecord, env semantics.Envelope) (RecordRef, error) {
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	sum := sha256.Sum256(append([]byte(rec.Verdict), rec.InputDigest.Value...))
	logger.Info("clc decision record",
		"recorder", ctx.RecorderID,
		"outcome", ctx.Outcome,
		"operation", ctx.OperationID,
		"method", ctx.Method,
		"path", ctx.Path,
		"trace_id", ctx.TraceID,
		"principal", ctx.Principal,
		"agent", ctx.AgentID,
		"verdict", rec.Verdict,
		"reason", rec.Reason,
		"unresolved", rec.Constraints.Unresolved,
		"input_digest", hex.EncodeToString(rec.InputDigest.Value),
		"record_fingerprint", hex.EncodeToString(sum[:]),
		"signatures", len(env.Signatures),
	)
	return RecordRef{Digest: hex.EncodeToString(rec.InputDigest.Value), Verdict: rec.Verdict}, nil
}

// EmitAdmission implements EvidenceSink for pipeline-level records.
func (s SlogSink) EmitAdmission(ctx EvidenceContext, rec AdmissionRecord, env semantics.Envelope) (RecordRef, error) {
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	ref, err := admissionRef(rec)
	if err != nil {
		return RecordRef{}, err
	}
	logger.Info("aic admission record",
		"recorder", ctx.RecorderID,
		"stage", rec.Stage,
		"outcome", rec.Outcome,
		"reason", rec.Reason,
		"operation", ctx.OperationID,
		"method", ctx.Method,
		"path", ctx.Path,
		"principal", ctx.Principal,
		"agent", ctx.AgentID,
		"digest", ref.Digest,
		"facts", len(rec.Facts),
	)
	return ref, nil
}

// EmitOutcome implements OutcomeSink for the structured-logger fallback.
func (s SlogSink) EmitOutcome(ctx EvidenceContext, rec OutcomeRecord, env semantics.Envelope) (RecordRef, error) {
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	ref := RecordRef{Verdict: rec.Outcome}
	if d, err := rec.Digest(); err == nil {
		ref.Digest = hex.EncodeToString(d.Value)
	}
	logger.Info("aic outcome record",
		"recorder", ctx.RecorderID,
		"outcome", rec.Outcome,
		"status", rec.StatusCode,
		"decision_digest", rec.DecisionDigest,
		"operation", ctx.OperationID,
		"method", ctx.Method,
		"path", ctx.Path,
		"principal", ctx.Principal,
		"agent", ctx.AgentID,
		"digest", ref.Digest,
	)
	return ref, nil
}

// FileSink writes one DSSE envelope per record, named by its input digest so the
// same decision recorded twice overwrites itself instead of accumulating.
type FileSink struct {
	Dir string
	// RecorderID is prefixed to the file name when set.
	RecorderID string

	mu sync.Mutex
}

// Emit implements EvidenceSink.
func (s *FileSink) Emit(ctx EvidenceContext, rec semantics.DecisionRecord, env semantics.Envelope) (RecordRef, error) {
	if s.Dir == "" {
		return RecordRef{}, errors.New("evidence: FileSink needs a directory")
	}
	body, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return RecordRef{}, err
	}
	name := hex.EncodeToString(rec.InputDigest.Value)
	if s.RecorderID != "" {
		name = s.RecorderID + "-" + name
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return RecordRef{}, err
	}
	path := filepath.Join(s.Dir, name+".json")
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		return RecordRef{}, err
	}
	return RecordRef{Digest: hex.EncodeToString(rec.InputDigest.Value), Verdict: rec.Verdict, Path: path}, nil
}

// EmitAdmission implements EvidenceSink for pipeline-level records; the file
// name carries an "admission-" marker so the two payload types never collide.
func (s *FileSink) EmitAdmission(ctx EvidenceContext, rec AdmissionRecord, env semantics.Envelope) (RecordRef, error) {
	if s.Dir == "" {
		return RecordRef{}, errors.New("evidence: FileSink needs a directory")
	}
	body, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return RecordRef{}, err
	}
	ref, err := admissionRef(rec)
	if err != nil {
		return RecordRef{}, err
	}
	name := "admission-" + ref.Digest
	if s.RecorderID != "" {
		name = s.RecorderID + "-" + name
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return RecordRef{}, err
	}
	path := filepath.Join(s.Dir, name+".json")
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		return RecordRef{}, err
	}
	ref.Path = path
	return ref, nil
}

// EmitOutcome implements OutcomeSink for pipelines that want every artifact on
// disk; the file name carries an "outcome-" marker so the payload types never
// collide.
func (s *FileSink) EmitOutcome(ctx EvidenceContext, rec OutcomeRecord, env semantics.Envelope) (RecordRef, error) {
	if s.Dir == "" {
		return RecordRef{}, errors.New("evidence: FileSink needs a directory")
	}
	body, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return RecordRef{}, err
	}
	digest, err := rec.Digest()
	if err != nil {
		return RecordRef{}, err
	}
	name := "outcome-" + hex.EncodeToString(digest.Value)
	if s.RecorderID != "" {
		name = s.RecorderID + "-" + name
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return RecordRef{}, err
	}
	path := filepath.Join(s.Dir, name+".json")
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		return RecordRef{}, err
	}
	return RecordRef{Digest: hex.EncodeToString(digest.Value), Verdict: rec.Outcome, Path: path}, nil
}

// evidenceRecorders returns the per-source grant sets this admission decided
// over, in the same shape AuthorizeOperation used (AIC capabilities plus the
// connection's authorization constraints; PA grants otherwise).
func evidenceRecorders(aic *AIC, pa *PrincipalAuthorization) map[string][]semantics.Grant {
	out := map[string][]semantics.Grant{}
	if aic != nil {
		if grants, err := ToGrantSet(aic.Capabilities); err == nil {
			if cs := ConstraintStrings(aic.AuthorizationConstraints); len(cs) > 0 {
				for i := range grants {
					grants[i].Constraints = append(grants[i].Constraints, cs...)
				}
			}
			out["aic"] = grants
		}
	}
	if pa != nil {
		if grants, err := ToGrantSet(pa.Grants); err == nil {
			if cs := ConstraintStrings(pa.AuthorizationConstraints); len(cs) > 0 {
				for i := range grants {
					grants[i].Constraints = append(grants[i].Constraints, cs...)
				}
			}
			out["principal-authorization"] = grants
		}
	}
	return out
}

// EmitOperationEvidence freezes and (when configured) signs one CLC decision
// record for a single projected operation, returning where it went.  It is the
// execution-boundary entry point (aic-exec): a component that adjudicates a
// concrete operation outside the admission pipeline leaves the same replayable
// record the pipeline would, without carrying the whole pipeline's inputs.  The
// record's verdict is recomputed from aic's grants, so a record that does not
// reproduce is impossible by construction.
func EmitOperationEvidence(cfg *EvidenceConfig, ctx EvidenceContext, cert *x509.Certificate, aic *AIC, op OperationDecision) ([]RecordRef, error) {
	return EmitDecisionRecords(cfg, ctx, cert, aic, nil, nil, []OperationDecision{op})
}

// EmitDecisionRecords freezes one record per (source, operation) and hands it to
// the sink, returning where each record went.  The verdict in each record is
// recomputed by RecordWith from the same grants and operation, so a record that
// does not reproduce is impossible by construction.
//
// sinkCtx carries the correlation (which request, who, admitted or refused);
// the per-operation fields are filled in here.
func EmitDecisionRecords(cfg *EvidenceConfig, sinkCtx EvidenceContext, cert *x509.Certificate, aic *AIC, pa *PrincipalAuthorization, userCert *x509.Certificate, ops []OperationDecision) ([]RecordRef, error) {
	if cfg == nil || len(ops) == 0 {
		return nil, nil
	}
	sink := cfg.Sink
	if sink == nil {
		sink = SlogSink{}
	}
	if cfg.profileNoDecision {
		return nil, nil
	}
	recorders := evidenceRecorders(aic, pa)
	if len(recorders) == 0 {
		return nil, nil
	}
	var sources *semantics.SourceChain
	if chain, err := BuildSourceChain(cert, aic, userCert); err == nil {
		sources = chain
	}

	// Every admission gets its own unpredictable nonce bound into the decision
	// context, whether or not a clock is pinned: the record digest is then
	// unique per admission *instance*, not per (grant, operation) tuple.  This
	// is what makes an outcome's decisionDigest point at exactly one execution
	// instead of "whichever identical decision happened to be recorded first" —
	// a TTL of zero must not collapse two identical requests into one
	// undistinguishable digest.  The TTL pin stays what it always was: explicit
	// timekeeping when configured, and only implicit (nonce) timekeeping when
	// not (RATS §10.2).
	instanceCtx := semantics.DecisionContext{Nonce: newEvidenceNonce()}
	if cfg.TTL > 0 {
		instanceCtx.At = cfg.now()
		instanceCtx.MaxAgeSec = int64(cfg.TTL.Seconds())
	}
	opts := semantics.RecordOptions{Context: &instanceCtx, Sources: sources, Requirement: cfg.Requirement}

	base := sinkCtx
	if base.At.IsZero() {
		base.At = cfg.now()
	}
	if base.RecorderID == "" {
		base.RecorderID = cfg.RecorderID
	}

	var refs []RecordRef
	for _, od := range ops {
		op := semantics.Operation{ID: od.ID, Params: od.Params}
		for _, name := range recorderNames(recorders) {
			rec, err := semantics.RecordWith(recorders[name], op, opts)
			if err != nil {
				return refs, fmt.Errorf("evidence: %s: %w", name, err)
			}
			env, err := semantics.NewEnvelope(rec)
			if err != nil {
				return refs, fmt.Errorf("evidence: %s: %w", name, err)
			}
			if env, err = tagEnvelope(env, cfg.Profile, cfg.recorder()); err != nil {
				return refs, fmt.Errorf("evidence: %s: %w", name, err)
			}
			if env, err = signEnvelope(env, cfg); err != nil {
				return refs, fmt.Errorf("evidence: %s: %w", name, err)
			}
			emitCtx := base
			emitCtx.OperationID = od.ID
			if emitCtx.Outcome == "" {
				emitCtx.Outcome = EvidenceAdmitted
				if od.Verdict == semantics.VerdictDeny {
					emitCtx.Outcome = EvidenceRefused
				}
			}
			ref, err := sink.Emit(emitCtx, rec, env)
			if err != nil {
				return refs, fmt.Errorf("evidence: %s: %w", name, err)
			}
			refs = append(refs, ref)
		}
	}
	return refs, nil
}

// recorderNames returns the recorder names in a stable order (AIC first, then
// the principal authorization) so a run produces the same files in the same
// sequence.
func recorderNames(recorders map[string][]semantics.Grant) []string {
	out := make([]string, 0, len(recorders))
	if _, ok := recorders["aic"]; ok {
		out = append(out, "aic")
	}
	if _, ok := recorders["principal-authorization"]; ok {
		out = append(out, "principal-authorization")
	}
	return out
}

// LoadEvidenceRecord reads a DSSE envelope written by FileSink and returns the
// decision record it carries, checking both the envelope (structure, subject
// binding) and the record (re-computation) on the way.  It is the bridge from
// the emission side to the reporting side: an EvidenceBundle gets its authority
// from this record.
func LoadEvidenceRecord(path string) (*semantics.DecisionRecord, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env semantics.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("evidence: %s is not an envelope: %w", path, err)
	}
	if err := env.Check(); err != nil {
		return nil, fmt.Errorf("evidence: %s: %w", path, err)
	}
	rec, err := env.DecisionRecord()
	if err != nil {
		return nil, fmt.Errorf("evidence: %s: %w", path, err)
	}
	if err := rec.Verify(); err != nil {
		return nil, fmt.Errorf("evidence: %s does not reproduce: %w", path, err)
	}
	return &rec, nil
}

// recorder returns the descriptor to publish, defaulting to one derived from
// RecorderID so a deployment that only set an id still gets a stable identity.
func (c *EvidenceConfig) recorder() *RecorderDescriptor {
	if c == nil {
		return nil
	}
	if c.Recorder != nil {
		return c.Recorder
	}
	if c.RecorderID != "" {
		return &RecorderDescriptor{ID: c.RecorderID, Kind: "aic-verifier"}
	}
	return nil
}

// recordRefusal freezes an AdmissionRecord for a refusal that never reached the
// language layer and hands it to the configured sink.  It is the single
// emission point for AdmissionRecords: the middleware's pre-language refusals
// (refusalEvidence) and the reverse proxy's post-admission policy refusals
// (Server.denialEvidence) both go through it.  A failure is reported through
// OnError and logged when no callback is set; the strict decision belongs to
// the caller (the middleware can still deny, the proxy records after the fact).
func recordRefusal(cfg *EvidenceConfig, log *slog.Logger, ctx EvidenceContext, err *AuthError) []RecordRef {
	rec := NewAdmissionRecord(ctx, err, ctx.Facts)
	env, envErr := NewAdmissionEnvelope(rec)
	if envErr == nil {
		env, envErr = tagEnvelope(env, cfg.Profile, cfg.recorder())
	}
	if envErr == nil {
		env, envErr = signEnvelope(env, cfg)
	}
	var ref RecordRef
	if envErr == nil {
		sink := cfg.Sink
		if sink == nil {
			sink = SlogSink{Logger: log}
		}
		ref, envErr = sink.EmitAdmission(ctx, rec, env)
		if envErr == nil {
			return []RecordRef{ref}
		}
	}
	if cfg.OnError != nil {
		cfg.gap()
		cfg.OnError(ctx, envErr)
	} else {
		logger := log
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("aic-verifier: admission record failed", "error", envErr, "path", ctx.Path)
		cfg.gap()
	}
	return nil
}
