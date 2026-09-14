// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 证据 profile：把"这个部署出**哪种形状**的证据"变成一个可声明的名字。
//
// 没有 profile 时，形状是散在配置里的（TTL 决定有没有上下文、Sources 总是带上、需求单开一个字段），
// 于是"我们出的是哪一种证据"这句话只能靠读代码回答。加上 profile 之后：
//
//	Config.EvidenceProfile = "clc-decision+admission+outcome@1"
//
// 就有了一个**具名、有版本、可校验**的答案，而且：
//
//   - 消费方看得出收到的是哪种形状（profile 以内容寻址的 subject 进信封）；
//   - 换形状 = 换 profile（或加一个 adapter），**不用改裁决路径**——这正是
//     "Iman 要别的格式就改代码"这句承诺的落点；
//   - 未知 profile 名 = 配置错误（fail-closed），不是"尽力而为"。
//
// 容器（目前只有 DSSE/in-toto 信封）也是 profile 的一个字段：换容器同样是一个值，
// 而不是散落各处的改动。

package aicverifier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/varwof/register/semantics"
)

// EvidenceContainer names the envelope shape.
type EvidenceContainer string

const (
	// ContainerDSSEInToto is the DSSE JSON envelope carrying an in-toto
	// Statement.  It is the only container implemented today.
	ContainerDSSEInToto EvidenceContainer = "dsse+in-toto"
)

// EvidenceProfile declares which evidence a deployment emits.
type EvidenceProfile struct {
	// Name is the profile identifier, e.g. "clc-decision+admission+outcome@1".
	Name string
	// Container is the envelope shape.
	Container EvidenceContainer
	// Decision emits CLC decision records (the language layer).
	Decision bool
	// Admission emits pipeline-level records for refusals that never reached the
	// language layer.
	Admission bool
	// Outcome allows an execution-boundary sink to report effect records.
	Outcome bool
	// Sources includes the authorization source chain in decision records.
	Sources bool
	// Freshness pins a RATS §10 explicit clock on each record for this duration
	// (0 = no context).
	Freshness time.Duration
	// Requirement binds the relying party's sufficiency bar into each record.
	Requirement *semantics.Requirement
}

// builtinProfiles are the named shapes this SDK knows.
var builtinProfiles = map[string]EvidenceProfile{
	// Decision only: the smallest useful shape — a replayable record per
	// language-layer decision, no pipeline or effect records.
	"clc-decision@1": {
		Name: "clc-decision@1", Container: ContainerDSSEInToto, Decision: true, Sources: true,
	},
	// Decision + admission: every refusal is recorded too, in its honest payload
	// type.
	"clc-decision+admission@1": {
		Name: "clc-decision+admission@1", Container: ContainerDSSEInToto, Decision: true, Admission: true, Sources: true,
	},
	// The full chain: decision + admission + effect.
	"clc-decision+admission+outcome@1": {
		Name: "clc-decision+admission+outcome@1", Container: ContainerDSSEInToto,
		Decision: true, Admission: true, Outcome: true, Sources: true,
	},
}

// LookupEvidenceProfile resolves a named profile.  An unknown name is an error:
// a deployment that asks for a shape we do not produce must hear about it at
// configuration time, not discover it later from missing records.
func LookupEvidenceProfile(name string) (EvidenceProfile, error) {
	if p, ok := builtinProfiles[name]; ok {
		return p, nil
	}
	known := make([]string, 0, len(builtinProfiles))
	for k := range builtinProfiles {
		known = append(known, k)
	}
	sort.Strings(known)
	return EvidenceProfile{}, fmt.Errorf("evidence profile: unknown %q (known: %s)", name, strings.Join(known, ", "))
}

// Validate checks the profile's own consistency.
func (p EvidenceProfile) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("evidence profile: name required")
	}
	switch p.Container {
	case "", ContainerDSSEInToto:
	default:
		return fmt.Errorf("evidence profile: unsupported container %q", p.Container)
	}
	if p.Freshness < 0 {
		return fmt.Errorf("evidence profile: negative freshness")
	}
	if !p.Decision && !p.Admission && !p.Outcome {
		return fmt.Errorf("evidence profile: %s emits nothing", p.Name)
	}
	if p.Requirement != nil {
		if err := p.Requirement.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// ID is the profile's identity, content-addressed over everything that shapes
// the emitted bytes.  Two deployments that emit the same shape share an ID.
func (p EvidenceProfile) ID() (semantics.Digest, error) {
	if err := p.Validate(); err != nil {
		return semantics.Digest{}, err
	}
	return semantics.DigestOf(struct {
		Name         string                 `json:"name"`
		Container    string                 `json:"container"`
		Decision     bool                   `json:"decision"`
		Admission    bool                   `json:"admission"`
		Outcome      bool                   `json:"outcome"`
		Sources      bool                   `json:"sources"`
		FreshnessSec int64                  `json:"freshnessSec"`
		Requirement  *semantics.Requirement `json:"requirement,omitempty"`
	}{
		Name: p.Name, Container: string(p.Container), Decision: p.Decision, Admission: p.Admission,
		Outcome: p.Outcome, Sources: p.Sources, FreshnessSec: int64(p.Freshness.Seconds()), Requirement: p.Requirement,
	})
}

// Apply fills an EvidenceConfig from the profile.  The plumbing (sink, strict,
// error hook, recorder id) stays with the deployment; the shape comes from here.
func (p EvidenceProfile) Apply(cfg *EvidenceConfig) (*EvidenceConfig, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if !p.Decision {
		// A profile without decision records still needs the config object for
		// admission/outcome records, but must not emit language-layer records.
		if cfg == nil {
			cfg = &EvidenceConfig{}
		}
		cfg.profileNoDecision = true
		cfg.EmitOutcome = p.Outcome
		return cfg, nil
	}
	if cfg == nil {
		cfg = &EvidenceConfig{}
	}
	cfg.Profile = &p
	cfg.TTL = p.Freshness
	cfg.EmitOutcome = p.Outcome
	if p.Requirement != nil {
		cfg.Requirement = p.Requirement
	}
	return cfg, nil
}

// RecorderDescriptor identifies the admission point that emitted a record.  It
// is published out of band (one descriptor per deployment); the envelope then
// carries its digest as a subject, so a consumer holding the descriptor can tell
// which recorder produced the record — and one that does not hold it can still
// tell that two records came from the same or different recorders.
type RecorderDescriptor struct {
	ID   string `json:"id"`
	Kind string `json:"kind,omitempty"`
	Note string `json:"note,omitempty"`
}

// Digest is the recorder's content-addressed identity.
func (r RecorderDescriptor) Digest() (semantics.Digest, error) {
	if r.ID == "" {
		return semantics.Digest{}, fmt.Errorf("recorder descriptor: id required")
	}
	return semantics.DigestOf(r)
}

// subjectNameProfile / subjectNameRecorder name the two provenance subjects.
const (
	subjectNameProfile  = "evidence-profile"
	subjectNameRecorder = "evidence-recorder"
)

// tagEnvelope adds the profile's and the recorder's content-addressed identities
// to the statement's subjects, so a consumer can tell which shape it received
// and which admission point produced it — by digest, without trusting a label.
// Extra subjects are allowed by the in-toto statement: a holder matches the ones
// it needs by name and digest.
func tagEnvelope(env semantics.Envelope, profile *EvidenceProfile, recorder *RecorderDescriptor) (semantics.Envelope, error) {
	add := map[string]semantics.Digest{}
	if profile != nil && profile.Name != "" {
		id, err := profile.ID()
		if err != nil {
			return env, err
		}
		add[subjectNameProfile] = id
	}
	if recorder != nil && recorder.ID != "" {
		id, err := recorder.Digest()
		if err != nil {
			return env, err
		}
		add[subjectNameRecorder] = id
	}
	if len(add) == 0 {
		return env, nil
	}

	var st struct {
		Type          string              `json:"_type"`
		Subject       []semantics.Subject `json:"subject"`
		PredicateType string              `json:"predicateType"`
		Predicate     json.RawMessage     `json:"predicate"`
	}
	if err := json.Unmarshal(env.Payload, &st); err != nil {
		return env, err
	}
	for name, id := range add {
		alg, err := digestKey(id)
		if err != nil {
			return env, err
		}
		replaced := false
		for i, s := range st.Subject {
			if s.Name == name {
				st.Subject[i].Digest = map[string]string{alg: hex.EncodeToString(id.Value)}
				replaced = true
			}
		}
		if !replaced {
			st.Subject = append(st.Subject, semantics.Subject{Name: name, Digest: map[string]string{alg: hex.EncodeToString(id.Value)}})
		}
	}
	payload, err := semantics.CanonicalJSON(st)
	if err != nil {
		return env, err
	}
	env.Payload = payload
	return env, nil
}

// SubjectDigestByName reads a named subject digest back out of an envelope, for
// the CLC statement and for the pipeline/outcome statements alike.
func SubjectDigestByName(env semantics.Envelope, name string) (semantics.Digest, bool, error) {
	var st struct {
		Subject []semantics.Subject `json:"subject"`
	}
	if err := json.Unmarshal(env.Payload, &st); err != nil {
		return semantics.Digest{}, false, err
	}
	for _, s := range st.Subject {
		if s.Name != name {
			continue
		}
		for algKey, v := range s.Digest {
			raw, err := hex.DecodeString(v)
			if err != nil {
				return semantics.Digest{}, false, err
			}
			alg := semantics.DigestAlgSHA256
			if algKey == "sha384" {
				alg = "sha-384"
			}
			return semantics.Digest{Alg: alg, Value: raw}, true, nil
		}
	}
	return semantics.Digest{}, false, nil
}

// ProfileSubjectDigest returns the digest a consumer should look for when it
// wants to know which evidence shape a statement carries.
func ProfileSubjectDigest(env semantics.Envelope) (semantics.Digest, bool, error) {
	return SubjectDigestByName(env, subjectNameProfile)
}

// RecorderSubjectDigest returns the digest of the recorder descriptor that
// emitted this envelope, when it carries one.
func RecorderSubjectDigest(env semantics.Envelope) (semantics.Digest, bool, error) {
	return SubjectDigestByName(env, subjectNameRecorder)
}

var _ = sha256.Sum256 // keep the import meaningful if tagEnvelope changes
