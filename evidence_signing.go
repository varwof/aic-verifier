// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 记录签名：让"这份证据是谁的"有密钥背书。
//
// 三类载荷（decision / admission / outcome）在构造完信封后统一走
// env.Sign(cfg.KeyID, cfg.Sign)。DSSE 签的是 PAE(payloadType, payload)，不是
// 裸载荷（payload 不能被换一个 type 重新解释）。配置了 Sign 就是"这个发射点
// 认账"；没配置就保持历史默认：记录可复算，但不署名（anyone 都能声称自己是
// pep-7 的那一句）。
//
// 验证侧新增统一入口 VerifyEvidenceEnvelope：结构校验是底线（同
// CheckEvidenceEnvelope 按 predicateType 分派三类载荷），传了 verify 回调则要求
// 至少一条签名通过。多签语义与 semantics.Envelope.VerifyRecord 对齐：第一条
// 验证通过的签名胜出，KeyID 只是未认证的提示，不得单独用于安全判断。

package aicverifier

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/varwof/register/semantics"
)

// signEnvelope applies the configured DSSE signer to an envelope.  A nil
// signer is a no-op: an unsigned record is the valid default, and a deployment
// decides whether records must be key-endorsed by setting EvidenceConfig.Sign.
func signEnvelope(env semantics.Envelope, cfg *EvidenceConfig) (semantics.Envelope, error) {
	if cfg == nil || cfg.Sign == nil {
		return env, nil
	}
	if err := env.Sign(cfg.KeyID, cfg.Sign); err != nil {
		return env, fmt.Errorf("evidence: sign record: %w", err)
	}
	return env, nil
}

// VerifyEvidenceEnvelope validates an envelope of any of the three payload
// kinds.  Structural shipping is always performed (dispatched on the statement's
// predicate type).  When verify is non-nil, at least one signature must verify
// over the DSSE PAE — mirroring Envelope.VerifyRecord's multi-signature rule:
// the first signature that verifies wins, KeyID is passed through as an
// unauthenticated hint, and a tampered payload fails because its PAE no longer
// matches what was signed.
func VerifyEvidenceEnvelope(env semantics.Envelope, verify func(keyID string, pae, sig []byte) error) (EvidenceKind, error) {
	kind, err := CheckEvidenceEnvelope(env)
	if err != nil {
		return kind, err
	}
	if verify == nil {
		return kind, nil
	}
	if len(env.Signatures) == 0 {
		return kind, fmt.Errorf("%w: no signatures", semantics.ErrEnvelopeSignature)
	}
	pae := semantics.PAE(env.PayloadType, env.Payload)
	var firstErr error
	for _, sig := range env.Signatures {
		if len(sig.Sig) == 0 {
			if firstErr == nil {
				firstErr = fmt.Errorf("%w: empty signature", semantics.ErrEnvelopeSignature)
			}
			continue
		}
		if err := verify(sig.KeyID, pae, sig.Sig); err == nil {
			return kind, nil
		} else if firstErr == nil {
			firstErr = fmt.Errorf("%w: %v", semantics.ErrEnvelopeSignature, err)
		}
	}
	return kind, firstErr
}

// ErrRecordSignerMismatch is returned when a record's signature does not verify
// against the key a deployment pinned via VerifyFnFromPublicKey.
var ErrRecordSignerMismatch = errors.New("aic-verifier: record signature does not verify against the pinned key")

// VerifyFnFromPublicKey returns the DSSE verification callback that
// VerifyEvidenceDir / VerifyEvidenceEnvelope expect, pinned to one trusted
// ECDSA public key (P-256 / P-384 / P-521).  It closes the "who trusts the
// record signer" question with one line instead of hand-rolled crypto per
// call site: the key passed here is the trust anchor, the unauthenticated
// keyid label is deliberately ignored.
//
// Both the raw r‖s form (the common DSSE/JSON-Sign convention, P-256 = 64
// bytes) and ASN.1 DER are accepted, over the SHA-256 of the DSSE PAE.
func VerifyFnFromPublicKey(pub *ecdsa.PublicKey) func(keyID string, pae, sig []byte) error {
	return func(_ string, pae, sig []byte) error {
		digest := sha256.Sum256(pae)
		r, s := splitDSSESignature(sig)
		if r == nil || s == nil || !ecdsa.Verify(pub, digest[:], r, s) {
			return ErrRecordSignerMismatch
		}
		return nil
	}
}

// splitDSSESignature reads r and s out of a signature in either the ASN.1 DER
// form (unambiguous ECDSA-Sig-Value) or the raw r‖s encoding (the fixed-width
// DSSE / JSON-Sign convention).  DER is tried first on purpose: a P-256 DER
// signature is 70/71/72 bytes, i.e. often even, so a length-based raw branch
// alone would mis-read it; a raw 64-byte r‖s blob is vanishingly unlikely to
// parse as a well-formed DER SEQUENCE, so DER-first ordering is safe.
func splitDSSESignature(sig []byte) (*big.Int, *big.Int) {
	var der struct {
		R *big.Int
		S *big.Int
	}
	if rest, err := asn1.Unmarshal(sig, &der); err == nil && len(rest) == 0 &&
		der.R != nil && der.S != nil && der.R.Sign() > 0 && der.S.Sign() > 0 {
		return der.R, der.S
	}
	if len(sig) >= 8 && len(sig)%2 == 0 {
		half := len(sig) / 2
		return new(big.Int).SetBytes(sig[:half]), new(big.Int).SetBytes(sig[half:])
	}
	return nil, nil
}
