// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 记录签名密钥的加载与封装。
//
// 合规场景要的默认姿态是「每条证据都有密钥背书」，而不是「默认不签、要用再自己写
// 一个 crypto 闭包」。这个文件把「从文件拿一把密钥、给每条 DSSE 记录签名、并给出
// 对应的验签回调」收敛成一个 helper：
//
//	signer, _ := aicverifier.LoadRecordSignerFile("/etc/aic/evidence-key.pem", "pep-1")
//	conf.Evidence = &aicverifier.EvidenceConfig{
//	    Sink:   &aicverifier.FileSink{Dir: "/var/lib/aic/evidence"},
//	    Signer: signer,
//	}
//
// 配了 Signer（或 SignKeyFile）就签，没有单独的开关——未签名的合规记录正是要被
// 关掉的那条缺口。文件密钥先支持（PEM：PKCS#1 / PKCS#8 / SEC1；RSA / ECDSA /
// Ed25519）；HSM/KMS 由部署方实现 crypto.Signer 后走 NewRecordSigner。

package aicverifier

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// RecordSigner is the key that endorses emitted evidence records: a
// crypto.Signer paired with the key id published in the DSSE signature.  It
// also carries the matching public key, so a holder can verify a record with
// VerifyFn without a separate out-of-band key exchange.
type RecordSigner struct {
	keyID  string
	signer crypto.Signer
}

// NewRecordSigner wraps any crypto.Signer as a record signer.  HSM/KMS-backed
// implementations that only expose signing plug in here.
func NewRecordSigner(keyID string, signer crypto.Signer) (*RecordSigner, error) {
	if signer == nil {
		return nil, errors.New("evidence: nil signing key")
	}
	return &RecordSigner{keyID: keyID, signer: signer}, nil
}

// LoadRecordSignerFile loads a PEM private key (PKCS#1, PKCS#8 or SEC1; RSA,
// ECDSA or Ed25519) and wraps it as a record signer.
func LoadRecordSignerFile(path, keyID string) (*RecordSigner, error) {
	key, err := ParsePrivateKeyPEMFile(path)
	if err != nil {
		return nil, fmt.Errorf("evidence: load signing key %q: %w", path, err)
	}
	return NewRecordSigner(keyID, key)
}

// KeyID is the unauthenticated hint published alongside each signature; it names
// a key but is never trusted on its own.
func (s *RecordSigner) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

// Public returns the verification key matching the signer.
func (s *RecordSigner) Public() crypto.PublicKey {
	if s == nil || s.signer == nil {
		return nil
	}
	return s.signer.Public()
}

// Sign implements the EvidenceConfig signing callback over the DSSE PAE.  RSA
// and ECDSA sign the SHA-256 digest of the PAE; Ed25519 signs the PAE itself.
func (s *RecordSigner) Sign(pae []byte) ([]byte, error) {
	if s == nil || s.signer == nil {
		return nil, errors.New("evidence: nil signing key")
	}
	if _, ok := s.signer.Public().(ed25519.PublicKey); ok {
		return s.signer.Sign(rand.Reader, pae, crypto.Hash(0))
	}
	digest := sha256.Sum256(pae)
	return s.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
}

// VerifyFn returns the DSSE verification callback pinned to this signer's public
// key, for VerifyEvidenceDir / VerifyEvidenceEnvelope.
func (s *RecordSigner) VerifyFn() func(keyID string, pae, sig []byte) error {
	return VerifyFnFromKey(s.Public())
}

// signingKey resolves the configured signer, preferring a key-carrying
// RecordSigner over a bare Sign closure.  A nil result means "unsigned".
func (c *EvidenceConfig) signingKey() (string, func(pae []byte) ([]byte, error)) {
	if c == nil {
		return "", nil
	}
	if c.Signer != nil {
		return c.Signer.KeyID(), c.Signer.Sign
	}
	if c.Sign != nil {
		return c.KeyID, c.Sign
	}
	return "", nil
}

// resolveSigner loads SignKeyFile once, when no explicit signer was supplied, so
// emission does no per-record file I/O.  Material loading belongs to handler
// construction, matching how the CA and JWT trust roots are handled.
func (c *EvidenceConfig) resolveSigner() error {
	if c == nil || c.Signer != nil || c.Sign != nil || c.SignKeyFile == "" {
		return nil
	}
	signer, err := LoadRecordSignerFile(c.SignKeyFile, c.KeyID)
	if err != nil {
		return err
	}
	c.Signer = signer
	return nil
}
