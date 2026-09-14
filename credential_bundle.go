// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Credential Bundle — the client-submitted agent, principal and CA chain bundle
//
// A credential bundle consists of three parts:
//   - Agent Certificate (contains AIC, agent chain first);
//   - Principal Certificate (contains PrincipalAuthorization, principal chain second);
//   - CA Chain (both chains anchor to the same trust root).
//
// Dual-chain verification: Agent chain → trust root, principal chain → same trust root,
// keyHash matches principal SPKI.
// Coexists with existing UserCertResolver: bundle takes priority; on absence, keyHash is
// used to look up the local store; fail-close if both fail.

package aicverifier

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// CredentialBundle is the credential bundle submitted by the client
// (Agent certificate chain + Principal certificate chain + CA).
type CredentialBundle struct {
	// AgentChain is the agent certificate chain containing AIC.
	// chain[0]=Agent, subsequent entries are intermediate/root CAs.
	AgentChain []*x509.Certificate
	// PrincipalChain is the principal certificate chain containing PA.
	// chain[0]=Principal (independently issued, not in the agent chain),
	// subsequent entries are intermediate CAs (optional).
	PrincipalChain []*x509.Certificate
	// CACerts are optional CA certs carried in the bundle for informational
	// purposes. They are never used as trust anchors (finding 20): callers must
	// supply operator-configured roots via VerifyBundle.
	CACerts []*x509.Certificate
}

// NewCredentialBundle constructs a credential bundle.
// Returns an error if either chain is empty.
func NewCredentialBundle(agentChain, principalChain, caCerts []*x509.Certificate) (*CredentialBundle, error) {
	if len(agentChain) == 0 {
		return nil, fmt.Errorf("credential_bundle: agent chain is required")
	}
	if len(principalChain) == 0 {
		return nil, fmt.Errorf("credential_bundle: principal chain is required")
	}
	return &CredentialBundle{
		AgentChain:     agentChain,
		PrincipalChain: principalChain,
		CACerts:        caCerts,
	}, nil
}

// Agent returns the Agent certificate (contains AIC, chain[0]).
func (b *CredentialBundle) Agent() *x509.Certificate {
	if b == nil || len(b.AgentChain) == 0 {
		return nil
	}
	return b.AgentChain[0]
}

// Principal returns the Principal certificate (contains PA, chain[0]).
func (b *CredentialBundle) Principal() *x509.Certificate {
	if b == nil || len(b.PrincipalChain) == 0 {
		return nil
	}
	return b.PrincipalChain[0]
}

// VerifyBundle verifies the credential bundle dual chain:
//   - Agent chain → trust root (default client authentication EKU);
//   - Principal chain → same trust root;
//   - keyHash match: AIC.PrincipalUid.KeyHash == SHA256(Principal SPKI).
//
// roots is the trust root pool; if empty, falls back to bundle.CACerts.
// Returns an error if any verification step fails.
func VerifyBundle(bundle *CredentialBundle, roots *x509.CertPool) error {
	if bundle == nil {
		return fmt.Errorf("credential_bundle: nil bundle")
	}
	// Finding 20: never trust client-supplied CACerts as trust roots. A
	// self-signed chain could otherwise self-anchor. Callers must supply
	// operator-configured roots; missing roots fail closed.
	if roots == nil {
		return fmt.Errorf("credential_bundle: no trust roots provided (client-supplied CA certs are not trusted)")
	}

	// Agent chain verification (AIC-containing certificate first, chain[0]=Agent).
	if len(bundle.AgentChain) == 0 {
		return fmt.Errorf("credential_bundle: empty agent chain")
	}
	if _, err := bundle.AgentChain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediatesPool(bundle.AgentChain[1:]),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("credential_bundle: agent chain: %w", err)
	}

	// Principal chain verification (independently issued, anchored to the same trust root).
	if len(bundle.PrincipalChain) == 0 {
		return fmt.Errorf("credential_bundle: empty principal chain")
	}
	if _, err := bundle.PrincipalChain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediatesPool(bundle.PrincipalChain[1:]),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("credential_bundle: principal chain: %w", err)
	}

	// keyHash match: AIC.PrincipalUid.KeyHash == SHA256(Principal SPKI).
	return VerifyPrincipalKeyHash(bundle.Agent(), bundle.Principal())
}

// VerifyPrincipalKeyHash verifies that AIC.PrincipalUid.KeyHash matches the
// SHA-256 of the principal certificate's SPKI. Returns an error (fail-close)
// if keyHash is missing or empty.
func VerifyPrincipalKeyHash(agent, principal *x509.Certificate) error {
	if agent == nil {
		return fmt.Errorf("credential_bundle: nil agent cert")
	}
	if principal == nil {
		return fmt.Errorf("credential_bundle: nil principal cert")
	}
	aic, err := ParseAIC(agent)
	if err != nil {
		return fmt.Errorf("credential_bundle: parse agent AIC: %w", err)
	}
	if aic == nil || len(aic.PrincipalUid.KeyHash) == 0 {
		return fmt.Errorf("credential_bundle: agent has no keyHash in PrincipalUid")
	}
	spki := sha256.Sum256(principal.RawSubjectPublicKeyInfo)
	if !bytes.Equal(spki[:], aic.PrincipalUid.KeyHash) {
		return fmt.Errorf("credential_bundle: principal cert SPKI hash mismatch with AIC keyHash")
	}
	return nil
}

// intermediatesPool constructs an intermediate certificate pool from a slice
// (returns nil if empty).
func intermediatesPool(certs []*x509.Certificate) *x509.CertPool {
	if len(certs) == 0 {
		return nil
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

// ParseCredentialBundlePEM parses a credential bundle from PEM data
// (order: agent chain first, principal second, CA chain last).
// Certificates are classified by extensions: AIC-containing → Agent chain,
// PA-containing → Principal chain, rest → CA. The parsed result must be
// verified via VerifyBundle before use.
func ParseCredentialBundlePEM(data []byte) (*CredentialBundle, error) {
	bundle := &CredentialBundle{}
	block, rest := pem.Decode(data)
	seen := 0
	for block != nil {
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("credential_bundle: parse PEM cert: %w", err)
			}
			seen++
			aic, _ := ParseAIC(cert)
			if aic != nil {
				bundle.AgentChain = append(bundle.AgentChain, cert)
			} else if pa, _ := ParseUserPermissionExtension(cert); pa != nil {
				bundle.PrincipalChain = append(bundle.PrincipalChain, cert)
			} else {
				bundle.CACerts = append(bundle.CACerts, cert)
			}
		}
		block, rest = pem.Decode(rest)
	}
	if seen == 0 {
		return nil, fmt.Errorf("credential_bundle: no certificates in PEM")
	}
	return bundle, nil
}
