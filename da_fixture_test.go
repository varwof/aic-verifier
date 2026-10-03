// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

// selfAuthorizeDA turns aic into a *verifiable* self-authorized delegation:
// PrincipalUid.KeyHash becomes the leaf public key's SPKI hash and the
// DelegationAuthorization is signed over its DelegationAuthTBS with the leaf
// private key.
//
// DelegationAuthorization verification is unconditional in the
// agent-certificate verification procedure (draft Section 12 step 4), so a
// fixture carrying a placeholder SignatureValue over an all-zero KeyHash is
// now correctly refused.  Building the fixture this way keeps these tests on
// the strict default path instead of switching DA verification off, and it
// matches the shape the admission code accepts when the peer certificate is
// itself the authorized principal.
//
// It must be called after the leaf key is generated and before the AIC is
// marshalled into the certificate.  requestedLifetime is raised to 86400 when
// unset or below the leaf's 2-hour validity, because the verifier requires
// the certificate validity period not to exceed requestedLifetime.
func selfAuthorizeDA(t testing.TB, key *ecdsa.PrivateKey, aic *pki.AIC) {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal spki: %v", err)
	}
	keyHash := sha256.Sum256(spki)
	aic.PrincipalUid.KeyHash = keyHash[:]
	if aic.Version == 0 {
		aic.Version = 1
	}
	if aic.DelegationAuthorization.RequestedLifetime < 7200 {
		aic.DelegationAuthorization.RequestedLifetime = 86400
	}
	if aic.DelegationAuthorization.Timestamp.IsZero() {
		aic.DelegationAuthorization.Timestamp = time.Now().UTC()
	}
	if len(aic.DelegationAuthorization.Nonce) == 0 {
		aic.DelegationAuthorization.Nonce = make([]byte, 32)
	}
	if len(aic.DelegationAuthorization.SignatureAlgorithm.Algorithm) == 0 {
		aic.DelegationAuthorization.SignatureAlgorithm = pki.AlgorithmIdentifier{
			Algorithm: pki.OIDSigECDSAWithSHA256,
		}
	}
	daTBS := pki.DelegationAuthTBS{
		Version:                  aic.Version,
		AgentId:                  aic.AgentId,
		PrincipalUid:             aic.PrincipalUid,
		Reason:                   aic.DelegationAuthorization.Reason,
		Capabilities:             aic.Capabilities,
		DelegationMode:           aic.DelegationMode,
		AuthorizationConstraints: aic.AuthorizationConstraints,
		RequestedLifetime:        aic.DelegationAuthorization.RequestedLifetime,
		Timestamp:                aic.DelegationAuthorization.Timestamp,
		Nonce:                    aic.DelegationAuthorization.Nonce,
	}
	daDER, err := asn1.Marshal(daTBS)
	if err != nil {
		t.Fatalf("marshal delegation TBS: %v", err)
	}
	daDigest := sha256.Sum256(daDER)
	daSig, err := ecdsa.SignASN1(rand.Reader, key, daDigest[:])
	if err != nil {
		t.Fatalf("sign delegation TBS: %v", err)
	}
	aic.DelegationAuthorization.SignatureValue = daSig
}
