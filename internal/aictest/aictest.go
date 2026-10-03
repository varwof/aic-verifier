// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Package aictest holds shared certificate-fixture helpers for the example
// programs.  It is not part of the library or its public API.
package aictest

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	pki "github.com/varwof/types"
)

// SelfAuthorizeDA turns aic into a verifiable self-authorized delegation: the
// principal is the agent itself, so PrincipalUid.KeyHash becomes the key's SPKI
// hash and the DelegationAuthorization is signed over its DelegationAuthTBS
// with the same key.
//
// DelegationAuthorization verification is unconditional in the
// agent-certificate verification procedure (draft Section 12 step 4), so an
// example certificate carrying an unsigned placeholder is refused.  A
// self-authorized delegation is a legitimate deployment shape and keeps the
// example on the strict path.  requestedLifetime is raised to 86400 when it
// would otherwise be below the certificate's validity period, because the
// verifier requires the validity period not to exceed requestedLifetime.
func SelfAuthorizeDA(key *ecdsa.PrivateKey, aic *pki.AIC) error {
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal spki: %w", err)
	}
	keyHash := sha256.Sum256(spki)
	aic.PrincipalUid.KeyHash = keyHash[:]
	aic.PrincipalUid.HashAlgo = pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256}
	if aic.Version == 0 {
		aic.Version = 1
	}
	da := &aic.DelegationAuthorization
	if da.RequestedLifetime < 7200 {
		da.RequestedLifetime = 86400
	}
	if da.Timestamp.IsZero() {
		da.Timestamp = time.Now().UTC()
	}
	if len(da.Nonce) == 0 {
		da.Nonce = make([]byte, 32)
	}
	if len(da.SignatureAlgorithm.Algorithm) == 0 {
		da.SignatureAlgorithm = pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256}
	}
	tbs := pki.DelegationAuthTBS{
		Version:                  aic.Version,
		AgentId:                  aic.AgentId,
		PrincipalUid:             aic.PrincipalUid,
		Reason:                   da.Reason,
		Capabilities:             aic.Capabilities,
		DelegationMode:           aic.DelegationMode,
		AuthorizationConstraints: aic.AuthorizationConstraints,
		RequestedLifetime:        da.RequestedLifetime,
		Timestamp:                da.Timestamp,
		Nonce:                    da.Nonce,
	}
	der, err := asn1.Marshal(tbs)
	if err != nil {
		return fmt.Errorf("marshal delegation TBS: %w", err)
	}
	digest := sha256.Sum256(der)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return fmt.Errorf("sign delegation TBS: %w", err)
	}
	da.SignatureValue = sig
	return nil
}
