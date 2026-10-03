// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"

	pki "github.com/varwof/types"
)

// draft -02 Section 12, step 4 *DelegationAuthorization Verification* is
// an unconditional MUST in the agent-certificate verification procedure:
// nothing in it is conditioned on a deployment option.  It used to sit
// behind AdmissionConfig.RequireUserAuth, whose zero value is false, so a
// default AdmissionConfig skipped DA verification entirely and admitted a
// certificate carrying a forged or absent delegation.
//
// The gate is now SkipDelegationAuthVerification: zero value = verify.
func TestDelegationAuthVerificationIsOnByDefault(t *testing.T) {
	principalKey, principalCert := mintCert(t, nil, nil, "principal.user", big.NewInt(9101), nil, nil, nil)
	principalKeyHash := sha256.Sum256(principalCert.RawSubjectPublicKeyInfo)
	principal := PrincipalUid{
		Version:    1,
		Realm:      "pki",
		Identifier: "alice",
		KeyHash:    principalKeyHash[:],
		HashAlgo:   AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
	}

	daFor := func(agentID string) AIC {
		return baseDelegationAIC(agentID, caps("std/database-v1", "query:SELECT"), principal)
	}

	mkAgent := func(t *testing.T, da []byte) *x509.Certificate {
		t.Helper()
		aic := daFor("scheduler-a")
		aic.DelegationAuthorization.SignatureValue = da
		_, cert := mintCert(t, nil, nil, "agent.example", big.NewInt(9102), &aic, nil, nil)
		return cert
	}

	signedDA := func(t *testing.T) []byte {
		t.Helper()
		aic := daFor("scheduler-a")
		return signDADigest(t, principalKey, &aic)
	}

	t.Run("forged_signature_is_denied_by_default", func(t *testing.T) {
		// The attacker signs nothing: a placeholder stands in for a forged
		// delegation. Under the old gate this reached an allow decision.
		cert := mkAgent(t, []byte{0x01})
		res := CheckAdmission(cert, AdmissionConfig{UserCert: principalCert})
		if res.Decision != DecisionDeny {
			t.Fatalf("default config accepted a DA it never verified: %+v", res)
		}
	})

	t.Run("absent_signature_is_denied_by_default", func(t *testing.T) {
		cert := mkAgent(t, nil)
		res := CheckAdmission(cert, AdmissionConfig{UserCert: principalCert})
		if res.Decision != DecisionDeny {
			t.Fatalf("default config accepted an AIC with no DA signature: %+v", res)
		}
	})

	t.Run("genuine_signature_is_accepted_by_default", func(t *testing.T) {
		cert := mkAgent(t, signedDA(t))
		res := CheckAdmission(cert, AdmissionConfig{UserCert: principalCert})
		if res.Decision != DecisionAllow {
			t.Fatalf("a correctly signed DA was refused: %+v", res)
		}
	})

	t.Run("explicit_opt_out_skips_verification", func(t *testing.T) {
		// The escape hatch exists so a deployment that cannot obtain the
		// principal certificate can still run; it is named, not accidental.
		cert := mkAgent(t, []byte{0x01})
		res := CheckAdmission(cert, AdmissionConfig{
			UserCert:                       principalCert,
			SkipDelegationAuthVerification: true,
		})
		if res.Decision == DecisionDeny {
			t.Fatalf("explicit opt-out still verified the DA: %+v", res)
		}
	})

	t.Run("missing_principal_certificate_fails_closed_by_default", func(t *testing.T) {
		// No UserCert, no resolver, and the peer is not the principal, so
		// there is no way to establish who signed the DA.
		cert := mkAgent(t, signedDA(t))
		res := CheckAdmission(cert, AdmissionConfig{})
		if res.Decision != DecisionDeny {
			t.Fatalf("admitted a delegation that could not be attributed: %+v", res)
		}
		if !strings.Contains(res.Reason, "user_auth") {
			t.Fatalf("denial reason = %q, want a user_auth refusal", res.Reason)
		}
	})
}
