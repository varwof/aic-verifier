// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"strings"

	pki "github.com/varwof/types"
)

// ── Type aliases ──
type (
	DelegationMode          = pki.DelegationMode
	PrincipalUid            = pki.PrincipalUid
	AlgorithmIdentifier     = pki.AlgorithmIdentifier
	Capability              = pki.Capability
	ExtField                = pki.ExtField
	DelegationAuthorization = pki.DelegationAuthorization
	Reason                  = pki.Reason
	AIC                     = pki.AIC
	DelegationAuthTBS       = pki.DelegationAuthTBS
)

// DelegationMode values.
const (
	DelegationAuthorized     DelegationMode = 0
	DelegationRepresentative DelegationMode = 1
)

// OID re-exports — signature algorithm OIDs.
var (
	OIDSigECDSAWithSHA256  = pki.OIDSigECDSAWithSHA256
	OIDSigECDSAWithSHA384  = pki.OIDSigECDSAWithSHA384
	OIDSigECDSAWithSHA512  = pki.OIDSigECDSAWithSHA512
	OIDSigRSAWithSHA256    = pki.OIDSigRSAWithSHA256
	OIDSigRSAWithSHA384    = pki.OIDSigRSAWithSHA384
	OIDSigRSAWithSHA512    = pki.OIDSigRSAWithSHA512
	OIDSigRSAPSSWithSHA256 = pki.OIDSigRSAPSSWithSHA256
	OIDSigEd25519          = pki.OIDSigEd25519
	OIDSHA256              = pki.OIDSHA256
	OIDSHA384              = pki.OIDSHA384
	OIDSHA512              = pki.OIDSHA512
)

// Private OID re-exports (used by tests)
var oidAIC = pki.OIDAIC

// ── Delegation functions ──

// ParseAIC delegates to pki-types.
func ParseAIC(cert *x509.Certificate) (*AIC, error) {
	return pki.ParseAIC(cert)
}

// HasAIC reports whether the certificate carries a valid AIC extension
// (G2: short-lived certificate identification).
// Malformed AIC returns false (such certificates are denied in the admission
// pipeline and will not enter the data plane).
func HasAIC(cert *x509.Certificate) bool {
	aic, err := pki.ParseAIC(cert)
	return err == nil && aic != nil
}

// ValidateAIC delegates to pki-types.
func ValidateAIC(aic *AIC) error {
	return pki.ValidateAIC(aic)
}

// sigAlgoToOID delegates to pki-types.
func sigAlgoToOID(algo x509.SignatureAlgorithm) AlgorithmIdentifier {
	return pki.SigAlgoToOID(algo)
}

// ParsePrincipalUid delegates to pki-types.
func ParsePrincipalUid(s string) (PrincipalUid, error) {
	return pki.ParsePrincipalUid(s)
}

// MakePrincipalUidFromCert constructs a PrincipalUid from a certificate DER
// (KeyHash = SPKI SHA-256, per spec §PrincipalUid).
func MakePrincipalUidFromCert(realm, identifier string, certDER []byte) PrincipalUid {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return PrincipalUid{
			Version:    1,
			Realm:      realm,
			Identifier: identifier,
			HashAlgo:   pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
		}
	}
	pubBytes, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	h := sha256.Sum256(pubBytes)
	return PrincipalUid{
		Version:    1,
		Realm:      realm,
		Identifier: identifier,
		KeyHash:    h[:],
		HashAlgo:   pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
	}
}

// matchCapability delegates to pki-types (kept for test compatibility).
func matchCapability(id, pattern string) bool {
	return pki.MatchCapability(id, pattern)
}

// matchDoubleStar — local copy of pki-types private helper (tested directly).
func matchDoubleStar(id, pattern string) bool {
	parts := strings.Split(pattern, "**")
	if len(parts) != 2 {
		return false
	}
	prefix := strings.TrimRight(parts[0], "/")
	suffix := strings.TrimLeft(parts[1], "/")

	remaining := id
	if prefix != "" {
		if !strings.HasPrefix(remaining, prefix) {
			return false
		}
		remaining = strings.TrimPrefix(remaining, prefix)
		remaining = strings.TrimPrefix(remaining, "/")
	}
	if suffix != "" {
		if !strings.HasSuffix(remaining, suffix) {
			return false
		}
		remaining = strings.TrimSuffix(remaining, suffix)
		remaining = strings.TrimSuffix(remaining, "/")
	}
	if remaining == "" {
		return true
	}
	for _, seg := range strings.Split(remaining, "/") {
		if seg == "" || seg == ".." {
			return false
		}
	}
	return true
}

// isKnownExtension — local copy of pki-types private helper (tested directly).
func isKnownExtension(oid asn1.ObjectIdentifier) bool {
	known := []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 4, 1, 66257, 1, 2}, // PrincipalAuthorization
		{1, 3, 6, 1, 4, 1, 66257, 3, 1}, // MarketAccessId
	}
	for _, k := range known {
		if oid.Equal(k) {
			return true
		}
	}
	return false
}
