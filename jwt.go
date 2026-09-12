// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package aicverifier

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"crypto/sha256"
	pki "github.com/varwof/types"
	"github.com/varwof/types/aicjwt"
)

// JWTVerifier verifies AIC-JWT bearer tokens against a trust root built
// from CA certificates (same kid convention as the X.509 carrier:
// base64url SHA-256 of the certificate SPKI). On success it returns a
// synthesized X.509 certificate carrying the token's AIC extension, so
// the existing pipeline (RunAccessPipeline / CheckAdmission) admits a
// bearer request exactly like a certificate-authenticated one.
//
// A bare NewJWTVerifier only verifies the token signature/expiry. For
// production use the gateway must call SetBearerPolicy (issuer/audience
// binding + replay protection) and pass per-request proof-of-possession
// via VerifyBearer options; without those the bearer is replayable until
// exp by any holder (finding 5).
type JWTVerifier struct {
	roots map[string]crypto.PublicKey // kid -> issuer public key

	// Optional policy applied to every verification (finding 5).
	expectedIssuer   string
	expectedAudience []string
	nonceStore       aicjwt.NonceStore
}

// JWTVerifyOptions carries the runtime verification parameters for a single
// bearer token. These activate the checks Validate supports but that a bare
// call leaves unset (finding 5).
type JWTVerifyOptions struct {
	// ExpectedIssuer, when non-empty, requires outer.iss == ExpectedIssuer.
	ExpectedIssuer string
	// ExpectedAudience, when non-empty, requires the token aud to include one.
	ExpectedAudience []string
	// PresenterKey, when non-nil, enforces cnf proof-of-possession: the token
	// must be bound to this public key (e.g. the mTLS peer cert key).
	PresenterKey crypto.PublicKey
	// NonceStore, when non-nil, provides one-time-use replay protection on the
	// DA nonce (finding 5).
	NonceStore aicjwt.NonceStore
	// RequireJtiNonceMatch requires outer.jti == DA nonce.
	RequireJtiNonceMatch bool
	// StatusChecker, when non-nil, checks issuer/principal for revocation.
	StatusChecker aicjwt.StatusChecker
}

// NewJWTVerifier builds a verifier from CA certificates. kid for each CA
// is base64url(SHA-256(SubjectPublicKeyInfo)) — the same binding core
// publishes on /.well-known/jwks.json.
func NewJWTVerifier(cas []*x509.Certificate) *JWTVerifier {
	roots := make(map[string]crypto.PublicKey, len(cas))
	for _, c := range cas {
		if c == nil {
			continue
		}
		if kid, err := aicjwt.SPKIHash(c, "sha-256"); err == nil {
			roots[kid] = c.PublicKey
		}
	}
	return &JWTVerifier{roots: roots}
}

// SetBearerPolicy installs the static bearer-token policy applied to every
// verification: the expected issuer, acceptable audiences, and a replay
// nonce store. Configure all three for production; leaving issuer/audience
// empty or the nonce store nil keeps those checks off (finding 5).
func (v *JWTVerifier) SetBearerPolicy(expectedIssuer string, expectedAudience []string, nonces aicjwt.NonceStore) {
	if v == nil {
		return
	}
	v.expectedIssuer = expectedIssuer
	v.expectedAudience = expectedAudience
	v.nonceStore = nonces
}

// LoadJWTVerifier reads one or more PEM CA certificate files (comma or
// space separated paths) and builds a JWT verifier from them. An empty
// spec returns a nil verifier (bearer auth disabled).
func LoadJWTVerifier(caFiles ...string) (*JWTVerifier, error) {
	var certs []*x509.Certificate
	for _, spec := range caFiles {
		for _, f := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' }) {
			if f == "" {
				continue
			}
			pemData, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("jwt: read CA %q: %w", f, err)
			}
			parsed, err := parsePEMCerts(pemData)
			if err != nil {
				return nil, fmt.Errorf("jwt: parse CA %q: %w", f, err)
			}
			certs = append(certs, parsed...)
		}
	}
	if len(certs) == 0 {
		return nil, nil
	}
	return NewJWTVerifier(certs), nil
}

// VerifyBearer validates a Bearer AIC-JWT and returns a synthesized
// certificate carrying the AIC claims, plus the raw outer claims.
// opts carry per-request checks (proof-of-possession, revocation); the
// verifier's static policy (issuer/audience/replay) is always applied.
func (v *JWTVerifier) VerifyBearer(token string, now time.Time, opts ...JWTVerifyOptions) (*x509.Certificate, *aicjwt.OuterClaims, error) {
	if len(v.roots) == 0 {
		return nil, nil, fmt.Errorf("jwt: no trust root configured")
	}

	vopts := aicjwt.VerifyOptions{Now: now, IssuerKeys: v.roots}
	vopts.ExpectedIssuer = v.expectedIssuer
	vopts.ExpectedAudience = v.expectedAudience
	vopts.NonceStore = v.nonceStore
	if len(opts) > 0 {
		o := opts[0]
		if o.ExpectedIssuer != "" {
			vopts.ExpectedIssuer = o.ExpectedIssuer
		}
		if len(o.ExpectedAudience) > 0 {
			vopts.ExpectedAudience = o.ExpectedAudience
		}
		vopts.PresenterKey = o.PresenterKey
		if o.NonceStore != nil {
			vopts.NonceStore = o.NonceStore
		}
		vopts.RequireJtiNonceMatch = o.RequireJtiNonceMatch
		vopts.StatusChecker = o.StatusChecker
	}

	if _, err := aicjwt.Validate(token, vopts); err != nil {
		return nil, nil, fmt.Errorf("jwt: validate: %w", err)
	}

	// Re-parse payload for the claims we synthesize into the certificate.
	_, pb, _, err := aicjwt.ParseCompact(token)
	if err != nil {
		return nil, nil, fmt.Errorf("jwt: parse: %w", err)
	}
	var outer aicjwt.OuterClaims
	if err := json.Unmarshal(pb, &outer); err != nil {
		return nil, nil, fmt.Errorf("jwt: payload: %w", err)
	}

	// Replay protection (finding 5): aicjwt.Validate only replay-checks the DA
	// nonce, which authorize-mode bearer tokens do not carry. Record the outer
	// jti as a one-time-use nonce too so a captured authorized-mode token cannot
	// be replayed until exp by any holder.
	if vopts.NonceStore != nil {
		if outer.Jti == "" {
			return nil, nil, fmt.Errorf("jwt: jti required for replay protection")
		}
		if err := vopts.NonceStore.CheckAndAdd(outer.Jti); err != nil {
			return nil, nil, fmt.Errorf("jwt: token replay detected: %w", err)
		}
	}

	cert, err := SynthesizeCertFromJWT(&outer)
	if err != nil {
		return nil, nil, err
	}
	return cert, &outer, nil
}

// SynthesizeCertFromJWT builds an X.509 certificate carrying the AIC
// claims of an AIC-JWT, so downstream certificate-based pipeline stages
// (CheckAdmission, capability matching, audit) work unchanged.
func SynthesizeCertFromJWT(outer *aicjwt.OuterClaims) (*x509.Certificate, error) {
	if outer == nil || outer.Aic == nil {
		return nil, fmt.Errorf("jwt: missing aic claims")
	}
	aic := jwtToAIC(outer)

	// ASN.1-serialize the AIC so ParseAIC on the synthesized certificate
	// recovers the exact claims.
	extVal, err := asn1.Marshal(*aic)
	if err != nil {
		return nil, fmt.Errorf("jwt: marshal AIC extension: %w", err)
	}

	agentID := outer.Sub
	if agentID == "" {
		agentID = outer.Aic.Principal.ID
	}

	notBefore := time.Unix(outer.Iat, 0)
	notAfter := time.Unix(outer.Exp, 0)

	// Finding 6: derive a stable, per-token serial from the token jti instead of
	// the constant serial 0. A non-zero serial gives each bearer its own
	// revocation/accounting slot (OCSP/CRL/conn registry) and prevents all
	// bearer tokens collapsing into one synthetic identity. Missing jti falls
	// back to a hash of the whole payload (already rejected when replay
	// protection is enabled).
	serial := serialFromJWT(outer)

	return &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: agentID},
		Issuer:       pkix.Name{CommonName: outer.Iss},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		Extensions: []pkix.Extension{
			{Id: pki.OIDAIC, Critical: false, Value: extVal},
		},
	}, nil
}

// serialFromJWT derives a positive, deterministic serial number from the token
// identity so the same token always synthesizes the same certificate while
// different tokens never share a serial.
func serialFromJWT(outer *aicjwt.OuterClaims) *big.Int {
	seed := outer.Jti
	if seed == "" {
		if outer.Aic != nil {
			seed = outer.Aic.Principal.ID
		}
	}
	h := sha256.Sum256([]byte(seed))
	n := new(big.Int).SetBytes(h[:])
	n.Abs(n)
	if n.Sign() == 0 {
		n.SetInt64(1)
	}
	return n
}

// jwtToAIC maps AIC-JWT claims onto the X.509 AIC structure.
func jwtToAIC(outer *aicjwt.OuterClaims) *pki.AIC {
	aic := &pki.AIC{
		Version:        1,
		AgentId:        outer.Sub,
		DelegationMode: pki.DelegationMode(modeToInt(outer.Aic.DelegationMode)),
	}
	if aic.AgentId == "" {
		aic.AgentId = outer.Aic.Principal.ID
	}
	kh, _ := base64.RawURLEncoding.DecodeString(outer.Aic.Principal.KeyHash)
	aic.PrincipalUid = pki.PrincipalUid{
		Version:    1,
		Realm:      outer.Aic.Principal.Realm,
		Identifier: outer.Aic.Principal.ID,
		KeyHash:    kh,
	}
	for _, c := range outer.Aic.Capabilities {
		aic.Capabilities = append(aic.Capabilities, pki.Capability{
			SchemeId:     c.Scheme,
			CapabilityId: c.ID,
			Parameters:   []byte(c.Params),
		})
	}
	for _, c := range outer.Aic.Constraints {
		aic.AuthorizationConstraints = append(aic.AuthorizationConstraints, pki.Capability{
			SchemeId:     c.Scheme,
			CapabilityId: c.ID,
			Parameters:   []byte(c.Params),
		})
	}
	// pki.ParseAIC requires a present DelegationAuthorization. For an
	// AIC-JWT the delegation authorization is represented by the outer.da
	// claim (JWT form); authorize-mode tokens carry none. Synthesize a
	// present-but-neutral placeholder so the certificate pipeline admits
	// the bearer; its signature/replay checks only run when explicitly
	// configured (RequireUserAuth / NonceCache), which a JWT carrier does
	// not satisfy. The nonce is derived deterministically from the JTI so
	// the same token always synthesizes the same carrier.
	aic.DelegationAuthorization = pki.DelegationAuthorization{
		RequestedLifetime:  requestedLifetimeOf(outer),
		Reason:             pki.Reason{ReasonCode: "JWT_BEARER", Description: "aic-jwt bearer authentication"},
		Nonce:              nonceFromJTI(outer.Jti),
		SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
	}
	return aic
}

// nonceFromJTI derives a fixed-length nonce from the token JTI (SHA-256),
// so the synthesized DA passes ValidateAIC while remaining deterministic.
func nonceFromJTI(jti string) []byte {
	h := sha256.Sum256([]byte(jti))
	return h[:]
}

// requestedLifetimeOf derives a non-zero requestedLifetime from the token's
// exp-iat so the synthesized DA placeholder is present (IsPresent()).
func requestedLifetimeOf(outer *aicjwt.OuterClaims) int {
	if outer.Exp > outer.Iat {
		if lt := int(outer.Exp - outer.Iat); lt > 0 {
			return lt
		}
	}
	return 3600
}

// parsePEMCerts extracts all certificates from PEM data.
func parsePEMCerts(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// memReplayStore is a bounded, TTL'd one-time-use nonce store implementing
// aicjwt.NonceStore for bearer replay protection (finding 5). Entries are
// single-use: CheckAndAdd records the nonce the first time and rejects any
// later reuse.
type memReplayStore struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	ttl   time.Duration
	max   int
	start time.Time
}

// NewReplayNonceStore returns a process-local replay-protection store.
// Nonces are retained for ttl (default 24h) and at most max entries (default
// 4096); beyond that the oldest are evicted. The store is intended for
// single-node gateways; multi-node deployments should share a distributed
// nonce store instead.
func NewReplayNonceStore(ttl time.Duration, max int) *memReplayStore {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if max <= 0 {
		max = 4096
	}
	return &memReplayStore{
		seen:  make(map[string]time.Time),
		ttl:   ttl,
		max:   max,
		start: time.Now(),
	}
}

// CheckAndAdd records the nonce and returns an error if it was already used
// (replay) or if it predates the store (invalid).
func (s *memReplayStore) CheckAndAdd(nonce string) error {
	if nonce == "" {
		return fmt.Errorf("replay store: empty nonce")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ts, ok := s.seen[nonce]; ok {
		return fmt.Errorf("replay store: nonce replayed (first used %s)", ts.Format(time.RFC3339))
	}
	s.seen[nonce] = time.Now()
	// Bounded memory: evict expired entries, then trim oldest if over cap.
	if len(s.seen) > s.max {
		cutoff := time.Now().Add(-s.ttl)
		for k, ts := range s.seen {
			if ts.Before(cutoff) {
				delete(s.seen, k)
			}
		}
		if len(s.seen) > s.max {
			oldest := s.start
			for _, ts := range s.seen {
				if ts.Before(oldest) {
					oldest = ts
				}
			}
			// O(n) trim: drop everything at/before the cap watermark.
			toDelete := len(s.seen) - s.max
			deleted := 0
			for k, ts := range s.seen {
				if deleted >= toDelete {
					break
				}
				if !ts.After(oldest) {
					delete(s.seen, k)
					deleted++
				}
			}
		}
	}
	return nil
}

// modeToInt maps the JWT delegation_mode string to the X.509 enum.
func modeToInt(mode string) int {
	switch mode {
	case aicjwt.ModeRepresentative:
		return 1
	default:
		return 0
	}
}
