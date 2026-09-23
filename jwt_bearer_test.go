// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pki "github.com/varwof/types"
	"github.com/varwof/types/aicjwt"
)

// newIssuerIdentity mints a self-signed JWT issuing CA (the certificate whose
// kid/SPKI the verifier keys on).
func newIssuerIdentity(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	return mintCert(t, nil, nil, "jwt-issuer", big.NewInt(700), nil, nil, nil)
}

// signBearerToken builds a compact AIC-JWT signed with the issuer key using the
// exact header shape the verifier expects (ES256, typ aic+jwt, kid = SPKI hash).
func signBearerToken(t *testing.T, issuerKey *ecdsa.PrivateKey, issuerCert *x509.Certificate, outer aicjwt.OuterClaims) string {
	t.Helper()
	kid, err := aicjwt.SPKIHash(issuerCert, "sha-256")
	if err != nil {
		t.Fatalf("SPKIHash: %v", err)
	}
	hdr, err := json.Marshal(map[string]string{"alg": "ES256", "typ": aicjwt.TypOuter, "kid": kid})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload, err := json.Marshal(outer)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	tok, err := aicjwt.SignCompact(hdr, payload, "ES256", issuerKey)
	if err != nil {
		t.Fatalf("SignCompact: %v", err)
	}
	return tok
}

// newOuterClaims builds a valid authorized-mode bearer claim set.
func newOuterClaims(t *testing.T, now time.Time, jti string) aicjwt.OuterClaims {
	t.Helper()
	principalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("principal key: %v", err)
	}
	kh, err := aicjwt.KeyHashOf(&principalKey.PublicKey, "sha-256")
	if err != nil {
		t.Fatalf("key_hash: %v", err)
	}
	jkt, err := aicjwt.KeyHashOf(&principalKey.PublicKey, "jkt")
	if err != nil {
		t.Fatalf("cnf jkt: %v", err)
	}
	return aicjwt.OuterClaims{
		Iss: "https://issuer.example",
		Sub: "agent-42",
		Aud: aicjwt.Audience{"https://gw.example"},
		Iat: now.Add(-time.Minute).Unix(),
		Exp: now.Add(time.Hour).Unix(),
		Jti: jti,
		Cnf: &aicjwt.Cnf{Jkt: jkt},
		Aic: &aicjwt.AICClaims{
			Ver:            1,
			Principal:      aicjwt.Principal{Realm: "varwof", ID: "principal-7", KeyHash: kh, HashAlg: "sha-256"},
			DelegationMode: aicjwt.ModeAuthorized,
			Capabilities: []aicjwt.Capability{
				{Scheme: "varwof/gateway-v1", ID: "admin:config"},
			},
			Constraints: []aicjwt.Capability{
				{Scheme: "varwof/constraint-v1", ID: "session:max-concurrent", Params: json.RawMessage(`{"max":4}`)},
			},
		},
	}
}

func writeCertPEMFileForJWT(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jwt-ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewJWTVerifier(t *testing.T) {
	_, cert := newIssuerIdentity(t)
	v := NewJWTVerifier([]*x509.Certificate{cert})
	if v == nil {
		t.Fatal("verifier = nil")
	}
	if len(v.roots) != 1 {
		t.Fatalf("roots = %d, want 1", len(v.roots))
	}
	empty := NewJWTVerifier([]*x509.Certificate{nil})
	if empty == nil || len(empty.roots) != 0 {
		t.Fatalf("nil-cert verifier = %v, want empty roots", empty)
	}
}

func TestLoadJWTVerifier(t *testing.T) {
	_, cert := newIssuerIdentity(t)
	path := writeCertPEMFileForJWT(t, cert)

	t.Run("loads_ca_pem", func(t *testing.T) {
		v, err := LoadJWTVerifier(path)
		if err != nil {
			t.Fatalf("LoadJWTVerifier: %v", err)
		}
		if v == nil || len(v.roots) == 0 {
			t.Fatalf("verifier = %v, want non-empty roots", v)
		}
	})

	t.Run("multiple_paths_split_by_comma_space", func(t *testing.T) {
		_, cert2 := mintCert(t, nil, nil, "jwt-issuer-2", big.NewInt(702), nil, nil, nil)
		path2 := filepath.Join(t.TempDir(), "jwt-ca-2.pem")
		data2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw})
		if err := os.WriteFile(path2, data2, 0o600); err != nil {
			t.Fatal(err)
		}
		v, err := LoadJWTVerifier(path+","+path2, " "+path)
		if err != nil {
			t.Fatalf("LoadJWTVerifier multi: %v", err)
		}
		// LoadJWTVerifier stores certs keyed by kid, so the repeated path
		// collapses to one unique root: 2 distinct CAs total.
		if v == nil || len(v.roots) != 2 {
			t.Fatalf("verifier roots = %v, want 2 unique (duplicate path yields same kid)", v)
		}
	})

	t.Run("missing_file_errors", func(t *testing.T) {
		if _, err := LoadJWTVerifier(filepath.Join(t.TempDir(), "nope.pem")); err == nil {
			t.Fatal("expected error for missing CA file")
		}
	})

	t.Run("corrupt_cert_block_errors", func(t *testing.T) {
		bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("broken der")})
		badPath := filepath.Join(t.TempDir(), "bad.pem")
		if err := os.WriteFile(badPath, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadJWTVerifier(badPath); err == nil {
			t.Fatal("expected error for corrupt certificate PEM")
		}
	})

	t.Run("empty_spec_disables_bearer", func(t *testing.T) {
		v, err := LoadJWTVerifier()
		if err != nil || v != nil {
			t.Fatalf("empty spec: v=%v err=%v, want nil,nil", v, err)
		}
	})

	t.Run("non_pem_content_yields_nil_verifier", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "text.pem")
		if err := os.WriteFile(f, []byte("plain text, no pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		v, err := LoadJWTVerifier(f)
		if err != nil || v != nil {
			t.Fatalf("non-pem: v=%v err=%v, want nil,nil", v, err)
		}
	})
}

func TestSetBearerPolicyEnforced(t *testing.T) {
	issuerKey, issuerCert := newIssuerIdentity(t)
	verifier := NewJWTVerifier([]*x509.Certificate{issuerCert})
	now := time.Now()

	verifier.SetBearerPolicy("https://issuer.example", []string{"https://gw.example"}, nil)

	outer := newOuterClaims(t, now, "jti-policy-1")
	tok := signBearerToken(t, issuerKey, issuerCert, outer)
	if _, _, err := verifier.VerifyBearer(tok, now); err != nil {
		t.Fatalf("VerifyBearer with matching issuer/audience: %v", err)
	}

	wrongIssuer := newOuterClaims(t, now, "jti-policy-2")
	wrongIssuer.Iss = "https://evil.example"
	tok = signBearerToken(t, issuerKey, issuerCert, wrongIssuer)
	_, _, err := verifier.VerifyBearer(tok, now)
	if err == nil || !strings.Contains(err.Error(), "expected issuer") {
		t.Fatalf("wrong issuer: err=%v, want issuer mismatch", err)
	}

	wrongAud := newOuterClaims(t, now, "jti-policy-3")
	wrongAud.Aud = aicjwt.Audience{"https://other.example"}
	tok = signBearerToken(t, issuerKey, issuerCert, wrongAud)
	_, _, err = verifier.VerifyBearer(tok, now)
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("wrong audience: err=%v, want audience failure", err)
	}
}

func TestVerifyBearer(t *testing.T) {
	issuerKey, issuerCert := newIssuerIdentity(t)
	now := time.Now()

	t.Run("accepts_valid_token", func(t *testing.T) {
		verifier := NewJWTVerifier([]*x509.Certificate{issuerCert})
		outer := newOuterClaims(t, now, "jti-ok-1")
		tok := signBearerToken(t, issuerKey, issuerCert, outer)
		cert, got, err := verifier.VerifyBearer(tok, now)
		if err != nil {
			t.Fatalf("VerifyBearer: %v", err)
		}
		if cert == nil || got == nil {
			t.Fatalf("cert=%v outer=%v", cert, got)
		}
		if cert.Subject.CommonName != outer.Sub {
			t.Errorf("cert CN = %q, want %q", cert.Subject.CommonName, outer.Sub)
		}
		if got.Sub != outer.Sub || got.Jti != outer.Jti {
			t.Errorf("outer = %+v, want sub=%q jti=%q", got, outer.Sub, outer.Jti)
		}
		if cert.SerialNumber.Cmp(serialFromJWT(&outer)) != 0 {
			t.Errorf("cert serial %v != serialFromJWT %v", cert.SerialNumber, serialFromJWT(&outer))
		}
		if NormalizeSerial(cert.SerialNumber) != NormalizeSerial(serialFromJWT(&outer)) {
			t.Errorf("serial does not round-trip through NormalizeSerial: %q", NormalizeSerial(cert.SerialNumber))
		}
	})

	t.Run("rejects_expired_token", func(t *testing.T) {
		verifier := NewJWTVerifier([]*x509.Certificate{issuerCert})
		outer := newOuterClaims(t, now, "jti-exp-1")
		outer.Iat = now.Add(-2 * time.Hour).Unix()
		outer.Exp = now.Add(-time.Hour).Unix()
		tok := signBearerToken(t, issuerKey, issuerCert, outer)
		if _, _, err := verifier.VerifyBearer(tok, now); err == nil {
			t.Fatal("expected rejection of expired token")
		}
	})

	t.Run("rejects_unknown_kid", func(t *testing.T) {
		verifier := NewJWTVerifier([]*x509.Certificate{issuerCert})
		_, otherCert := newIssuerIdentity(t)
		otherKey, _ := mintCert(t, nil, nil, "jwt-issuer-2", big.NewInt(701), nil, nil, nil)
		outer := newOuterClaims(t, now, "jti-kid-1")
		tok := signBearerToken(t, otherKey, otherCert, outer)
		if _, _, err := verifier.VerifyBearer(tok, now); err == nil {
			t.Fatal("expected unknown-kid rejection")
		}
	})

	t.Run("no_trust_root_fails_closed", func(t *testing.T) {
		verifier := NewJWTVerifier(nil)
		outer := newOuterClaims(t, now, "jti-noroot-1")
		tok := signBearerToken(t, issuerKey, issuerCert, outer)
		if _, _, err := verifier.VerifyBearer(tok, now); err == nil {
			t.Fatal("expected error for empty trust root")
		}
	})

	t.Run("replay_protection_via_nonce_store", func(t *testing.T) {
		verifier := NewJWTVerifier([]*x509.Certificate{issuerCert})
		store := NewReplayNonceStore(0, 0)
		opts := JWTVerifyOptions{NonceStore: store}
		outer := newOuterClaims(t, now, "jti-replay-1")

		tok := signBearerToken(t, issuerKey, issuerCert, outer)
		if _, _, err := verifier.VerifyBearer(tok, now, opts); err != nil {
			t.Fatalf("first use: %v", err)
		}
		if _, _, err := verifier.VerifyBearer(tok, now, opts); err == nil {
			t.Fatal("expected replay rejection on second use")
		}
	})

	t.Run("replay_policy_through_verifier", func(t *testing.T) {
		verifier := NewJWTVerifier([]*x509.Certificate{issuerCert})
		verifier.SetBearerPolicy("https://issuer.example", nil, NewReplayNonceStore(0, 0))
		outer := newOuterClaims(t, now, "jti-instore-1")
		tok := signBearerToken(t, issuerKey, issuerCert, outer)
		if _, _, err := verifier.VerifyBearer(tok, now); err != nil {
			t.Fatalf("first use with in-verifier store: %v", err)
		}
		if _, _, err := verifier.VerifyBearer(tok, now); err == nil {
			t.Fatal("expected replay rejection through in-verifier store")
		}
	})
}

func TestSynthesizeCertFromJWT(t *testing.T) {
	now := time.Now()
	outer := newOuterClaims(t, now, "jti-synth-1")

	t.Run("nil_outer_errors", func(t *testing.T) {
		if _, err := SynthesizeCertFromJWT(nil); err == nil {
			t.Fatal("expected error for nil outer claims")
		}
	})

	t.Run("missing_aic_errors", func(t *testing.T) {
		noAic := newOuterClaims(t, now, "jti-synth-2")
		noAic.Aic = nil
		if _, err := SynthesizeCertFromJWT(&noAic); err == nil {
			t.Fatal("expected error for missing aic claims")
		}
	})

	t.Run("produces_pipeline_certificate", func(t *testing.T) {
		cert, err := SynthesizeCertFromJWT(&outer)
		if err != nil {
			t.Fatalf("SynthesizeCertFromJWT: %v", err)
		}
		if cert.Subject.CommonName != outer.Sub {
			t.Errorf("CN = %q, want %q", cert.Subject.CommonName, outer.Sub)
		}
		if !cert.NotBefore.Equal(time.Unix(outer.Iat, 0)) || !cert.NotAfter.Equal(time.Unix(outer.Exp, 0)) {
			t.Errorf("validity = %v..%v, want %v..%v", cert.NotBefore, cert.NotAfter, time.Unix(outer.Iat, 0), time.Unix(outer.Exp, 0))
		}
		if cert.SerialNumber == nil || cert.SerialNumber.Sign() == 0 {
			t.Fatalf("serial = %v, want positive", cert.SerialNumber)
		}
		foundAIC := false
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(pki.OIDAIC) {
				foundAIC = true
				if len(ext.Value) == 0 {
					t.Error("AIC extension value empty")
				}
			}
		}
		if !foundAIC {
			t.Error("synthesized cert missing AIC extension")
		}
		parsed, err := ParseAIC(cert)
		if err != nil {
			t.Fatalf("ParseAIC on synthesized cert: %v", err)
		}
		if parsed.AgentId != outer.Sub {
			t.Errorf("parsed AgentId = %q, want %q", parsed.AgentId, outer.Sub)
		}
		// The placeholder DA must be present so the pipeline admits the bearer.
		if err := ValidateAIC(parsed); err != nil {
			t.Fatalf("ValidateAIC: %v", err)
		}
	})
}

func TestSerialFromJWT(t *testing.T) {
	now := time.Now()
	a1 := newOuterClaims(t, now, "jti-serial-1")
	a2 := newOuterClaims(t, now, "jti-serial-2")

	t.Run("deterministic_and_positive", func(t *testing.T) {
		s1 := serialFromJWT(&a1)
		s2 := serialFromJWT(&a1)
		if s1.Cmp(big.NewInt(0)) <= 0 {
			t.Fatalf("serial %v not positive", s1)
		}
		if s1.Cmp(s2) != 0 {
			t.Errorf("serial not deterministic: %v vs %v", s1, s2)
		}
	})

	t.Run("different_jti_different_serial", func(t *testing.T) {
		if serialFromJWT(&a1).Cmp(serialFromJWT(&a2)) == 0 {
			t.Error("distinct jti must yield distinct serials")
		}
	})

	t.Run("falls_back_to_principal_id", func(t *testing.T) {
		noJti := newOuterClaims(t, now, "")
		noJti.Jti = ""
		noJti.Aic.Principal.ID = "principal-id-fallback"
		got := serialFromJWT(&noJti)
		if got.Cmp(big.NewInt(0)) <= 0 {
			t.Errorf("fallback serial %v not positive", got)
		}
	})
}

func TestJWTToAIC(t *testing.T) {
	now := time.Now()
	outer := newOuterClaims(t, now, "jti-aic-1")
	outer.Aic.DelegationMode = aicjwt.ModeRepresentative

	aic := jwtToAIC(&outer)
	if aic.Version != 1 {
		t.Errorf("Version = %d", aic.Version)
	}
	if aic.AgentId != outer.Sub {
		t.Errorf("AgentId = %q, want %q", aic.AgentId, outer.Sub)
	}
	if int(aic.DelegationMode) != 1 {
		t.Errorf("DelegationMode = %d, want representative(1)", aic.DelegationMode)
	}
	if aic.PrincipalUid.Realm != outer.Aic.Principal.Realm ||
		aic.PrincipalUid.Identifier != outer.Aic.Principal.ID {
		t.Errorf("PrincipalUid = %+v", aic.PrincipalUid)
	}
	if kh, err := base64.RawURLEncoding.DecodeString(outer.Aic.Principal.KeyHash); err != nil || string(kh) != string(aic.PrincipalUid.KeyHash) {
		t.Errorf("KeyHash mismatch: err=%v", err)
	}
	if len(aic.Capabilities) != 1 || aic.Capabilities[0].SchemeId != "varwof/gateway-v1" || aic.Capabilities[0].CapabilityId != "admin:config" {
		t.Errorf("Capabilities = %+v", aic.Capabilities)
	}
	if len(aic.AuthorizationConstraints) != 1 || aic.AuthorizationConstraints[0].CapabilityId != "session:max-concurrent" {
		t.Errorf("Constraints = %+v", aic.AuthorizationConstraints)
	}
	if aic.DelegationAuthorization.Reason.ReasonCode != "JWT_BEARER" {
		t.Errorf("Reason = %+v", aic.DelegationAuthorization.Reason)
	}
	if aic.DelegationAuthorization.RequestedLifetime != requestedLifetimeOf(&outer) {
		t.Errorf("RequestedLifetime = %d", aic.DelegationAuthorization.RequestedLifetime)
	}
	if string(aic.DelegationAuthorization.Nonce) != string(nonceFromJTI(outer.Jti)) {
		t.Error("DA nonce != nonceFromJTI(jti)")
	}
	if !aic.DelegationAuthorization.SignatureAlgorithm.Algorithm.Equal(pki.OIDSHA256) {
		t.Errorf("SignatureAlgorithm = %v", aic.DelegationAuthorization.SignatureAlgorithm.Algorithm)
	}
}

func TestNonceFromJTI(t *testing.T) {
	n1 := nonceFromJTI("jti-nonce-1")
	n2 := nonceFromJTI("jti-nonce-1")
	n3 := nonceFromJTI("jti-nonce-2")
	if len(n1) != 32 {
		t.Errorf("nonce length = %d, want 32", len(n1))
	}
	if string(n1) != string(n2) {
		t.Error("nonceFromJTI not deterministic")
	}
	if string(n1) == string(n3) {
		t.Error("distinct jti must yield distinct nonces")
	}
}

func TestRequestedLifetimeOf(t *testing.T) {
	now := time.Now()
	outer := newOuterClaims(t, now, "jti-life-1")
	want := int(outer.Exp - outer.Iat)
	if got := requestedLifetimeOf(&outer); got != want {
		t.Errorf("requestedLifetimeOf = %d, want %d", got, want)
	}

	inverted := newOuterClaims(t, now, "jti-life-2")
	inverted.Exp = inverted.Iat - 5
	if got := requestedLifetimeOf(&inverted); got != 3600 {
		t.Errorf("invalid lifetime clamps to 3600, got %d", got)
	}
}

func TestModeToInt(t *testing.T) {
	if got := modeToInt(aicjwt.ModeRepresentative); got != 1 {
		t.Errorf("representative = %d, want 1", got)
	}
	if got := modeToInt(aicjwt.ModeAuthorized); got != 0 {
		t.Errorf("authorized = %d, want 0", got)
	}
	if got := modeToInt("garbage"); got != 0 {
		t.Errorf("garbage = %d, want 0", got)
	}
}

func TestParsePEMCerts(t *testing.T) {
	_, c1 := mintCert(t, nil, nil, "one", big.NewInt(1), nil, nil, nil)
	_, c2 := mintCert(t, nil, nil, "two", big.NewInt(2), nil, nil, nil)

	t.Run("parses_multi_cert_pem", func(t *testing.T) {
		data := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c1.Raw}),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c2.Raw})...)
		certs, err := parsePEMCerts(data)
		if err != nil {
			t.Fatalf("parsePEMCerts: %v", err)
		}
		if len(certs) != 2 {
			t.Fatalf("parsed %d certs, want 2", len(certs))
		}
	})

	t.Run("empty_input_returns_empty", func(t *testing.T) {
		certs, err := parsePEMCerts(nil)
		if err != nil {
			t.Fatalf("parsePEMCerts(empty): %v", err)
		}
		if len(certs) != 0 {
			t.Errorf("parsed %d certs, want 0", len(certs))
		}
	})

	t.Run("non_certificate_blocks_skipped", func(t *testing.T) {
		data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("x")})
		certs, err := parsePEMCerts(data)
		if err != nil {
			t.Fatalf("parsePEMCerts(other block): %v", err)
		}
		if len(certs) != 0 {
			t.Errorf("parsed %d certs, want 0", len(certs))
		}
	})
}
