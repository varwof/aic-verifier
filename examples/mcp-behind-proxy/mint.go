// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/varwof/types/aicjwt"
)

const (
	caCert = "ca.pem"
	caKey  = "ca-key.pem"
)

// ensureCA writes ca.pem + ca-key.pem when missing, so the demo runs with a
// single command. The server trusts this CA via Config.JWTCAFile and the
// tokens are signed with its key (kid = CA SPKI hash).
func ensureCA() error {
	if _, err := os.Stat(caCert); err == nil {
		if _, err := os.Stat(caKey); err == nil {
			return nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "aic-verifier mcp demo CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * 365 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}
	if err := writePEM(caCert, "CERTIFICATE", der); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(caKey, "EC PRIVATE KEY", keyDER)
}

type caPair struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func readCAPair(certFile, keyFile string) (*caPair, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, fmt.Errorf("no cert in %s", certFile)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("no key in %s", keyFile)
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &caPair{cert: cert, key: key}, nil
}

// signAICJWT builds a bearer token for sub carrying the given capabilities,
// signed with the demo CA (kid = CA SPKI hash, the same trust root aic-verifier
// derives from JWTCAFile).
func signAICJWT(ca *caPair, sub, iss, aud string, caps []aicjwt.Capability) (string, error) {
	now := time.Now()
	kid, err := aicjwt.SPKIHash(ca.cert, "sha-256")
	if err != nil {
		return "", err
	}
	keyHash, err := aicjwt.KeyHashOf(&ca.key.PublicKey, "sha-256")
	if err != nil {
		return "", err
	}
	jwk, err := aicjwt.PublicKeyToJWK(&ca.key.PublicKey)
	if err != nil {
		return "", err
	}
	jkt, err := aicjwt.JWKThumbprint(jwk)
	if err != nil {
		return "", err
	}

	outer := aicjwt.OuterClaims{
		Iss: iss,
		Sub: sub,
		Aud: aicjwt.Audience{aud},
		Iat: now.Unix(),
		Exp: now.Add(time.Hour).Unix(),
		Jti: fmt.Sprintf("t-%d", now.UnixNano()),
		Cnf: &aicjwt.Cnf{Jkt: jkt},
		Aic: &aicjwt.AICClaims{
			Ver:            1,
			Principal:      aicjwt.Principal{Realm: "example", ID: sub, KeyHash: keyHash, HashAlg: "sha-256"},
			DelegationMode: aicjwt.ModeAuthorized,
			Capabilities:   caps,
		},
	}

	headerJSON, _ := json.Marshal(aicjwt.Header{Alg: "ES256", Typ: aicjwt.TypOuter, Kid: kid})
	payloadJSON, _ := json.Marshal(outer)
	return aicjwt.SignCompact(headerJSON, payloadJSON, "ES256", ca.key)
}

func writePEM(path, typ string, der []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}
