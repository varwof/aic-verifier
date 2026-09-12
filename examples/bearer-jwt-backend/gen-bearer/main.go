// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Command gen-bearer generates a CA keypair and signs a sample AIC-JWT bearer
// token for the bearer-jwt-backend example. It prints the token to stdout.
//
// The server trusts the same CA via aicverifier.Config.JWTCAFile, so the token
// it prints is exactly what the SDK accepts.
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

	tlsCert = "server-cert.pem"
	tlsKey  = "server-key.pem"
)

func main() {
	if err := ensureCA(); err != nil {
		fmt.Fprintln(os.Stderr, "gen-bearer:", err)
		os.Exit(1)
	}

	if err := ensureTLSPair(); err != nil {
		fmt.Fprintln(os.Stderr, "gen-bearer:", err)
		os.Exit(1)
	}

	ca, err := readCAPair(caCert, caKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-bearer:", err)
		os.Exit(2)
	}

	token, err := signAICJWT(ca)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-bearer:", err)
		os.Exit(3)
	}
	fmt.Println(token)
}

type caPair struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// ensureCA writes ca.pem + ca-key.pem when missing.
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
		Subject:               pkix.Name{CommonName: "aic-verifier example CA"},
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

// ensureTLSPair writes server-cert.pem + server-key.pem when missing.  The
// example proxy terminates TLS with this self-signed localhost pair; generating
// it here keeps private key material out of the repository.
func ensureTLSPair() error {
	if _, err := os.Stat(tlsCert); err == nil {
		if _, err := os.Stat(tlsKey); err == nil {
			return nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate TLS key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * 365 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create TLS cert: %w", err)
	}
	if err := writePEM(tlsCert, "CERTIFICATE", der); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(tlsKey, "EC PRIVATE KEY", keyDER)
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

// signAICJWT builds and signs a bearer token with the CA key. The token's kid
// is the CA SPKI hash, which is the same trust root aic-verifier builds from
// JWTCAFile.
func signAICJWT(ca *caPair) (string, error) {
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

	principal := aicjwt.Principal{
		Realm:   "example",
		ID:      "agent-001",
		KeyHash: keyHash,
		HashAlg: "sha-256",
	}
	outer := aicjwt.OuterClaims{
		Iss: "aic-verifier-example",
		Sub: "agent-001",
		Aud: aicjwt.Audience{"myapi"},
		Iat: now.Unix(),
		Exp: now.Add(time.Hour).Unix(),
		Jti: fmt.Sprintf("t-%d", now.UnixNano()),
		Cnf: &aicjwt.Cnf{Jkt: jkt},
		Aic: &aicjwt.AICClaims{
			Ver:            1,
			Principal:      principal,
			DelegationMode: aicjwt.ModeAuthorized,
			Capabilities: []aicjwt.Capability{
				{Scheme: "demo", ID: "demo:http:*", Params: json.RawMessage(`{"role":"read"}`)},
				{Scheme: "demo", ID: "api:read", Params: json.RawMessage(`{"scope":"public"}`)},
			},
		},
	}

	header := aicjwt.Header{Alg: "ES256", Typ: aicjwt.TypOuter, Kid: kid}
	headerJSON, _ := json.Marshal(header)
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
