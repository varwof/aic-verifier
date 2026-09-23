// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	pki "github.com/varwof/types"
	"github.com/varwof/types/aicjwt"
)

const (
	caCert = "ca.pem"
	caKey  = "ca-key.pem"
)

// ensureCA writes ca.pem + ca-key.pem when missing, so the demo runs with a
// single command. The server trusts this CA via Config.JWTCAFile / CACertFile
// and the demo credentials are signed with its key.
func ensureCA(dir string) error {
	cert, key := dirPath(dir, caCert), dirPath(dir, caKey)
	if _, err := os.Stat(cert); err == nil {
		if _, err := os.Stat(key); err == nil {
			return nil
		}
	}
	keyPair, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &keyPair.PublicKey, keyPair)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}
	if err := writePEM(cert, "CERTIFICATE", der); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(keyPair)
	if err != nil {
		return err
	}
	return writePEM(key, "EC PRIVATE KEY", keyDER)
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

// mintAICClientCert mints an AIC X.509 client certificate for the --mtls front
// end, signed by the demo CA. The certificate carries the same mcp:* capability
// set as the operator bearer token, so the mTLS and bearer demos admit the same
// tools. Output: client-cert.pem / client-key.pem.
func mintAICClientCert(dir string) error {
	if err := ensureCA(dir); err != nil {
		return err
	}
	ca, err := readCAPair(dirPath(dir, caCert), dirPath(dir, caKey))
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	subjectKey, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	keyHash := sha256.Sum256(subjectKey)
	aic := pki.AIC{
		Version: 1,
		AgentId: "agent-001",
		PrincipalUid: pki.PrincipalUid{
			Version: 1, Realm: "example", Identifier: "agent-001",
			KeyHash: keyHash[:],
		},
		Capabilities: []pki.Capability{
			{SchemeId: "mcp", CapabilityId: "db_query"},
			{SchemeId: "mcp", CapabilityId: "trade_exec"},
		},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "operator-request", Description: "mcp-behind-proxy demo"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
		},
	}
	aicDER, err := asn1.Marshal(aic)
	if err != nil {
		return fmt.Errorf("asn1.Marshal AIC: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "agent-001"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: pki.OIDAIC, Critical: false, Value: aicDER},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return fmt.Errorf("mint AIC client cert: %w", err)
	}
	if err := writePEM(dirPath(dir, "client-cert.pem"), "CERTIFICATE", der); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(dirPath(dir, "client-key.pem"), "EC PRIVATE KEY", keyDER)
}

// dirPath joins an artifact path with the --certs directory, the same layout
// the mtls-backend example uses (ca.pem / client-*.pem under one dir).
func dirPath(dir, file string) string {
	if dir == "" || dir == "." {
		return file
	}
	return fmt.Sprintf("%s/%s", dir, file)
}
