// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Command gen-mtls generates a demo CA, a server certificate, and an mTLS
// client certificate carrying an AIC extension, for the mtls-backend example.
//
//	$ go run . --out ./dev-certs
//	$ go run . --client    # also print the path of the client cert/key
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	pki "github.com/varwof/types"
)

func main() {
	out := flag.String("out", "dev-certs", "output directory")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}

	caKey, caCert := makeCA(*out)
	serverCert := makeServer(*out, caKey, caCert)
	clientCert := makeClient(*out, caKey, caCert)

	fmt.Printf("generated in %s:\n", *out)
	fmt.Printf("  ca-cert.pem  ca-key.pem\n  server-cert.pem  server-key.pem\n")
	fmt.Printf("  client-cert.pem  client-key.pem  (mTLS + AIC)\n")
	_, _ = serverCert, clientCert
}

func makeCA(dir string) (*ecdsa.PrivateKey, *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "aic-verifier mtls CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	writeCert(filepath.Join(dir, "ca-cert.pem"), der)
	writeKey(filepath.Join(dir, "ca-key.pem"), key)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}
	return key, cert
}

func makeServer(dir string, caKey *ecdsa.PrivateKey, ca *x509.Certificate) *x509.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	writeCert(filepath.Join(dir, "server-cert.pem"), der)
	writeKey(filepath.Join(dir, "server-key.pem"), key)
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func makeClient(dir string, caKey *ecdsa.PrivateKey, ca *x509.Certificate) *x509.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	aic := pki.AIC{
		Version: 1,
		AgentId: "agent-002",
		PrincipalUid: pki.PrincipalUid{
			Version: 1, Realm: "example", Identifier: "agent-002",
			KeyHash: make([]byte, 32),
		},
		Capabilities: []pki.Capability{
			// SchemeId must be the CLC scheme form (vendor/product-vN); the
			// full capability id is scheme + ":" + CapabilityId.
			{SchemeId: "demo/example-v1", CapabilityId: "api:read"},
			{SchemeId: "demo/example-v1", CapabilityId: "http:*"},
		},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "TEST", Description: "mtls example"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
		},
	}
	aicDER, err := asn1.Marshal(aic)
	if err != nil {
		log.Fatal("asn1.Marshal AIC:", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "agent-002"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: pki.OIDAIC, Critical: false, Value: aicDER},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		log.Fatal("CreateCertificate:", err)
	}
	writeCert(filepath.Join(dir, "client-cert.pem"), der)
	writeKey(filepath.Join(dir, "client-key.pem"), key)
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func writeCert(path string, der []byte) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		log.Fatal(err)
	}
}

func writeKey(path string, key *ecdsa.PrivateKey) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		log.Fatal(err)
	}
}
