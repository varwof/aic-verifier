// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"
)

// SecureCipherSuites is the list of secure cipher suites (GCM/CHACHA).
var SecureCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
}

var cipherSuiteNames = map[string]uint16{
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	"TLS_AES_128_GCM_SHA256":                  tls.TLS_AES_128_GCM_SHA256,
	"TLS_AES_256_GCM_SHA384":                  tls.TLS_AES_256_GCM_SHA384,
	"TLS_CHACHA20_POLY1305_SHA256":            tls.TLS_CHACHA20_POLY1305_SHA256,
}

// BuildCipherSuites builds a cipher suite list from name strings.
func BuildCipherSuites(names []string) []uint16 {
	if len(names) == 0 {
		return SecureCipherSuites
	}
	suites := make([]uint16, 0, len(names))
	for _, name := range names {
		if id, ok := cipherSuiteNames[name]; ok {
			suites = append(suites, id)
		}
	}
	if len(suites) == 0 {
		log.Printf("WARNING: no recognized cipher suites in %v, falling back to defaults", names)
		return SecureCipherSuites
	}
	return suites
}

// TLSVersionFromString converts a version string to a TLS version number.
func TLSVersionFromString(s string) uint16 {
	switch s {
	case "1.2":
		return uint16(tls.VersionTLS12)
	case "1.3":
		return uint16(tls.VersionTLS13)
	default:
		return uint16(tls.VersionTLS12)
	}
}

// BaseTLSConfig creates a base TLS configuration.
func BaseTLSConfig(cipherSuites []string, minTLSVersion string) *tls.Config {
	ciphers := SecureCipherSuites
	minVer := uint16(tls.VersionTLS12)
	if len(cipherSuites) > 0 {
		ciphers = BuildCipherSuites(cipherSuites)
	}
	if minTLSVersion != "" {
		minVer = TLSVersionFromString(minTLSVersion)
	}
	return &tls.Config{
		MinVersion:   minVer,
		CipherSuites: ciphers,
	}
}

// LoadCert loads a TLS certificate key pair.
func LoadCert(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load keypair (%s, %s): %w", certFile, keyFile, err)
	}
	return &cert, nil
}

// LoadCA loads a CA certificate pool and validates that every certificate in the bundle is a CA.
func LoadCA(caCertFile string) (*x509.CertPool, error) {
	data, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %s: %w", caCertFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no valid CA cert in %s", caCertFile)
	}
	// L1: iterate over every block in the bundle. The previous loop re-decoded
	// `data` (the first block) on every iteration, so only the first cert was
	// ever validated and subsequent certs were silently ignored.
	block, rest := pem.Decode(data)
	for block != nil {
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse cert in %s: %w", caCertFile, parseErr)
		}
		if !cert.IsCA {
			return nil, fmt.Errorf("certificate %q in %s is not a CA (IsCA=false)", cert.Subject.String(), caCertFile)
		}
		block, rest = pem.Decode(rest)
	}
	return pool, nil
}

// ServerTLSConfig creates a server-side TLS configuration.
func ServerTLSConfig(cert *tls.Certificate, cipherSuites []string, minTLSVersion string) *tls.Config {
	cfg := BaseTLSConfig(cipherSuites, minTLSVersion)
	cfg.Certificates = []tls.Certificate{*cert}
	return cfg
}

// MTLSServerConfig creates an mTLS server-side configuration.
func MTLSServerConfig(caCertFile string, cert *tls.Certificate, cipherSuites []string, minTLSVersion string) (*tls.Config, error) {
	caPool, err := LoadCA(caCertFile)
	if err != nil {
		return nil, err
	}
	cfg := BaseTLSConfig(cipherSuites, minTLSVersion)
	cfg.Certificates = []tls.Certificate{*cert}
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = caPool
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) == 0 {
			return fmt.Errorf("no verified certificate chain")
		}
		chain := verifiedChains[0]
		now := time.Now()
		for i := 0; i < len(chain)-1; i++ {
			if now.Before(chain[i].NotBefore) || now.After(chain[i].NotAfter) {
				return fmt.Errorf("certificate %q expired", chain[i].Subject.String())
			}
			if i > 0 && chain[i].KeyUsage&x509.KeyUsageCertSign == 0 {
				return fmt.Errorf("intermediate CA %q missing KeyUsageCertSign", chain[i].Subject.String())
			}
		}
		return nil
	}
	return cfg, nil
}

// LoadCACert loads and parses a single CA certificate (first PEM block).
func LoadCACert(caCertFile string) (*x509.Certificate, error) {
	data, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %s: %w", caCertFile, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data in %s", caCertFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert %s: %w", caCertFile, err)
	}
	return cert, nil
}

// ClientTLSConfig creates an mTLS client-side configuration.
func ClientTLSConfig(caCertFile, certFile, keyFile string, cipherSuites []string, minTLSVersion string) (*tls.Config, error) {
	caPool, err := LoadCA(caCertFile)
	if err != nil {
		return nil, err
	}
	cfg := BaseTLSConfig(cipherSuites, minTLSVersion)
	cfg.RootCAs = caPool
	if certFile != "" && keyFile != "" {
		cert, err := LoadCert(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return cfg, nil
}
