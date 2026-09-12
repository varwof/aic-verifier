// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
)

// SPIFFEID represents a parsed SPIFFE identity.
type SPIFFEID struct {
	TrustDomain string
	Path        string
}

// String returns the SPIFFE ID in URI format.
func (s *SPIFFEID) String() string {
	if s == nil {
		return ""
	}
	return "spiffe://" + s.TrustDomain + s.Path
}

// Equal checks whether two SPIFFEID values are identical.
func (s *SPIFFEID) Equal(other *SPIFFEID) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.TrustDomain == other.TrustDomain && s.Path == other.Path
}

// ExtractSPIFFEIDFromCert extracts a SPIFFE ID from a certificate's SAN URIs.
// Returns "" if no SPIFFE URI is found.
func ExtractSPIFFEIDFromCert(cert *x509.Certificate) string {
	for _, u := range cert.URIs {
		if u.Scheme == "spiffe" {
			return u.String()
		}
	}
	return ""
}

// ExtractSPIFFEID extracts a parsed SPIFFE ID from a certificate's SAN URIs.
// Returns nil if no valid SPIFFE URI is found.
func ExtractSPIFFEID(cert *x509.Certificate) *SPIFFEID {
	if cert == nil {
		return nil
	}
	raw := ExtractSPIFFEIDFromCert(cert)
	if raw == "" {
		return nil
	}
	sid, _ := ParseSPIFFEID(raw)
	return sid
}

// VerifySPIFFESAN validates that a certificate carries the expected SPIFFE ID in its SAN URIs.
func VerifySPIFFESAN(cert *x509.Certificate, expectedID string) bool {
	return ExtractSPIFFEIDFromCert(cert) == expectedID
}

// ParseSPIFFEID parses a SPIFFE ID string into its components (trust domain, path).
func ParseSPIFFEID(id string) (*SPIFFEID, error) {
	u, err := url.Parse(id)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "spiffe" {
		return nil, errors.New("not a SPIFFE ID")
	}
	trustDomain := u.Hostname()
	if trustDomain == "" {
		return nil, errors.New("empty trust domain")
	}
	// Validate trust domain contains at least one dot (RFC 7555)
	if !strings.Contains(trustDomain, ".") {
		return nil, errors.New("trust domain must contain at least one dot")
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return &SPIFFEID{
		TrustDomain: trustDomain,
		Path:        path,
	}, nil
}
