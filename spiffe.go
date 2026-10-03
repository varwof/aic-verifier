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

// VerifySPIFFESAN validates that a certificate carries the expected SPIFFE ID
// in its SAN URIs. Because SPIFFE trust domains are case-insensitive (RFC 7555
// §2.1), both the certificate value and the expected ID are compared in
// canonical form: trust domain lowercased, path compared verbatim.
func VerifySPIFFESAN(cert *x509.Certificate, expectedID string) bool {
	return canonicalSPIFFEID(ExtractSPIFFEIDFromCert(cert)) == canonicalSPIFFEID(expectedID)
}

// ParseSPIFFEID parses a SPIFFE ID string into its components (trust domain, path).
//
// Per RFC 7555 §2.1 a trust domain is case-insensitive, so the parsed trust
// domain is canonicalized to lowercase and validated against the trust-domain
// character set [a-z0-9-._] (at least one dot). The path is preserved verbatim
// (path segments are case-sensitive).
func ParseSPIFFEID(id string) (*SPIFFEID, error) {
	u, err := url.Parse(id)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "spiffe" {
		return nil, errors.New("not a SPIFFE ID")
	}
	trustDomain := strings.ToLower(u.Hostname())
	if trustDomain == "" {
		return nil, errors.New("empty trust domain")
	}
	// RFC 7555 §2.1: trust domain charset is [a-z0-9-._] and must contain at
	// least one dot.
	if !validTrustDomainCharset(trustDomain) {
		return nil, errors.New("trust domain contains invalid characters")
	}
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

// validTrustDomainCharset reports whether td is composed solely of the RFC 7555
// §2.1 trust-domain characters [a-z0-9-._]. Input is expected to be lowercase.
func validTrustDomainCharset(td string) bool {
	for i := 0; i < len(td); i++ {
		c := td[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		case c == '_':
		case c == '.':
		default:
			return false
		}
	}
	return true
}

// canonicalSPIFFEID returns a canonical form of a SPIFFE ID whose trust domain
// is lowercased (RFC 7555 case-insensitivity) while the path stays verbatim.
// This lets allowlist/trust-domain comparisons treat "spiffe://VARWOF.com/x"
// and "spiffe://varwof.com/x" as equivalent without loosening path matching.
func canonicalSPIFFEID(id string) string {
	const p = "spiffe://"
	if !strings.HasPrefix(id, p) {
		return id
	}
	rest := id[len(p):]
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return p + strings.ToLower(rest)
	}
	return p + strings.ToLower(rest[:i]) + rest[i:]
}
