// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Translator is the internationalization translation interface.
type Translator interface {
	T(lang, key string, args ...any) string
}

// CRLCache is a CRL cache that supports periodic refresh and forced reload.
type CRLCache struct {
	caCert      *x509.Certificate
	caDN        string
	url         string
	refreshSec  time.Duration
	translator  Translator
	lang        string
	mu          sync.RWMutex
	revoked     map[string]bool
	thisUpdate  time.Time
	nextUpdate  time.Time
	lastRefresh time.Time
	client      *http.Client
	// refreshMu serializes the entire refresh (fetch + commit). Previously only
	// commit was under mu; periodic refresh from Start and concurrent ForceRefresh
	// could fetch then commit out of order — two CRLs with identical thisUpdate
	// would trigger false replay detection (flaky rel test). After serialization,
	// the later request always gets a newer thisUpdate.
	refreshMu sync.Mutex
}

// NewCRLCache creates a CRL cache instance.
func NewCRLCache(caCert *x509.Certificate, url string, refreshSec int, translator Translator, lang string) *CRLCache {
	d := time.Duration(refreshSec) * time.Second
	if d <= 0 {
		d = 5 * time.Minute
	}
	// H3: bound the connection phases so a hung CRL distribution point cannot
	// pin gateway goroutines forever: 5s dial + 5s TLS handshake, plus the
	// client-level 30s total timeout below.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &CRLCache{
		caCert:     caCert,
		caDN:       caCert.Subject.String(),
		url:        url,
		refreshSec: d,
		translator: translator,
		lang:       lang,
		revoked:    make(map[string]bool),
		client:     &http.Client{Timeout: 30 * time.Second, Transport: tr},
	}
}

// Start starts the CRL periodic refresh loop.
func (c *CRLCache) Start(stop <-chan struct{}) {
	for {
		if err := c.refresh(); err != nil {
			c.printf("crl.initial_refresh_failed", err)
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		break
	}
	ticker := time.NewTicker(c.refreshSec)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := c.refresh(); err != nil {
				c.printf("crl.refresh_failed", err)
			}
		case <-stop:
			return
		}
	}
}

func (c *CRLCache) printf(key string, args ...any) {
	msg := key
	if c.translator != nil {
		msg = c.translator.T(c.lang, key)
	}
	fmt.Printf(msg+"\n", args...)
}

// ForceRefresh forces an immediate CRL cache refresh.
func (c *CRLCache) ForceRefresh() error {
	return c.refresh()
}

// IsRevoked checks whether a given certificate serial number has been revoked.
func (c *CRLCache) IsRevoked(caDN string, serial *big.Int) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if time.Now().After(c.nextUpdate) {
		return false, fmt.Errorf("CRL expired (nextUpdate %s)", c.nextUpdate.Format(time.RFC3339))
	}
	key := caDN + "|" + serial.Text(16)
	return c.revoked[key], nil
}

// IsRevokedCert checks whether the given certificate is revoked, matching the
// certificate's issuer against this cache's CA robustly (finding 13): the raw
// issuer bytes are compared first, falling back to a structural RDN comparison
// that tolerates RDN ordering/formatting differences. A certificate not issued
// by this cache's CA is not covered by it and returns not-revoked.
func (c *CRLCache) IsRevokedCert(cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, fmt.Errorf("crl: nil certificate")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if time.Now().After(c.nextUpdate) {
		return false, fmt.Errorf("CRL expired (nextUpdate %s)", c.nextUpdate.Format(time.RFC3339))
	}
	if !c.issuerMatchesCA(cert) {
		return false, nil // not issued by this CA; this CRL does not cover it
	}
	return c.revoked[c.caDN+"|"+cert.SerialNumber.Text(16)], nil
}

// issuerMatchesCA reports whether cert's issuer names this cache's CA, robust
// to RDN ordering/formatting differences (finding 13).
func (c *CRLCache) issuerMatchesCA(cert *x509.Certificate) bool {
	if c.caCert == nil {
		return false
	}
	if bytes.Equal(cert.RawIssuer, c.caCert.RawSubject) {
		return true
	}
	return rdnSequenceEqual(cert.RawIssuer, c.caCert.RawSubject)
}

// rdnSequenceEqual compares two DER RDN sequences structurally, ignoring RDN
// and attribute ordering (semantic equality for certificate name matching).
func rdnSequenceEqual(a, b []byte) bool {
	var ra, rb pkix.RDNSequence
	if _, err := asn1.Unmarshal(a, &ra); err != nil {
		return false
	}
	if _, err := asn1.Unmarshal(b, &rb); err != nil {
		return false
	}
	return canonicalRDNs(ra) == canonicalRDNs(rb)
}

// canonicalRDNs renders an RDN sequence as a canonical string: each RDN's
// attributes sorted by "type=value", RDNs sorted lexically.
func canonicalRDNs(seq pkix.RDNSequence) string {
	var rdns []string
	for _, rdn := range seq {
		var attrs []string
		for _, atv := range rdn {
			attrs = append(attrs, atv.Type.String()+"="+fmt.Sprintf("%v", atv.Value))
		}
		sort.Strings(attrs)
		rdns = append(rdns, strings.Join(attrs, "+"))
	}
	sort.Strings(rdns)
	return strings.Join(rdns, ",")
}

// Stats returns CRL cache statistics (revocation count, this update, next update).
func (c *CRLCache) Stats() (int, time.Time, time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.revoked), c.thisUpdate, c.nextUpdate
}

// LastRefresh returns the time of the last successful refresh.
func (c *CRLCache) LastRefresh() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastRefresh
}

func (c *CRLCache) refresh() error {
	// Serialize fetch+commit: concurrent refresh could commit out of order triggering false replay detection.
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	resp, err := c.client.Get(c.url)
	if err != nil {
		return fmt.Errorf("fetch CRL: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read CRL body: %w", err)
	}

	block, _ := pem.Decode(body)
	if block != nil && block.Type == "X509 CRL" {
		body = block.Bytes
	}

	crl, err := x509.ParseDERCRL(body)
	if err != nil {
		return fmt.Errorf("parse CRL DER: %w", err)
	}

	crlIssuerStr := crl.TBSCertList.Issuer.String()
	var caRDN pkix.RDNSequence
	if _, err := asn1.Unmarshal(c.caCert.RawSubject, &caRDN); err != nil {
		return fmt.Errorf("unmarshal CA subject: %w", err)
	}
	if caRDN.String() != crlIssuerStr {
		return fmt.Errorf("CRL issuer %q does not match CA %q", crlIssuerStr, caRDN.String())
	}

	if err := c.caCert.CheckCRLSignature(crl); err != nil {
		return fmt.Errorf("CRL signature verification failed: %w", err)
	}

	revoked := make(map[string]bool, len(crl.TBSCertList.RevokedCertificates))
	prefix := c.caDN + "|"
	for _, entry := range crl.TBSCertList.RevokedCertificates {
		revoked[prefix+entry.SerialNumber.Text(16)] = true
	}

	c.mu.Lock()
	if !crl.TBSCertList.ThisUpdate.After(c.thisUpdate) && !c.thisUpdate.IsZero() {
		c.mu.Unlock()
		return fmt.Errorf("CRL thisUpdate %v is not newer than cached %v (replay?)",
			crl.TBSCertList.ThisUpdate, c.thisUpdate)
	}
	c.revoked = revoked
	c.thisUpdate = crl.TBSCertList.ThisUpdate
	c.nextUpdate = crl.TBSCertList.NextUpdate
	c.lastRefresh = time.Now()
	nextUpdate := c.nextUpdate
	c.mu.Unlock()

	c.printf("crl.refreshed", c.url, len(revoked), nextUpdate.Format(time.RFC3339))
	return nil
}
