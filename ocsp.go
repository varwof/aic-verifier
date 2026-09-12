// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ocspHTTPClient is an HTTP client with a timeout for OCSP requests.
// A hung OCSP responder must not block gateway goroutines indefinitely.
var ocspHTTPClient = &http.Client{Timeout: 10 * time.Second}

// AIAOID is the Authority Information Access method OID.
// OCSPOID is the OCSP responder OID.
var (
	AIAOID  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	OCSPOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
)

type accessDescription struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

// OCSPCache is an OCSP response cache with request coalescing.
type OCSPCache struct {
	mu         sync.RWMutex
	entries    map[string]*ocspCacheEntry
	ttl        time.Duration
	fallback   string
	translator Translator
	lang       string
	// crlCheck is consulted when fallback == OCSPFallbackCRL so the "crl"
	// fallback performs a real revocation check (finding 3).
	crlCheck CRLRevokedFunc
	// inflightMu guards inflight independently from mu (which guards entries)
	// to avoid a lock-ordering deadlock between the read path (RLock) and the
	// coalescing wait path (Lock + <-wait) on the same RWMutex.
	inflightMu sync.Mutex
	inflight   map[string]chan struct{}
}

type ocspCacheEntry struct {
	status     int
	revokedAt  time.Time
	cachedAt   time.Time
	thisUpdate time.Time
	nextUpdate time.Time
	ttl        time.Duration
}

// OCSPFallbackAllow/Deny/CRL are OCSP fallback policy constants.
const (
	OCSPFallbackAllow = "allow"
	OCSPFallbackDeny  = "deny"
	OCSPFallbackCRL   = "crl"
)

// NewOCSPCache creates an OCSP cache instance.
func NewOCSPCache(ttl time.Duration, fallback string, translator Translator, lang string) *OCSPCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	switch fallback {
	case OCSPFallbackAllow, OCSPFallbackDeny, OCSPFallbackCRL:
	default:
		fallback = OCSPFallbackDeny
	}
	return &OCSPCache{
		entries:    make(map[string]*ocspCacheEntry),
		ttl:        ttl,
		fallback:   fallback,
		translator: translator,
		lang:       lang,
		inflight:   make(map[string]chan struct{}),
	}
}

// SetCRLChecker installs the CRL revocation lookup used by the "crl" OCSP
// fallback. It must be set for OCSPFallbackCRL to fail closed instead of
// silently allowing (finding 3).
func (c *OCSPCache) SetCRLChecker(fn CRLRevokedFunc) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.crlCheck = fn
}

// ExtractOCSPURL extracts the OCSP URL from the certificate's AIA extension.
func ExtractOCSPURL(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(AIAOID) {
			var descs []accessDescription
			if _, err := asn1.Unmarshal(ext.Value, &descs); err != nil {
				continue
			}
			for _, desc := range descs {
				if desc.Method.Equal(OCSPOID) {
					if desc.Location.Tag == 6 && desc.Location.Class == asn1.ClassContextSpecific {
						return string(desc.Location.Bytes)
					}
				}
			}
		}
	}
	return ""
}

// responseFresh reports whether the OCSP response's declared validity window
// covers now. A response with no usable ThisUpdate/NextUpdate is considered
// stale (finding 7): a captured or expired "Good" response must not be honored
// indefinitely.
func responseFresh(entry *ocspCacheEntry, now time.Time) bool {
	if entry == nil {
		return false
	}
	if !entry.thisUpdate.IsZero() && now.Before(entry.thisUpdate) {
		return false
	}
	if !entry.nextUpdate.IsZero() {
		return now.Before(entry.nextUpdate)
	}
	// No NextUpdate: the responder gave no expiry bound. Honor the cache TTL
	// only — the entry must have been fetched within the TTL to be usable.
	return now.Before(entry.cachedAt.Add(entry.ttl))
}

// Check queries the OCSP responder and caches the result.
func (c *OCSPCache) Check(cert, issuer *x509.Certificate) error {
	ocspURL := ExtractOCSPURL(cert)
	if ocspURL == "" {
		// No OCSP responder in the certificate. When the configured fallback is
		// "crl", the certificate must still be checked against the CRL rather
		// than silently allowed (finding 3).
		return c.fallbackErr(cert, "no OCSP URL in certificate AIA")
	}

	key := fmt.Sprintf("%s|%s", cert.SerialNumber.Text(16), ocspURL)

	c.mu.RLock()
	entry, hit := c.entries[key]
	if hit && time.Since(entry.cachedAt) < c.ttl && responseFresh(entry, time.Now()) {
		c.mu.RUnlock()
		switch entry.status {
		case ocsp.Good:
			return nil
		case ocsp.Revoked:
			return fmt.Errorf("certificate revoked by OCSP at %s", entry.revokedAt.Format(time.RFC3339))
		default:
			return fmt.Errorf("certificate status unknown by OCSP")
		}
	}
	// miss (or stale): must release the read lock before fetching
	c.mu.RUnlock()

	// B12 — request coalescing: register as the fetcher under a single lock
	// (inflightMu, separate from the cache RWMutex) so the check-and-set is
	// atomic (no two goroutines both observe !inFlight and both fetch the same
	// key), without risking a deadlock between the read path and the wait path.
	c.inflightMu.Lock()
	if wait, inFlight := c.inflight[key]; inFlight {
		c.inflightMu.Unlock()
		<-wait
		// re-check cache after the other goroutine finished
		c.mu.RLock()
		entry, hit = c.entries[key]
		c.mu.RUnlock()
		if hit && responseFresh(entry, time.Now()) {
			switch entry.status {
			case ocsp.Good:
				return nil
			case ocsp.Revoked:
				return fmt.Errorf("certificate revoked by OCSP at %s", entry.revokedAt.Format(time.RFC3339))
			default:
				return fmt.Errorf("certificate status unknown by OCSP")
			}
		}
		return c.fallbackErr(cert, "OCSP request completed but no fresh cache entry")
	}
	ch := make(chan struct{})
	c.inflight[key] = ch
	c.inflightMu.Unlock()

	defer func() {
		c.inflightMu.Lock()
		delete(c.inflight, key)
		c.inflightMu.Unlock()
		close(ch)
	}()

	// B26 — issuer guard: ocsp.CreateRequest requires the issuer certificate to
	// build the request (issuer name + public key). When the client presents only
	// the leaf (single-cert chain), issuer is nil and must not reach CreateRequest.
	// Resolve via the fallback policy instead (allow/deny/crl) — unverifiable
	// OCSP status must not panic the gateway.
	if issuer == nil {
		return c.fallbackErr(cert, "OCSP issuer certificate unavailable for %s", cert.Subject.CommonName)
	}

	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return fmt.Errorf("create OCSP request: %w", err)
	}

	httpResp, err := ocspHTTPClient.Post(ocspURL, "application/ocsp-request", bytes.NewReader(ocspReq))
	if err != nil {
		return c.fallbackErr(cert, "OCSP request failed: %v", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return c.fallbackErr(cert, "read OCSP response: %v", err)
	}

	resp, err := ocsp.ParseResponseForCert(body, cert, issuer)
	if err != nil {
		return c.fallbackErr(cert, "parse OCSP response: %v", err)
	}

	// Freshness (finding 7): a stale/captured response must not be honored.
	// Require a produced-at/this-update in the past and either a next-update in
	// the future or a this-update that bounds the cache window.
	now := time.Now()
	entry = &ocspCacheEntry{
		status:     resp.Status,
		revokedAt:  resp.RevokedAt,
		cachedAt:   now,
		thisUpdate: resp.ThisUpdate,
		nextUpdate: resp.NextUpdate,
		ttl:        c.ttl,
	}
	if resp.ThisUpdate.IsZero() && resp.ProducedAt.IsZero() {
		return c.fallbackErr(cert, "OCSP response has no produced_at/this_update")
	}
	if !resp.NextUpdate.IsZero() && now.After(resp.NextUpdate) {
		return c.fallbackErr(cert, "OCSP response stale: next_update %s is in the past", resp.NextUpdate.Format(time.RFC3339))
	}
	if resp.ThisUpdate.After(now) {
		return c.fallbackErr(cert, "OCSP response not yet valid: this_update %s is in the future", resp.ThisUpdate.Format(time.RFC3339))
	}
	if !responseFresh(entry, now) {
		return c.fallbackErr(cert, "OCSP response outside its validity window")
	}

	c.mu.Lock()
	c.entries[key] = entry
	c.mu.Unlock()

	switch resp.Status {
	case ocsp.Good:
		return nil
	case ocsp.Revoked:
		return fmt.Errorf("certificate revoked by OCSP at %s", resp.RevokedAt.Format(time.RFC3339))
	default:
		return fmt.Errorf("certificate status unknown by OCSP (status %d)", resp.Status)
	}
}

// CRLRevokedFunc reports whether the certificate serial has been revoked by the
// CA identified by caDN. An error must fail closed (the OCSP crl fallback cannot
// prove the certificate valid when the CRL cannot be consulted).
type CRLRevokedFunc func(caDN string, serial *big.Int) (bool, error)

func (c *OCSPCache) fallbackErr(cert *x509.Certificate, format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	// Translator is optional (may be nil in tests / embedded usage); fall back to
	// returning the raw message key when not set.
	t := func(lang, key string, args ...any) string { return key }
	if c.translator != nil {
		t = c.translator.T
	}
	switch c.fallback {
	case OCSPFallbackAllow:
		fmt.Printf(t(c.lang, "ocsp.fallback_allow")+"\n", msg)
		return nil
	case OCSPFallbackCRL:
		// Finding 3: the "crl" fallback must actually consult the CRL instead of
		// silently allowing. If no CRL checker is configured, or the CRL cannot
		// be consulted, fail closed.
		if c.crlCheck == nil {
			s := t(c.lang, "ocsp.fallback_crl_unconfigured")
			return errors.New(s + ": " + msg)
		}
		if cert == nil {
			return errors.New("OCSP crl fallback: no certificate to check against CRL")
		}
		revoked, err := c.crlCheck(cert.Issuer.String(), cert.SerialNumber)
		if err != nil {
			return fmt.Errorf("OCSP crl fallback: CRL check failed, failing closed: %w", err)
		}
		if revoked {
			return fmt.Errorf("certificate %s revoked per CRL", cert.SerialNumber.Text(16))
		}
		return nil
	default:
		s := fmt.Sprintf(t(c.lang, "ocsp.fallback_deny"), msg)
		return errors.New(s)
	}
}

// Stats returns the count of good/revoked entries in the OCSP cache.
func (c *OCSPCache) Stats() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var good, revoked int
	for _, e := range c.entries {
		switch e.status {
		case ocsp.Good:
			good++
		case ocsp.Revoked:
			revoked++
		}
	}
	return good, revoked
}

// Flush clears the OCSP cache.
func (c *OCSPCache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*ocspCacheEntry)
}

// FetchOCSPResponseRaw fetches the raw OCSP response bytes.
func FetchOCSPResponseRaw(cert, issuer *x509.Certificate, ocspURL string) ([]byte, error) {
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("create OCSP request: %w", err)
	}
	httpResp, err := ocspHTTPClient.Post(ocspURL, "application/ocsp-request", bytes.NewReader(req))
	if err != nil {
		return nil, fmt.Errorf("OCSP request: %w", err)
	}
	defer httpResp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read OCSP response: %w", err)
	}
	return body, nil
}

// StartOCSPStapling starts the OCSP stapling background refresh.
func StartOCSPStapling(tlsCert *tls.Certificate, cfg *tls.Config, caCertFile string, stopCh <-chan struct{}, translator Translator, lang string) {
	if tlsCert == nil || len(tlsCert.Certificate) == 0 || cfg == nil {
		return
	}
	leaf := tlsCert.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return
		}
	}
	ocspURL := ExtractOCSPURL(leaf)
	if ocspURL == "" {
		return
	}
	issuer, err := LoadCACert(caCertFile)
	if err != nil {
		return
	}

	var certAtomic atomic.Value
	certAtomic.Store(tlsCert)
	cfg.GetCertificate = func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return certAtomic.Load().(*tls.Certificate), nil
	}

	refresh := func() {
		staple, err := FetchOCSPResponseRaw(leaf, issuer, ocspURL)
		if err != nil {
			fmt.Printf(translator.T(lang, "ocsp_stapling.refresh_error"), leaf.Subject.CommonName, err)
			return
		}
		if _, err := ocsp.ParseResponse(staple, issuer); err != nil {
			return
		}
		newCert := *tlsCert
		newCert.OCSPStaple = staple
		certAtomic.Store(&newCert)
	}

	refresh()
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				refresh()
			case <-stopCh:
				return
			}
		}
	}()
}
