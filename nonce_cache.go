// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"sync"
	"time"
)

// NonceCache provides a nonce replay protection cache (v1.4 §3.2).
// Thread-safe with automatic cleanup of expired entries.
type NonceCache struct {
	m        sync.Map
	done     chan struct{}
	stopOnce sync.Once
}

// nonceEntry records the certificate scope and time of a nonce's first appearance.
type nonceEntry struct {
	scope string
	seen  time.Time
}

// NewNonceCache creates a NonceCache and starts automatic cleanup (hourly, retaining entries within 24h).
func NewNonceCache() *NonceCache {
	nc := &NonceCache{
		done: make(chan struct{}),
	}
	go nc.run()
	return nc
}

func (nc *NonceCache) run() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			nc.cleanup()
		case <-nc.done:
			return
		}
	}
}

// Stop stops the background cleanup goroutine. It is idempotent: calling it more
// than once (e.g. Config.Close after an explicit Stop) does not panic on a
// double channel close.
func (nc *NonceCache) Stop() {
	if nc == nil {
		return
	}
	nc.stopOnce.Do(func() { close(nc.done) })
}

// CheckAndAdd checks whether a nonce has been replayed by a different certificate
// (DA replay attack detection).
// scope is the certificate identity (issuer/serial), used to distinguish "same cert
// replaying the same nonce" (normal) from "DA evidence copied into a different cert"
// (attack). Returns true to allow.
//
// Same-scope reuse is deliberately NOT bounded. The DA nonce lives inside the
// certificate, so a long-lived agent re-presents the identical (scope, nonce)
// pair on every request; capping reuses denies legitimate traffic from the 4th
// request onward. Reuse within one scope carries no new authority — the same
// key proved the same evidence — so the attack this cache exists to stop (DA
// evidence copied into a *different* certificate) is the cross-scope case
// below. Mirrored in varwof/gateway-core nonce_cache.go; keep the two in step.
func (nc *NonceCache) CheckAndAdd(scope string, nonce []byte) bool {
	if len(nonce) == 0 {
		return false
	}
	key := string(nonce)
	entry := &nonceEntry{scope: scope, seen: time.Now()}
	actual, loaded := nc.m.LoadOrStore(key, entry)
	if !loaded {
		return true
	}
	if e, ok := actual.(*nonceEntry); ok && e.scope == scope {
		return true
	}
	return false
}

// cleanup removes entries older than 24h (conservative upper bound; all cert lifetimes are shorter).
func (nc *NonceCache) cleanup() {
	deadline := time.Now().Add(-24 * time.Hour)
	nc.m.Range(func(key, value interface{}) bool {
		if e, ok := value.(*nonceEntry); ok && e.seen.Before(deadline) {
			nc.m.Delete(key)
		}
		return true
	})
}

// Len returns the current number of nonces in the cache (for testing and monitoring only).
func (nc *NonceCache) Len() int {
	count := 0
	nc.m.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}
