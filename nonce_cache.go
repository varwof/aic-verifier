// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"sync"
	"sync/atomic"
	"time"
)

// NonceCache provides a nonce replay protection cache (v1.4 §3.2).
// Thread-safe with automatic cleanup of expired entries.
type NonceCache struct {
	m        sync.Map
	done     chan struct{}
	stopOnce sync.Once
}

// nonceEntry records the certificate scope, time of a nonce's first appearance,
// and how many times it has been used. count bounds same-scope reuses so a
// nonce captured from one cert cannot be driven unchecked inside its own scope
// (C2).
type nonceEntry struct {
	scope string
	seen  time.Time
	count atomic.Int32
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
// Same-scope reuse is allowed only a bounded number of times (maxScopeUse) to
// close the case where the "same scope" carve-out was an unbounded allow (C2):
// a legitimate retry is a handful of attempts, so unlimited reuse indicates the
// nonce is being driven in a loop.
const maxScopeUse = 3

func (nc *NonceCache) CheckAndAdd(scope string, nonce []byte) bool {
	if len(nonce) == 0 {
		return false
	}
	key := string(nonce)
	entry := &nonceEntry{scope: scope, seen: time.Now()}
	entry.count.Store(1)
	actual, loaded := nc.m.LoadOrStore(key, entry)
	if !loaded {
		return true
	}
	if e, ok := actual.(*nonceEntry); ok && e.scope == scope {
		return e.count.Add(1) <= maxScopeUse
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
