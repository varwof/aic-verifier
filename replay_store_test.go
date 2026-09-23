// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 防重放存储的边界：容量上限必须 fail-closed（修复前满容量会逐出最老条目
// → 被逐出的 nonce 在其 token 过期前可被重放）；重放必须被识别；过期的标记
// 仍需被惰性清理。

package aicverifier

import (
	"testing"
	"time"
)

func TestReplayStoreReplayDetected(t *testing.T) {
	store := NewReplayNonceStore(time.Hour, 100)
	if err := store.CheckAndAdd("nonce-a"); err != nil {
		t.Fatalf("first CheckAndAdd: %v", err)
	}
	err := store.CheckAndAdd("nonce-a")
	if err == nil {
		t.Fatal("reusing a nonce must be rejected")
	}
	if err.Error() != "replay store: nonce replayed (first used "+store.seen["nonce-a"].Format(time.RFC3339)+")" {
		t.Errorf("unexpected replay error: %v", err)
	}
}

func TestReplayStoreCapsAtMaxRefusesLiveOverflow(t *testing.T) {
	store := NewReplayNonceStore(time.Hour, 2)
	for _, n := range []string{"a", "b"} {
		if err := store.CheckAndAdd(n); err != nil {
			t.Fatalf("CheckAndAdd(%s): %v", n, err)
		}
	}
	// All four markers are younger than the 1h TTL, so none may be evicted:
	// further inserts must fail closed and leave the store at capacity.
	for _, n := range []string{"c", "d"} {
		if err := store.CheckAndAdd(n); err == nil {
			t.Fatalf("CheckAndAdd(%s): want fail-closed error at capacity with live markers", n)
		}
	}
	store.mu.Lock()
	got := len(store.seen)
	_, hasA := store.seen["a"]
	_, hasB := store.seen["b"]
	_, hasC := store.seen["c"]
	_, hasD := store.seen["d"]
	store.mu.Unlock()
	if got != 2 {
		t.Fatalf("len(seen) = %d, want capped at 2", got)
	}
	if !hasA || !hasB || hasC || hasD {
		t.Errorf("live markers must survive, new ones refused: a=%v b=%v c=%v d=%v (want t t f f)", hasA, hasB, hasC, hasD)
	}
}

func TestReplayStorePurgesExpired(t *testing.T) {
	store := NewReplayNonceStore(time.Minute, 1)
	if err := store.CheckAndAdd("old"); err != nil {
		t.Fatalf("CheckAndAdd(old): %v", err)
	}
	store.mu.Lock()
	store.seen["old"] = time.Now().Add(-2 * time.Minute)
	store.mu.Unlock()
	// "old" has lapsed its TTL; its replay window is closed, so it can be
	// purged to make room for a live marker instead of failing closed.
	if err := store.CheckAndAdd("fresh"); err != nil {
		t.Fatalf("CheckAndAdd(fresh) after expired purge: %v", err)
	}
	store.mu.Lock()
	_, hasFresh := store.seen["fresh"]
	_, hasOld := store.seen["old"]
	store.mu.Unlock()
	if !hasFresh || hasOld {
		t.Errorf("expired marker must be purged, fresh marker recorded: fresh=%v old=%v (want t f)", hasFresh, hasOld)
	}
}

func TestReplayStoreDefaults(t *testing.T) {
	store := NewReplayNonceStore(0, 0)
	if store.ttl != 24*time.Hour || store.max != 65536 {
		t.Errorf("defaults: ttl=%v max=%d, want 24h/65536", store.ttl, store.max)
	}
}
