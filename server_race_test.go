// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// TestServerAddrConcurrentWithListenClose pins the fix for the listener-state
// data race: Listen/Serve write the listener and HTTP server, while Addr and
// Close read them from other goroutines. Without the mutex this races under
// `go test -race`, which is exactly the failure this regression guards.
func TestServerAddrConcurrentWithListenClose(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 8; i++ {
		s, err := NewServer(&Config{}, []Route{{Path: "/", Target: target}})
		if err != nil {
			t.Fatal(err)
		}

		stop := make(chan struct{})
		var wg sync.WaitGroup
		// Readers race the Listen write below and keep reading through Serve/Close.
		for r := 0; r < 4; r++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
						_ = s.Addr()
					}
				}
			}()
		}

		ln, err := s.Listen("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- s.Serve(ln) }()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := s.Close(ctx); err != nil {
			t.Fatalf("Close: %v", err)
		}
		cancel()

		close(stop)
		wg.Wait()
		if err := <-done; err != nil && err != http.ErrServerClosed {
			t.Fatalf("Serve: %v", err)
		}
	}
}

// TestServerAddrBeforeListenAndDoubleClose covers the lifecycle edges: Addr is
// nil and Close is a no-op before Listen, and Close is idempotent after.
func TestServerAddrBeforeListenAndDoubleClose(t *testing.T) {
	s, err := NewServer(&Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Addr() != nil {
		t.Fatal("Addr() must be nil before Listen")
	}
	ctx := context.Background()
	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close before Listen must be a no-op: %v", err)
	}
	if _, err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if s.Addr() == nil {
		t.Fatal("Addr() must be set after Listen")
	}
	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatalf("second Close must be a no-op: %v", err)
	}
}
