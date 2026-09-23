// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// H1: the Streamable-HTTP transport bounds request bodies at 8 MiB. A body at
// or past 8 MiB is answered 413 before any JSON-RPC dispatch, so an attacker
// cannot force unbounded buffering of the request body on the gateway.
//
// This test lives in the mcp subpackage (not alongside the aicverifier tests)
// because mcp imports aicverifier: a test file in package aicverifier that
// routed through NewHandler would create an import cycle.

package mcp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMCPBodySizeLimit(t *testing.T) {
	counters := map[string]int{}
	_, handler, _, _ := newTestHandler(t, &counters)

	const limit = 8 << 20 // 8 MiB, in sync with enforcement.ServeHTTP

	tests := []struct {
		name string
		body []byte
		want int
	}{
		{
			name: "over_8mib_rejected_413",
			body: make([]byte, limit+1),
			want: http.StatusRequestEntityTooLarge,
		},
		{
			name: "at_8mib_rejected_413", // LimitReader yields exactly the cap → treated as too large
			body: make([]byte, limit),
			want: http.StatusRequestEntityTooLarge,
		},
		{
			name: "small_json_passes_body_check",
			body: []byte(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}`),
			want: http.StatusOK,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://mcp.test/mcp", bytes.NewReader(tc.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if tc.want == http.StatusRequestEntityTooLarge {
				if rec.Code != tc.want {
					t.Errorf("body of %d bytes: code = %d, want %d (H1 8 MiB limit)", len(tc.body), rec.Code, tc.want)
				}
				return
			}
			// Undersized bodies must pass the body-limit gate. The transport may
			// still answer 400 (e.g. an un-initialized session); that is the
			// protocol layer, not the H1 body bound.
			if rec.Code == http.StatusRequestEntityTooLarge {
				t.Errorf("body of %d bytes rejected as too large, want body-limit gate to pass it", len(tc.body))
			}
		})
	}
}
