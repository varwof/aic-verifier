// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"context"
	"crypto/x509"
	"net/http"
	"testing"
)

// BenchmarkDecideMTLS measures the full admission decision path for a valid
// AIC mTLS credential: chain validation, AIC parsing, policy evaluation.
// This is the per-request hot path of the verifier.
func BenchmarkDecideMTLS(b *testing.B) {
	cert := testAICCert(b, false)
	a := decideAuth(b, cert)
	view := &RequestView{
		CertChain:       []*x509.Certificate{cert},
		TransportSecure: true,
		Method:          http.MethodPost,
		Path:            "/query",
		RawQuery:        "limit=5",
		ClientIP:        "10.0.0.7",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.Decide(context.Background(), view); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecideNoCredential measures the reject path that hits the most —
// unauthenticated traffic must be refused as cheaply as possible.
func BenchmarkDecideNoCredential(b *testing.B) {
	a := decideAuth(b, testAICCert(b, false))
	view := &RequestView{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = a.Decide(context.Background(), view)
	}
}

// BenchmarkPolicyParse measures authorization-policy parsing (load path,
// not the per-request hot path).
func BenchmarkPolicyParse(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseAuthorizationPolicy([]byte(policyFixture)); err != nil {
			b.Fatal(err)
		}
	}
}
