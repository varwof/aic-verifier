// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"encoding/json"
	"testing"

	"github.com/varwof/register/semantics"
)

// FuzzAdmissionEnvelope exercises the pipeline-level admission record decoder:
// the verifier parses these from the data plane (attacker-controlled), so the
// decoder must never panic on arbitrary payloads.
func FuzzAdmissionEnvelope(f *testing.F) {
	good, err := NewAdmissionEnvelope(NewAdmissionRecord(EvidenceContext{}, &AuthError{}, nil))
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := json.Marshal(good)
	f.Add(raw)
	f.Add([]byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]}`))
	f.Add([]byte(`garbage`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var env semantics.Envelope
		if json.Unmarshal(raw, &env) != nil {
			return
		}
		_, _ = ParseAdmissionEnvelope(env)
	})
}

// FuzzOutcomeEnvelope exercises the outcome record decoder.
func FuzzOutcomeEnvelope(f *testing.F) {
	env, err := NewOutcomeEnvelope(OutcomeRecord{
		Ver: OutcomeRecordVersion, Outcome: OutcomeObserved,
	})
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := json.Marshal(env)
	f.Add(raw)
	f.Add([]byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30="}`))
	f.Add([]byte(`garbage`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var env semantics.Envelope
		if json.Unmarshal(raw, &env) != nil {
			return
		}
		_, _ = ParseOutcomeEnvelope(env)
	})
}

// FuzzCredentialBundlePEM exercises the credential-bundle PEM decoder:
// certificates and keys carried in a bundle are attacker-supplied, so parsing
// must be total (no panic) on arbitrary bytes.
func FuzzCredentialBundlePEM(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte(`-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIRAPVYv+2i3v0x6Jv6vkWqm0AwCgYIKoZIzj0EAwIwEDEO
MAwGA1UEAwwFdGVzdENBMB4XDTI2MDkxNTAwMDAwMFoXDTI2MDkxNjAwMDAwMFow
EDEOMAwGA1UEAwwFdGVzdENBMBkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0+9P
3kMhW77w/nH1Y7QFk4HMLfGqv+lxNwBqTZKxcXJ4BJ7WXGzF0Z7Xz8Yh3VjL8c9j
mE9m4nO2mZqV7/im9aMYMBgwCgYDVR0PAQH/BAQDAgEGMA4GA1UdDwEB/wQEAwIB
BjAKBggqhkjOPQQDAgNIADBFAiEAuQwQqWJbHU8L3G9p7XS1OdBqjJ1yVQd5yW
0v3XbhKb4CIBDP5mvo1efZSTELgvO+AdGvUbDu0YIRfzKG8U0C9v+R
-----END CERTIFICATE-----`))
	f.Add([]byte(`garbage`))
	f.Add([]byte(`-----BEGIN PRIVATE KEY-----
garbage
-----END PRIVATE KEY-----`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseCredentialBundlePEM(raw)
	})
}

// FuzzAuthorizationPolicy exercises the policy JSON decoder.
func FuzzAuthorizationPolicy(f *testing.F) {
	f.Add([]byte(`{"version":"1","identity":{}}`))
	f.Add([]byte(`garbage`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseAuthorizationPolicy(raw)
	})
}

// FuzzSPIFFEID exercises the SPIFFE ID parser.
func FuzzSPIFFEID(f *testing.F) {
	f.Add("spiffe://example.org/ns/ns1/sa/sa1")
	f.Add("")
	f.Add("spiffe:///missing-trust")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseSPIFFEID(s)
	})
}
