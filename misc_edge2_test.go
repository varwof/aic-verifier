// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Remaining small helpers: bearerToken, asAuthError, ouFallbackPrincipal,
// matchesAuditQuery, findTSACert.

package aicverifier

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestBearerToken(t *testing.T) {
	get := func(auth string) *http.Request {
		r, err := http.NewRequest(http.MethodGet, "http://x/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		return r
	}
	if got := bearerToken(get("")); got != "" {
		t.Errorf("empty header = %q", got)
	}
	if got := bearerToken(get("Basic abc=")); got != "" {
		t.Errorf("basic scheme = %q", got)
	}
	if got := bearerToken(get("bearer tok")); got != "tok" {
		t.Errorf("case-insensitive scheme = %q", got)
	}
	if got := bearerToken(get("Bearer   ")); got != "" {
		t.Errorf("whitespace-only = %q", got)
	}
	if got := bearerToken(get("Bearer tok\r\ninjected")); got != "" {
		t.Errorf("CRLF injection accepted: %q", got)
	}
	if got := bearerToken(get("Bearer abc.def.ghi")); got != "abc.def.ghi" {
		t.Errorf("plain bearer = %q", got)
	}
}

func TestAsAuthError(t *testing.T) {
	ae := &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: "reason"}
	if got := AsAuthError(ae); got != ae {
		t.Error("asAuthError did not pass through an *AuthError")
	}
	if got := AsAuthError(nil); got.Code != ErrDenied || got.Message != "admission failed" {
		t.Errorf("AsAuthError(nil) = %+v", got)
	}
	if got := AsAuthError(errors.New("boom")); got.Status != http.StatusForbidden || got.Message != "boom" {
		t.Errorf("AsAuthError(err) = %+v", got)
	}
}

func TestOUFallbackPrincipal(t *testing.T) {
	if got := ouFallbackPrincipal(nil); got != "" {
		t.Errorf("nil cert = %q", got)
	}
	cert := &x509.Certificate{}
	cert.Subject.CommonName = "cn-1"
	if got := ouFallbackPrincipal(cert); got != "cn-1" {
		t.Errorf("CN path = %q", got)
	}
	cert.Subject.CommonName = ""
	cert.Subject.OrganizationalUnit = []string{"ou-1", "ou-2"}
	if got := ouFallbackPrincipal(cert); got != "ou-1" {
		t.Errorf("OU path = %q", got)
	}
	cert.Subject.OrganizationalUnit = nil
	if got := ouFallbackPrincipal(cert); got != "" {
		t.Errorf("empty subject = %q", got)
	}
}

func TestMatchesAuditQuery(t *testing.T) {
	base := AuditEntry{
		TraceId: "op-1", TargetID: "target-1", DaHash: "hash1",
		AgentId: "agent-1", ClientCN: "cn-1",
		Time: time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
	if !matchesAuditQuery(base, EvidenceQuery{}) {
		t.Error("empty query must match")
	}
	if !matchesAuditQuery(base, EvidenceQuery{OperationID: "op-1"}) {
		t.Error("trace id match failed")
	}
	if !matchesAuditQuery(base, EvidenceQuery{OperationID: "target-1"}) {
		t.Error("target id match failed")
	}
	if matchesAuditQuery(base, EvidenceQuery{OperationID: "other"}) {
		t.Error("operation id mismatch matched")
	}
	if matchesAuditQuery(base, EvidenceQuery{DaHash: "hash2"}) {
		t.Error("da hash mismatch matched")
	}
	if !matchesAuditQuery(base, EvidenceQuery{AgentID: "cn-1"}) {
		t.Error("agent-id/CN match failed")
	}
	if matchesAuditQuery(base, EvidenceQuery{AgentID: "nobody"}) {
		t.Error("agent mismatch matched")
	}

	start := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	if !matchesAuditQuery(base, EvidenceQuery{TimeRange: &TimeRange{Start: start, End: end}}) {
		t.Error("in-range entry rejected")
	}
	if matchesAuditQuery(base, EvidenceQuery{TimeRange: &TimeRange{Start: start.Add(48 * time.Hour)}}) {
		t.Error("too-early entry matched")
	}
	if matchesAuditQuery(base, EvidenceQuery{TimeRange: &TimeRange{End: start}}) {
		t.Error("too-late entry matched")
	}

	badTime := base
	badTime.Time = "not-a-time"
	if matchesAuditQuery(badTime, EvidenceQuery{TimeRange: &TimeRange{}}) {
		t.Error("unparseable entry time matched a ranged query")
	}
}

func TestFindTSACert(t *testing.T) {
	ca := &x509.Certificate{IsCA: true, Subject: pkix.Name{CommonName: "ca"}}
	plain := &x509.Certificate{IsCA: false, Subject: pkix.Name{CommonName: "leaf"}}
	tsa := &x509.Certificate{IsCA: false, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}

	if got := findTSACert([]*x509.Certificate{ca, plain, tsa}); got != tsa {
		t.Error("TSA cert (ExtKeyUsage) not preferred")
	}
	if got := findTSACert([]*x509.Certificate{ca, plain}); got != plain {
		t.Error("non-CA fallback not chosen")
	}
	if got := findTSACert([]*x509.Certificate{ca}); got != ca {
		t.Error("first-cert fallback not chosen")
	}
	if got := findTSACert(nil); got != nil {
		t.Error("empty list must return nil")
	}
}
