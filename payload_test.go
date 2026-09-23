// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"bytes"
	"crypto/x509"
	"net/http"
	"testing"
)

func TestDecideRequestDTOsRoundTrip(t *testing.T) {
	cert := testAICCert(t, false)

	v := &RequestView{
		CertChain:       []*x509.Certificate{cert},
		TransportSecure: true,
		Method:          http.MethodPost,
		Path:            "/query",
		RawQuery:        "limit=5",
		Header:          http.Header{"X-Request-Id": {"trace-1"}, "Authorization": {"Bearer x"}},
		ClientIP:        "10.0.0.7",
		Body:            []byte(`{"q":"SELECT 1"}`),
	}
	dto := v.ToDTO()
	back, err := dto.ToView()
	if err != nil {
		t.Fatalf("ToView: %v", err)
	}
	if len(back.CertChain) != 1 || !bytes.Equal(back.CertChain[0].Raw, cert.Raw) {
		t.Fatalf("cert chain not preserved")
	}
	if back.PresentedCert == nil || !bytes.Equal(back.PresentedCert.Raw, cert.Raw) {
		t.Error("presented cert not derived from the chain leaf")
	}
	if !back.TransportSecure || back.Method != "POST" || back.Path != "/query" || back.RawQuery != "limit=5" {
		t.Errorf("request facts not preserved: %+v", back)
	}
	if back.Header.Get("X-Request-Id") != "trace-1" || back.ClientIP != "10.0.0.7" {
		t.Errorf("headers/ip not preserved: %+v", back)
	}
	if string(back.Body) != `{"q":"SELECT 1"}` {
		t.Errorf("body not preserved: %q", back.Body)
	}

	// EncodeDecode helpers agree with the same wire doc.
	raw, err := EncodeDecideRequest(v)
	if err != nil {
		t.Fatalf("EncodeDecideRequest: %v", err)
	}
	w, err := DecodeDecideRequest(raw)
	if err != nil {
		t.Fatalf("DecodeDecideRequest: %v", err)
	}
	if !bytes.Equal(w.CertChain[0].Raw, cert.Raw) || !w.TransportSecure || w.Path != "/query" {
		t.Errorf("EncodeDecode round trip drifted: %+v", w)
	}
}

func TestDecideVerifiedCertOnWire(t *testing.T) {
	cert := testAICCert(t, false)
	v := &RequestView{VerifiedCert: cert, ClientIP: "10.0.0.9"}
	dto := v.ToDTO()
	if len(dto.VerifiedCertDER) == 0 || len(dto.CertChainDER) != 0 {
		t.Fatalf("verified cert should travel, chain should not: %+v", dto)
	}
	back, err := dto.ToView()
	if err != nil {
		t.Fatalf("ToView: %v", err)
	}
	if back.VerifiedCert == nil || !bytes.Equal(back.VerifiedCert.Raw, cert.Raw) {
		t.Error("verified cert not preserved")
	}
	if len(back.CertChain) != 0 {
		t.Error("an empty chain must stay empty")
	}
}

func TestDecideResultDTOsRoundTrip(t *testing.T) {
	cert := testAICCert(t, false)
	a := decideAuth(t, cert)
	view := &RequestView{CertChain: []*x509.Certificate{cert}, TransportSecure: true, Method: http.MethodPost, Path: "/query"}
	ac, err := a.Decide(t.Context(), view)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}

	dto := &DecideResultDTO{}
	dto.FromAuthContext(ac)
	back, err := dto.ToAuthContext()
	if err != nil {
		t.Fatalf("ToAuthContext: %v", err)
	}
	if back == nil || back.AgentID != "agent-1" || len(back.Capabilities) != 1 || back.Capabilities[0] != "query:SELECT" {
		t.Fatalf("decided identity drifted: %+v", back)
	}
	if back.AIC == nil || back.AIC.AgentId != "agent-1" {
		t.Error("AIC not carried through as ASN.1 DER")
	}
	if back.ClientCert == nil || !bytes.Equal(back.ClientCert.Raw, cert.Raw) {
		t.Error("client cert not carried through")
	}

	// Wire encode/decode agree.
	raw, err := EncodeDecideResult(ac, nil)
	if err != nil {
		t.Fatalf("EncodeDecideResult: %v", err)
	}
	wireBack, ae, err := DecodeDecideResult(raw)
	if err != nil {
		t.Fatalf("DecodeDecideResult: %v", err)
	}
	if ae != nil || wireBack.AgentID != "agent-1" {
		t.Fatalf("wire outcome drifted: ae=%v ac=%+v", ae, wireBack)
	}
}

func TestDecideResultDTOsCarryDenial(t *testing.T) {
	raw, err := EncodeDecideResult(nil, &AuthError{Code: ErrChainInvalid, Status: http.StatusForbidden, Message: "certificate chain invalid"})
	if err != nil {
		t.Fatalf("EncodeDecideResult: %v", err)
	}
	ac, ae, err := DecodeDecideResult(raw)
	if err != nil {
		t.Fatalf("DecodeDecideResult: %v", err)
	}
	if ac != nil {
		t.Fatal("a denial must decode to a nil AuthContext")
	}
	if ae == nil || ae.Code != ErrChainInvalid || ae.Status != http.StatusForbidden || ae.Message != "certificate chain invalid" {
		t.Fatalf("denial drifted: %+v", ae)
	}
}
