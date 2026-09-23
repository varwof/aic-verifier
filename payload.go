// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Wire payload specification for the transport-independent decision core: a
// JSON codec over the RequestView / AuthContext pair so gRPC, queue adapters
// and in-process callers exchange the identical, stable document.  DER base64
// for certificates; every field optional so carriers carry only what they
// have.

package aicverifier

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/varwof/register/semantics"
	pki "github.com/varwof/types"
)

// DecideRequestDTO is the wire form of a RequestView.  Cert chains are DER
// bytes (leaf first, base64 through JSON).  A carrier that already verified
// the credential sends verified_cert instead of a chain.
type DecideRequestDTO struct {
	CertChainDER    [][]byte            `json:"cert_chain,omitempty"`
	BearerToken     string              `json:"bearer_token,omitempty"`
	TransportSecure bool                `json:"transport_secure,omitempty"`
	VerifiedCertDER []byte              `json:"verified_cert,omitempty"`
	Method          string              `json:"method,omitempty"`
	Path            string              `json:"path,omitempty"`
	RawQuery        string              `json:"raw_query,omitempty"`
	Headers         map[string][]string `json:"headers,omitempty"`
	ClientIP        string              `json:"client_ip,omitempty"`
	Body            []byte              `json:"body,omitempty"`
}

// ToView converts the wire request back into a RequestView for the decision
// core.  The presented leaf (for refusal recording) is the first chain entry.
func (d *DecideRequestDTO) ToView() (*RequestView, error) {
	v := &RequestView{
		Method:          d.Method,
		Path:            d.Path,
		RawQuery:        d.RawQuery,
		Header:          http.Header(d.Headers),
		ClientIP:        d.ClientIP,
		Body:            d.Body,
		BearerToken:     d.BearerToken,
		TransportSecure: d.TransportSecure,
	}
	for i, der := range d.CertChainDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("aic-verifier: parse chain cert %d: %w", i, err)
		}
		v.CertChain = append(v.CertChain, cert)
	}
	if len(d.CertChainDER) > 0 {
		v.PresentedCert = v.CertChain[0]
	}
	if len(d.VerifiedCertDER) > 0 {
		cert, err := x509.ParseCertificate(d.VerifiedCertDER)
		if err != nil {
			return nil, fmt.Errorf("aic-verifier: parse verified cert: %w", err)
		}
		v.VerifiedCert = cert
	}
	return v, nil
}

// ToDTO renders the view's carrier-writable fields.  The adapter hooks
// (EvidenceFactsWith / RequireApprovalWith / HTTPAdapter) never cross the wire.
func (v *RequestView) ToDTO() *DecideRequestDTO {
	if v == nil {
		return &DecideRequestDTO{}
	}
	d := &DecideRequestDTO{
		BearerToken:     v.BearerToken,
		TransportSecure: v.TransportSecure,
		Method:          v.Method,
		Path:            v.Path,
		RawQuery:        v.RawQuery,
		Headers:         map[string][]string(v.Header),
		ClientIP:        v.ClientIP,
		Body:            v.Body,
	}
	for _, c := range v.CertChain {
		d.CertChainDER = append(d.CertChainDER, c.Raw)
	}
	if v.VerifiedCert != nil {
		d.VerifiedCertDER = v.VerifiedCert.Raw
	}
	return d
}

// DecideResultDTO is the wire form of an admission decision: the granted
// AuthContext mirror, or the denial (code/status/message).  AIC travels as its
// ASN.1 DER so the document needs no aic-verifier type dependency to be
// inspected by peers.
type DecideResultDTO struct {
	Granted            bool                         `json:"granted"`
	Code               string                       `json:"code,omitempty"`
	Status             int                          `json:"status,omitempty"`
	Message            string                       `json:"message,omitempty"`
	Principal          string                       `json:"principal,omitempty"`
	AgentID            string                       `json:"agent_id,omitempty"`
	SpiffeID           string                       `json:"spiffe_id,omitempty"`
	Roles              []string                     `json:"roles,omitempty"`
	Capabilities       []string                     `json:"capabilities,omitempty"`
	AICDER             []byte                       `json:"aic_der,omitempty"`
	Bearer             bool                         `json:"bearer,omitempty"`
	Serial             string                       `json:"serial,omitempty"`
	Verdict            string                       `json:"verdict,omitempty"`
	Reason             string                       `json:"reason,omitempty"`
	Unresolved         []string                     `json:"unresolved,omitempty"`
	OperationDecisions []OperationDecision          `json:"operation_decisions,omitempty"`
	Evidence           []RecordRef                  `json:"evidence,omitempty"`
	Satisfaction       *semantics.RequirementResult `json:"satisfaction,omitempty"`
	ClientCertDER      []byte                       `json:"client_cert_der,omitempty"`
}

// FromAuthContext fills the DTO from an admitted decision.
func (d *DecideResultDTO) FromAuthContext(ac *AuthContext) {
	d.Granted = true
	if ac == nil {
		return
	}
	d.Principal = ac.Principal
	d.AgentID = ac.AgentID
	d.SpiffeID = ac.SPIFFEID
	d.Roles = ac.Roles
	d.Capabilities = ac.Capabilities
	d.Bearer = ac.Bearer
	d.Serial = ac.Serial
	d.Verdict = ac.Verdict
	d.Reason = ac.Reason
	d.Unresolved = ac.Unresolved
	d.OperationDecisions = ac.OperationDecisions
	d.Evidence = ac.Evidence
	d.Satisfaction = ac.Satisfaction
	if ac.ClientCert != nil {
		d.ClientCertDER = ac.ClientCert.Raw
	}
	if ac.AIC != nil {
		if der, err := asn1.Marshal(*ac.AIC); err == nil {
			d.AICDER = der
		}
	}
}

// ToAuthContext reconstructs the decision's identity payload for peers that
// need the full AuthContext shape (certificate re-parsed from the DER).  The
// reconstructed context is read-oriented: hooks and stores never travel.
func (d *DecideResultDTO) ToAuthContext() (*AuthContext, error) {
	if !d.Granted {
		return nil, nil
	}
	ac := &AuthContext{
		Principal:          d.Principal,
		AgentID:            d.AgentID,
		SPIFFEID:           d.SpiffeID,
		Roles:              d.Roles,
		Capabilities:       d.Capabilities,
		Bearer:             d.Bearer,
		Serial:             d.Serial,
		Verdict:            d.Verdict,
		Reason:             d.Reason,
		Unresolved:         d.Unresolved,
		OperationDecisions: d.OperationDecisions,
		Evidence:           d.Evidence,
		Satisfaction:       d.Satisfaction,
	}
	if len(d.ClientCertDER) > 0 {
		cert, err := x509.ParseCertificate(d.ClientCertDER)
		if err != nil {
			return nil, fmt.Errorf("aic-verifier: parse client cert: %w", err)
		}
		ac.ClientCert = cert
	}
	if len(d.AICDER) > 0 {
		var aic pki.AIC
		if _, err := asn1.Unmarshal(d.AICDER, &aic); err != nil {
			return nil, fmt.Errorf("aic-verifier: parse aic der: %w", err)
		}
		ac.AIC = &aic
	}
	return ac, nil
}

// EncodeDecideRequest serializes a view for the wire.
func EncodeDecideRequest(v *RequestView) ([]byte, error) {
	return json.Marshal(v.ToDTO())
}

// DecodeDecideRequest parses a wire request back into a view.
func DecodeDecideRequest(b []byte) (*RequestView, error) {
	var d DecideRequestDTO
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("aic-verifier: decode decide request: %w", err)
	}
	return d.ToView()
}

// EncodeDecideResult serializes an admission outcome for the wire.  err may be
// an *AuthError to carry a denial; any other error is folded into a generic
// denial so the wire stays typed.
func EncodeDecideResult(ac *AuthContext, err error) ([]byte, error) {
	d := &DecideResultDTO{}
	if err != nil {
		d.Code = ErrDenied.String()
		d.Status = http.StatusForbidden
		d.Message = err.Error()
		if ae := AsAuthError(err); ae != nil {
			d.Code = ae.Code.String()
			d.Status = ae.Status
			d.Message = ae.Message
		}
		return json.Marshal(d)
	}
	d.FromAuthContext(ac)
	return json.Marshal(d)
}

// DecodeDecideResult parses a wire outcome into (AuthContext, *AuthError, err).
// A nil ac with a nil auth error on a granted=... means parsing failed.
func DecodeDecideResult(b []byte) (*AuthContext, *AuthError, error) {
	var d DecideResultDTO
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, nil, fmt.Errorf("aic-verifier: decode decide result: %w", err)
	}
	if !d.Granted {
		code := ErrDenied
		if c, err := ParseErrorCode(d.Code); err == nil {
			code = c
		}
		return nil, &AuthError{Code: code, Status: d.Status, Message: d.Message}, nil
	}
	ac, err := d.ToAuthContext()
	if err != nil {
		return nil, nil, err
	}
	return ac, nil, nil
}

// parseErrorCode maps a wire code string back to the ErrorCode enum.
func ParseErrorCode(s string) (ErrorCode, error) {
	switch s {
	case "no_credential":
		return ErrNoCredential, nil
	case "access_denied":
		return ErrDenied, nil
	case "bearer_not_configured":
		return ErrNoVerifier, nil
	case "bearer_tls_required":
		return ErrBearerNeedsTLS, nil
	case "invalid_bearer":
		return ErrInvalidBearer, nil
	case "chain_invalid":
		return ErrChainInvalid, nil
	case "config_error":
		return ErrConfig, nil
	}
	return ErrDenied, fmt.Errorf("aic-verifier: unknown error code %q", s)
}
