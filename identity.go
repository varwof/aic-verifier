// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"

	pki "github.com/varwof/types"
)

// trustHeaderNames lists the identity header namespace the SDK owns. Any
// client-supplied value is stripped before an admitted request is forwarded so
// backends can trust these headers as server-asserted identity.
func trustHeaderNames() []string {
	return []string{
		"X-Client-Cert-DER",
		"X-Client-Cert-SPKI-Hash",
		"X-Client-Cert-Serial",
		"X-Client-Cert-CN",
		"X-Client-Cert-O",
		"X-Client-Cert-OU",
		"X-Client-Cert-Principal",
		"X-Client-Cert-Agent-ID",
		"X-AIC-Agent-Id",
		"X-AIC-Principal-Uid",
		"X-AIC-Capabilities",
		"X-AIC-Capabilities-Full",
		"X-AIC-Verified-By",
		"X-Agent-ID",
		"X-Agent-Principal",
		"X-Forwarded-Client-CN",
		"X-Forwarded-Client-O",
		"X-Forwarded-Client-OU",
		"X-Forwarded-Client-Serial",
	}
}

// IdentityHeaderMode selects how much identity detail is forwarded to backends.
type IdentityHeaderMode int

const (
	// IdentityMinimal strips every identity header (backend trusts the proxy only).
	IdentityMinimal IdentityHeaderMode = iota
	// IdentityForwardClientCert forwards the full client certificate (DER) plus
	// the X-AIC-* structured views.
	IdentityForwardClientCert
	// IdentityXForwarded sets only X-Forwarded-Client-* (CN/O/OU/serial).
	IdentityXForwarded
	// IdentityAIC only sets the X-AIC-* structured headers.
	IdentityAIC
)

// SetIdentityHeaderMode is kept for the per-request (middleware) integration
// style. Security note: callers must only pass an identity mode derived from
// server configuration, never from a client-supplied header value; the reverse
// proxy reads its mode from Config.IdentityMode so clients cannot influence how
// much identity is disclosed to backends.
func SetIdentityHeaderMode(r *http.Request, mode IdentityHeaderMode) {
	if r != nil {
		r.Header.Set("X-AICN-Identity-Mode", string(rune(mode)))
	}
}

// identityHeaderModeOf returns the identity forwarding mode. In middleware
// style it honours a mode previously set via SetIdentityHeaderMode; callers of
// that function must ensure the value originates from server configuration. For
// reverse-proxy traffic identityHeaderModeOf is unused — the proxy uses
// Config.IdentityMode directly so the decision never depends on client-supplied
// request headers.
func identityHeaderModeOf(r *http.Request) IdentityHeaderMode {
	v := r.Header.Get("X-AICN-Identity-Mode")
	switch v {
	case string(rune(IdentityMinimal)):
		return IdentityMinimal
	case string(rune(IdentityXForwarded)):
		return IdentityXForwarded
	case string(rune(IdentityAIC)):
		return IdentityAIC
	default:
		return IdentityForwardClientCert
	}
}

// injectIdentityHeaders sets server-asserted identity headers on the request
// before forwarding. It always strips the client-supplied namespace first, so
// backends can treat these headers as trusted identity. mode is supplied by the
// caller (from server configuration), never read from the request headers.
func injectIdentityHeaders(r *http.Request, ac *AuthContext, mode IdentityHeaderMode) {
	for _, h := range trustHeaderNames() {
		r.Header.Del(h)
	}
	if ac == nil || ac.ClientCert == nil {
		return
	}
	cert := ac.ClientCert
	switch mode {
	case IdentityForwardClientCert:
		r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(cert.Raw))
		r.Header.Set("X-Client-Cert-SPKI-Hash", certSPKIHashHex(cert))
		if cert.SerialNumber != nil {
			r.Header.Set("X-Client-Cert-Serial", cert.SerialNumber.Text(16))
		}
		r.Header.Set("X-Client-Cert-CN", cert.Subject.CommonName)
		if len(cert.Subject.Organization) > 0 {
			r.Header.Set("X-Client-Cert-O", strings.Join(cert.Subject.Organization, ","))
		}
		if len(cert.Subject.OrganizationalUnit) > 0 {
			r.Header.Set("X-Client-Cert-OU", strings.Join(cert.Subject.OrganizationalUnit, ","))
		}
		r.Header.Set("X-Client-Cert-Principal", ac.Principal)
		if ac.AgentID != "" {
			r.Header.Set("X-Client-Cert-Agent-ID", ac.AgentID)
		}
		setAICHeaders(r, ac)
	case IdentityXForwarded:
		r.Header.Set("X-Forwarded-Client-CN", cert.Subject.CommonName)
		if len(cert.Subject.Organization) > 0 {
			r.Header.Set("X-Forwarded-Client-O", strings.Join(cert.Subject.Organization, ","))
		}
		if len(cert.Subject.OrganizationalUnit) > 0 {
			r.Header.Set("X-Forwarded-Client-OU", strings.Join(cert.Subject.OrganizationalUnit, ","))
		}
		if cert.SerialNumber != nil {
			r.Header.Set("X-Forwarded-Client-Serial", cert.SerialNumber.Text(16))
		}
	case IdentityAIC:
		setAICHeaders(r, ac)
	case IdentityMinimal:
		// nothing
	}
}

func setAICHeaders(r *http.Request, ac *AuthContext) {
	if ac.AIC == nil {
		return
	}
	if ac.AIC.AgentId != "" {
		r.Header.Set("X-AIC-Agent-Id", ac.AIC.AgentId)
	}
	if ac.Principal != "" {
		r.Header.Set("X-AIC-Principal-Uid", ac.Principal)
	}
	if len(ac.AIC.Capabilities) > 0 {
		var caps, full []string
		for _, c := range ac.AIC.Capabilities {
			caps = append(caps, c.CapabilityId)
			full = append(full, c.FullID())
		}
		r.Header.Set("X-AIC-Capabilities", strings.Join(caps, ","))
		r.Header.Set("X-AIC-Capabilities-Full", strings.Join(full, ","))
	}
	if ac.AIC.DelegationAuthorization.Timestamp.Unix() > 0 {
		r.Header.Set("X-AIC-Verified-By", ac.AIC.DelegationAuthorization.SignatureAlgorithm.Algorithm.String())
	}
	if ac.AgentID != "" {
		r.Header.Set("X-Agent-ID", ac.AgentID)
	}
	if ac.Principal != "" {
		r.Header.Set("X-Agent-Principal", ac.Principal)
	}
}

// certSPKIHashHex returns the hex SHA-256 of the certificate SPKI.
func certSPKIHashHex(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// AuthContextFromHeaders reconstructs a minimal AuthContext from the identity
// headers the reverse proxy injects after admission (X-AIC-Agent-Id,
// X-AIC-Principal-Uid, X-AIC-Capabilities-Full, X-Agent-ID). It is meant for
// backends that run behind the aic-verifier proxy on a trusted network: the proxy
// strips this whole header namespace from client input and only re-emits values
// it verified, so a loopback-only backend may trust them. Returns nil when no
// identity headers are present, so callers can fail closed.
//
// Capabilities are restored as full scheme:capabilityId identifiers into both
// Capabilities (the bare capability ids, as regular admission produces) and
// AIC.Capabilities (with SchemeId/CapabilityId split for FullID matching). The
// rest of the AuthContext (ClientCert, DA evidence, cross-signed chains) is not
// recoverable from headers and stays empty — authorization on such a backend
// must not depend on data the proxy did not forward.
func AuthContextFromHeaders(r *http.Request) *AuthContext {
	if r == nil {
		return nil
	}
	agentID := r.Header.Get("X-AIC-Agent-Id")
	principal := r.Header.Get("X-AIC-Principal-Uid")
	full := r.Header.Get("X-AIC-Capabilities-Full")
	if agentID == "" {
		agentID = r.Header.Get("X-Agent-ID")
	}
	if agentID == "" && principal == "" && full == "" {
		return nil
	}
	ac := &AuthContext{
		Principal: principal,
		AgentID:   agentID,
		AIC:       &AIC{AgentId: agentID},
	}
	for _, id := range strings.Split(full, ",") {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		ac.Capabilities = append(ac.Capabilities, id)
		scheme, capability, found := strings.Cut(id, ":")
		if !found {
			scheme, capability = "", id
		}
		ac.AIC.Capabilities = append(ac.AIC.Capabilities, pki.Capability{
			SchemeId:     scheme,
			CapabilityId: capability,
		})
	}
	return ac
}
