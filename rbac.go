// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto/x509"
	"net/http"
	"strings"
)

// RolePrefix is the gateway role OU prefix.
const RolePrefix = "gateway:"

// RoleAdmin/Ops/Audit/Deploy/Read/Wild are role constants.
const (
	RoleAdmin  = "gateway:admin"
	RoleOps    = "gateway:ops"
	RoleAudit  = "gateway:audit"
	RoleDeploy = "gateway:deploy"
	RoleRead   = "gateway:read"
	RoleWild   = "gateway:*"
)

// OfflineRBAC provides offline RBAC decision capability for degraded scenarios where
// the core is unreachable. Injected with a role list extracted from certificates or
// configuration at construction time via NewOfflineRBAC.
type OfflineRBAC struct {
	roles []string
}

// NewOfflineRBAC creates an offline RBAC instance storing the specified roles.
func NewOfflineRBAC(roles []string) *OfflineRBAC {
	if roles == nil {
		roles = []string{}
	}
	return &OfflineRBAC{roles: roles}
}

// NewOfflineRBACFromCert creates an offline RBAC instance by extracting roles from a certificate's OU.
func NewOfflineRBACFromCert(cert *x509.Certificate) *OfflineRBAC {
	return NewOfflineRBAC(ExtractRoles(cert))
}

// CheckRole checks whether roles contains at least one role from allowed. If roles contains
// gateway:*, it passes immediately. Supports gateway:* wildcard in allowed.
func (r *OfflineRBAC) CheckRole(allowed []string) bool {
	return CheckRole(r.roles, allowed)
}

// ExtractRoles extracts the gateway role list from the certificate OU.
func ExtractRoles(cert *x509.Certificate) []string {
	var roles []string
	for _, ou := range cert.Subject.OrganizationalUnit {
		normalized := strings.TrimSpace(ou)
		if strings.HasPrefix(normalized, RolePrefix) {
			roles = append(roles, normalized)
		}
	}
	return roles
}

// CheckRole checks whether the role list contains an allowed role.
func CheckRole(roles []string, allowed []string) bool {
	for _, role := range roles {
		if role == RoleWild {
			return true
		}
		for _, allow := range allowed {
			if role == allow || (allow == RoleWild && strings.HasPrefix(role, RolePrefix)) {
				return true
			}
		}
	}
	return false
}

// PeerCertRoles extracts roles from the first peer certificate in the request's
// TLS connection. Returns nil if the request has no TLS or no peer certs.
func PeerCertRoles(r *http.Request) []string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return ExtractRoles(r.TLS.PeerCertificates[0])
}

// RequireRoles checks whether the mTLS peer certificate in the request carries
// at least one of the given allowedRoles. It is a convenience wrapper around
// PeerCertRoles + CheckRole for HTTP handler middleware.
func RequireRoles(r *http.Request, allowedRoles []string) bool {
	return CheckRole(PeerCertRoles(r), allowedRoles)
}
