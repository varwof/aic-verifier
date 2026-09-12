// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto/x509"
	pki "github.com/varwof/types"
)

// ── Type aliases ──
type (
	PrincipalAuthorization = pki.PrincipalAuthorization
	DelegationPolicy       = pki.DelegationPolicy
	ExternalPolicyRef      = pki.ExternalPolicyRef
	ResourceScope          = pki.ResourceScope
	UserPermission         = pki.UserPermission
	PermissionLevel        = pki.PermissionLevel
	PermissionDef          = pki.PermissionDef
	RoleDef                = pki.RoleDef
)

// PermissionLevel constants.
const (
	PermissionAuto             PermissionLevel = 0
	PermissionRequiresApproval PermissionLevel = 1
)

// Private OID re-exports (used by tests)
var oidPrincipalAuthorization = pki.OIDPrincipalAuthorization
var oidUserPermission = oidPrincipalAuthorization

// ParseUserPermissionExtension delegates to pki-types.
func ParseUserPermissionExtension(cert *x509.Certificate) (*PrincipalAuthorization, error) {
	return pki.ParseUserPermissionExtension(cert)
}
