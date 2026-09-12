// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import "sync/atomic"

// CapabilityRegistry is the capability registration validation interface (single source of truth).
// Gateway data plane validates AIC-declared capabilities against the registry during
// admission pipeline (RunAccessPipeline) phase one: unregistered scheme/capability
// is treated as an illegal declaration.
//
// Injected by gateways (gateway-*/protocol modules): internally holds a register.Registry
// (embedded + disk override), atomically replaced after SIGHUP hot reload.
//
// Returns nil when the capability is registered; returns an error when unregistered
// (caller rejects the connection).
type CapabilityRegistry interface {
	// ValidateCapability validates the full identifier "scheme:capability_id".
	ValidateCapability(formatted string) error
	// Enabled reports whether the registry has been loaded.
	Enabled() bool
}

// globalCapRegistry is the package-level default capability registry.
// Set by gateways during startup/hot reload via SetGlobalCapabilityRegistry;
// RunAccessPipeline falls back to it when PipelineConfig.CapabilityRegistry is nil.
// Uses atomic pointer for lock-free hot reload.
var globalCapRegistry atomic.Pointer[CapabilityRegistry]

// SetGlobalCapabilityRegistry sets the package-level default capability registry.
// Passing nil clears it (disables capability registration validation).
func SetGlobalCapabilityRegistry(cr CapabilityRegistry) {
	if cr == nil {
		globalCapRegistry.Store(nil)
		return
	}
	globalCapRegistry.Store(&cr)
}

// GetGlobalCapabilityRegistry returns the current package-level capability registry (may be nil).
func GetGlobalCapabilityRegistry() CapabilityRegistry {
	ptr := globalCapRegistry.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}
