// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Package gw provides the shared security engine for varwof gateways.
//
// Capability plugin types (CapabilityPlugin, PluginContext, PluginResult,
// PluginDecision, HTTPFacts, PluginRegistry) are defined in the types
// module and re-exported here for backward compatibility.
package aicverifier

import (
	pki "github.com/varwof/types"
)

// PluginDecision represents the decision result after plugin execution.
type PluginDecision = pki.PluginDecision

// PluginAllow/Deny/Bypass are plugin decision constants.
const (
	PluginAllow  PluginDecision = pki.PluginAllow
	PluginDeny   PluginDecision = pki.PluginDeny
	PluginBypass PluginDecision = pki.PluginBypass
)

// PluginResult is the return result after plugin execution.
type PluginResult = pki.PluginResult

// HTTPFacts carries per-request HTTP facts for capability plugins.
type HTTPFacts = pki.HTTPFacts

// PluginContext is the context during plugin execution.
type PluginContext = pki.PluginContext

// CapabilityPlugin is the interface for all capability plugins.
type CapabilityPlugin = pki.CapabilityPlugin

// PluginRegistry manages plugin registration and lookup.
type PluginRegistry = pki.PluginRegistry

// NewPluginRegistry creates a new empty registry.
func NewPluginRegistry() *PluginRegistry {
	return pki.NewPluginRegistry()
}

// RegisterPlugin registers a plugin in the global registry.
func RegisterPlugin(p CapabilityPlugin) error {
	return pki.RegisterPlugin(p)
}

// findPlugin looks up a registered plugin by schemeID.
func findPlugin(schemeID string) (CapabilityPlugin, error) {
	return pki.FindPlugin(schemeID)
}

// ExecutePlugin is a convenience wrapper for findPlugin + Execute.
func ExecutePlugin(schemeID string, cap *pki.Capability, ctx *PluginContext) (*PluginResult, error) {
	return pki.ExecutePlugin(schemeID, cap, ctx)
}

// ResetPlugins clears the global registry (testing only).
func ResetPlugins() {
	pki.ResetPlugins()
}
