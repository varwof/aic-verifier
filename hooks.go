// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import "net/http"

// Hooks are optional lifecycle callbacks a service operator can plug into the
// request pipeline. Every hook is invoked synchronously; nil hooks are skipped.
// This is the reserved extension point for callers that need to observe or veto
// AIC decisions without writing a full capability plugin.
type Hooks struct {
	// Authenticated runs on every admitted request, before the upstream handler
	// (middleware style) or backend proxy (proxy style) is invoked. Returning a
	// non-nil error denies the request with 403 and the error text is logged.
	Authenticated func(ctx *AuthContext, r *http.Request) error

	// Denied runs when a request is rejected by the admission pipeline. err is
	// the typed *AuthError carrying the error code and HTTP status.
	Denied func(r *http.Request, err *AuthError)

	// Forwarded runs after an admitted request returned from the backend (proxy
	// style only). resp is non-nil when the upstream responded; it is nil when
	// the reverse proxy failed before a response was produced.
	Forwarded func(r *http.Request, resp *http.Response)
}
