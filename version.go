// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

// Version is the single source of truth for the aic-verifier version.
// Every consumer reads this value (do not hard-code a version elsewhere).
//
// Released tag: v<Version>. Bump it and tag together (hack/versioncheck.sh
// enforces that Version is not older than the latest tag).
var Version = "0.2.0"
