// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"strings"
)

// DefaultMaskRune is the character used to replace sensitive content.
const DefaultMaskRune = '*'

// MaskString replaces all but the last `visible` characters with the mask rune.
// If the input is shorter than visible, it returns the input unchanged.
// If visible is 0, the entire string is masked.
// Returns empty string unchanged.
func MaskString(s string, visible int) string {
	if s == "" || visible < 0 {
		return s
	}
	if len(s) <= visible {
		return s
	}
	return strings.Repeat(string(DefaultMaskRune), len(s)-visible) + s[len(s)-visible:]
}

// MaskCertSerial masks a certificate serial number, keeping only the last 4 hex chars.
// Example: "A1:B2:C3:D4:E5:F6" → "**********E5:F6"
func MaskCertSerial(serial string) string {
	// Remove colons for counting, then mask
	clean := strings.ReplaceAll(serial, ":", "")
	if clean == "" {
		return serial
	}
	masked := MaskString(clean, 4)
	// Re-insert colons every 2 chars for readability
	var b strings.Builder
	for i, r := range masked {
		if i > 0 && i%2 == 0 {
			b.WriteByte(':')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// MaskFilePath masks the filename portion of a path, keeping the directory.
// Example: "/etc/pki/certs/secret.pem" → "/etc/pki/certs/********.pem"
func MaskFilePath(path string) string {
	if path == "" {
		return ""
	}
	// Find last separator
	lastSlash := strings.LastIndexAny(path, "/\\")
	if lastSlash < 0 {
		return maskBasename(path)
	}
	dir := path[:lastSlash+1]
	base := path[lastSlash+1:]
	return dir + maskBasename(base)
}

func maskBasename(name string) string {
	dot := strings.LastIndex(name, ".")
	if dot < 0 {
		// No extension — mask entire name
		return strings.Repeat(string(DefaultMaskRune), len(name))
	}
	ext := name[dot:]
	base := name[:dot]
	if len(base) <= 2 {
		return strings.Repeat(string(DefaultMaskRune), len(base)) + ext
	}
	// Keep first and last char of base, mask the rest
	return string(base[0]) + strings.Repeat(string(DefaultMaskRune), len(base)-2) + string(base[len(base)-1]) + ext
}

// MaskToken masks an API token or key, keeping only first and last 4 chars
// for long tokens, and proportionally fewer for short tokens so that at least
// half of the token is always masked (finding 21: a 9-char token must not
// reveal 8 chars).
// Example: "sk-abc123def456ghi789" → "sk-a*******i789"
func MaskToken(token string) string {
	if token == "" {
		return ""
	}
	n := len(token)
	if n <= 8 {
		return strings.Repeat(string(DefaultMaskRune), n)
	}
	// Keep at most 4 chars per side, but never more than half of the token
	// combined — for 9..16 char tokens this reduces the visible portion.
	keep := 4
	if maxKeep := n / 2; keep > maxKeep/2 {
		keep = maxKeep / 2
	}
	if keep < 1 {
		keep = 1
	}
	return token[:keep] + strings.Repeat(string(DefaultMaskRune), n-2*keep) + token[n-keep:]
}

// MaskEmail masks an email address, keeping domain visible.
// Example: "alice@example.com" → "a***e@example.com"
func MaskEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return MaskString(email, 4)
	}
	local := email[:at]
	domain := email[at:]
	if len(local) <= 2 {
		return strings.Repeat(string(DefaultMaskRune), len(local)) + domain
	}
	return string(local[0]) + strings.Repeat(string(DefaultMaskRune), len(local)-2) + string(local[len(local)-1]) + domain
}

// AuditSafe returns a copy of the AuditEntry with sensitive fields masked.
// This is used before logging or displaying audit entries to non-admin users.

// SanitizeString removes non-printable characters and trims whitespace.
// Useful for sanitizing user input before logging.
func SanitizeString(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 32 && r <= 126 || r == '\n' || r == '\t' {
			return r
		}
		return -1
	}, strings.TrimSpace(s))
}
