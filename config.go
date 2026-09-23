// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// fileConfig is the JSON representation of Config, kept in sync with it. It
// lets operators configure the gateway (server, log file, authorization
// verification files) from a single file without code changes.
type fileConfig struct {
	// Comment is allowed metadata for example/compliance preset files (ignored
	// at parse). It is the only tolerated "unknown" key; every other unknown
	// field is still rejected so typos surface as errors.
	Comment string `json:"_comment,omitempty"`

	// LogFile is the SDK log output file (see Config.LogFile).
	LogFile string `json:"log_file,omitempty"`

	// Server tunes the embedded http.Server in proxy style.
	Server struct {
		ReadTimeout       string `json:"read_timeout,omitempty"`
		ReadHeaderTimeout string `json:"read_header_timeout,omitempty"`
		WriteTimeout      string `json:"write_timeout,omitempty"`
		IdleTimeout       string `json:"idle_timeout,omitempty"`
		MaxHeaderBytes    int    `json:"max_header_bytes,omitempty"`
	} `json:"server,omitempty"`

	// TLS/mTLS termination (proxy style).
	TLSCertFile string `json:"tls_cert_file,omitempty"`
	TLSKeyFile  string `json:"tls_key_file,omitempty"`

	// Authorization verification files: the mTLS CA bundle, the Bearer AIC-JWT
	// trust root, and the JWT issuer/audience policy.
	CACertFile    string   `json:"ca_cert_file,omitempty"`
	JWTCAFile     string   `json:"jwt_ca_file,omitempty"`
	JWTIssuer     string   `json:"jwt_issuer,omitempty"`
	JWTAudience   []string `json:"jwt_audience,omitempty"`
	BackendRootCA string   `json:"backend_root_ca,omitempty"`

	// ReplayProtection can be "true"/"false" (default true).
	ReplayProtection *bool `json:"replay_protection,omitempty"`

	// AuthMode: "mtls", "bearer", or "mtls_or_bearer" (default mtls_or_bearer).
	AuthMode string `json:"auth_mode,omitempty"`
	// IdentityMode: "minimal", "forward_client_cert" (default),
	// "xforwarded", or "aic".
	IdentityMode string `json:"identity_mode,omitempty"`

	// Admission policy.
	RequireAIC             bool     `json:"require_aic,omitempty"`
	RequiredCapabilities   []string `json:"required_capabilities,omitempty"`
	DisallowRepresentative bool     `json:"disallow_representative,omitempty"`
	RequireUserAuth        bool     `json:"require_user_auth,omitempty"`
	EnforceConstraints     bool     `json:"enforce_constraints,omitempty"`
	StreamBody             bool     `json:"stream_body,omitempty"`

	// Supervision policy: mirrors Config.SupervisionPolicy.  The interface
	// implementations (ApprovalRequester / OverrideRecorder / EvidenceExporter)
	// are code-injected, so the JSON only carries the policy switches plus the
	// file paths the built-in store/exporter read.
	Supervision struct {
		RequireRuntimeApproval *bool `json:"require_runtime_approval,omitempty"`
		AllowBreakGlass        *bool `json:"allow_break_glass,omitempty"`
		RequireEvidenceExport  *bool `json:"require_evidence_export,omitempty"`
	} `json:"supervision_policy,omitempty"`

	// AuditLogFile / AuditTSAURL / SupervisionLogFile map to the Config fields
	// of the same name (SupervisionStore / audit chain / evidence export).
	AuditLogFile       string `json:"audit_log_file,omitempty"`
	AuditTSAURL        string `json:"audit_tsa_url,omitempty"`
	SupervisionLogFile string `json:"supervision_log_file,omitempty"`
}

// LoadConfigFile reads a JSON configuration file into a Config. Unknown fields
// are rejected so typos surface as errors instead of silently ignored options.
func LoadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("aic-verifier: read config %q: %w", path, err)
	}
	return ParseConfig(data)
}

// ParseConfig decodes JSON configuration bytes into a Config.
func ParseConfig(data []byte) (*Config, error) {
	var fc fileConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fc); err != nil {
		return nil, fmt.Errorf("aic-verifier: parse config: %w", err)
	}

	c := &Config{
		LogFile:                fc.LogFile,
		TLSCertFile:            fc.TLSCertFile,
		TLSKeyFile:             fc.TLSKeyFile,
		CACertFile:             fc.CACertFile,
		JWTCAFile:              fc.JWTCAFile,
		JWTIssuer:              fc.JWTIssuer,
		JWTAudience:            fc.JWTAudience,
		BackendRootCA:          fc.BackendRootCA,
		ReplayProtection:       fc.ReplayProtection,
		RequireAIC:             fc.RequireAIC,
		RequiredCapabilities:   fc.RequiredCapabilities,
		DisallowRepresentative: fc.DisallowRepresentative,
		RequireUserAuth:        fc.RequireUserAuth,
		EnforceConstraints:     fc.EnforceConstraints,
		StreamBody:             fc.StreamBody,
	}

	if fc.AuthMode != "" {
		switch fc.AuthMode {
		case "mtls":
			c.AuthMode = MTLSOnly
		case "bearer":
			c.AuthMode = BearerOnly
		case "mtls_or_bearer":
			c.AuthMode = MTLSOrBearer
		default:
			return nil, fmt.Errorf("aic-verifier: unknown auth_mode %q", fc.AuthMode)
		}
	}

	if fc.IdentityMode != "" {
		switch fc.IdentityMode {
		case "minimal":
			c.IdentityMode = IdentityMinimal
		case "forward_client_cert":
			c.IdentityMode = IdentityForwardClientCert
		case "xforwarded":
			c.IdentityMode = IdentityXForwarded
		case "aic":
			c.IdentityMode = IdentityAIC
		default:
			return nil, fmt.Errorf("aic-verifier: unknown identity_mode %q", fc.IdentityMode)
		}
	}

	if fc.Supervision.RequireRuntimeApproval != nil {
		c.SupervisionPolicy.RequireRuntimeApproval = *fc.Supervision.RequireRuntimeApproval
	}
	if fc.Supervision.AllowBreakGlass != nil {
		c.SupervisionPolicy.AllowBreakGlass = *fc.Supervision.AllowBreakGlass
	}
	if fc.Supervision.RequireEvidenceExport != nil {
		c.SupervisionPolicy.RequireEvidenceExport = *fc.Supervision.RequireEvidenceExport
	}
	c.AuditLogFile = fc.AuditLogFile
	c.AuditTSAURL = fc.AuditTSAURL
	c.SupervisionLogFile = fc.SupervisionLogFile

	// M3: wire the configured supervision log file into a SupervisionStore so
	// supervision_log_file actually takes effect instead of being silently
	// ignored. Empty path stays unwired (no persistence), mirroring how the
	// audit logger treats an empty AuditLogFile.
	if c.SupervisionLogFile != "" {
		st, err := NewSupervisionStore(c.SupervisionLogFile, nil, 64<<20, 3)
		if err != nil {
			return nil, fmt.Errorf("aic-verifier: supervision store: %w", err)
		}
		c.SupervisionStore = st
	}

	if fc.Server.ReadTimeout != "" || fc.Server.ReadHeaderTimeout != "" ||
		fc.Server.WriteTimeout != "" || fc.Server.IdleTimeout != "" ||
		fc.Server.MaxHeaderBytes != 0 {
		o := &ServerOptions{MaxHeaderBytes: fc.Server.MaxHeaderBytes}
		if d, err := parseDur(fc.Server.ReadTimeout, "server.read_timeout"); err != nil {
			return nil, err
		} else {
			o.ReadTimeout = d
		}
		if d, err := parseDur(fc.Server.ReadHeaderTimeout, "server.read_header_timeout"); err != nil {
			return nil, err
		} else {
			o.ReadHeaderTimeout = d
		}
		if d, err := parseDur(fc.Server.WriteTimeout, "server.write_timeout"); err != nil {
			return nil, err
		} else {
			o.WriteTimeout = d
		}
		if d, err := parseDur(fc.Server.IdleTimeout, "server.idle_timeout"); err != nil {
			return nil, err
		} else {
			o.IdleTimeout = d
		}
		c.ServerOptions = o
	}

	return c, nil
}

func parseDur(s, field string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("aic-verifier: config %s: %w", field, err)
	}
	return d, nil
}
