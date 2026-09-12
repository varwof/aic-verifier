// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Package superv provides the shared supervision demonstration helpers used by
// the mtls-backend and bearer-jwt-backend examples: a DemoApprover that
// implements aicverifier.ApprovalRequester and a wire helper that turns the
// aic-verifier supervision config (policy + store + evidence export + trigger)
// into a runnable demo.
package superv

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/varwof/aic-verifier"
)

const (
	// Approver is the demo human approver identity recorded on supervision
	// events. It stands in for a real admin console / user signer.
	Approver = "demo-admin"

	// TransferPath is the demo high-risk route that requires runtime approval.
	TransferPath = "/api/transfer"
	// TransferCapability is the capability the transfer route demands.
	TransferCapability = "api:transfer"
)

// Options configures the supervision demo wiring.
type Options struct {
	// DenyRisk makes the DemoApprover deny every request flagged for approval,
	// demonstrating the deny(approval_required) audit path. Default allows.
	DenyRisk bool
	// AuditLogFile is the audit JSON Lines file the EvidenceExporter reads
	// (also written by the example's AuditLogger).
	AuditLogFile string
	// TSAURL optionally adds an RFC 3161 timestamping client to the
	// supervision store and audit logger.
	TSAURL string
	// SupervisionLog is the supervision event JSON Lines file.
	SupervisionLog string
}

// DemoApprover is a hardcoded human-approval stand-in for the examples. It
// returns a decision with Approver=Approver and an evidence_ref of the form
// "demo-ev-<operation_id>" so the evidence-bundle demo has a concrete, human
// readable reference to correlate with the AIC native supervision events.
type DemoApprover struct {
	DenyRisk bool
}

// Request implements aicverifier.ApprovalRequester.
func (d *DemoApprover) Request(ctx context.Context, risk aicverifier.RiskAssessment) (*aicverifier.SupervisionResult, error) {
	if d.DenyRisk {
		return &aicverifier.SupervisionResult{
			Decision:    supervisionDenied,
			Approver:    Approver,
			Reason:      "demo: transfer exceeds approved risk threshold",
			EvidenceRef: "demo-ev-" + risk.OperationID,
		}, nil
	}
	return &aicverifier.SupervisionResult{
		Decision:    supervisionApproved,
		Approver:    Approver,
		Reason:      "demo: transfer within approved scope",
		EvidenceRef: "demo-ev-" + risk.OperationID,
	}, nil
}

const (
	supervisionApproved = "approved"
	supervisionDenied   = "denied"
)

// Wire fills the aic-verifier Config with the demo supervision setup in place:
// the DemoApprover, the policy switches (runtime approval + evidence export),
// the SupervisionStore and the built-in EvidenceExporter over the two log
// files, and the RequireApproval trigger restricted to the TransferPath route.
// It must be called before aicverifier.NewServer / Config.Handler build the
// authorization chain, so the startup validations see non-nil interfaces.
func Wire(c *aicverifier.Config, o Options) error {
	c.ApprovalRequester = &DemoApprover{DenyRisk: o.DenyRisk}
	if o.TSAURL != "" {
		c.AuditTSAURL = o.TSAURL
	}

	var tsa *aicverifier.TSAClient
	if o.TSAURL != "" {
		tsa = aicverifier.NewTSAClient(o.TSAURL)
	}

	if o.AuditLogFile != "" {
		l, err := aicverifier.NewAuditLogger(o.AuditLogFile, tsa, 64<<20, 3)
		if err != nil {
			return err
		}
		c.AuditLogger = l
	}

	if o.SupervisionLog != "" {
		st, err := aicverifier.NewSupervisionStore(o.SupervisionLog, tsa, 64<<20, 3)
		if err != nil {
			return err
		}
		c.SupervisionStore = st
	}

	c.EvidenceExporter = aicverifier.NewFileEvidenceExporter(o.AuditLogFile, o.SupervisionLog)
	c.SupervisionPolicy.RequireRuntimeApproval = true
	c.SupervisionPolicy.RequireEvidenceExport = true

	c.RequireApproval = func(ctx *aicverifier.AuthContext, r *http.Request) bool {
		return strings.HasPrefix(r.URL.Path, TransferPath)
	}

	log.Printf("supervision demo wired: approver=%s trigger=%s deny_risk=%v audit_file=%q supervision_log=%q tsa=%q",
		Approver, TransferPath, o.DenyRisk, o.AuditLogFile, o.SupervisionLog, o.TSAURL)
	return nil
}
