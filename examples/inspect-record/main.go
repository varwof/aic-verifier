// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command inspect-record reads a decision record written by the SDK and prints
// what was decided, why, and the digest a third party recomputes.
//
// The load is itself the check: LoadEvidenceRecord re-runs the language over the
// record's frozen inputs, so a record whose verdict, reason or residual
// obligations no longer follow from its inputs is reported as an error instead
// of being printed.
//
// Usage:
//
//	go run ./examples/inspect-record records/smoke-verify-<digest>.json
package main

import (
	"encoding/base64"
	"fmt"
	"os"

	aicverifier "github.com/varwof/aic-verifier"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: inspect-record <record.json>")
		os.Exit(2)
	}

	rec, err := aicverifier.LoadEvidenceRecord(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "inspect-record:", err)
		os.Exit(1)
	}

	fmt.Printf("language   %s (%s)\n", rec.Lang, rec.Ver)
	for _, op := range rec.Inputs.Operations {
		fmt.Printf("operation  %s\n", op.ID)
	}
	fmt.Printf("verdict    %s\n", rec.Verdict)
	if rec.Reason != "" {
		fmt.Printf("reason     %s\n", rec.Reason)
	}
	for _, obligation := range rec.Constraints.Unresolved {
		fmt.Printf("unresolved %s\n", obligation)
	}
	fmt.Printf("inputs     %s:%s\n", rec.InputDigest.Alg,
		base64.RawURLEncoding.EncodeToString(rec.InputDigest.Value))

	// Re-running the language is what makes the file evidence: the digest above
	// is over the inputs, and the verdict is derived from them, never trusted.
	if decision, err := rec.Recompute(); err == nil {
		fmt.Printf("recomputed %s\n", decision.Verdict)
	}
}
