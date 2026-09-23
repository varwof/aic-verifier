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
	"io"
	"os"

	aicverifier "github.com/varwof/aic-verifier"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: inspect-record <record.json>")
		return 2
	}

	rec, err := aicverifier.LoadEvidenceRecord(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "inspect-record:", err)
		return 1
	}

	fmt.Fprintf(stdout, "language   %s (%s)\n", rec.Lang, rec.Ver)
	for _, op := range rec.Inputs.Operations {
		fmt.Fprintf(stdout, "operation  %s\n", op.ID)
	}
	fmt.Fprintf(stdout, "verdict    %s\n", rec.Verdict)
	if rec.Reason != "" {
		fmt.Fprintf(stdout, "reason     %s\n", rec.Reason)
	}
	for _, obligation := range rec.Constraints.Unresolved {
		fmt.Fprintf(stdout, "unresolved %s\n", obligation)
	}
	fmt.Fprintf(stdout, "inputs     %s:%s\n", rec.InputDigest.Alg,
		base64.RawURLEncoding.EncodeToString(rec.InputDigest.Value))

	// Re-running the language is what makes the file evidence: the digest above
	// is over the inputs, and the verdict is derived from them, never trusted.
	if decision, err := rec.Recompute(); err == nil {
		fmt.Fprintf(stdout, "recomputed %s\n", decision.Verdict)
	}
	return 0
}
