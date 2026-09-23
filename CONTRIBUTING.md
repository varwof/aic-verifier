# Contributing to aic-verifier

Thanks for contributing. This is a small, security-sensitive SDK; the review bar
is correspondingly exact. Everything that merges must keep the checks in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) green, keep the evidence
and API surfaces coherent across docs, and stay within the API-stability
contract published in the README.

## Development setup

- **Go 1.26+** (the module declares `go 1.26`). No cgo.
- Clone the repo; there are no local `replace` directives and nothing is
  vendored — the module resolves the published
  `github.com/varwof/register`, `github.com/varwof/types`, and
  `github.com/varwof/pkcs7` from the proxy.
- Do not introduce a `replace` directive to point at a sibling checkout. If a
  dependency change is not yet published, publish it first and then bump here.
  CI enforces this via the `consumer-view` script.

## The checks

Run all of these locally before pushing; CI runs exactly this set (on Linux and
macOS):

```sh
go mod tidy && git diff --exit-code -- go.mod go.sum   # module hygiene
./hack/versioncheck.sh                                   # version tag not behind
./hack/consumer-view.sh                                  # resolves from the proxy only
go vet ./...
test -z "$(gofmt -l .)"
go build ./...
go test -race ./...
go test -tags smoke ./smoke/                             # CLC corpus via the HTTP glue
go run ./examples/showcase                               # end-to-end; must exit 0
```

`showcase` spins up a real instance over the mTLS demo path and asserts the
evidence pipeline end to end (decision → admission → outcome → verify) — it is
the closest thing to a manual reproduction, so keep it runnable.

### Test layout

| Where | What it covers |
|---|---|
| `*_test.go` at the package root | unit tests for the pipeline, evidence sink/verify, challenge, replay protection |
| `smoke/` (`-tags smoke`) | the normative CLC-v1 corpus driven through the SDK glue |
| `examples/supervision-demo` | approver + evidence exporter wiring used by the mTLS example |
| `examples/showcase` | full end-to-end effect-evidence walk (run as a binary) |

New behaviour needs a test that fails without it — including on the race
detector (`-race` is in the default gate). Evidence-side changes in particular
should prove round-trips (emit → read back → verify) and the failure modes
(emission failure with `Strict`, orphan outcome with an unresolvable
`decisionDigest`).

## Style and conventions

- **gofmt** clean, and `go vet` silent. Run them before you ask for review.
- **godoc**: exported identifiers carry a doc comment describing behaviour, not
  history. Prefer "refuses when…" over listing internal claim identifiers.
- **SPDX licenses**: every file carries the header
  `SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)` / `SPDX-License-Identifier:
  Apache-2.0`. The idempotent helper `add-spdx.sh` lives at the workspace root
  (`/home/varwof/src/github.com/add-spdx.sh`); add headers to new files.
- **Errors**: refusals are typed (`*AuthError` with a stable `Code`, HTTP
  `Status`, `Stage`, records, optional RFC 9457 `Problem`). A new refusal path
  must produce the stable code it documents; do not reuse a code with a
  different meaning.
- **No comments that restate code.** A comment explains the *contract* (canonical
  input boundaries, digest scope, TTL/nonce semantics); rename or restructure
  rather than describing implementation steps.

## Commit messages

Conventional-style, imperative subject, scope for the touched area:

```
feat(clc): …, fix(challenge): …, docs(evidence): …, build(deps): …,
chore(examples): …, test: …, ci: …
```

Examples from history: `feat(evidence): record decisions, admissions and
outcomes at the enforcement point`, `fix(challenge): carry the retry lower bound
on evidence-required denials`, `build(deps): depend on register v0.3.0`.

## Changing the API surface

- **Frozen surfaces** (see the README stability table) are additive-only before
  v1.0: no field removed or renamed, no default changed silently. A deliberate
  behavioural change must ship with a documented deprecation and a bump call.
- `Config` and `AuthContext` gain fields often; default behavior must not change
  without a note in `docs/api.md` and the changelog.
- The CLC revision the binary decides with moves only via an explicit
  `CLCRevision` bump, never piecemeal.

## Documentation

Docs are part of the change, not an afterthought:

- API surface changes update `docs/api.md` (and this file's comfort with
  `go doc`).
- Evidence/record changes update `docs/evidence.md`, and the README's
  "Evidence in one paragraph" if the public shape changed.
- The record-inspection and smoke example headers document the exact run
  commands that pair with the example; keep them honest.
- Keep `config.example.json` in sync when `Config` changes; it is strict
  (unknown fields rejected), and it exists so a typo cannot disable a control.
- The CHANGELOG gets an entry under `Unreleased` for user-visible changes.

## Review process

- Push a branch; open a PR against `main` (CI runs on push and PR). Fill in the
  PR body with what changed, why, and how it was verified.
- A green CI run is the entry ticket, not the verdict: reviewers re-run the
  evidence round-trips mentally and may ask for the reproduction that shows the
  new test would have failed before.
- Ask before force-pushing shared branches; keep history readable rather than
  squashed-happy.
- Do not merge your own PR unless there is an explicit repo-level agreement that
  maintainers may.

## Reporting security issues

Do not open a public issue. Follow [`SECURITY.md`](SECURITY.md) and report
privately via the GitHub Security Advisory flow.