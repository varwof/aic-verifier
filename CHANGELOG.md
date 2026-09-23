# Changelog

All notable changes to `aic-verifier` are documented here. The format is based on
the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) style, and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for tagged releases. Before v1.0, still and all: the API-stability contract in
[the README stability table](README.md#stability) governs what may change within
a minor.

## [Unreleased]

### Added

- **mTLS front end for the `mcp-behind-proxy` example.** A new `--mtls` mode
  runs the reverse proxy with `AuthMode: MTLSOnly` + `CACertFile`, admitting
  AIC X.509 client certificates instead of Bearer AIC-JWTs while the loopback
  MCP backend keeps `TrustProxy` semantics unchanged. `--certs <dir>` redirects
  all demo artifacts (ca.pem / client-*.pem / server-*.pem) out of the checkout,
  matching the `mtls-backend --certs` layout. The demo mints a real AIC client
  certificate (`mint.go mintAICClientCert`) so both front ends drive the same
  tools.
- **Effect evidence from the middleware**, not only the reverse proxy. With
  `Config.Evidence.EmitOutcome`, `Config.Handler` / `AuthMiddleware` probe the
  downstream handler, observe the status it actually wrote, and emit an outcome
  record at the effect boundary. The reverse proxy continues to do the same.
  Handlers the `Server` build already reports for itself are not doubled, so an
  `http.Server` built from the SDK's proxy and the middleware probing it cannot
  emit two records for one request.
- **Per-admission decision nonces** (RATS §10.2). `EmitDecisionRecords` binds
  every decision to a randomness-backed nonce (`crypto/rand`) regardless of
  TTL, so decision digests are unique across admissions by construction and a
  zero-TTL deployment still gets recomputable, collision-resistant records. With
  `TTL > 0` the record additionally carries the `At`/`MaxAgeSec` clock.
- **Linkage verification with orphan reporting.** `VerifyEvidenceDir` now
  verifies outcome records against the decisions actually present in the same
  directory: it collects the decision input-digest set first, then counts only
  outcomes whose `decisionDigest` resolves. Outcomes that resolve to nothing are
  reported through `OrphanOutcome` (and a matching failure) — they are never
  silent and never counted as consent.
- **Showcase end-to-end example** (`examples/showcase`): decision → admission →
  outcome → verify walk, including a demonstration of the orphan case.
- Sprint-tested coverage for middleware outcome emission
  (`TestMiddlewareEmitsOutcomeRecord`), turnover of unique digests
  (`TestNoTTLStillBindsUniqueDigest`), and orphan linkage
  (`TestVerifyEvidenceDirReportsGaps`).
- **`config.example.json` sync tests** (`example_config_sync_test.go`): the
  operator reference must keep parsing (every key recognized) and must document
  the full JSON surface, so a renamed/tagged field or an undocumented new option
  fails in CI instead of shipping quietly.

### Fixed

- Evidence-required denials now carry the retry lower bound (`Retry-After`) on
  the challenge, so a corrected presentation does not pound the gate before it
  is welcome (CLC challenge semantics).

### Changed

- **gRPC binding moved to a `grpc/` subpackage.** The root package no longer
  imports `google.golang.org/grpc` (or protobuf), so consumers that only need
  the HTTP middleware do not build the grpc dependency tree. The binding is
  unchanged and still manual — no protoc, codec `aic-json-v1`, service
  `varwof.aic.v1.AICDecisionService`. The symbols moved from the root
  (`NewGRPCDecisionService` etc.) to `grpc.NewDecisionService` /
  `grpc.NewDecisionClient` / `aicverifier.AsAuthError` /
  `aicverifier.ParseErrorCode`. It now ships with black-box end-to-end tests
  against the public API.
- `VerifyEvidenceDir` no longer counts a stray outcome as evidence of consent;
  a decision and its outcome must reference each other.
- `docs/api.md`, `docs/evidence.md`, `docs/comparison.md`, and the README
  updated to the nonce/linkage/orphan model.

### Dependencies

- `github.com/varwof/register` and `github.com/varwof/types` moved to **v0.6.0**
  (matches the `CLC-1.8` revision the SDK evaluates).

## [v0.2.0] — 2026-09-14

### Added

- **Bearer-JWT backend example** (`examples/bearer-jwt-backend`): the mTLS demo
  path backstopped by `Authorization: Bearer <AIC-JWT>`.
- **Record inspection** (`examples/inspect-record`): read a decision record back
  and recompute its verdict.
- **Chinese README** (`README_CN.md`) and a README quick start expanded into
  four explained steps.
- **Supervision and evidence wiring** on the HTTP path — decision records,
  admission records, and outcome records at the enforcement point, plus the
  evidence/challenge surfaces (`Evidence`, `Challenge`, requirement hooks).
- **Evidence directory + challenge flags** on `examples/smoke-verify`.
- Evidence details moved into their own document, `docs/evidence.md`, with the
  README keeping a one-paragraph summary.
- Decision authoring details now describe behaviour instead of internal claim
  identifiers (comments), and examples generate their server TLS keypair at
  runtime instead of tracking a private key.

### Fixed

- Refusals now produce an RFC 9457 `application/problem+json` challenge where a
  corrected presentation could fix the denial, with a stable reason and the
  records the refusal itself produced.

### Dependencies

- `github.com/varwof/register` pinned at v0.3.0 (semantics: allow_unresolved
  residual obligations and per-operation decisions).
- CI: build, vet, `-race` unit tests, and the `smoke`-tagged suite on Linux and
  macOS; consumer-view module-proxy gate.

## [v0.1.0] — 2026-09-12

### Added

- Initial import of `aic-verifier` as the AIC service-side SDK.
- **CLC core** — decide operations with the CLC-v1 language, including concrete
  operations and principal constraint inheritance, plus human PA grants carried
  into `AuthContext` and a PKI smoke example.
- **TLS and evidence posture** — published `register` v0.2.0 / `types` v0.6.0
  (no local `replace`), the CLC corpus smoke runner, and runtime-generated demo
  TLS keypairs.
- README with status, install, scope and related-repository sections; SPDX
  headers on example sources.

[Unreleased]: https://github.com/varwof/aic-verifier/compare/v0.2.0...HEAD
[v0.2.0]: https://github.com/varwof/aic-verifier/releases/tag/v0.2.0
[v0.1.0]: https://github.com/varwof/aic-verifier/releases/tag/v0.1.0