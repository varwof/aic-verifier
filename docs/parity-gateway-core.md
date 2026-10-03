# Protocol-layer parity with gateway-core

Last verified: 2026-09-26

This is the `aic-verifier` half of a two-repository parity contract. The
`gateway-core` copy lives at
[`varwof/gateway-core/docs/parity-aic-verifier.md`](https://github.com/varwof/gateway-core/blob/main/docs/parity-aic-verifier.md).

## 1. Why this file exists

`varwof/gateway` depends on `varwof/gateway-core` at build time
(`gateway/go.mod` pins `v0.4.7`), so gateway-core is what actually decides for
the gateway. This repository is an independent extraction of the same admission
engine for services that do not run a gateway — see
[`architecture.md`](architecture.md) for how the pieces map.

The two modules **share no code**: this one does not depend on gateway-core.
Parity is maintained by hand, which means it decays silently unless every change
is checked against the other side. This report records the current state, the
divergences that are intentional, and how to re-verify.

## 2. Snapshot

| Repository | Branch | HEAD |
|---|---|---|
| `aic-verifier` | `main` | `df24fc0` |
| `gateway-core` | `feat/acps-aac` | `b112ee4` |

The parity changes described here are **not yet committed**.

## 3. File-level parity

### 3.1 Identical (comments differ only)

These 18 files are identical line for line once the package clause and comments
are normalised: `aic.go`, `capregistry.go`, `constraints.go`,
`credential_bundle.go`, `crl.go`, `delegation_chain.go`, `jwt.go`, `mask.go`,
`merkle.go`, `nonce_cache.go`, `ocsp.go`, `parameters.go`, `plugin.go`,
`rbac.go`, `riskmonitor.go`, `spiffe.go`, `tsa.go`, `user_permission.go`.

The only remaining textual delta is **comments**: gateway-core annotates patent
claim ids (`P1-B-27`, `P2-A-01`, …) and this repository, as a clean open-source
extraction, deliberately omits them. `nonce_cache.go` additionally carries a
cross-reference comment naming its mirror, correctly pointing in opposite
directions on each side.

### 3.2 Divergent by design

18 of the 22 mirror files are identical. The remaining 4 hold 60 changed lines
and contain **no shared decision logic any more** — only exported type fields and
a few one-line seams:

| File | Changed lines | Nature of the divergence |
|---|---|---|
| `policy.go` | 3 | this repo threads `*AuthorizationPolicy` into `extractPolicyRoles`; gateway-core reads the global `GetAuthorizationPolicy()` |
| `trust_model.go` | 5 | the `applyCLCAdmissionConfig` seam + the policy injection point |
| `pipeline.go` | 24 | CLC fields on `PipelineConfig` / `PipelineResult` + 2 seams |
| `decision.go` | 28 | CLC fields on `AdmissionResult` / `AdmissionConfig` + `VerifyDelegationAuth` kept at 2 arguments |

## 4. Why each divergence is safe

### 4.1 The CLC operation layer

This repo's `AdmissionConfig` carries `Operations`, `UnresolvedEvaluator`,
`DischargeObligations`, `ObligationsUnderstood`, `RequireFreshDecisionContext`,
`DecisionContext` and `ConstraintRegistry`; `AdmissionResult` carries
`OperationDecisions` and `Sources`; `PipelineConfig` and `PipelineResult` carry a
matching set. These are **exported API fields** and stay as they are on both
sides. gateway-core deliberately does not gain inert counterparts — adding
`DecisionContext` would pull `register/semantics` into the gateway for nothing.

The CLC **implementation** used to sit inline in the shared files. It now lives
entirely in this repo's own `clc.go`:

| Moved | Now in |
|---|---|
| the 56-line per-operation authorization loop | `clc.go` `evaluateCLCOperations` |
| `checkDecisionContext` | `clc.go` |
| `ConstraintToCapability`, `ConnectionConstraintEvaluator` | `clc.go` |
| `aggregateCLCDecisions` | `clc.go` |
| the 6 lines carrying `OperationDecisions` into a refusal | `clc.go` `denyWithAdmission` |
| assembly of the 7 CLC fields | `clc.go` `applyCLCAdmissionConfig` |

Only two one-line seams remain in the shared files:

```go
applyCLCAdmissionConfig(&ac, cfg)   // assembles the 7 CLC fields
if denied := evaluateCLCOperations(aic, &result, &cfg); denied != nil { return *denied }
```

The CLC layer is the feature that makes `aic-verifier` usable as a standalone CLC
decision point, so the divergence is the point of the extraction, not drift. The
shared path is identical.

### 4.2 The constraint evaluation path

**The constraint registry is not a divergence.** `globalConstraintRegistry`,
`NewConstraintRegistry`, `Register` / `Replace` / `Remove` / `Reset` / `Find` /
`Len` / `Keys`, the `RegisterConstraint` / `ReplaceConstraint` / `ResetConstraints`
extension points, the 8 evaluators registered in `init()`, and the semantics of
`isKnownConstraintType` are line-for-line identical to gateway-core.

The only real delta left is that this repo's `admissionConstraintRegistry`
prefers `cfg.ConstraintRegistry`; gateway-core's always returns the global one.
The three registry-parameterised forms (`checkConstraintsReg`,
`firstUnknownConstraintReg`, `isKnownConstraintTypeReg`) and the indirection
itself were added to gateway-core too, purely so this stretch of code reads
identically on both sides — the constraint-evaluation stretch is now line-for-line
identical, which is what made `constraints.go` a zero-difference file.

With `cfg.ConstraintRegistry` nil (the default) and no custom registration, both
sides resolve to the same `globalConstraintRegistry`, so the verdicts are
identical. The delta only becomes observable when an embedder supplies a custom
registry: that widens the "known constraint type" set, changing the
`unknown constraint type %q` denial under `StrictConstraints` and the
`ActionUnknownConstraint` audit entry. gateway-core has no per-admission registry
override by design — the gateway's constraint vocabulary is fixed.

### 4.3 Policy injection point

`extractPolicyRoles(cert, policy)` takes the policy as a parameter;
gateway-core's `ExtractPolicyRoles(cert)` reads the global
`GetAuthorizationPolicy()`. Same roles, different fetch site.

### 4.4 `VerifyDelegationAuth` stays 2-argument here

gateway-core has the 3-argument
`VerifyDelegationAuth(aic, userCert, agentCert)`. This repo keeps the published
2-argument `VerifyDelegationAuth(aic, userCert)` as a wrapper and puts v2
verification in a new `VerifyDelegationAuthWithAgent(aic, userCert, agentCert)`.

This is required by the API-stability contract in this repo's README: the
2-argument form is already public, and pre-1.0 changes are additive-only. Both
forms share one implementation and produce identical denial reasons, and the
admission path and delegation chain both call the 3-argument version — so a DA
v2 `agentKeyBinding` is verified here exactly as it is in the gateway. Only the
exported name differs.

## 5. Divergences closed in this pass

### 5.0 Divergence compression (second pass)

Behaviour unchanged; shared-file divergence down from 290 lines to 60, with
18/22 mirror files at zero difference. The table in §5.1/§5.2 below lists the
substantive fixes; the compression itself was:

| Action | Effect |
|---|---|
| moved the CLC implementation into this repo's own `clc.go` | see §4.1 |
| `applyCLCAdmissionConfig` assembles the 7 CLC fields | the 19-field `AdmissionConfig` literal in `pipeline.go` / `trust_model.go` is now identical on both sides |
| `denyWithAdmission` extracted from the refusal path | `pipeline.go` loses 6 lines |
| added the `*Reg` parameterised forms + the indirection to gateway-core | constraint evaluation became line-for-line identical; costs that module ~20 unused lines |
| ported 6 SPIFFE case-insensitivity tests from gateway-core | see §5.4 |

`policy.go`'s 3-line delta was **not** compressed — see §4.3.

### 5.1 Substantive fixes taken from gateway-core

| File | Problem | Fix |
|---|---|---|
| `spiffe.go`, `pipeline.go` | trust domain not case-normalised per RFC 7555 §2.1; allowlist compared un-normalised strings | `canonicalSPIFFEID`, trust-domain lowercasing + character-set validation, canonical allowlist comparison |
| `decision.go` | `DefaultDAAgeMax = 30s`, contradicting `varwof/core/internal.DefaultDATimestampSkew` | now `time.Minute` |
| `decision.go` | no DA v2 `agentKeyBinding` support | added `VerifyDelegationAuthWithAgent` (§4.4) |
| `nonce_cache.go` | `maxScopeUse = 3` cap on same-scope reuse | **removed** (§6.2) |

### 5.2 Substantive fixes given to gateway-core

| File | Problem |
|---|---|
| `constraints.go` | `geoResolvers` written under `RegisterGeoResolver` and read unsynchronised in `checkGeoFence` — a data race under `-race` |
| `tsa.go` | 4 ASN.1 defects, incl. `parseSignerInfo` swallowing Unmarshal errors and yielding an empty signer |
| `jwt.go` | replay store capacity 4096, evicting the oldest nonce at saturation — a replay window |
| `crl.go` | no dial/TLS-handshake timeouts on the CRL client |
| `nonce_cache.go` | `Stop()` not idempotent |
| `ocsp.go` | `fallback_allow`, the only fail-open path, recorded no certificate |
| `decision_test.go` | `TestVerifyDelegationAuth_SPKIHashMismatch` fixture never produced a valid TBS, and asserted only `err != nil` — a false green |

### 5.3 The DA v1→v0 fallback, fixed on both sides

The v1 → legacy-v0 fallback in `verifyDelegationAuthTBS` could mask the real
error: after the `PrincipalUid.KeyHash` cross-check failed it kept trying the v0
encoding and returned v0's "signature verification failed", even though the
original signature was valid. Both sides now gate the fallback on an
`errDASignatureMismatch` sentinel.

### 5.4 A regression this process caught

During the compression pass a `git checkout -- pipeline.go` also wiped the SPIFFE
canonicalisation ported in the previous round, and `go test -race ./...` stayed
green — because this repo had **no** test covering it, which is exactly the gap
recorded in §8. Fixed by porting the six tests into
`spiffe_case_test.go` and verifying that all six fail when the canonicalisation
is removed.

Lesson: **port the tests alongside the implementation** — a clean diff does not
mean matching behaviour.

## 6. Two "alignments" that were rejected

### 6.1 The DA 30s in core's docs

`varwof/core`'s `docs/openapi.yaml:1147` states `da_max_timestamp_skew`
defaults to 30s and `docs/bench/{zh,en}/benchmark-report-2026-08-27.md` sizes
nonce capacity from "skew 30s"; `core/internal/config.go:208` sets
`DefaultDATimestampSkew = time.Minute`. The docs are stale. gateway-core was
already correct, so this repo moved to 1m — not the other way round.

### 6.2 This repo's same-scope nonce cap

The `maxScopeUse = 3` cap looked stricter, and it was wrong to keep for a
different reason than it first appears:

- the DA nonce is a static value inside an X.509 extension, not per-request;
- `Config.NonceCache` defaults to nil here, so the cap never actually fired —
  it was latent, not protective;
- gateway creates a nonce cache unconditionally (`http/gateway.go:82`), so
  porting it would have rejected everything from the 4th request onward for any
  long-lived certificate.

Both sides now allow unbounded same-scope reuse and refuse only cross-scope
replay. The rationale is in the `nonce_cache.go` comments on both sides.

## 7. Authoritative values

| Value | Source of truth |
|---|---|
| `DefaultDAAgeMax = 1m` | `varwof/core` `internal.DefaultDATimestampSkew` (core's docs say 30s — stale) |
| replay store default capacity 65536, fail-closed at saturation | `jwt.go`, `NewReplayNonceStore` comment |
| same-scope nonce reuse is uncapped | `nonce_cache.go`, `CheckAndAdd` comment |
| SPIFFE trust domain is case-insensitive | RFC 7555 §2.1; implementation in `spiffe.go` |
| 8 built-in constraint types | `constraints.go` `init()`; hard-coded in gateway-core |

## 8. Known test gaps

Both are "implementation aligned, tests not caught up" — do not cite "verified on
both sides" as grounds for editing these until they are closed:

1. ~~This repo took `spiffe.go`'s RFC 7555 canonicalisation but **not** the
   case-insensitivity tests~~ — **closed in §5.4**, see `spiffe_case_test.go`.
2. gateway-core took `ocsp.go`'s fail-open trace but has no `fallback_allow` test
   of its own. Still open.

The general rule, learned the hard way in §5.4: test files such as `spiffe_test.go`
and `decision_test.go` are **not** among the 22 mirror files, so an implementation
is easy to port and its test to leave behind. A clean diff does not mean matching
behaviour.

## 9. Re-verifying

```sh
cd /path/to/aic-verifier
for f in aic.go capregistry.go constraints.go credential_bundle.go crl.go \
         delegation_chain.go jwt.go mask.go merkle.go nonce_cache.go ocsp.go \
         parameters.go plugin.go rbac.go riskmonitor.go spiffe.go tsa.go \
         user_permission.go; do
  diff <(sed -e 's/^package .*/package X/' "$f") \
       <(sed -e 's/^package .*/package X/' ../gateway-core/$f)
done
```

Expected: no output at all for those 18. The other 4 (`policy.go`,
`trust_model.go`, `pipeline.go`, `decision.go`) are expected to hold only the §4
seams, 60 lines in total. Then the full gate from
[`CONTRIBUTING.md`](../CONTRIBUTING.md):

```sh
gofmt -l . && go vet ./... && go build ./... && go test -race ./...
./hack/versioncheck.sh && go run ./examples/showcase
```

## 10. Rules for future changes

1. Change it here first, then copy it into gateway-core in the same commit
   (package `aicverifier` → `gw`, import paths adjusted).
2. Admission verdicts, denial-reason strings, TTL/time windows and fail-closed
   behaviour must be identical. Denial-reason strings are the de facto
   cross-implementation contract; never change one side only.
3. New divergence may only land inside §4. Update this report before exceeding
   it. Same for the §8 test gaps.
4. Keep the patent-claim ids out of this repo's comments; that comment-only
   delta is expected and is not drift.
