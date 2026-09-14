# Quick start

Fifteen minutes, no configuration files: you generate a demo CA, run a protected
service, watch a request pass, watch one be refused, and then read the decision
back as evidence.

## Before you start

| Requirement | Notes |
|---|---|
| Go **1.26+** | the module declares `go 1.26`; no cgo, nothing vendored |
| `curl` | any client that can present a client certificate works |
| free ports | **9444** (demo proxy), **9081** (demo backend, started by the same process), **9443** (the evidence demo in step 5) |

Dependencies are fetched by `go run` itself: `varwof/register v0.3.0` (the CLC
evaluator and record format), `varwof/types v0.6.0` (AIC structures) and
`varwof/pkcs7 v0.1.0`. No CRL/OCSP responder, timestamp authority or database is
needed for this walkthrough.

## What runs where

| Process | Address | Role |
|---|---|---|
| `examples/mtls-backend` | `:9444` (mTLS) | the admission proxy you are testing |
| its demo backend | `:9081` | the "real API"; it is only reachable through the proxy in this walkthrough |
| `examples/smoke-verify` (step 5) | `127.0.0.1:9443` (mTLS) | the smallest server that emits decision records |

## 1. Generate demo certificates

```bash
git clone https://github.com/varwof/aic-verifier && cd aic-verifier
go run ./examples/mtls-backend/gen-cert -out ./demo-certs
```

You get `ca-cert.pem` / `ca-key.pem`, `server-cert.pem` / `server-key.pem` (SAN
`localhost`, `127.0.0.1`) and `client-cert.pem` / `client-key.pem` — the client
certificate is the agent: it carries an **AIC extension** declaring scheme
`demo/example-v1` with the capabilities `api:read` and `http:*`.

## 2. Run the protected service

This one process is the whole test rig: it starts the demo backend, then listens
for agents on `:9444`.

```bash
go run ./examples/mtls-backend --certs ./demo-certs
```

```
supervision demo wired: approver=demo-admin trigger=/api/transfer ...
AIC-protected mTLS proxy listening on :9444 -> backend http://127.0.0.1:9081
```

The proxy terminates mTLS, runs the admission pipeline, and forwards admitted
requests to the demo backend (started in the same process).

## 3. Call it as the agent

Nothing here is authenticated by a password: the certificate *is* the identity,
and the capability it carries *is* the permission.

```bash
curl -sS --cert demo-certs/client-cert.pem --key demo-certs/client-key.pem \
     --cacert demo-certs/ca-cert.pem https://127.0.0.1:9444/api
```

```json
{"backend":"real-api-mtls","identity":{"X-Forwarded-For":"127.0.0.1, 127.0.0.1"}}
```

The request reached the backend because the agent certificate verified against
the demo CA **and** held the capability the route requires.

## 4. Watch it be refused

Two different refusals, at two different layers.

Without a client certificate there is no agent to verify, and mTLS refuses the
connection before HTTP exists:

```bash
curl -sS --cacert demo-certs/ca-cert.pem https://127.0.0.1:9444/api
# curl: (56) ... tlsv13 alert certificate required
```

A certificate that verifies but does not hold the capability the route requires
gets an HTTP refusal before the backend sees anything (the `/api/transfer` route
requires a different capability):

```bash
curl -sS --cert demo-certs/client-cert.pem --key demo-certs/client-key.pem \
     --cacert demo-certs/ca-cert.pem https://127.0.0.1:9444/api/transfer
# {"code":"access_denied","message":"agent missing required capabilities"}
```

## 5. Keep the decision as evidence

The proxy decides; where the record goes is a separate choice. Stop the proxy
from step 2 first (`Ctrl-C`), then run the smallest server that emits records.

The proxy decides, but does not have to be the place that stores records. The
smallest server that emits them is `examples/smoke-verify`:

```bash
go run ./examples/smoke-verify \
  --addr 127.0.0.1:9443 \
  --ca ./demo-certs/ca-cert.pem \
  --cert ./demo-certs/server-cert.pem --key ./demo-certs/server-key.pem \
  --cap 'demo/example-v1:api:read' --op 'demo/example-v1:api:read' \
  --evidence-dir ./records
```

```bash
curl -sS --cert demo-certs/client-cert.pem --key demo-certs/client-key.pem \
     --cacert demo-certs/ca-cert.pem https://127.0.0.1:9443/whoami
# agent=agent-002 principal=example:agent-002:AAAA... caps=[api:read http:*]

ls records/
# smoke-verify-9f13afb2...json    one DSSE envelope per decided operation
```

Read the record back — loading it re-runs the language over the record's frozen
inputs, which is what makes it evidence rather than a log line:

```bash
go run ./examples/inspect-record records/smoke-verify-d355cc50...json
```

```
language   clc-v1 (CLC-1.5)
operation  demo/example-v1:api:read
verdict    allow
inputs     sha-256:01XMUHOFFVE76Rc4NIn2IZnL_m0wyLyDt6pyWYvmvOE
recomputed allow
```

An `allow_unresolved` record prints its residual obligations on the `unresolved`
lines; the `recomputed` line is the check, and it is the same one
`LoadEvidenceRecord` performs before returning.

The `register` repository checks the same file from the outside:

```bash
go run ./cmd/record -verify records/smoke-verify-9f13afb2...json
# ok allow sha-256:...
```

## What to look at next

- **Refusals that presenting evidence could fix.** If a grant carries a
  constraint the language core does not evaluate (a time window, a CIDR, a
  `max_rows` bound), the verdict is `allow_unresolved` — the operation is not
  released, and the refusal carries an RFC 9457 problem document with a
  `CLC-CHALLENGE-v1` challenge saying what is missing. Add `--challenge` to the
  `smoke-verify` command above to see the envelope; the machinery is in
  [evidence.md](evidence.md).
- **Who issued a record.** `EvidenceConfig.Sign` + `KeyID` sign every envelope;
  `VerifyEvidenceDir` checks a whole directory and reports gaps.
- **Every configuration field**: [api.md](api.md).
- **Why the layering is what it is**: [DESIGN.md](DESIGN.md).
