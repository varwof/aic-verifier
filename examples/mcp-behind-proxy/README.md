# MCP server behind the aic-verifier reverse proxy

This example shows the MCP server in its canonical deployment: the **aic-verifier
reverse proxy** is the single public door (TLS termination + bearer AIC-JWT
admission + audit), and the **MCP backend** runs on a **loopback-only** port in
`TrustProxy` mode — it trusts the server-asserted `X-AIC-*` identity headers
the proxy injects after admission, instead of re-verifying a credential.

```
        Bearer AIC-JWT                aic-verifier reverse proxy           loopback (127.0.0.1)
client ───────────────▶ HTTPS :9443  TLS term + admission + audit ──▶  MCP backend (TrustProxy)
   curl / any MCP client              /mcp route, strip credential      capability + param barrier
                                       inject X-AIC-* headers           mcp_* decision audit
```

Why this split: the proxy strips the `Authorization` header before forwarding
(SDK reverse-proxy policy, so the live bearer token never leaks downstream) and
re-emits identity only as server-injected headers. The backend therefore
reconstructs its `AuthContext` from those headers (`TrustProxy`) and keeps doing
its own job — per-tool capability matching and the deterministic parameter
barriers (`tools/call` deny → JSON-RPC `-32602`), plus the `mcp_*` audit trail.

`TrustProxy` is safe here **only because the backend is bound to 127.0.0.1** and
is unreachable by any direct client. Never expose a TrustProxy backend directly;
a directly reachable server must use the standalone bearer/mTLS admission
wrapper instead (see `examples/mcp-server`).

## Run

```
$ go run .                      # from examples/mcp-behind-proxy
OPERATOR TOKEN (mcp:db_query + mcp:trade_exec):   <…>  $OP
AUDITOR TOKEN (mcp:db_query only):                <…>  $AUD
AIC-gated MCP proxy listening on :9443 -> backend http://127.0.0.1:<auto-port>
```

Then the smoke test is identical to the standalone example, but against
`https://localhost:9443/mcp`:

```
$ SESS=$(curl -sk -D - https://localhost:9443/mcp \
      -H "Content-Type: application/json" -H "Authorization: Bearer $OP" \
      -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
           "params":{"protocolVersion":"2025-11-25","capabilities":{},
           "clientInfo":{"name":"curl","version":"1.0"}}}' \
      | grep -i '^mcp-session-id' | awk '{print $2}')

$ curl -sk https://localhost:9443/mcp -H "Content-Type: application/json" \
      -H "Mcp-Session-Id: $SESS" -H "Authorization: Bearer $OP" \
      -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
           "params":{"name":"db_query","arguments":{"sql":"SELECT * FROM users","max_rows":2}}}'

# param barrier:   max_rows:5000  → -32602  (audited in audit-mcp.jsonl)
# cap barrier:     auditor token calling trade_exec → -32602  (audited in audit-mcp.jsonl)
# admission:       bad/missing bearer token → 401  (audited in proxy-audit.jsonl)
```

## Two audit streams

`proxy-audit.jsonl` records the outer gate (an `allow INFO` row per admitted
request from the `Authenticated` hook, `deny WARN` rows from the `Denied` hook —
bad token, missing credential, no-route). `audit-mcp.jsonl` records the inner
`initialize` / `tools/list` / `tools/call` decisions with the redacted argument
digests. Full-chain mode (`--no-mint --jwt-ca <issuer-ca>.pem`) and the pinned
protocol revision (MCP **2025-11-25**, mark3labs/mcp-go v1.0.0) are unchanged
from `examples/mcp-server/README.md`; the out-of-scope list there applies here
too.

Flags: `--addr` (proxy), `--backend-port` (`0` = auto-assigned loopback port),
`--tools` (default `../mcp-server/tools.json`), `--proxy-audit-file`,
`--mcp-audit-file`, `--jwt-ca/--issuer/--audience`, `--tls-cert/--tls-key`,
`--no-mint`.