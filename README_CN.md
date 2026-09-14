# aic-verifier

让任何 HTTP 服务都能检查**智能体是谁、它被允许做什么、以及这次到底记录下了什么** ——
面向通过 mTLS 或签名 JWT 出示 AIC（Agent Identity Certificate）的智能体。

它是一个小的 Go 库，不是网关：包一层你的 handler，或者把自带的反向代理放到 API 前面。

[English](README.md) · [中文](README_CN.md)

> **状态**：早期。首个稳定版之前 API 仍可能变化。当前求值 **CLC-1.5**；
> 分层设计见 [docs/DESIGN.md](docs/DESIGN.md)，证据侧见 [docs/evidence.md](docs/evidence.md)。

## 它做什么

每个请求走同一条管线：证书有效性 → CRL/OCSP → 角色 → AIC 裁决 →
能力 ∩（主体授权）→ 参数边界 → **allow / allow_unresolved / deny**，
并可选地写出一条可以被独立复算的裁决记录。

- **两种凭据形态**：带 AIC 扩展的 mTLS 客户端证书，或 `Authorization: Bearer <AIC-JWT>`。
- **两种集成方式**：`(*Config).Handler` / `AuthMiddleware` 包住你自己的 handler，
  或者用 `Server` 做反向代理，向后端注入 `X-AIC-*` 身份头。
- **是证据，不是日志**：每次裁决都可以落成 DSSE 封装的 CLC 裁决记录；语言层之前的拒绝
  落成 admission 记录，执行边界的效果落成 outcome 记录。

## 依赖要求

| 要求 | 说明 |
|---|---|
| **Go 1.26 或更高** | 模块声明 `go 1.26`；不用 cgo |
| `github.com/varwof/register v0.3.0` | CLC 求值器与裁决记录格式 |
| `github.com/varwof/types v0.6.0` | AIC / AIC-JWT 结构 |
| `github.com/varwof/pkcs7 v0.1.0` | 语义层分离签名校验 |
| `github.com/mark3labs/mcp-go v1.0.0` | 只有 import `mcp` 子包才需要 |

依赖随 `go get` 进来，仓库里没有 `replace`、也没有 vendor。SDK 本身不依赖任何外部服务：
CRL/OCSP 响应端与 RFC 3161 时间戳服务都是可选的，配置了才会用。

下面的演示另需 `curl`（任何能出示客户端证书的客户端都行）和三个空闲端口：
**9444**（代理）、**9081**（演示后端，进程自己起）、以及后面用到的 **9443**（证据演示）。

## 快速开始（两分钟）

四步，每步都很短。演示会自己生成 CA 和证书，不用先做配置。

**1. 取代码并生成演示证书** —— 一个 CA，加一张服务端证书和一张带 AIC 扩展的 agent 证书：

```bash
git clone https://github.com/varwof/aic-verifier && cd aic-verifier
go run ./examples/mtls-backend/gen-cert -out ./demo-certs
```

**2. 起受保护的服务** —— 它在 `:9444` 上终止 mTLS，把获准的请求转发到同一个进程起的
演示后端 `:9081`。让它在当前 shell 一直运行：

```bash
go run ./examples/mtls-backend --certs ./demo-certs
```

**3. 以 agent 身份访问** —— 另开一个 shell，用 agent 证书调用：

```bash
curl -sS --cert demo-certs/client-cert.pem --key demo-certs/client-key.pem \
     --cacert demo-certs/ca-cert.pem https://localhost:9444/api
# {"backend":"real-api-mtls","identity":{"X-Forwarded-For":"127.0.0.1, 127.0.0.1"}}
```

**4. 看一次拒绝** —— 请求一个 agent 无权做的操作，请求根本到不了后端：

```bash
curl -sS --cert demo-certs/client-cert.pem --key demo-certs/client-key.pem \
     --cacert demo-certs/ca-cert.pem https://localhost:9444/api/transfer
# {"code":"access_denied","message":"agent missing required capabilities"}
```

在第一个 shell 按 `Ctrl-C` 停掉演示。这次请求留下了什么、怎么复算，见
**[docs/quickstart.md](docs/quickstart.md)**（也包含不带客户端证书的调用会怎样）。

## 在自己的服务里用它

包住一个已有的 handler —— SDK 负责认证、提前拒绝，并把已验证身份交给你：

```go
conf := &aicverifier.Config{
    CACertFile:           "certs/ca-cert.pem",
    AuthMode:             aicverifier.MTLSOnly,
    RequireAIC:           true,
    RequiredCapabilities: []string{"demo/example-v1:api:read"},
}

mux := http.NewServeMux()
mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
    ac := aicverifier.FromContext(r.Context()) // 智能体 id、主体、能力、裁决
    fmt.Fprintf(w, "hello %s\n", ac.AgentID)
})

handler, err := conf.Handler(mux) // 把整条管线套在 mux 外面
if err != nil {
    log.Fatal(err)
}
srv := &http.Server{
    Addr:      ":8443",
    Handler:   handler,
    TLSConfig: muxTLSConfig, // ClientAuth: tls.RequireAndVerifyClientCert，ClientCAs: 你的 CA
}
log.Fatal(srv.ListenAndServeTLS("certs/server-cert.pem", "certs/server-key.pem"))
```

或者直接跑反向代理，后端一行不改：

```go
target, _ := url.Parse("http://127.0.0.1:8080")
server, err := aicverifier.NewServer(conf, []aicverifier.Route{
    {Path: "/api", Target: target, RequiredCapabilities: []string{"demo/example-v1:api:read"}},
})
log.Fatal(server.ListenAndServe(":9444"))
```

拒绝是有类型的：`*aicverifier.AuthError` 带着 HTTP 状态、稳定原因码、这次拒绝产生的记录，
以及在"补交证据就能过"时附上的 RFC 9457 problem 文档与 `CLC-CHALLENGE-v1` 挑战。

## 你实际会碰到的配置

| 字段 | 作用 |
|---|---|
| `CACertFile` / `JWTCAFile` | mTLS 客户端证书 / bearer 令牌的信任锚 |
| `AuthMode` | `MTLSOnly`、`BearerOnly`、`MTLSOrBearer`（默认） |
| `RequireAIC` | 拒绝没有 AIC 扩展的证书 |
| `RequiredCapabilities` | 调用方必须持有的能力 ID（`Config` 与每条 `Route` 都可设） |
| `EnforceConstraints` | 求值授权约束（时间窗、CIDR、`max_rows`） |
| `AdmissionConfig` | CRL/OCSP、角色、SPIFFE、委托链、监控钩子 |
| `Evidence` | sink、证据 profile、新鲜度 TTL、签名、效果记录 |
| `Challenges` | 可补救的拒绝是否带挑战，以及它的 TTL 与受众 |

完整字段、类型与默认值见 **[docs/api.md](docs/api.md)**。

## 一段话讲证据

只给一个"允许"没什么用，如果事后没人能查。配置了 `Evidence` 之后，SDK 会通过
`EvidenceSink` 发出一条 CLC 裁决记录（输入在规范边界处冻结、对输入取摘要、给出裁决与稳定
原因码），可选地签名并包在 DSSE 信封里；到不了语言层的拒绝改发 admission 记录；代理还可以
回报执行边界观察到的效果。已识别但核心不求值的约束会以残差义务的形式留在
`allow_unresolved` 上，绝不会被静默当成 `allow`。细节与固定形状的 profile 见
[docs/evidence.md](docs/evidence.md)。

## 示例

| 示例 | 展示什么 |
|---|---|
| [`examples/mtls-backend`](examples/mtls-backend) | mTLS + AIC、反向代理、身份头、监督与证据演示 |
| [`examples/bearer-jwt-backend`](examples/bearer-jwt-backend) | 同一个服务改用 `Authorization: Bearer` AIC-JWT 保护 |
| [`examples/mcp-server`](examples/mcp-server) / [`mcp-behind-proxy`](examples/mcp-behind-proxy) | 受 AIC 保护的 MCP 服务，以及放在代理后面的那种 |
| [`examples/smoke-verify`](examples/smoke-verify) | 冒烟测试与快速开始用的最小服务 |
| [`examples/inspect-record`](examples/inspect-record) | 读回一条裁决记录并复算它的裁决 |
| [`examples/supervision-demo`](examples/supervision-demo) | mTLS 示例用到的审批者与证据导出器 |

## 相关仓库

- [`varwof/types`](https://github.com/varwof/types) —— AIC 与 AIC-JWT 结构
- [`varwof/register`](https://github.com/varwof/register) —— 本 SDK 用来求值的 CLC 参考实现（钉在 `v0.3.0`）
- [`varwof/capability`](https://github.com/varwof/capability) —— CLC 规范及其一致性语料

## 许可证

Apache-2.0。
