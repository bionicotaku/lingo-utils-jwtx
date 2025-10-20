# JWTx 抽象库设计与落地指南

> 目标：在 `pkg/jwtx` 中封装可复用的 JWT 校验/签发组件，使所有微服务（Gateway、Catalog、Media…）可以用统一接口处理 Supabase 与 GCP Identity Token，同时兼顾本地开发与未来上云场景。

---

## 1. 设计目标

1. **统一校验入口**：提供单一 API 校验不同 Issuer（Supabase、Google）的 JWT；调用方只需提交 `IssuerConfig` 与 token。
2. **高性能 JWKS 缓存**：封装 `lestrrat-go/jwx/v2` 的 cache，支持预热、轮换、刷新失败回退。
3. **灵活校验规则**：可配置 audience、subject/email 白名单、自定义 claim 校验。
4. **易于扩展**：新增 Issuer 仅需配置，不必改业务代码。
5. **导出辅助能力**：Outbound Token 获取（基于 Google identity token）在同一组件提供，保证调用方式统一。

---

## 2. 目录结构

建议在仓库新增 `pkg/jwtx` 模块，用于封装 UI 以外的复用工具（遵守现有工具目录规范）。

```
pkg/jwtx/
├── go.mod / go.sum      # 独立模块，便于版本管理或单独编译
├── README.md            # 本文档
├── config.go            # ValidatorConfig、IssuerConfig 定义
├── validator.go         # 核心校验逻辑
├── validator_test.go    # 校验器单测
├── provider.go          # Google Identity Token 获取器
├── provider_test.go     # Provider 单测
├── claims.go / errors.go# 通用类型与错误封装
├── cmd/                 # 实战脚本（supabase-validate、google-validate）
└── test_cli.sh          # 一键演示脚本，串行执行两个 CLI
```

### 3.3 Provider 接口

```go
type Provider interface {
    Token(ctx context.Context, audience string, opts ...jwtx.TokenOption) (string, error)
}
```

默认实现使用 Google IAM (idtoken/impersonate) 获取 Identity Token。可配合 `ProviderConfig` 设置默认 service account、是否包含 email、委托链等参数。

说明：
- 使用独立 `go.mod`，可以更轻量地复用到多个服务中；顶层 `go.work` 将其纳入工作区。
- 如需打包成 CLI（检查 JWKS、打印分析），可在 `cmd` 子目录添加工具，但 MVP 不强制。

---

## 3. API 设计

### 3.1 配置结构

```go
type IssuerConfig struct {
    Name             string        // 逻辑名称，如 “supabase”/“google”
    JWKSURL          string        // JWKS 地址；为空表示使用 Google 官方验证
    Issuer           string        // 预期 iss；Google 模式可留空，默认 https://accounts.google.com
    Audience         string        // 单一 audience
    AllowedSubjects  []string      // 可选：允许的 sub/email 列表
    ClockSkew        time.Duration // 可选：容忍的时钟偏差
    MinRefresh       time.Duration // JWKS 最小刷新间隔
    Timeout          time.Duration // 获取 JWKS 的超时
}

type ValidatorConfig struct {
    Issuers []IssuerConfig
}
```

### 3.2 Validator 接口

```go
type Validator interface {
    // Validate 校验 token 并返回标准化 Claims。
    Validate(ctx context.Context, token string, issuerName string) (*Claims, error)

    // Warmup 预热指定 issuer 的 JWKS（可选）。
    Warmup(ctx context.Context, issuerName string) error

    // Close 释放资源（如主动关闭缓存后台协程）。
    Close(ctx context.Context) error
}
```

```go
type Claims struct {
    Subject   string
    Issuer    string
    Audience  string
    ExpiresAt time.Time
    NotBefore time.Time
    IssuedAt  time.Time
    JWTID     string

    Email         string
    Role          string
    SessionID     string
    CustomClaims  map[string]any
}
```

统一 Claims 方便业务层继续做授权控制，例如 Gateway Session 撤销、服务白名单等。

### 3.4 Provider 接口

```go
type Provider interface {
    Token(ctx context.Context, audience string, opts ...TokenOption) (string, error)
}
```

默认实现基于 Google IAM：在 Cloud Run/GCE/GKE 等环境会自动走 Metadata Server，本地开发若配置 ADC 或服务账号 JSON 也能生成 Identity Token。`ProviderConfig` 可设置默认 service account、是否包含 email、委托链等参数，每次调用可通过 `WithServiceAccount`、`WithIncludeEmail` 等选项覆盖。

---

## 4. 核心实现

### 4.1 JWKS 缓存封装 (`cache.go`)

- 基于 `jwk.Cache`；启动时注册各 Issuer 的 JWKS 地址 `cache.Register(url, jwk.WithMinRefreshInterval(cfg.MinRefresh))`。
- 提供 `Fetch(ctx, issuerName) (*jwk.Set, error)`，内部管理 `map[string]*cacheEntry`，确保每个 Issuer 单独缓存。
- Warmup 时调用 `cache.Refresh(ctx, jwksURL)`；失败可记录日志但不 panic（按需回退）。

### 4.2 Token 校验 (`validator.go`)

1. 从配置中取 IssuerConfig。
2. 若 `JWKSURL` 为空，使用 `google.golang.org/api/idtoken.Validate` 走 Google 官方验证流程，并比对 issuer / audience；否则走 JWKS 模式。
3. JWKS 模式下：获取缓存的 `jwk.Set`，`jwt.Parse` + `jwt.Validate` 校验签名、issuer、audience。
4. 将标准字段与自定义 claims 统一映射为 `Claims`。
5. 如配置 `AllowedSubjects`，校验 `claims.Subject` 或 `claims.Email`。
6. 返回 `Claims`；若失败，包装成统一错误码（`ErrInvalidAudience`、`ErrExpired` 等）。

### 4.3 失败策略

- JWKS 获取失败 → 返回 `ErrJWKSUnavailable`（业务层可决定是降级还是拒绝）。
- token 解析失败 → `ErrInvalidToken`。
- audience/issuer 不匹配 → `ErrInvalidIssuer` / `ErrInvalidAudience`。
- `AllowedSubjects` 不包含 → `ErrSubjectNotAllowed`。

所有错误基于 `errors.Is` 可判断，便于业务自定义 Problem Details。

### 4.4 Outbound Token Provider（可选）

位于 `pkg/jwtx/provider.go`：

- `type Provider interface { ForAudience(ctx context.Context, audience string, opts ...Option) (string, error) }`
- 默认实现：
  - 直接用 `idtoken.NewTokenSource(ctx, audience)`。
  - 如果配置 `targetServiceAccount`，使用 `impersonate.IDTokenSource`（`IncludeEmail` 由配置决定）。
- 内部缓存 `map[key]oauth2.TokenSource`，token 过期前 5 分钟刷新。

这部分可被 Gateway/Form 的 outbound 调用复用。

---

## 5. 对现有服务的改造

1. 在 `go.work` 中新增：
   ```bash
   use (
     ...
     ./pkg/jwtx
   )
   ```

2. 各服务的 `go.mod` 引入：
   ```go
   require github.com/bionicotaku/lingo-utils-jwtx v0.0.0
   replace github.com/bionicotaku/lingo-utils-jwtx => ../../pkg/jwtx
   ```

3. **Inbound 拦截器重构**：
   - Template/Gateway 的 `internal/infra/auth` 中使用 `jwtx.NewValidator(cfg)`。
   - 校验逻辑变为：
     ```go
     claims, err := validator.Validate(ctx, token, "google")
     ```
     Supabase 则传 `"supabase"`。
   - 根据 `claims` 注入 `ctx` 或进行业务逻辑。

4. **Outbound Service Token**：
   - 在 Gateway `invoker` 等位置注入 `jwtx.Provider`。
   - 例如：
     ```go
     token, err := provider.ForAudience(ctx, backend.ServiceAuth.Audience,
         jwtx.WithTargetServiceAccount(backend.ServiceAuth.Target),
         jwtx.WithIncludeEmail(true))
     ```

5. **配置映射**：各服务 `config` 结构映射到 `IssuerConfig`/`ValidatorConfig`。Supabase 与 Google 配置示例见第 6 节。

---

## 6. 示例配置

```yaml
auth:
  required: true
  issuers:
    - name: "supabase"
      jwks_url: "https://your.supabase.co/auth/v1/certs"
      issuer: "https://your.supabase.co/auth/v1"
      audiences: ["authenticated"]
    - name: "google"
      jwks_url: "https://www.googleapis.com/oauth2/v3/certs"
      issuer: "https://accounts.google.com"
      audiences: ["https://template.local.dev"]
      allowed_subjects:
        - "svc-gateway@project.iam.gserviceaccount.com"
  clock_skew: 30s
```

在服务启动时构造 `ValidatorConfig` 并传给 `jwtx.NewValidator`。

---

## 7. 测试策略

- **单元测试**：
  - 使用内存 JWKS：创建临时 RSA key，生成 JWKS，测试签名验证、aud/iss 校验。
  - 错误场景：过期 token、issuer mismatch、subject 不在白名单。
- **集成测试**：
  - 模拟 Supabase Token（可固定 payload + 自签 key）。
  - 使用 `go run ./pkg/jwtx/cmd/google-validate` 生成并校验 Google Identity Token（依赖 ADC 或服务账号 JSON）。
  - Outbound Provider：mock `impersonate.IDTokenSource` 成功与失败。
  - 本地快速验证：`./pkg/jwtx/test_cli.sh` 会加载 `pkg/jwtx/.env`（或设置 `ENV_FILE=/path/to/.env`），依次运行两个 CLI 并输出结果，适合 smoke test。

---

## 8. 发布与版本控制

- `pkg/jwtx` 独立模块，便于版本化；当接口变更时可打 `tag` 并在 `go.work` 中更新。
- 如果需要在 CI 中复用，可提供 `go run pkg/jwtx/examples/basic` 作为 smoke test。

---

## 9. 框架整合计划

1. **MVP**：提供 Validator + Outbound Provider，Gateway/Template 落地。
2. **扩展**：迁移 Catalog/Search/Media 等服务到统一库。
3. **下沉**：将 Gateway 现有 JWT 验证代码重构为调用 `jwtx`，减少重复。
4. **高级功能（可选）**：支持 JWE、Token 变更事件、熔断/重试等。

---

## 10. 附录：常用辅助函数

- Audience 仅支持单值；如需支持多个受众，可在配置层为不同受众各配置一个 issuer。
- `jwtx.SubjectAllowed(subject, email string, allowed []string) bool`：通用白名单逻辑。
- `jwtx.ConvertError(err error) jwtx.Error`：统一错误类型，便于业务层映射 HTTP/gRPC 状态。

通过在 `pkg/jwtx` 搭建上述抽象层，所有微服务都可以共享同一套 JWT 校验/签发逻辑，降低安全实现的重复成本，并为后续引入更多 Issuer（Okta、Auth0 等）提供扩展基础。

---

## 11. 实战脚本：Supabase JWT 验证

目录 `cmd/supabase-validate` 提供一个 CLI，可直接对 Supabase 颁发的 JWT 做现场验证，并支持通过邮箱/密码自动拉取一次性 Access Token。推荐先在 shell 中准备 `.env`：

```bash
cp pkg/jwtx/.env.example pkg/jwtx/.env
# 编辑 pkg/jwtx/.env 填入项目域名、匿名/Service Key、账号与密码（如需自动取 token）
```

执行命令（脚本会自动读取 `.env`，也可以使用 `-env` 指定路径）：

```bash
go run ./pkg/jwtx/cmd/supabase-validate \
  -env pkg/jwtx/.env
```

行为说明：

- 若 `SUPABASE_JWT`（或 `-token`）已经设置，则直接使用该 Access Token 校验。
- 如果未提供 token，但 `.env`/环境变量中存在 `SUPABASE_API_KEY`（匿名或 Service Role）、`SUPABASE_EMAIL`、`SUPABASE_PASSWORD`，脚本会调用 `auth/v1/token?grant_type=password` 获取一次性 Access Token，再继续校验。
- 输出包含 subject/email/audience/过期时间等标准化信息；失败时给出具体错误，有助于排查项目配置或账号权限问题。
- 如需一键执行 Supabase 与 Google 两个验证，可运行仓库根目录的 `./pkg/jwtx/test_cli.sh`（自动加载 `pkg/jwtx/.env`），或通过 `ENV_FILE=/custom/.env ./pkg/jwtx/test_cli.sh` 指定配置路径。

> ⚠️ 安全提示：`SUPABASE_PASSWORD` 仅用于本地调试，注意不要提交 `.env`（已在 `.gitignore` 中忽略）。建议使用专门的测试账号并定期重置密码。

---

## 12. Google Identity Token 验证（手动流程）

`.env.example` 同时准备了 Google 相关占位符：

```env
GOOGLE_JWKS_URL=
GOOGLE_ISSUER=
GOOGLE_AUDIENCE=https://template.local.dev    # 与服务侧校验配置保持一致
GOOGLE_SERVICE_ACCOUNT=svc-template@project.iam.gserviceaccount.com
```

本地测试建议：

1. 运行 CLI 自动通过 jwtx.Provider 获取 Identity Token（确保 `aud` 与 `GOOGLE_AUDIENCE` 对齐）：
   ```bash
   go run ./pkg/jwtx/cmd/google-validate \
     -env pkg/jwtx/.env \
     -service-account "svc-template@project.iam.gserviceaccount.com"
   ```
   - 若当前登录账号即可代表调用者，可省略 `-service-account`。
   - 命令依赖 ADC（`gcloud auth application-default login`）或 `GOOGLE_APPLICATION_CREDENTIALS` 指定的服务账号 JSON。需要 `roles/iam.serviceAccountTokenCreator` 权限用于 impersonation。
   - 也可使用上文的 `test_cli.sh` 一次性跑通 Google/Supabase 两个验证流程。
2. 如果想在自定义脚本中复用验证逻辑，可直接调用 `jwtx`：

   ```go
   ctx := context.Background()
   provider := jwtx.NewProvider(jwtx.ProviderConfig{
     ServiceAccount: os.Getenv("GOOGLE_SERVICE_ACCOUNT"),
   })
   token, err := provider.Token(ctx, os.Getenv("GOOGLE_AUDIENCE"))
   if err != nil {
     log.Fatalf("issue token: %v", err)
   }
   validator, _ := jwtx.NewValidator(jwtx.ValidatorConfig{
     Issuers: []jwtx.IssuerConfig{{
       Name:     "google",
       Issuer:   os.Getenv("GOOGLE_ISSUER"),
       Audience: os.Getenv("GOOGLE_AUDIENCE"),
     }},
   })
   claims, err := validator.Validate(ctx, token, "google")
   ```

   输出的 claims 中会包含 `sub`、`email`、`aud`、`exp` 等信息，便于核对配置是否正确。

同样地，别把真实凭据提交到仓库；推荐使用专门的测试服务账号，并确保当前用户拥有 `roles/iam.serviceAccountTokenCreator` 权限，才能成功获取 impersonated token。
