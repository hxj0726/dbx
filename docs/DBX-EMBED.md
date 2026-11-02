# 把 DBX Web 嵌入 next-tdc 控制台

> 本文是 dbx 与 next-tdc 两侧的对齐依据：**部署形态、代理层、身份头、URL/postMessage 契约**。
> 签名算法的权威实现见 `crates/dbx-web/src/identity.rs` 与 next-tdc 的 `lib/tdc/dbx-tenant.js`，
> 两侧用同一个测试向量互相钉死。

## 1. 部署形态

dbx-web 仍是**独立进程**，但不再是"独立部署的服务"：

| 项 | 改造前 | 改造后 |
|---|---|---|
| 暴露面 | 公网可达，自带登录页 | 只听 `127.0.0.1`，仅 next-tdc 代理可达 |
| 鉴权 | 单密码 + `dbx_session` cookie | next-tdc 签名头（`DBX_TRUST_PROXY=1`） |
| 租户 | 全局单租户 | `DBX_DATA_DIR/tenants/<uuid>/` 一用户一租户 |
| 用户感知 | 无 | 角色 `admin` / `member` |

启动参数：

```bash
DBX_TRUST_PROXY=1
DBX_TRUST_KEY=<>=32 字节，与 next-tdc 同值>
DBX_BIND_ADDR=127.0.0.1
DBX_DATA_DIR=/var/lib/dbx      # 租户目录在其下的 tenants/
DBX_TENANT_CAP=64              # 同时驻留租户上限
DBX_TENANT_IDLE_SECS=1800      # 空闲驱逐阈值
```

`DBX_TRUST_PROXY=1` 与 `DBX_PASSWORD` **互斥**，同时设置会启动失败（避免出现"既是单密码又是多租户"的半开状态）。

本部署的 `DBX_PUBLIC_BASE_PATH` **不要设**：next-tdc 的 Route Handler 会先把 `/dbx` 前缀剥掉再转发（见 §6），
dbx-web 始终按根路径服务。只有反代**保留**前缀（例如 nginx `proxy_pass .../dbx/`）时才设 `/dbx/`，
两种反代风格只能二选一，混用会出现双重前缀或 404。

## 2. 三层结构

```
浏览器 ──/dbx/*──> next-tdc 代理 ──x-dbx-* 签名头──> dbx-web (127.0.0.1:4224)
                    (HTTP/SSE/WS 全透传，剥掉 /dbx 前缀)
```

- **网络层**：`/dbx` 整体转发，必须支持 WebSocket Upgrade。
- **路径层**：代理剥掉 `/dbx`，dbx-web 按根路径服务；因此不要设 `DBX_PUBLIC_BASE_PATH`（见 §6、§10.1）。
- **身份层**：代理为每个请求签名；浏览器不直连 dbx-web，也拿不到任何 dbx cookie。
- **展示层**：Next 页面里一个 iframe。

**不要**让浏览器直接访问 dbx-web：那样签名头要么缺失、要么必须暴露在浏览器里，等于放弃隔离。

## 3. 身份头契约

```
canonical = tenant + "\n" + role + "\n" + actAs + "\n" + ts
sig       = base64url_nopad( HMAC-SHA256(DBX_TRUST_KEY, canonical) )

x-dbx-tenant: <uuid>
x-dbx-role:   admin | member
x-dbx-act-as: <uuid>        # 可选，仅 admin
x-dbx-ts:     <unix 秒>
x-dbx-sig:    <base64url>
```

规则：

- `ts` 允许 ±60 秒偏移，窗口内同一 `(tenant, ts)` 重复出现判为重放。
- 角色 fail-closed：除 `admin` 外一律按 `member` 处理。
- `act-as` 仅 `admin` 可用，且每次都会写 `$DBX_DATA_DIR/audit/tenant-access.log`。
- 测试向量（两侧测试都用它）：key = `"k"*32`、tenant `u-1`、role `admin`、actAs `u-2`、ts `1700000000`
  → `5W1dUP29DL5dQn0Q3cwdT92iUfC56sv61TX58BzKwdU`

### 两条调用链路

| 链路 | 发起方 | tenant | act-as | 用途 |
|---|---|---|---|---|
| 浏览器链路 | iframe → 代理 | 当前登录用户 | 禁止 | DBX 自己的 UI（连接、SQL、schema） |
| 服务端链路 | next-tdc API route | 当前用户 | 数据源归属用户 | 受授权约束的 SQL 执行 |

服务端链路走 act-as 的前提是 next-tdc 已完成 `assertCan()` / `listVisibleDataSourceUuids()` 判定——
**授权只发生在 next-tdc**，dbx-web 只负责隔离存储与执行。

## 4. iframe 的 URL 契约

```
/dbx/?embed=1&theme=dark&locale=zh-CN&connection=<id>&db=<name>&panel=editor
```

| 参数 | 说明 |
|---|---|
| `embed=1` | 嵌入模式：隐藏 DBX 自己的顶栏、侧边栏、关于页；只留内容区 |
| `theme` | `light` / `dark`，覆盖用户在 DBX 内的偏好 |
| `locale` | 如 `zh-CN` |
| `connection` | 深链到指定连接（缺省则显示连接列表） |
| `db` | 目标数据库名 |
| `sql` | 预填 SQL（需 URL 编码） |
| `panel` | `editor` / `schema` / `both` |

**租户不在 URL 里传**——它由代理按登录态签发，避免用户改 URL 越权。

## 5. postMessage 协议

统一信封：`{ source: "tdc"|"dbx", type: string, payload: any }`，双向都校验 `event.origin` 与 `event.source`。

父 → iframe：

| type | payload | 说明 |
|---|---|---|
| `set-theme` | `{ theme }` | 跟随 next-tdc 主题 |
| `set-locale` | `{ locale }` | |
| `open-connection` | `{ connectionId, db? }` | 父页面数据源树点击 |
| `run-sql` | `{ sql }` | 把父页面的 SQL 送进编辑器 |

iframe → 父：

| type | payload | 说明 |
|---|---|---|
| `ready` | `{ version }` | iframe 完成初始化 |
| `navigate` | `{ connectionId?, db?, tab? }` | 同步面包屑/标题 |
| `dirty` | `{ dirty: boolean }` | 有未保存 SQL，父页面据此拦截离开 |
| `query-done` | `{ ok, durationMs, rowCount }` | 父页面刷新审计/统计 |

## 6. 代理实现要点

### nginx

以下 nginx 示例**保留** `/dbx` 前缀（`proxy_pass .../dbx/`），因此需要
`DBX_PUBLIC_BASE_PATH=/dbx/`。next-tdc 的 Route Handler 走的是**剥前缀**写法
（先去掉 `/dbx` 再转发），那种部署**不要设** `DBX_PUBLIC_BASE_PATH`。两者不能混用。

```nginx
location /dbx/ {
    proxy_pass http://127.0.0.1:4224/dbx/;   # 保留 /dbx 前缀（需设 DBX_PUBLIC_BASE_PATH=/dbx/）
    proxy_http_version 1.1;

    # WebSocket（redis pub/sub、插件 WS）
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;

    # SSE：必须关缓冲，否则流式结果会被攒到最后一次性返回
    proxy_buffering off;
    proxy_cache off;

    # 大结果集与导出
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    client_max_body_size 512m;

    # 身份头由 next-tdc 代理进程注入，这里禁止客户端伪造
    proxy_set_header x-dbx-tenant "";
    proxy_set_header x-dbx-role "";
    proxy_set_header x-dbx-act-as "";
    proxy_set_header x-dbx-ts "";
    proxy_set_header x-dbx-sig "";
}
```

### Node 代理（需要逐请求签名时）

若身份头必须在 Node 里按登录态动态签名，则不要用 nginx 直连，改为：

```
浏览器 → nginx(/dbx) → dbx-proxy.cjs（签名 + 透传）→ dbx-web
```

`dbx-proxy.cjs` 只做三件事：读 next-tdc 会话 → 调 `signDbxHeaders()` → 转发（含 Upgrade 与流式 body）。
Next 的 route handler **不支持 Upgrade**，WS 必须落在 nginx 或这个独立进程上。

## 7. 权限与模块分工

| 能力 | 归属 |
|---|---|
| 用户 / 角色 / 分组 | next-tdc |
| 数据源授权（谁能用哪个库） | next-tdc（`dataSourceGrants`） |
| 连接配置、SQL 编辑、schema 浏览、导出 | dbx-web |
| 审计 | 两侧都写：next-tdc 记业务操作，dbx-web 记 act-as |

**全局配置**（非管理员 403，界面上隐藏入口）：`/api/mcp`、`/api/system`、`/api/tenants`、插件市场安装。
其余配置（外观、编辑器、AI、保存的 SQL、历史、快捷键、备份）随租户隔离，普通用户随便改，天然不影响他人。

## 8. 一期 / 二期

**一期**：`/console/dbx` 整页 iframe，保留 next-tdc 顶栏与左侧数据源树；点数据源 → 改 iframe src。
管理员多一个"以该用户打开"（服务端签发 act-as）。

**二期**：`panel=editor` 分屏，schema 树改用 next-tdc 组件，只嵌编辑器。

## 9. 已知坑

1. **WS 必须独立进程或 nginx**，Next route handler 不能 Upgrade。
2. **SSE 关缓冲**，否则流式查询变"转圈到结束"。
3. **iframe 加 `allow="clipboard-read; clipboard-write; downloads"`**，否则 DBX 的复制与导出静默失败。
4. **高度链路**每一层都要 `height:100%` + `min-height:0`，否则双滚动条或滚不动。
5. **iframe 内历史不进父页面**，浏览器后退会直接退出控制台；用 `postMessage` 的 `dirty`/`navigate` 兜。
6. **插件资源的 CSP `frame-ancestors 'self'`** 在同源代理下成立（`'self'` 即 next-tdc 域）；换成独立域名代理会失效。
7. **旧数据迁移**：`ensureDbxConnection` 是每次查询都会执行的幂等 upsert，所以
   next-tdc 登记过的数据源会在用户首次以本人身份访问时自动落到他自己的租户，**不需要迁移脚本**。
   但历史 `DBX_DATA_DIR/dbx.db` 里可能还有**只在 dbx 界面里建、next-tdc 没有登记**的连接——
   这类没有归属信息，只能人工处理：把整个旧库拷进某个租户目录作为起始数据，或让用户重新添加。

## 10. 运维手册：多租户模式

### 10.1 环境变量

dbx-web 侧（两侧 `DBX_TRUST_KEY` 必须一致）：

| 变量 | 必填 | 说明 |
|---|---|---|
| `DBX_TRUST_PROXY` | 是 | 置 `1` 开启签名身份模式；不设则维持单租户，行为不变 |
| `DBX_TRUST_KEY` | 是 | HMAC 密钥，≥32 字节随机串 |
| `DBX_DATA_DIR` | 是 | 租户数据根目录 |
| `DBX_TENANT_CAP` | 否 | 驻留租户上限，默认 64 |
| `DBX_TENANT_IDLE_SECS` | 否 | 空闲回收秒数，默认 1800 |
| `DBX_PUBLIC_BASE_PATH` | 视反代 | 反代**保留** `/dbx` 前缀时设 `/dbx/`；反代**剥掉** `/dbx`（next-tdc Route Handler）时**不要设**。混用会出现双重前缀或 404 |

next-tdc 侧：

| 变量 | 说明 |
|---|---|
| `DBX_WEB_URL` | 指向 dbx-web，建议 `127.0.0.1:4224` |
| `DBX_TRUST_KEY` | 与 dbx-web 相同的密钥 |

### 10.2 数据布局

```
$DBX_DATA_DIR/
  dbx.db            # 单租户根状态；trust 模式下 /mcp 不再使用它
  tenants/
    u-<uuid>/       # 每个用户一份
      dbx.db
      plugins/
      agent/
      secrets.key   # 每租户独立
```

`secrets.key` 每租户独立是关键的隔离边界：即便拿到别的租户的 `dbx.db`，也无法解密其中的密码。

### 10.3 隔离与授权边界

- **存储隔离**：连接、凭据、历史、保存的 SQL 全在各自租户目录。
- **身份来源**：只认服务端签名的 `x-dbx-*` 头；浏览器自带的一律丢弃。
- **角色**：只承认 `admin`，其余一律 `member`（fail-closed）。
- **全局模块**：`/api/mcp`、`/api/system`、`/api/tenants`、插件市场安装 —— member 403。
- **act-as**：仅 admin 可代管，且落审计。

### 10.4 容量与回收

租户按需创建。超过 `DBX_TENANT_CAP` 返回 503；空闲超过 `DBX_TENANT_IDLE_SECS` 的租户
在 60s 一轮的清扫中回收（有在途请求的跳过）。回收只关句柄，磁盘数据保留，下次访问重新装配。

### 10.5 回滚

去掉 `DBX_TRUST_PROXY` 即回到单租户模式，`tenants/` 下的数据原样保留且不会被读取或改动。
因此"先关反代观察、再开"是安全的。

### 10.6 尚未覆盖

- **WebSocket**：需 nginx 或独立 Node 进程转发 Upgrade（见第 9 节第 1 条）。
- **`/mcp` 在可信代理模式下已按租户分发**：`/api` 与 `/mcp` 共用同一个
  `TenantRegistry`，每个租户一套 MCP Router（独立 session、策略、历史）；外部鉴权由
  next-tdc 的 `/dbx` 反代完成。单租户模式仍把 `/mcp` 挂在根状态上。面向 AI 客户端的
  实际接入方式见第 11 节。
- **租户删除**：`TenantRegistry::remove` 已实现但尚无调用方，删除用户后其租户目录需人工清理。

## 11. MCP 接入（AI 客户端）

有两条正式入口，按“要不要 DBX 原生工具”选：

- **TDC 网关**（`http://<TDC_HOST>:8000/mcp`）：暴露 TDC 工具集，权限/审计按 TDC 用户。
- **官方 DBX MCP**（`http://<TDC_HOST>:3000/dbx/mcp`）：暴露 DBX 原生 `dbx_*` 工具；
  由 next-tdc 的 `/dbx` 反代用 `X-API-Key` 鉴权并签 `x-dbx-tenant`，DBX `/mcp` 按租户分发。
  这是本次改造后的多租户模式，不需要 `DBX_WEB_MCP_TOKEN`。

| 候选 | 判定 | 说明 |
|---|---|---|
| `http://<TDC_HOST>:3000/dbx/mcp` | ✅ 官方 DBX MCP / 多租户 | next-tdc 反代鉴权 + DBX 按签名头分发；DBX 原生工具；客户端只带 `X-API-Key` |
| `http://<TDC_HOST>:8000/mcp` | ✅ TDC 工具网关 | TDC 工具集，SQL/查询类工具经 dbx 执行；只覆盖 TDC 已登记数据源 |
| `http://<TDC_HOST>:3000/mcp` | ❌ | next-tdc 控制台页面（创建令牌、查看示例），不是 MCP 端点 |
| `http://<TDC_HOST>:3000/dbx` | ❌ | DBX Web 页面/API 基地址，不是 MCP 端点 |
| `http://127.0.0.1:4224/mcp` | ⚠️ | 仅本机；单租户模式需 `DBX_WEB_MCP_TOKEN`；可信代理模式下没有 `x-dbx-*` 会 401，且不按租户分发 |

### 11.1 官方 DBX MCP（多租户，需要原生工具时）

调用链：

```
AI 客户端
  POST http://<TDC_HOST>:3000/dbx/mcp
  X-API-Key: tdc_...
        │
        ▼
next-tdc /dbx 反代
  requireUser() 校验 API Key
  签 x-dbx-tenant = user.uuid
  x-dbx-role / x-dbx-ts / x-dbx-nonce / x-dbx-sig
        │
        ▼
dbx-web /mcp（可信代理模式）
  验签 → TenantId = user.uuid
  TenantRegistry 取/建 tenants/<uuid>
  投进该租户的 MCP Router
        │
        ▼
该租户的 dbx.db
  connections / MCP policy / history / sessions
```

客户端配置（也可直接使用 `examples/mcp/tdc-native-mcp.json`）：

```json
{
  "mcpServers": {
    "dbx": {
      "type": "http",
      "url": "http://<TDC_HOST>:3000/dbx/mcp",
      "headers": { "X-API-Key": "tdc_..." }
    }
  }
}
```

DBX 控制台的「MCP 设置 → 接入方式 → HTTP 服务」在可信代理模式下会自动切成
「官方 DBX MCP（多租户）」卡片：显示 `/dbx/mcp` 端点、`X-API-Key` 请求头和
TDC 令牌页面入口，不再显示旧的单租户 Web MCP Token。Web 控制台只保留 HTTP
接入，不再提供本地 stdio；桌面端仍保留本地 stdio。

Claude Code：

```bash
claude mcp add --transport http dbx \
  http://<TDC_HOST>:3000/dbx/mcp \
  --header "X-API-Key: tdc_..."
```

前置条件：

- dbx-web 已按第 10 节开启 `DBX_TRUST_PROXY=1` + `DBX_TRUST_KEY`；
- next-tdc 已配置同一个 `DBX_TRUST_KEY`，且 `DBX_WEB_URL` 指向 dbx-web；
- **不要设** `DBX_PUBLIC_BASE_PATH`（next-tdc 会剥掉 `/dbx` 前缀）；
- 不需要设置 `DBX_WEB_MCP_TOKEN`；可信代理模式下 `/mcp` 走租户分发，根 token 不参与；
- **不要设置** `DBX_MCP_SCOPE_CONNECTION_IDS` / `_CONNECTION_ID` 等进程级 scope：
  它们会套到所有租户上，多租户模式应让每个用户用自己的连接；
- 浏览器类 MCP 客户端如果发 `Origin`，在 dbx-web 侧配置
  `DBX_WEB_MCP_ALLOWED_ORIGINS=http://<TDC_HOST>:3000`；CLI 客户端通常不发 Origin；
- next-tdc 对普通请求默认 30s 超时，MCP 的长查询/长工具调用需要调大
  `DBX_REQUEST_TIMEOUT`（例如 `600000`），或把 `/mcp` 加进 `/dbx` 反代的
  `LONG_RUNNING_PREFIXES`。否则大查询会在反代层 504。

验证：

```bash
curl -sS http://<TDC_HOST>:3000/dbx/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'X-API-Key: tdc_...' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}'
```

不带 `X-API-Key` 应返回 401；带无效令牌也是 401；带有效令牌应返回 `result`。
用该用户的令牌调 `dbx_list_connections`，只应看到该用户租户下的连接。

注意：

- TDC 令牌按用户签发；`tenant = user.uuid`，一个用户一个 DBX 租户。
  不是“一个组织一个租户”，也不是“多个用户共享一个租户”。
- 同一个用户的多个 API Key 权限相同；令牌没有 per-key scope。吊销令牌后，该 Key
  立即失效；其他 Key 不受影响。
- 直连 `http://<DBX_HOST>:4224/mcp` 不接受 TDC API Key：可信代理模式下它只认
  `x-dbx-*` 签名头，没有就走 401。要直连必须再加一层“API Key → 用户/租户”的
  DBX 侧校验器，当前未实现。

### 11.2 TDC 网关（只需要 TDC 工具时）

```json
{
  "mcpServers": {
    "tdc": {
      "type": "http",
      "url": "http://<TDC_HOST>:8000/mcp",
      "headers": { "X-API-Key": "tdc_..." }
    }
  }
}
```

令牌创建：登录 next-tdc → 侧栏「MCP 服务」（`/mcp`）→ 创建令牌。明文只显示一次；
权限、审计、可用工具都按令牌所属用户判定。

网关暴露的是 **TDC 工具集**（工具清单以控制台「MCP 服务」页为准；其中的 SQL/查询类工具经 dbx 执行），
只覆盖 next-tdc 已登记的数据源。直接在 dbx 界面里创建、next-tdc 没有登记过的连接，网关看不到。

### 11.3 stdio 旁路（本机 / 兼容旧客户端）

如果客户端只支持 stdio，或网络策略不允许直接访问 HTTP MCP，可以让本地
`dbx-mcp-server` 以 stdio 方式连到 next-tdc 的 `/dbx` 代理，并把 TDC 令牌放进
`DBX_WEB_HEADERS`。这条路径仍然能拿到 DBX 原生工具，但多一层本地进程：

```json
{
  "mcpServers": {
    "dbx": {
      "command": "dbx-mcp-server",
      "env": {
        "DBX_WEB_URL": "http://<TDC_HOST>:3000/dbx",
        "DBX_WEB_HEADERS": "{\"X-API-Key\":\"tdc_...\"}"
      }
    }
  }
}
```

注意：

- **不要设** `DBX_WEB_PASSWORD`：本部署没有 dbx-web 登录口令，设置后只会让客户端等待一个
  不存在的登录接口。
- `/dbx` 代理的 `requireUser()` 接受 `X-API-Key` 后，会用该用户身份签发 `x-dbx-*` 头，
  所以 MCP 看到的是该令牌所属用户的租户数据。
- 这是**非文档化旁路**，不是 next-tdc 的正式契约；后续若收紧 `/dbx` 的令牌访问会失效。
- next-tdc 对非长耗时接口默认 30s 超时（`DBX_REQUEST_TIMEOUT`），大查询可能返回 504。

### 11.4 TDC 网关验证

带令牌向网关发一次 MCP `initialize`，能返回 `result` 即 URL 与令牌都正确：

```bash
curl -sS http://<TDC_HOST>:8000/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'X-API-Key: tdc_...' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}'
```

未带令牌时网关返回的是 HTTP 200 + JSON-RPC 错误（不是 HTTP 401），看到 `error` 即说明
URL 通、只是缺令牌。
