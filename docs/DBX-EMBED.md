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
DBX_PUBLIC_BASE_PATH=/dbx/     # 挂在 next-tdc 的 /dbx 子路径
DBX_BIND_ADDR=127.0.0.1
DBX_DATA_DIR=/var/lib/dbx      # 租户目录在其下的 tenants/
DBX_TENANT_CAP=64              # 同时驻留租户上限
DBX_TENANT_IDLE_SECS=1800      # 空闲驱逐阈值
```

`DBX_TRUST_PROXY=1` 与 `DBX_PASSWORD` **互斥**，同时设置会启动失败（避免出现"既是单密码又是多租户"的半开状态）。

## 2. 三层结构

```
浏览器 ──/dbx/*──> next-tdc 代理 ──x-dbx-* 签名头──> dbx-web (127.0.0.1:4224)
                    (HTTP/SSE/WS 全透传)              DBX_PUBLIC_BASE_PATH=/dbx/
```

- **网络层**：`/dbx` 整体转发，必须支持 WebSocket Upgrade。
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

```nginx
location /dbx/ {
    proxy_pass http://127.0.0.1:4224/dbx/;
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
7. **旧数据迁移**：历史 `DBX_DATA_DIR/dbx.db` 用 `dbx-web tenant migrate --from <dir> --to <uuid>` 落到指定租户后再对外。
