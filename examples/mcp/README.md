# MCP 客户端配置示例

| 文件 | 适用场景 | 鉴权 |
| --- | --- | --- |
| `claude-code.mcp.json` | 本机 DBX 桌面版（可执行文件在 `PATH` 中） | 无需 |
| `cursor.mcp.json` | 本机 DBX 桌面版（通过 `npx` 启动） | 无需 |
| `web-deployment.mcp.json` | **仅** dbx-web 自己管理登录页的单密码部署 | `DBX_WEB_PASSWORD` |
| `tdc-native-mcp.json` | next-tdc 多租户 + 需要 DBX 原生工具（推荐） | `X-API-Key: tdc_...` |
| `tdc-gateway.mcp.json` | next-tdc 多租户 + 只需要 TDC 工具 | `X-API-Key: tdc_...` |
| `tdc-web-stdio.mcp.json` | 同上，但客户端只支持 stdio（兼容旁路） | `X-API-Key: tdc_...` |

> `web-deployment.mcp.json` **不适用**于 next-tdc 部署：该部署没有 dbx-web 登录口令，
> `/dbx` 由 next-tdc 代理完成鉴权。拿它去连只会一直收到 401。

next-tdc 部署有两个正式 HTTP 入口：

- `tdc-native-mcp.json` → `http://<TDC_HOST>:3000/dbx/mcp`：DBX 官方 `/mcp`，
  暴露 `dbx_*` 原生工具。next-tdc 的 `/dbx` 反代用 `X-API-Key` 鉴权并签
  `x-dbx-tenant`，DBX 按用户租户分发。**不需要** `DBX_WEB_MCP_TOKEN`。
- `tdc-gateway.mcp.json` → `http://<TDC_HOST>:8000/mcp`：TDC 工具网关，
  只覆盖 next-tdc 已登记的数据源。

令牌都在 next-tdc 控制台的「MCP 服务」页（`/mcp`）创建，明文只显示一次。
`tdc-*` 文件里的 `<TDC_HOST>`、`<tdc_api_token>` 需要替换为实际主机和令牌。

使用官方 `/dbx/mcp` 时注意：

- dbx-web 必须已开启 `DBX_TRUST_PROXY=1` + `DBX_TRUST_KEY`，且不要设
  `DBX_PUBLIC_BASE_PATH`；
- next-tdc `/dbx` 反代默认 30s 超时，长查询需调大 `DBX_REQUEST_TIMEOUT`
  （例如 `600000`），否则可能 504；
- TDC 令牌按用户签发，一个用户一个 DBX 租户；同一个用户的多个 Key 权限相同。

只有客户端只支持 stdio 时，才用 `tdc-web-stdio.mcp.json`；它还需要本机已安装
`dbx-mcp-server`。详见 [`docs/DBX-EMBED.md`](../../docs/DBX-EMBED.md) 第 11 节。
