//! 受信任反代模式下的按租户请求分发。
//!
//! 处理器里有 1300 余处直接读 `state.app`，无法把租户贯穿进处理器签名，因此这里
//! 为每个租户装配一份完整的 `WebState` 与 `api_router`，再按签好名的身份把请求投进
//! 对应租户的路由。分发本身只做三件事：验签、取/建租户、`oneshot`。

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::header::{self, HeaderValue};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use tower::ServiceExt;

use crate::tenant::{Error, TenantId, TenantRegistry};

/// 一个租户的装配结果。
///
/// `runtime` 必须跟着 payload 一起存活：它持有后台任务的取消令牌，提前丢弃会让
/// 定时备份等任务失去停止开关（`JoinHandle` 丢弃只是 detach，不会 abort）。
pub struct TenantPayload {
    pub _runtime: crate::runtime::TenantRuntime,
    pub router: Router,
    /// 只挂在本进程内存里的租户 MCP 路由。外部请求先由 next-tdc 反代用
    /// `X-API-Key` 鉴权并签 `x-dbx-tenant`，再分发到这里；客户端拿不到
    /// `mcp_token`，也直接访问不到这个 Router。
    pub mcp_router: Router,
    pub mcp_token: String,
}

pub struct DispatchState {
    pub registry: Arc<TenantRegistry<TenantPayload>>,
    pub trust: Arc<crate::identity::TrustConfig>,
}

/// `/mcp` 的租户分发状态。和 `/api` 共用同一个 `TenantRegistry`，避免同一租户
/// 被装配两套 `AppState`（SQLite/连接池会互相打架）。
pub struct McpDispatchState {
    pub registry: Arc<TenantRegistry<TenantPayload>>,
    pub trust: Arc<crate::identity::TrustConfig>,
}

async fn build_payload(dir: PathBuf, base_path: String) -> Result<TenantPayload, String> {
    let runtime = crate::runtime::build_tenant(dir, base_path).await?;
    let router = crate::api_router(runtime.state.clone());
    // 每个租户一个内部 Bearer，仅用于把已通过身份头认证的请求交给该租户的
    // MCP Router；客户端无法获得，也不参与外部鉴权。
    let mcp_token = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    let mcp_router = crate::tenant_mcp_router(&runtime.state, &mcp_token)?;
    Ok(TenantPayload { _runtime: runtime, router, mcp_router, mcp_token })
}

pub fn dispatcher_router(state: Arc<DispatchState>) -> Router {
    Router::new().fallback(dispatch).with_state(state)
}

/// 把请求投进身份所属租户的路由。
///
/// 这里验出来的 `Identity` 会塞进请求扩展：租户路由内部的 `auth_middleware` 见到已
/// 有身份就直接复用。`TrustConfig::verify_parts` 带重放检测，同一组头验两次第二次
/// 会被判成 `Replayed`，所以整个请求链路上只能验一次。
async fn dispatch(State(state): State<Arc<DispatchState>>, mut req: Request<Body>) -> Response {
    let identity = match crate::auth::identity_from_headers(&state.trust, req.headers()) {
        Ok(identity) => identity,
        Err(error) => return crate::auth::identity_error_response(error),
    };
    let tenant_id = match TenantId::parse(identity.effective_tenant()) {
        Ok(tenant_id) => tenant_id,
        Err(_) => return (StatusCode::BAD_REQUEST, "租户标识非法").into_response(),
    };
    let entry = match state.registry.get_or_create(&tenant_id, build_payload).await {
        Ok(entry) => entry,
        Err(error) => return registry_error_response(error),
    };
    // 请求期间必须持有 inflight 计数，否则空闲回收可能在查询跑到一半时取消租户。
    let guard = entry.begin();
    req.extensions_mut().insert(identity);
    let router = guard.payload().router.clone();
    match router.oneshot(req).await {
        Ok(response) => response,
        Err(infallible) => match infallible {},
    }
}

/// `/mcp` 的租户分发入口。
///
/// 与 `/api` 的区别：MCP 客户端只带 `X-API-Key`，由 next-tdc 的 `/dbx` 反代先
/// 鉴权并签 `x-dbx-tenant`，所以这里同样只验签名头。验完把请求投进该租户的
/// MCP Router；后者用一次性内部 Bearer 通过 `HttpAuth`，不再暴露给客户端。
pub fn mcp_dispatcher_router(state: Arc<McpDispatchState>) -> Router {
    Router::new().route("/mcp", any(mcp_dispatch)).with_state(state)
}

async fn mcp_dispatch(State(state): State<Arc<McpDispatchState>>, mut req: Request<Body>) -> Response {
    let identity = match crate::auth::identity_from_headers(&state.trust, req.headers()) {
        Ok(identity) => identity,
        Err(error) => return crate::auth::identity_error_response(error),
    };
    let tenant_id = match TenantId::parse(identity.effective_tenant()) {
        Ok(tenant_id) => tenant_id,
        Err(_) => return (StatusCode::BAD_REQUEST, "租户标识非法").into_response(),
    };
    let entry = match state.registry.get_or_create(&tenant_id, build_payload).await {
        Ok(entry) => entry,
        Err(error) => return registry_error_response(error),
    };
    // 请求期间必须持有 inflight 计数，否则空闲回收可能在 MCP 调用跑到一半时取消租户。
    let guard = entry.begin();
    let (router, mcp_token) = {
        let payload = guard.payload();
        (payload.mcp_router.clone(), payload.mcp_token.clone())
    };
    if identity.is_acting_as() {
        state.trust.audit_act_as(&identity, req.uri().path());
    }
    // 覆盖客户端带来的 Authorization，只让内部 Bearer 通过租户 MCP Router 的
    // HttpAuth；外部鉴权已经由签名头完成。
    match HeaderValue::from_str(&format!("Bearer {mcp_token}")) {
        Ok(value) => {
            req.headers_mut().insert(header::AUTHORIZATION, value);
        }
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "MCP 内部凭据无效").into_response(),
    }
    req.extensions_mut().insert(identity);
    match router.oneshot(req).await {
        Ok(response) => response,
        Err(infallible) => match infallible {},
    }
}

fn registry_error_response(error: Error) -> Response {
    match error {
        Error::Capacity { cap } => {
            let message = format!("租户数量已达上限 {cap}");
            (StatusCode::SERVICE_UNAVAILABLE, message).into_response()
        }
        Error::InvalidId(_) => (StatusCode::BAD_REQUEST, "租户标识非法").into_response(),
        Error::Build(reason) => {
            tracing::error!("装配租户失败: {reason}");
            (StatusCode::BAD_GATEWAY, "租户初始化失败").into_response()
        }
    }
}

/// 定期回收空闲租户。
///
/// 回收前会跳过仍有 inflight 请求的条目，因此在途查询不会被误伤。
pub fn spawn_tenant_reaper(registry: Arc<TenantRegistry<TenantPayload>>) {
    tokio::spawn(async move {
        let period = std::time::Duration::from_secs(60);
        let mut ticker = tokio::time::interval(period);
        loop {
            ticker.tick().await;
            for tenant_id in registry.evict_idle() {
                tracing::info!("回收空闲租户 {}", tenant_id.as_str());
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Role, TrustConfig};
    use base64::Engine as _;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const KEY: &str = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";

    /// 这几条用例都只覆盖"进入 `get_or_create` 之前"的分支，不会真的装配租户，
    /// 所以 root 指向一个不存在的目录也没关系。
    fn state(root: &str) -> Arc<DispatchState> {
        Arc::new(DispatchState {
            registry: Arc::new(TenantRegistry::new(
                PathBuf::from(root),
                String::new(),
                4,
                Duration::from_secs(60),
            )),
            trust: Arc::new(TrustConfig::for_test(KEY.as_bytes())),
        })
    }

    fn headers(tenant: &str, ts: u64) -> Vec<(String, String)> {
        let trust = TrustConfig::for_test(KEY.as_bytes());
        let canonical = TrustConfig::canonical(tenant, Role::Member, "", ts);
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(trust.sign(&canonical));
        vec![
            ("x-dbx-tenant".to_string(), tenant.to_string()),
            ("x-dbx-role".to_string(), "member".to_string()),
            ("x-dbx-ts".to_string(), ts.to_string()),
            ("x-dbx-sig".to_string(), sig),
        ]
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).expect("系统时间应晚于 1970").as_secs()
    }

    async fn dispatch_status(root: &str, headers: Vec<(String, String)>) -> StatusCode {
        let mut request = Request::builder().uri("/api/connection/list");
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let request = request.body(Body::empty()).expect("请求应可构造");
        dispatcher_router(state(root)).oneshot(request).await.expect("分发不应失败").status()
    }

    #[tokio::test]
    async fn rejects_requests_without_identity_headers() {
        let status = dispatch_status("/tmp/dbx-dispatch-none", vec![]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_forged_signatures() {
        let mut forged = headers("u-1", now());
        forged[3].1 = "A".repeat(43);
        let status = dispatch_status("/tmp/dbx-dispatch-forged", forged).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// 签名合法但租户 id 含路径分隔符：必须停在 400，不能拿去拼目录。
    #[tokio::test]
    async fn rejects_tenant_ids_that_escape_the_data_root() {
        let status = dispatch_status("/tmp/dbx-dispatch-escape", headers("../etc", now())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn maps_registry_errors_to_distinct_status_codes() {
        assert_eq!(registry_error_response(Error::Capacity { cap: 3 }).status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(registry_error_response(Error::InvalidId("x".into())).status(), StatusCode::BAD_REQUEST);
        assert_eq!(registry_error_response(Error::Build("boom".into())).status(), StatusCode::BAD_GATEWAY);
    }
}
