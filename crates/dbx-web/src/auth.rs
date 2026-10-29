use std::sync::Arc;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::identity::{self, Identity, IdentityError, TrustConfig};
use crate::state::WebState;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct AuthCheckResponse {
    pub authenticated: bool,
    pub required: bool,
    pub setup_required: bool,
    /// 可信代理模式下的角色（admin/member）；None 表示沿用口令会话模式。
    /// 前端据此对"公共配置"类模块做门禁。
    pub role: Option<&'static str>,
}

const MAX_ATTEMPTS: u32 = 5;
const LOCKOUT_SECS: u64 = 60;

fn session_cookie_path(state: &WebState) -> &str {
    state.public_base_path.as_str()
}

/// `Secure` is opt-in: LAN/HTTP deployments would otherwise never receive the
/// session cookie back. Reverse-proxy TLS deployments set DBX_WEB_COOKIE_SECURE=1.
fn cookie_secure_enabled() -> bool {
    static SECURE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SECURE.get_or_init(|| matches!(std::env::var("DBX_WEB_COOKIE_SECURE").ok().as_deref(), Some("1") | Some("true")))
}

pub(crate) fn session_cookie(state: &WebState, token: &str) -> String {
    let secure = if cookie_secure_enabled() { "; Secure" } else { "" };
    format!("dbx_session={token}; Path={}; HttpOnly; SameSite=Lax{secure}", session_cookie_path(state))
}

fn api_path_suffix<'a>(path: &'a str, public_base_path: &str) -> Option<&'a str> {
    if let Some(suffix) = path.strip_prefix("/api/") {
        return Some(suffix);
    }
    let base = public_base_path.trim_end_matches('/');
    if base.is_empty() || base == "/" {
        return None;
    }
    path.strip_prefix(base)?.strip_prefix("/api/")
}

pub(crate) fn middleware_api_path_suffix<'a>(path: &'a str, public_base_path: &str) -> Option<&'a str> {
    if let Some(suffix) = api_path_suffix(path, public_base_path) {
        return Some(suffix);
    }

    let base = public_base_path.trim_end_matches('/');
    if !base.is_empty() && base != "/" && path.strip_prefix(base).is_some() {
        return None;
    }

    path.strip_prefix('/').filter(|suffix| !suffix.is_empty())
}

pub async fn login(State(state): State<Arc<WebState>>, Json(body): Json<LoginRequest>) -> Result<Response, StatusCode> {
    let hash_guard = state.password_hash.read().await;
    let hash_str = match hash_guard.as_deref() {
        // No password configured: nothing to authenticate against. Answer
        // explicitly instead of an ok:true that reads as "authenticated" —
        // the API remains locked by the middleware until setup completes.
        Some(h) => h.to_string(),
        None => {
            return Ok((StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "setup_required"}))).into_response());
        }
    };
    drop(hash_guard);

    // Check rate limit
    {
        let rl = state.login_rate_limit.lock().await;
        if let Some(locked_until) = rl.locked_until {
            if locked_until > std::time::Instant::now() {
                let remaining = (locked_until - std::time::Instant::now()).as_secs();
                return Ok((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({"error": format!("Please try again in {remaining}s")})),
                )
                    .into_response());
            }
        }
    }

    let parsed_hash = PasswordHash::new(&hash_str).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if Argon2::default().verify_password(body.password.as_bytes(), &parsed_hash).is_err() {
        let mut rl = state.login_rate_limit.lock().await;
        rl.fail_count += 1;
        if rl.fail_count >= MAX_ATTEMPTS {
            rl.locked_until = Some(std::time::Instant::now() + std::time::Duration::from_secs(LOCKOUT_SECS));
            rl.fail_count = 0;
        }
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Success — reset rate limit
    {
        let mut rl = state.login_rate_limit.lock().await;
        rl.fail_count = 0;
        rl.locked_until = None;
    }

    let token = uuid::Uuid::new_v4().to_string();
    state.sessions.write().await.insert(token.clone());

    let cookie = session_cookie(&state, &token);
    Ok((StatusCode::OK, [("set-cookie", cookie.as_str())], Json(serde_json::json!({"ok": true}))).into_response())
}

pub async fn setup(State(state): State<Arc<WebState>>, Json(body): Json<LoginRequest>) -> Result<Response, StatusCode> {
    if state.password_disabled {
        return Err(StatusCode::FORBIDDEN);
    }

    // Only allow setup when no password is configured
    if state.password_hash.read().await.is_some() {
        return Err(StatusCode::FORBIDDEN);
    }

    if body.password.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    // Save to database
    state.app.storage.save_password_hash(&hash).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update in-memory state
    *state.password_hash.write().await = Some(hash);
    if state.migration_ready.load(std::sync::atomic::Ordering::Acquire) {
        if let Err(error) = state.web_mcp.reload(&state.app.storage, true).await {
            log::error!("Web MCP remained disabled after password setup: {error}");
        }
    }

    // Auto-login: create session
    let token = uuid::Uuid::new_v4().to_string();
    state.sessions.write().await.insert(token.clone());

    let cookie = session_cookie(&state, &token);
    Ok((StatusCode::OK, [("set-cookie", cookie.as_str())], Json(serde_json::json!({"ok": true}))).into_response())
}

pub async fn check(State(state): State<Arc<WebState>>, req: Request<axum::body::Body>) -> Json<AuthCheckResponse> {
    let role = req.extensions().get::<Identity>().map(|identity| identity.role.as_str());
    // 可信代理模式：身份由签名头决定，既不需要口令，也不该提示初始化口令。
    if role.is_some() {
        return Json(AuthCheckResponse { authenticated: true, required: false, setup_required: false, role });
    }
    if state.password_disabled {
        return Json(AuthCheckResponse { authenticated: true, required: false, setup_required: false, role: None });
    }
    let has_password = state.password_hash.read().await.is_some();
    if !has_password {
        return Json(AuthCheckResponse { authenticated: false, required: false, setup_required: true, role: None });
    }
    let authenticated = match extract_session_token(&req) {
        Some(token) => state.sessions.read().await.contains(&token),
        None => false,
    };
    Json(AuthCheckResponse { authenticated, required: true, setup_required: false, role: None })
}

pub async fn change_password(
    State(state): State<Arc<WebState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Response, StatusCode> {
    // Session-bound: this endpoint used to sit outside the auth middleware,
    // giving unauthenticated callers an unlimited online guess at the admin
    // password with none of login's lockout. It now requires a live session
    // (defense in depth — the middleware gates it too) and, after a successful
    // change, revokes every OTHER session so a stolen old cookie cannot survive
    // a credential rotation.
    let current_token = session_token_from_headers(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    if !state.sessions.read().await.contains(&current_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let hash_guard = state.password_hash.read().await;
    let hash_str = match hash_guard.as_deref() {
        Some(h) => h.to_string(),
        None => return Err(StatusCode::BAD_REQUEST),
    };
    drop(hash_guard);

    if body.new_password.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let parsed_hash = PasswordHash::new(&hash_str).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if Argon2::default().verify_password(body.old_password.as_bytes(), &parsed_hash).is_err() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let salt = SaltString::generate(&mut OsRng);
    let new_hash = Argon2::default()
        .hash_password(body.new_password.as_bytes(), &salt)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    state.app.storage.save_password_hash(&new_hash).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    *state.password_hash.write().await = Some(new_hash);

    // Rotation revokes sibling sessions; only the caller stays logged in.
    {
        let mut sessions = state.sessions.write().await;
        for token in sessions.iter().filter(|token| **token != current_token) {
            dbx_core::query::pl_debug::pl_debug_revoke_web_owner_core(&state.app, token);
        }
        sessions.retain(|token| *token == current_token);
    }

    Ok((StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response())
}

pub async fn logout(State(state): State<Arc<WebState>>, req: Request<axum::body::Body>) -> Response {
    if let Some(token) = extract_session_token(&req) {
        {
            let mut sessions = state.sessions.write().await;
            sessions.remove(&token);
            dbx_core::query::pl_debug::pl_debug_revoke_web_owner_core(&state.app, &token);
        }
        // 登出只清除当前登录会话的临时密码，不影响其他会话与桌面端凭据。
        state.app.session_credentials.clear_owner(&token);
    }
    let cookie = format!("dbx_session=; Path={}; HttpOnly; Max-Age=0", session_cookie_path(&state));
    (StatusCode::OK, [("set-cookie", cookie.as_str())], Json(serde_json::json!({"ok": true}))).into_response()
}

pub fn session_token_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix("dbx_session=") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn extract_session_token<B>(req: &Request<B>) -> Option<String> {
    session_token_from_headers(req.headers())
}

pub(crate) fn identity_from_headers(trust: &TrustConfig, headers: &HeaderMap) -> Result<Identity, IdentityError> {
    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    let tenant = header(identity::HEADER_TENANT).ok_or(IdentityError::MissingHeaders)?;
    let role = header(identity::HEADER_ROLE).ok_or(IdentityError::MissingHeaders)?;
    let ts = header(identity::HEADER_TS).ok_or(IdentityError::MissingHeaders)?;
    let sig = header(identity::HEADER_SIG).ok_or(IdentityError::MissingHeaders)?;
    trust.verify_parts(tenant, role, header(identity::HEADER_ACT_AS), ts, sig, identity::now_secs())
}

pub(crate) fn identity_error_response(error: IdentityError) -> Response {
    let status = match &error {
        IdentityError::NotConfigured => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::UNAUTHORIZED,
    };
    (status, error.to_string()).into_response()
}

pub async fn auth_middleware(
    State(state): State<Arc<WebState>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if let Some(trust) = state.trust.clone() {
        // 受信任反代模式：身份完全由签名头决定，口令与会话逻辑整体让位。
        // 这段必须放在下面 `api_suffix` 之前（这里要可变借 req），也必须放在
        // bootstrap 白名单之前——反代是唯一入口，任何路径都不能免签。
        let path = req.uri().path().to_string();
        // 分发器可能已经验过签（见 dispatch.rs），此时直接复用：`verify_parts`
        // 带重放检测，同一组头验两次第二次会被判成 Replayed。
        let identity = match req.extensions().get::<Identity>().cloned() {
            Some(identity) => identity,
            None => match identity_from_headers(&trust, req.headers()) {
                Ok(identity) => identity,
                Err(error) => return identity_error_response(error),
            },
        };
        let suffix = middleware_api_path_suffix(&path, &state.public_base_path);
        if !identity.role.is_admin() && suffix.is_some_and(identity::is_admin_only_path) {
            return (StatusCode::FORBIDDEN, "该模块仅管理员可操作").into_response();
        }
        if identity.is_acting_as() {
            trust.audit_act_as(&identity, &path);
        }
        req.extensions_mut().insert(identity);
        return next.run(req).await;
    }

    // Only the bootstrap auth endpoints are reachable without a session —
    // login/setup/check. change-password and logout require one: change-password
    // must not be an unauthenticated password oracle.
    let api_suffix = middleware_api_path_suffix(req.uri().path(), &state.public_base_path);
    if api_suffix.is_some_and(|suffix| matches!(suffix, "auth/login" | "auth/setup" | "auth/check")) {
        return next.run(req).await;
    }

    // Non-API requests (static files) are always accessible.
    if api_suffix.is_none() {
        return next.run(req).await;
    }

    if state.password_disabled {
        return next.run(req).await;
    }

    if state.password_hash.read().await.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // Check session token
    let token = extract_session_token(&req);
    if let Some(ref token) = token {
        if state.sessions.read().await.contains(token) {
            // 在下游处理器及其 await 到的池创建路径上注入当前登录会话的 owner 作用域，
            // 使 save_password=false 连接的临时密码按会话隔离（见 SessionCredentialStore）。
            let owner = token.clone();
            return dbx_core::session_credentials::with_credential_owner(
                Some(owner),
                async move { next.run(req).await },
            )
            .await;
        }
    }

    StatusCode::UNAUTHORIZED.into_response()
}

#[cfg(test)]
mod tests {
    use super::{api_path_suffix, middleware_api_path_suffix};

    #[test]
    fn api_path_suffix_handles_root_api_paths() {
        assert_eq!(api_path_suffix("/api/auth/check", "/"), Some("auth/check"));
        assert_eq!(api_path_suffix("/api/query/execute", "/"), Some("query/execute"));
        assert_eq!(api_path_suffix("/dbx/api/auth/check", "/"), None);
    }

    #[test]
    fn api_path_suffix_handles_mounted_api_paths() {
        assert_eq!(api_path_suffix("/dbx/api/auth/check", "/dbx"), Some("auth/check"));
        assert_eq!(api_path_suffix("/tools/dbx/api/query/execute", "/tools/dbx"), Some("query/execute"));
        assert_eq!(api_path_suffix("/dbx/login", "/dbx"), None);
    }

    #[test]
    pub(crate) fn middleware_api_path_suffix_handles_nested_router_paths() {
        assert_eq!(middleware_api_path_suffix("/auth/check", "/"), Some("auth/check"));
        assert_eq!(middleware_api_path_suffix("/connection/list", "/"), Some("connection/list"));
        assert_eq!(middleware_api_path_suffix("/api/connection/list", "/"), Some("connection/list"));
        assert_eq!(middleware_api_path_suffix("/dbx/api/connection/list", "/dbx"), Some("connection/list"));
        assert_eq!(middleware_api_path_suffix("/dbx/login", "/dbx"), None);
    }
}
