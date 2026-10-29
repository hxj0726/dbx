//! 可信代理身份校验（多租户模式）
//!
//! dbx-web 原生只有「单密码 + 单租户」。多租户部署下由 next-tdc 承担登录与
//! 授权，它用一个共享密钥给每个请求签名，dbx-web 验签后把请求派发给对应租户的
//! `AppState`。本模块只做三件事：验签、解出角色/代管目标、拒绝重放。
//!
//! 签名契约（与 next-tdc `lib/tdc/dbx-tenant.js` 逐字对应）：
//! ```text
//! canonical = tenant + "\n" + role + "\n" + actAs + "\n" + ts
//! sig       = base64url_nopad( HMAC-SHA256(DBX_TRUST_KEY, canonical) )
//! ```
//! 测试向量：key = "k"*32, tenant = "u-1", role = "admin", actAs = "u-2",
//! ts = 1700000000 → `5W1dUP29DL5dQn0Q3cwdT92iUfC56sv61TX58BzKwdU`。

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use pbkdf2::hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// 允许的时钟偏移（秒）；next-tdc 与 dbx-web 应指向同一时间源。
pub const MAX_TS_SKEW_SECS: u64 = 60;
/// 防重放窗口内最多记忆的签名数，超出按时间淘汰。
const REPLAY_CAPACITY: usize = 8192;
/// 密钥最小长度，短于该值拒绝启动（避免弱密钥）。
pub const MIN_KEY_LEN: usize = 32;

pub const HEADER_TENANT: &str = "x-dbx-tenant";
pub const HEADER_ROLE: &str = "x-dbx-role";
pub const HEADER_ACT_AS: &str = "x-dbx-act-as";
pub const HEADER_TS: &str = "x-dbx-ts";
pub const HEADER_SIG: &str = "x-dbx-sig";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Member,
}

impl Role {
    fn parse(raw: &str) -> Self {
        // 只认 "admin"，其余一律降级为 member（fail closed）。
        if raw.eq_ignore_ascii_case("admin") {
            Self::Admin
        } else {
            Self::Member
        }
    }

    pub fn is_admin(self) -> bool {
        matches!(self, Self::Admin)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }
}

/// 一次请求解出的身份。
#[derive(Debug, Clone)]
pub struct Identity {
    /// 调用者自己的租户。
    pub tenant: String,
    pub role: Role,
    /// 被代管的租户；仅 admin 可用。
    pub acted_as: Option<String>,
}

impl Identity {
    /// 实际生效的租户：有代管目标时用它。
    pub fn effective_tenant(&self) -> &str {
        self.acted_as.as_deref().unwrap_or(&self.tenant)
    }

    pub fn is_acting_as(&self) -> bool {
        self.acted_as.is_some()
    }
}

#[derive(Debug)]
pub enum IdentityError {
    MissingHeaders,
    BadTenant,
    BadTimestamp,
    Expired,
    Replayed,
    BadSignature,
    ActAsForbidden,
    NotConfigured,
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::MissingHeaders => "缺少 dbx 身份头",
            Self::BadTenant => "租户标识非法",
            Self::BadTimestamp => "时间戳非法",
            Self::Expired => "时间戳超出允许窗口",
            Self::Replayed => "重放的签名",
            Self::BadSignature => "签名校验失败",
            Self::ActAsForbidden => "非管理员不允许代管其它租户",
            Self::NotConfigured => "可信代理模式未配置密钥",
        };
        f.write_str(text)
    }
}

impl std::error::Error for IdentityError {}

/// 可信代理配置（`DBX_TRUST_PROXY=1` + `DBX_TRUST_KEY`）。
pub struct TrustConfig {
    key: Vec<u8>,
    replay: Mutex<VecDeque<(String, u64)>>,
    audit_path: Option<PathBuf>,
}

impl TrustConfig {
    /// 从环境变量读取；未启用返回 `None`，启用但配置错误返回 `Err`。
    pub fn from_env(data_dir: &Path) -> Result<Option<Self>, String> {
        let enabled = std::env::var("DBX_TRUST_PROXY")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        if !enabled {
            return Ok(None);
        }
        let key = std::env::var("DBX_TRUST_KEY").map_err(|_| "DBX_TRUST_PROXY=1 时必须设置 DBX_TRUST_KEY")?;
        if key.len() < MIN_KEY_LEN {
            return Err(format!("DBX_TRUST_KEY 至少需要 {MIN_KEY_LEN} 字节"));
        }
        if std::env::var("DBX_DISABLE_PASSWORD").is_err() && std::env::var("DBX_PASSWORD").is_ok() {
            return Err("可信代理模式与 DBX_PASSWORD 互斥：请只保留一种鉴权方式".to_string());
        }
        Ok(Some(Self {
            key: key.into_bytes(),
            replay: Mutex::new(VecDeque::new()),
            audit_path: Some(data_dir.join("audit").join("tenant-access.log")),
        }))
    }

    /// 计算 canonical 字符串（测试与排障时直接比对）。
    pub fn canonical(tenant: &str, role: Role, act_as: &str, ts: u64) -> String {
        format!("{tenant}\n{}\n{act_as}\n{ts}", role.as_str())
    }

    pub(crate) fn sign(&self, canonical: &str) -> Vec<u8> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("HMAC 接受任意长度密钥");
        mac.update(canonical.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// 仅供单元测试构造：不读环境变量，也不写审计日志。
    ///
    /// 其他模块的测试需要自己签发身份头，而 `key` 是私有的，所以在这里开一个小口子。
    #[cfg(test)]
    pub(crate) fn for_test(key: &[u8]) -> Self {
        Self { key: key.to_vec(), replay: Mutex::new(VecDeque::new()), audit_path: None }
    }

    /// 校验一组头（已抽出，便于单测）。
    pub fn verify_parts(
        &self,
        tenant: &str,
        role: &str,
        act_as: Option<&str>,
        ts: &str,
        sig: &str,
        now: u64,
    ) -> Result<Identity, IdentityError> {
        let tenant = tenant.trim();
        if tenant.is_empty() || tenant.len() > 64 || !tenant.bytes().all(is_tenant_byte) {
            return Err(IdentityError::BadTenant);
        }
        let ts_num: u64 = ts.trim().parse().map_err(|_| IdentityError::BadTimestamp)?;
        if ts_num > now + MAX_TS_SKEW_SECS || now > ts_num + MAX_TS_SKEW_SECS {
            return Err(IdentityError::Expired);
        }

        let role = Role::parse(role);
        let act_as = act_as.map(str::trim).filter(|value| !value.is_empty());
        if let Some(target) = act_as {
            if !role.is_admin() {
                return Err(IdentityError::ActAsForbidden);
            }
            if target.len() > 64 || !target.bytes().all(is_tenant_byte) {
                return Err(IdentityError::BadTenant);
            }
        }

        let canonical = Self::canonical(tenant, role, act_as.unwrap_or(""), ts_num);
        let expected = self.sign(&canonical);
        let provided = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig.trim())
            .map_err(|_| IdentityError::BadSignature)?;
        // `Mac::verify_slice` 为常量时间比较。
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("HMAC 接受任意长度密钥");
        mac.update(canonical.as_bytes());
        mac.verify_slice(&provided).map_err(|_| IdentityError::BadSignature)?;
        debug_assert_eq!(expected.len(), provided.len());

        self.check_replay(tenant, ts_num, now)?;

        Ok(Identity { tenant: tenant.to_string(), role, acted_as: act_as.map(str::to_string) })
    }

    fn check_replay(&self, tenant: &str, ts: u64, now: u64) -> Result<(), IdentityError> {
        let mut seen = self.replay.lock().expect("replay 锁中毒");
        // 淘汰窗口之外的记录，窗口内重复即判重放。
        while let Some((_, stamp)) = seen.front() {
            if *stamp + MAX_TS_SKEW_SECS * 2 < now {
                seen.pop_front();
            } else {
                break;
            }
        }
        if seen.iter().any(|(t, stamp)| t == tenant && *stamp == ts) {
            return Err(IdentityError::Replayed);
        }
        seen.push_back((tenant.to_string(), ts));
        while seen.len() > REPLAY_CAPACITY {
            seen.pop_front();
        }
        Ok(())
    }

    /// 记录一次代管访问（仅 act-as 时写，正常请求不产生 IO）。
    pub fn audit_act_as(&self, identity: &Identity, path: &str) {
        let Some(path_on_disk) = self.audit_path.as_deref() else {
            return;
        };
        if !identity.is_acting_as() {
            return;
        }
        let line = format!(
            "{{\"ts\":{},\"actor\":\"{}\",\"role\":\"{}\",\"target\":\"{}\",\"path\":\"{}\"}}\n",
            now_secs(),
            identity.tenant,
            identity.role.as_str(),
            identity.effective_tenant(),
            path.replace('"', "")
        );
        if let Some(dir) = path_on_disk.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        use std::io::Write as _;
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path_on_disk) {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

/// 租户标识白名单：字母、数字、`-`、`_`，用于直接拼路径，必须挡住 `../`。
fn is_tenant_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// 仅管理员可访问的接口前缀（相对 `/api`，不含 base path）。
pub const ADMIN_ONLY_PREFIXES: &[&str] =
    &["/mcp", "/system", "/tenants", "/plugins/install-url", "/plugins/marketplace/install"];

/// 判断某个 API 路径是否属于全局配置（非管理员 403）。
pub fn is_admin_only_path(path: &str) -> bool {
    ADMIN_ONLY_PREFIXES.iter().any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";

    fn config() -> TrustConfig {
        TrustConfig { key: KEY.as_bytes().to_vec(), replay: Mutex::new(VecDeque::new()), audit_path: None }
    }

    #[test]
    fn canonical_string_matches_next_tdc_contract() {
        assert_eq!(TrustConfig::canonical("u-1", Role::Admin, "u-2", 1_700_000_000), "u-1\nadmin\nu-2\n1700000000");
    }

    #[test]
    fn signature_vector_matches_next_tdc() {
        // 与 lib/tdc/dbx-tenant.js 的 node:crypto 输出逐字一致。
        let sig = "5W1dUP29DL5dQn0Q3cwdT92iUfC56sv61TX58BzKwdU";
        let identity = config()
            .verify_parts("u-1", "admin", Some("u-2"), "1700000000", sig, 1_700_000_000)
            .expect("测试向量应通过");
        assert_eq!(identity.tenant, "u-1");
        assert_eq!(identity.effective_tenant(), "u-2");
        assert!(identity.role.is_admin());
    }

    #[test]
    fn member_cannot_act_as() {
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(config().sign(&TrustConfig::canonical(
            "u-1",
            Role::Member,
            "u-2",
            1_700_000_000,
        )));
        let err = config()
            .verify_parts("u-1", "member", Some("u-2"), "1700000000", &sig, 1_700_000_000)
            .expect_err("member 不得代管");
        assert!(matches!(err, IdentityError::ActAsForbidden));
    }

    #[test]
    fn unknown_role_degrades_to_member() {
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(config().sign(&TrustConfig::canonical(
            "u-1",
            Role::Member,
            "",
            1_700_000_000,
        )));
        let identity = config().verify_parts("u-1", "root", None, "1700000000", &sig, 1_700_000_000).expect("应通过");
        assert_eq!(identity.role, Role::Member);
    }

    #[test]
    fn rejects_expired_timestamp() {
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(config().sign(&TrustConfig::canonical(
            "u-1",
            Role::Member,
            "",
            1_700_000_000,
        )));
        let err = config()
            .verify_parts("u-1", "member", None, "1700000000", &sig, 1_700_000_000 + MAX_TS_SKEW_SECS + 1)
            .expect_err("过期应拒绝");
        assert!(matches!(err, IdentityError::Expired));
    }

    #[test]
    fn rejects_replay() {
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(config().sign(&TrustConfig::canonical(
            "u-1",
            Role::Member,
            "",
            1_700_000_000,
        )));
        let cfg = config();
        cfg.verify_parts("u-1", "member", None, "1700000000", &sig, 1_700_000_000).expect("首次通过");
        let err = cfg.verify_parts("u-1", "member", None, "1700000000", &sig, 1_700_000_000).expect_err("重复应拒绝");
        assert!(matches!(err, IdentityError::Replayed));
    }

    #[test]
    fn rejects_path_traversal_tenant() {
        let err = config()
            .verify_parts("../etc", "member", None, "1700000000", "AAAA", 1_700_000_000)
            .expect_err("穿越应拒绝");
        assert!(matches!(err, IdentityError::BadTenant));
    }

    #[test]
    fn admin_only_paths() {
        assert!(is_admin_only_path("/mcp"));
        assert!(is_admin_only_path("/mcp/tools"));
        assert!(is_admin_only_path("/system/info"));
        assert!(!is_admin_only_path("/mcpfoo"));
        assert!(!is_admin_only_path("/connections"));
    }
}
