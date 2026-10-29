//! 租户注册表：把租户 id 映射到各自的运行时（`TenantRuntime`）。
//!
//! 多租户模式下一个租户 = 一个数据目录 = 一套 `AppState` / `WebState`。
//! 注册表负责三件事：
//!
//! 1. **校验 id**：[`TenantId`] 只接受 `[A-Za-z0-9_-]`，因此天然排除 `.`、
//!    `..`、`/` 这类可以逃出数据根目录的片段。
//! 2. **限量**：同时驻留的租户不超过 `cap`（`DBX_TENANT_CAP`），超限返回
//!    [`Error::Capacity`]，由 HTTP 层映射成 503，而不是把进程 OOM 掉。
//! 3. **空闲回收**：超过 `idle`（`DBX_TENANT_IDLE_SECS`）未使用的租户会被
//!    驱逐并取消其后台服务；有进行中请求（[`TenantEntry::begin`] 的 guard
//!    存在）的租户不会被回收。
//!
//! 负载类型对 `T` 泛型化，测试可以用 `T = ()` 覆盖并发/容量/回收逻辑，
//! 而不必真的打开 SQLite。

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

/// 租户 id 的最大字节长度。
pub const MAX_TENANT_ID_LEN: usize = 64;
/// 同时驻留的租户数上限，可由 `DBX_TENANT_CAP` 覆盖。
pub const DEFAULT_TENANT_CAP: usize = 64;
/// 空闲回收阈值，可由 `DBX_TENANT_IDLE_SECS` 覆盖。
pub const DEFAULT_TENANT_IDLE: Duration = Duration::from_secs(1800);

/// 共享的租户条目句柄。
pub type TenantRef<T> = Arc<TenantEntry<T>>;

/// 校验过的租户 id。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TenantId(String);

impl TenantId {
    /// 只接受 `[A-Za-z0-9_-]`，长度 1..=[`MAX_TENANT_ID_LEN`]。
    pub fn parse(raw: &str) -> Result<Self, Error> {
        if raw.is_empty() || raw.len() > MAX_TENANT_ID_LEN {
            return Err(Error::InvalidId(raw.to_string()));
        }
        let allowed = raw.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        if !allowed {
            return Err(Error::InvalidId(raw.to_string()));
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 该租户的数据目录：`<root>/<id>`。
    pub fn dir_in(&self, root: &Path) -> PathBuf {
        root.join(&self.0)
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// 注册表错误。
#[derive(Debug)]
pub enum Error {
    /// id 为空、超长或含白名单外字符。
    InvalidId(String),
    /// 驻留租户已达上限。
    Capacity { cap: usize },
    /// 租户运行时构建失败（透传底层错误文本）。
    Build(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidId(raw) => write!(f, "invalid tenant id \"{raw}\""),
            Self::Capacity { cap } => write!(f, "tenant capacity reached ({cap} in memory)"),
            Self::Build(error) => write!(f, "failed to build tenant: {error}"),
        }
    }
}

impl std::error::Error for Error {}

/// 一个已装配的租户。
pub struct TenantEntry<T> {
    id: TenantId,
    dir: PathBuf,
    payload: T,
    shutdown: CancellationToken,
    last_used: Mutex<Instant>,
    inflight: AtomicUsize,
}

impl<T> TenantEntry<T> {
    pub fn id(&self) -> &TenantId {
        &self.id
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// 取消即让该租户的后台服务（备份 worker 等）退出。
    pub fn shutdown(&self) -> &CancellationToken {
        &self.shutdown
    }

    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Acquire)
    }

    fn touch(&self) {
        let mut last = self.last_used.lock().unwrap_or_else(|poison| poison.into_inner());
        *last = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        let last = self.last_used.lock().unwrap_or_else(|poison| poison.into_inner());
        last.elapsed()
    }

    /// 标记一次进行中的请求；guard 存活期间该条目不会被空闲回收。
    pub fn begin(self: &Arc<Self>) -> InflightGuard<T> {
        self.inflight.fetch_add(1, Ordering::AcqRel);
        InflightGuard { entry: Arc::clone(self) }
    }
}

/// [`TenantEntry::begin`] 返回的守卫，析构时递减进行中计数。
///
/// 它持有 `Arc`，因此即使条目此刻被 `remove` 从表里摘掉，正在进行的请求
/// 仍能安全地把手上这一轮跑完。
pub struct InflightGuard<T> {
    entry: TenantRef<T>,
}

impl<T> InflightGuard<T> {
    pub fn payload(&self) -> &T {
        self.entry.payload()
    }
}

impl<T> Drop for InflightGuard<T> {
    fn drop(&mut self) {
        self.entry.inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// 租户注册表。
pub struct TenantRegistry<T> {
    root: PathBuf,
    base_path: String,
    cap: usize,
    idle: Duration,
    entries: RwLock<HashMap<String, TenantRef<T>>>,
}

impl<T> TenantRegistry<T> {
    pub fn new(root: PathBuf, base_path: String, cap: usize, idle: Duration) -> Self {
        Self { root, base_path, cap, idle, entries: RwLock::new(HashMap::new()) }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn base_path(&self) -> &str {
        &self.base_path
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    pub fn idle(&self) -> Duration {
        self.idle
    }

    pub fn len(&self) -> usize {
        let entries = self.entries.read().unwrap_or_else(|poison| poison.into_inner());
        entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 命中时刷新最近使用时间。
    pub fn get(&self, id: &TenantId) -> Option<TenantRef<T>> {
        let entries = self.entries.read().unwrap_or_else(|poison| poison.into_inner());
        let entry = entries.get(id.as_str()).map(Arc::clone);
        drop(entries);
        if let Some(hit) = &entry {
            hit.touch();
        }
        entry
    }

    /// 取已有租户，没有则用 `build` 装配一个。
    ///
    /// `build` 在**不持锁**的情况下等待，因此慢速构建不会阻塞其他租户；构建
    /// 完成后会再查一次表，并发首次访问同一个租户时只保留先插入的那份。
    pub async fn get_or_create<F, Fut>(&self, id: &TenantId, build: F) -> Result<TenantRef<T>, Error>
    where
        F: FnOnce(PathBuf, String) -> Fut,
        Fut: Future<Output = Result<T, String>>,
    {
        if let Some(existing) = self.get(id) {
            return Ok(existing);
        }

        if self.len() >= self.cap {
            return Err(Error::Capacity { cap: self.cap });
        }

        let dir = id.dir_in(&self.root);
        let payload = match build(dir.clone(), self.base_path.clone()).await {
            Ok(payload) => payload,
            Err(error) => return Err(Error::Build(error)),
        };

        let mut entries = self.entries.write().unwrap_or_else(|poison| poison.into_inner());
        if let Some(existing) = entries.get(id.as_str()) {
            existing.touch();
            return Ok(Arc::clone(existing));
        }
        let entry = Arc::new(TenantEntry {
            id: id.clone(),
            dir,
            payload,
            shutdown: CancellationToken::new(),
            last_used: Mutex::new(Instant::now()),
            inflight: AtomicUsize::new(0),
        });
        entries.insert(id.as_str().to_string(), Arc::clone(&entry));
        Ok(entry)
    }

    /// 回收空闲租户，返回被驱逐的 id。
    ///
    /// 有进行中请求的条目会被保留：它们手上的 `InflightGuard` 还引用着
    /// `WebState`，此时取消后台服务会让正在执行的查询失败。
    pub fn evict_idle(&self) -> Vec<TenantId> {
        let mut evicted = Vec::new();
        let mut entries = self.entries.write().unwrap_or_else(|poison| poison.into_inner());
        entries.retain(|_, entry| {
            let busy = entry.inflight() > 0;
            if busy || entry.idle_for() < self.idle {
                return true;
            }
            entry.shutdown().cancel();
            evicted.push(entry.id().clone());
            false
        });
        evicted
    }

    /// 立即移除一个租户（用户被删除时调用），并取消其后台服务。
    pub fn remove(&self, id: &TenantId) -> bool {
        let mut entries = self.entries.write().unwrap_or_else(|poison| poison.into_inner());
        match entries.remove(id.as_str()) {
            Some(entry) => {
                entry.shutdown().cancel();
                true
            }
            None => false,
        }
    }
}

/// 解析 `DBX_TENANT_CAP` 取值；空、非数字、0 都回落到默认值。
pub fn cap_from_env_value(value: Option<&str>) -> usize {
    let parsed = value.and_then(|raw| raw.trim().parse::<usize>().ok());
    parsed.filter(|cap| *cap > 0).unwrap_or(DEFAULT_TENANT_CAP)
}

/// 解析 `DBX_TENANT_IDLE_SECS` 取值；空、非数字、0 都回落到默认值。
pub fn idle_from_env_value(value: Option<&str>) -> Duration {
    let parsed = value.and_then(|raw| raw.trim().parse::<u64>().ok());
    match parsed.filter(|secs| *secs > 0) {
        Some(secs) => Duration::from_secs(secs),
        None => DEFAULT_TENANT_IDLE,
    }
}

pub fn cap_from_env() -> usize {
    cap_from_env_value(std::env::var("DBX_TENANT_CAP").ok().as_deref())
}

pub fn idle_from_env() -> Duration {
    idle_from_env_value(std::env::var("DBX_TENANT_IDLE_SECS").ok().as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(raw: &str) -> TenantId {
        TenantId::parse(raw).unwrap()
    }

    fn registry(cap: usize, idle: Duration) -> TenantRegistry<()> {
        TenantRegistry::new(PathBuf::from("/tmp/dbx-tenants"), "/dbx".to_string(), cap, idle)
    }

    async fn unit(_dir: PathBuf, _base: String) -> Result<(), String> {
        Ok(())
    }

    async fn failing(_dir: PathBuf, _base: String) -> Result<(), String> {
        Err("boom".to_string())
    }

    #[test]
    fn tenant_id_rejects_path_fragments_and_oddities() {
        for raw in ["", ".", "..", "a/b", "a\\b", "a b", "租户"] {
            assert!(TenantId::parse(raw).is_err(), "should reject {raw:?}");
        }
    }

    #[test]
    fn tenant_id_accepts_uuid_and_enforces_length() {
        let ok = "2f1c9a4e-7b3d-4f2a-9c1b-8d6e5a4f3b2c";
        assert_eq!(TenantId::parse(ok).unwrap().as_str(), ok);
        assert!(TenantId::parse(&"a".repeat(MAX_TENANT_ID_LEN)).is_ok());
        assert!(TenantId::parse(&"a".repeat(MAX_TENANT_ID_LEN + 1)).is_err());
    }

    #[tokio::test]
    async fn get_or_create_is_idempotent() {
        let reg = registry(DEFAULT_TENANT_CAP, Duration::from_secs(3600));
        let first = reg.get_or_create(&id("t1"), unit).await.unwrap();
        let second = reg.get_or_create(&id("t1"), unit).await.unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(reg.len(), 1);
        assert_eq!(first.dir(), Path::new("/tmp/dbx-tenants/t1"));
    }

    #[tokio::test]
    async fn capacity_is_enforced() {
        let reg = registry(2, Duration::from_secs(3600));
        reg.get_or_create(&id("t1"), unit).await.unwrap();
        reg.get_or_create(&id("t2"), unit).await.unwrap();
        let result = reg.get_or_create(&id("t3"), unit).await;
        assert!(matches!(result, Err(Error::Capacity { cap: 2 })));
    }

    #[tokio::test]
    async fn build_failure_is_reported_and_not_cached() {
        let reg = registry(DEFAULT_TENANT_CAP, Duration::from_secs(3600));
        let result = reg.get_or_create(&id("t1"), failing).await;
        assert!(matches!(result, Err(Error::Build(_))));
        assert_eq!(reg.len(), 0);
    }

    #[tokio::test]
    async fn evict_idle_drops_stale_entries() {
        let reg = registry(DEFAULT_TENANT_CAP, Duration::ZERO);
        reg.get_or_create(&id("t1"), unit).await.unwrap();
        let evicted = reg.evict_idle();
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].as_str(), "t1");
        assert_eq!(reg.len(), 0);
    }

    #[tokio::test]
    async fn evict_idle_keeps_fresh_entries() {
        let reg = registry(DEFAULT_TENANT_CAP, Duration::from_secs(3600));
        reg.get_or_create(&id("t1"), unit).await.unwrap();
        assert!(reg.evict_idle().is_empty());
        assert_eq!(reg.len(), 1);
    }

    #[tokio::test]
    async fn evict_idle_skips_entries_with_inflight_requests() {
        let reg = registry(DEFAULT_TENANT_CAP, Duration::ZERO);
        let entry = reg.get_or_create(&id("t1"), unit).await.unwrap();
        let guard = entry.begin();
        assert!(reg.evict_idle().is_empty());
        assert_eq!(reg.len(), 1);
        drop(guard);
        assert_eq!(reg.evict_idle().len(), 1);
    }

    #[tokio::test]
    async fn remove_cancels_shutdown_and_drops_entry() {
        let reg = registry(DEFAULT_TENANT_CAP, Duration::from_secs(3600));
        let entry = reg.get_or_create(&id("t1"), unit).await.unwrap();
        assert!(!entry.shutdown().is_cancelled());
        assert!(reg.remove(&id("t1")));
        assert!(entry.shutdown().is_cancelled());
        assert_eq!(reg.len(), 0);
        assert!(!reg.remove(&id("t1")));
    }

    #[test]
    fn env_values_are_parsed_defensively() {
        assert_eq!(cap_from_env_value(None), DEFAULT_TENANT_CAP);
        assert_eq!(cap_from_env_value(Some("0")), DEFAULT_TENANT_CAP);
        assert_eq!(cap_from_env_value(Some(" 8 ")), 8);
        assert_eq!(cap_from_env_value(Some("nope")), DEFAULT_TENANT_CAP);
        assert_eq!(idle_from_env_value(None), DEFAULT_TENANT_IDLE);
        assert_eq!(idle_from_env_value(Some("0")), DEFAULT_TENANT_IDLE);
        assert_eq!(idle_from_env_value(Some("60")), Duration::from_secs(60));
    }
}
