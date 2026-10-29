//! 租户运行时装配：把一个数据目录变成一个可服务的 [`WebState`]。
//!
//! 这里刻意只包含"租户级"状态。进程级的一次性初始化（tracing 订阅器、rustls
//! crypto provider、SSH 提示网关）不在这里：前两者重复初始化会直接 panic，后者
//! 是全局单例，在多租户下只能装一次再由调度层分发。调用方（当前是 `serve()`，
//! 将来是 `tenant` 注册表）负责在正确的作用域里完成那些动作。
//!
//! 单租户模式下 [`build_tenant`] 只被调用一次，行为与抽取前完全一致；多租户模式
//! 下每个租户数据目录调用一次，租户之间不共享 `AppState`、连接池、`secrets.key`
//! 与插件目录。

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use dbx_core::connection::AppState;
use dbx_core::persistence::secret_codec::SecretKeyPolicy;
use dbx_core::sql_dialect::dialect_loader::{register_core_dialects, DialectPluginLoader, DialectRegistry};
use dbx_core::sql_dialect::hot_reload::DialectHotReload;
use dbx_core::storage::Storage;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::demo;
use crate::password_viewer_enabled_from_env;
use crate::routes;
use crate::ssh_prompt::SshPromptHub;
use crate::state::{LoginRateLimit, WebState};
use crate::storage_migration_ready;
use crate::web_agent_dir;
use crate::web_mcp::WebMcpRuntime;
use crate::web_mcp_startup_error;

/// 单个租户的运行时句柄。
pub struct TenantRuntime {
    pub state: Arc<WebState>,
    /// 取消后备份 worker 停止调度；关闭流程应先 `cancel()` 再等 `backup_worker`。
    pub backup_stop: CancellationToken,
    /// 备份 worker 的句柄。必须由调用方持有并等待：直接丢弃会 detach 任务，
    /// 让"worker 未排空"这件事再也无法影响进程退出码。
    pub backup_worker: JoinHandle<()>,
}

/// 按数据目录装配一个租户的完整运行时。
///
/// `public_base_path` 必须是已归一化的形式（见 `normalize_public_base_path`）；
/// 调用方保留原始值以便静态资源挂载复用，这里存进 [`WebState`] 供鉴权与路由
/// 中间件按前缀剥离路径。
pub async fn build_tenant(data_dir: PathBuf, public_base_path: String) -> Result<TenantRuntime, String> {
    if let Err(error) = std::fs::create_dir_all(&data_dir) {
        return Err(format!("Failed to create data directory {}: {error}", data_dir.display()));
    }

    let app_state = {
        let db_path = data_dir.join("dbx.db");
        let storage = match Storage::open_unmigrated(&db_path).await {
            Ok(storage) => storage.with_secret_key_policy(SecretKeyPolicy::ManagedDataDir),
            Err(error) => return Err(format!("Failed to open storage {}: {error}", db_path.display())),
        };

        // Initialize core dialect registry and load external plugin dialects
        register_core_dialects();
        let registry = DialectRegistry::global();
        let plugin_dirs = vec![data_dir.join("plugins").join("dialects")];
        let load_result = DialectPluginLoader::scan_and_load(registry, &plugin_dirs);
        log::info!(
            "Dialect plugins loaded: {} success, {} errors, {} skipped",
            load_result.loaded.len(),
            load_result.errors.len(),
            load_result.skipped.len()
        );

        // Start dialect YAML hot-reload watcher
        let watch_dirs = plugin_dirs.clone();
        tokio::spawn(async move {
            if let Err(e) = DialectHotReload::run_forever(watch_dirs, DialectRegistry::global()).await {
                log::error!("Dialect hot-reload watcher exited: {e}");
            }
        });
        log::info!("Dialect hot-reload watcher started");

        Arc::new(AppState::new_with_plugin_and_agent_dir_and_app_version(
            storage,
            data_dir.join("plugins"),
            web_agent_dir(&data_dir),
            env!("CARGO_PKG_VERSION"),
        ))
    };

    app_state.set_honor_fixed_ssh_local_ports(true);

    // Password hash: env var takes priority, then database
    let password_disabled = std::env::var("DBX_DISABLE_PASSWORD")
        .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    let password_viewer_enabled =
        password_viewer_enabled_from_env(std::env::var("DBX_DISABLE_PASSWORD_VIEWER").ok().as_deref());

    let password_hash = if password_disabled {
        None
    } else if let Ok(pw) = std::env::var("DBX_PASSWORD") {
        let salt = SaltString::generate(&mut OsRng);
        match Argon2::default().hash_password(pw.as_bytes(), &salt) {
            Ok(hash) => Some(hash.to_string()),
            Err(error) => return Err(format!("Failed to hash DBX_PASSWORD: {error}")),
        }
    } else {
        app_state.storage.load_password_hash().await.unwrap_or(None)
    };

    let demo_mode = demo::demo_mode_from_env();

    let migration_ready = storage_migration_ready(&app_state).await;
    let web_mcp = Arc::new(if migration_ready {
        let allow_managed = !password_disabled && password_hash.is_some();
        match WebMcpRuntime::load(&app_state.storage, allow_managed).await {
            Ok(runtime) => runtime,
            Err(error) => return Err(web_mcp_startup_error(error)),
        }
    } else {
        WebMcpRuntime::disabled()
    });

    // 受信任反代模式（next-tdc 注入签名头）在这里一次性判定：配置非法时启动
    // 直接失败，而不是等到第一个请求才暴露。
    let trust = match crate::identity::TrustConfig::from_env(&data_dir) {
        Ok(trust) => trust.map(Arc::new),
        Err(error) => return Err(format!("invalid trust proxy configuration: {error}")),
    };

    let web_state = Arc::new(WebState {
        app: app_state,
        data_dir,
        notes_roots: routes::docs::notes_roots_from_env(std::env::var_os("DBX_DOCS_NOTES_ROOTS").as_deref()),
        public_base_path,
        demo_mode,
        password_disabled,
        password_viewer_enabled,
        password_hash: RwLock::new(password_hash),
        sessions: RwLock::new(HashSet::new()),
        sse_channels: RwLock::new(HashMap::new()),
        transfer_progress_channels: RwLock::new(HashMap::new()),
        table_import_channels: RwLock::new(HashMap::new()),
        sql_file_executions: RwLock::new(HashMap::new()),
        sql_file_failure_logs: Default::default(),
        managed_sql_previews: Default::default(),
        nacos_imports: RwLock::new(HashMap::new()),
        login_rate_limit: tokio::sync::Mutex::new(LoginRateLimit { fail_count: 0, locked_until: None }),
        export_files: RwLock::new(HashMap::new()),
        ssh_prompts: Arc::new(SshPromptHub::new()),
        migration_ready: Arc::new(std::sync::atomic::AtomicBool::new(migration_ready)),
        trust,
        web_mcp,
    });

    routes::sql_file::start_sql_file_cleanup(&web_state);
    routes::connection::start_connection_idle_sweeper(&web_state);

    // `DBX_BACKUP_ROOT` 未设置时回落到 `<data_dir>/backups`。这里必须在
    // `service()` 之前把目录建出来：`service()` 会对同一个路径做
    // `canonicalize()`，目录不存在时直接失败，而不是等到上传时才暴露。
    let backup_root =
        std::env::var_os("DBX_BACKUP_ROOT").map(PathBuf::from).unwrap_or_else(|| web_state.data_dir.join("backups"));
    if let Err(error) = std::fs::create_dir_all(&backup_root) {
        return Err(format!("Failed to create server backup root {}: {error}", backup_root.display()));
    }
    let backup_service = match routes::scheduled_backup::service(&web_state) {
        Ok(service) => service,
        Err(error) => return Err(format!("Failed to resolve server backup root: {error}")),
    };
    let backup_stop = CancellationToken::new();
    let backup_worker = backup_service.start(backup_stop.clone());

    Ok(TenantRuntime { state: web_state, backup_stop, backup_worker })
}
