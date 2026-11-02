use crate::{error::AppError, state::WebState};
use axum::{
    body::Body,
    extract::{Path as AxumPath, State},
    http::header,
    response::Response,
    Json,
};
use dbx_core::scheduled_backup::{BackupCommand, BackupService};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio_util::io::ReaderStream;

/// `DBX_BACKUP_ROOT` 是进程级配置。受信多租户下若所有租户直接共用这个根，
/// 成员可以通过 `import` 引用别人的备份文件再下载。这里按租户目录名再分一层，
/// 让共享存储只共享物理磁盘、不共享可见范围。未配置时保持 `<tenant>/backups`。
pub(crate) fn backup_root(state: &WebState) -> PathBuf {
    scoped_backup_root(std::env::var_os("DBX_BACKUP_ROOT").map(PathBuf::from), &state.data_dir, state.trust.is_some())
}

fn scoped_backup_root(configured: Option<PathBuf>, data_dir: &Path, multi_tenant: bool) -> PathBuf {
    match configured {
        Some(base) if multi_tenant => base.join(tenant_segment(data_dir)),
        Some(base) => base,
        None => data_dir.join("backups"),
    }
}

/// 租户数据目录名形如 `u-<uuid>`；只保留文件名安全字符，避免 env 根下出现
/// 路径分隔符或 `..`。无法取得文件名时用固定段，至少不会退化成共享根。
fn tenant_segment(data_dir: &Path) -> String {
    let raw = data_dir.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    let segment: String = raw
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' { ch } else { '_' })
        .collect();
    if segment.is_empty() {
        "default".to_string()
    } else {
        segment
    }
}

pub fn service(state: &WebState) -> Result<BackupService, String> {
    let root = backup_root(state);
    let root = root.canonicalize().map_err(|e| format!("Cannot resolve the server backup root: {e}"))?;
    Ok(BackupService::new(state.app.clone(), &state.data_dir, Some(root)))
}

#[cfg(test)]
mod tests {
    use super::{scoped_backup_root, tenant_segment};
    use std::path::{Path, PathBuf};

    #[test]
    fn default_backup_root_stays_under_the_tenant() {
        assert_eq!(
            scoped_backup_root(None, Path::new("/data/tenants/u-1"), true),
            PathBuf::from("/data/tenants/u-1/backups")
        );
    }

    #[test]
    fn configured_backup_root_is_scoped_for_multi_tenant() {
        assert_eq!(
            scoped_backup_root(Some(PathBuf::from("/mnt/backups")), Path::new("/data/tenants/u-1"), true),
            PathBuf::from("/mnt/backups/u-1")
        );
    }

    #[test]
    fn configured_backup_root_is_unchanged_for_single_tenant() {
        assert_eq!(
            scoped_backup_root(Some(PathBuf::from("/mnt/backups")), Path::new("/data"), false),
            PathBuf::from("/mnt/backups")
        );
    }

    #[test]
    fn tenant_segment_is_filesystem_safe() {
        assert_eq!(tenant_segment(Path::new("/data/tenants/u-abc_123")), "u-abc_123");
        assert_eq!(tenant_segment(Path::new("/data/tenants/u/a")), "a");
        assert_eq!(tenant_segment(Path::new("/")), "default");
    }
}

pub async fn command(
    State(state): State<Arc<WebState>>,
    Json(command): Json<BackupCommand>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(service(&state)?.command(command).await?))
}

pub async fn download(
    State(state): State<Arc<WebState>>,
    AxumPath((id, index)): AxumPath<(String, usize)>,
) -> Result<Response, AppError> {
    let path = service(&state)?.file(&id, index).await?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let disposition = super::export_download::attachment_content_disposition(&name);
    let file = tokio::fs::File::open(&path).await.map_err(|e| AppError::from(e.to_string()))?;
    Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from_stream(ReaderStream::new(file)))
        .map_err(|e| AppError::from(e.to_string()))
}

pub async fn prepare_restore(
    State(state): State<Arc<WebState>>,
    AxumPath((id, index)): AxumPath<(String, usize)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let source = service(&state)?.file(&id, index).await?;
    Ok(Json(super::sql_file::prepare_backup_preview(&state, source).await?))
}
