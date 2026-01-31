//! Sync scaffolding for wa (asupersync integration)
//!
//! Provides plan-only sync primitives and target inspection utilities.
//! Actual file transfer logic is intentionally deferred to follow-on work.

use crate::config::{Config, SyncDirection, SyncTargetConfig, WorkspaceLayout};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Result type for sync operations.
pub type SyncResult<T> = Result<T, SyncError>;

/// High-level payload categories eligible for sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncCategory {
    Binary,
    Config,
    Snapshots,
}

/// Sync status summary.
#[derive(Debug, Clone, Serialize)]
pub struct SyncStatus {
    pub enabled: bool,
    pub allow_binary: bool,
    pub allow_config: bool,
    pub allow_snapshots: bool,
    pub allow_overwrite: bool,
    pub require_confirmation: bool,
    pub allow_paths: Vec<String>,
    pub deny_paths: Vec<String>,
    pub targets: Vec<SyncTargetStatus>,
    pub warnings: Vec<String>,
}

/// Target summary (effective settings).
#[derive(Debug, Clone, Serialize)]
pub struct SyncTargetStatus {
    pub name: String,
    pub transport: String,
    pub endpoint: String,
    pub root: String,
    pub default_direction: SyncDirection,
    pub allow_binary: bool,
    pub allow_config: bool,
    pub allow_snapshots: bool,
}

/// Plan options for sync operations.
#[derive(Debug, Clone)]
pub struct SyncPlanOptions {
    pub target: Option<String>,
    pub direction: SyncDirection,
    pub dry_run: bool,
    pub apply: bool,
    pub yes: bool,
    pub allow_overwrite: bool,
    pub include: Vec<SyncCategory>,
    pub config_path: Option<PathBuf>,
}

/// Plan for a sync operation.
#[derive(Debug, Clone, Serialize)]
pub struct SyncPlan {
    pub target: SyncTargetStatus,
    pub direction: SyncDirection,
    pub dry_run: bool,
    pub apply: bool,
    pub allow_overwrite: bool,
    pub warnings: Vec<String>,
    pub payloads: Vec<SyncPayload>,
}

/// Planned payload.
#[derive(Debug, Clone, Serialize)]
pub struct SyncPayload {
    pub category: SyncCategory,
    pub source: String,
    pub destination: String,
    pub note: Option<String>,
}

/// Sync plan/build errors.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("sync is disabled; set [sync].enabled = true in wa.toml")]
    Disabled,
    #[error("no sync targets configured")]
    NoTargets,
    #[error("sync target '{name}' not found (available: {available})")]
    UnknownTarget { name: String, available: String },
    #[error("multiple sync targets configured; specify --target (available: {available})")]
    AmbiguousTarget { available: String },
    #[error("confirmation required; re-run with --yes")]
    ConfirmationRequired,
}

fn default_warnings() -> Vec<String> {
    vec![
        "Live SQLite DB files are never synced; export snapshots only.".to_string(),
        "Secrets are always redacted and never synced.".to_string(),
    ]
}

fn effective_allow(global: bool, override_value: Option<bool>) -> bool {
    override_value.unwrap_or(global)
}

fn target_status(config: &Config, target: &SyncTargetConfig) -> SyncTargetStatus {
    SyncTargetStatus {
        name: target.name.clone(),
        transport: target.transport.clone(),
        endpoint: target.endpoint.clone(),
        root: target.root.clone(),
        default_direction: target.default_direction,
        allow_binary: effective_allow(config.sync.allow_binary, target.allow_binary),
        allow_config: effective_allow(config.sync.allow_config, target.allow_config),
        allow_snapshots: effective_allow(config.sync.allow_snapshots, target.allow_snapshots),
    }
}

/// Build sync status information from config.
#[must_use]
pub fn build_sync_status(config: &Config) -> SyncStatus {
    let mut targets: Vec<SyncTargetStatus> = config
        .sync
        .targets
        .iter()
        .map(|target| target_status(config, target))
        .collect();
    targets.sort_by(|a, b| a.name.cmp(&b.name));

    SyncStatus {
        enabled: config.sync.enabled,
        allow_binary: config.sync.allow_binary,
        allow_config: config.sync.allow_config,
        allow_snapshots: config.sync.allow_snapshots,
        allow_overwrite: config.sync.allow_overwrite,
        require_confirmation: config.sync.require_confirmation,
        allow_paths: config.sync.allow_paths.clone(),
        deny_paths: config.sync.deny_paths.clone(),
        targets,
        warnings: default_warnings(),
    }
}

fn select_target<'a>(
    targets: &'a [SyncTargetConfig],
    name: Option<&str>,
) -> Result<&'a SyncTargetConfig, SyncError> {
    if targets.is_empty() {
        return Err(SyncError::NoTargets);
    }

    if let Some(name) = name {
        return targets
            .iter()
            .find(|target| target.name == name)
            .ok_or_else(|| SyncError::UnknownTarget {
                name: name.to_string(),
                available: targets
                    .iter()
                    .map(|target| target.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            });
    }

    if targets.len() == 1 {
        Ok(&targets[0])
    } else {
        Err(SyncError::AmbiguousTarget {
            available: targets
                .iter()
                .map(|target| target.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        })
    }
}

fn include_category(include: &[SyncCategory], category: SyncCategory) -> bool {
    if include.is_empty() {
        return true;
    }
    include.iter().any(|value| *value == category)
}

/// Build a sync plan (plan-only; does not mutate any files).
pub fn build_sync_plan(
    config: &Config,
    layout: &WorkspaceLayout,
    options: SyncPlanOptions,
) -> SyncResult<SyncPlan> {
    if !config.sync.enabled {
        return Err(SyncError::Disabled);
    }

    if options.apply && config.sync.require_confirmation && !options.yes {
        return Err(SyncError::ConfirmationRequired);
    }

    let target = select_target(&config.sync.targets, options.target.as_deref())?;
    let target_info = target_status(config, target);

    let local_paths = LocalSyncPaths::from_config(config, layout, options.config_path.as_deref());
    let mut payloads = Vec::new();
    let mut warnings = default_warnings();

    let allow_overwrite = options.allow_overwrite || config.sync.allow_overwrite;

    let allow_binary =
        target_info.allow_binary && include_category(&options.include, SyncCategory::Binary);
    let allow_config =
        target_info.allow_config && include_category(&options.include, SyncCategory::Config);
    let allow_snapshots =
        target_info.allow_snapshots && include_category(&options.include, SyncCategory::Snapshots);

    if allow_binary {
        payloads.push(build_payload(
            SyncCategory::Binary,
            &local_paths.binary_path,
            &remote_root_for(&target_info, "bin/wa"),
            options.direction,
        ));
    } else if target_info.allow_binary {
        warnings.push("Binary sync excluded by --include filter.".to_string());
    } else {
        warnings.push("Binary sync disabled for this target.".to_string());
    }

    if allow_config {
        payloads.push(build_payload(
            SyncCategory::Config,
            &local_paths.config_root,
            &remote_root_for(&target_info, "config"),
            options.direction,
        ));
    } else if target_info.allow_config {
        warnings.push("Config sync excluded by --include filter.".to_string());
    } else {
        warnings.push("Config sync disabled for this target.".to_string());
    }

    if allow_snapshots {
        payloads.push(build_payload(
            SyncCategory::Snapshots,
            &local_paths.snapshots_root,
            &remote_root_for(&target_info, "snapshots"),
            options.direction,
        ));
    } else if target_info.allow_snapshots {
        warnings.push("Snapshot sync excluded by --include filter.".to_string());
    } else {
        warnings.push("Snapshot sync disabled for this target.".to_string());
    }

    if options.apply {
        warnings.push("Sync apply is not implemented yet; no changes were made.".to_string());
    }

    Ok(SyncPlan {
        target: target_info,
        direction: options.direction,
        dry_run: options.dry_run,
        apply: options.apply,
        allow_overwrite,
        warnings,
        payloads,
    })
}

fn build_payload(
    category: SyncCategory,
    local_path: &Path,
    remote_path: &Path,
    direction: SyncDirection,
) -> SyncPayload {
    let (source, destination) = match direction {
        SyncDirection::Push => (local_path, remote_path),
        SyncDirection::Pull => (remote_path, local_path),
    };

    SyncPayload {
        category,
        source: path_to_string(source),
        destination: path_to_string(destination),
        note: Some("plan-only scaffolding (no file transfers)".to_string()),
    }
}

fn remote_root_for(target: &SyncTargetStatus, suffix: &str) -> PathBuf {
    let base = PathBuf::from(&target.root);
    if suffix.is_empty() {
        base
    } else {
        base.join(suffix)
    }
}

struct LocalSyncPaths {
    binary_path: PathBuf,
    config_root: PathBuf,
    snapshots_root: PathBuf,
}

impl LocalSyncPaths {
    fn from_config(config: &Config, layout: &WorkspaceLayout, config_path: Option<&Path>) -> Self {
        let binary_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("wa"));
        let config_root = config_path
            .and_then(|path| path.parent().map(PathBuf::from))
            .unwrap_or_else(default_config_root);
        let snapshots_root = crate::backup::backup_destination_root(
            &layout.root,
            config.backup.scheduled.destination.as_deref(),
        );

        Self {
            binary_path,
            config_root,
            snapshots_root,
        }
    }
}

fn default_config_root() -> PathBuf {
    if let Some(dir) = dirs::config_dir() {
        dir.join("wa")
    } else if let Some(home) = dirs::home_dir() {
        home.join(".config").join("wa")
    } else {
        PathBuf::from(".config/wa")
    }
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_sync_status_sorts_targets() {
        let mut config = Config::default();
        config.sync.enabled = true;
        config.sync.targets = vec![
            SyncTargetConfig {
                name: "zeta".to_string(),
                endpoint: "zeta".to_string(),
                root: "/tmp/zeta".to_string(),
                ..SyncTargetConfig::default()
            },
            SyncTargetConfig {
                name: "alpha".to_string(),
                endpoint: "alpha".to_string(),
                root: "/tmp/alpha".to_string(),
                ..SyncTargetConfig::default()
            },
        ];

        let status = build_sync_status(&config);
        assert_eq!(status.targets[0].name, "alpha");
        assert_eq!(status.targets[1].name, "zeta");
    }
}
