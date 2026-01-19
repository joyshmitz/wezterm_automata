//! Configuration management for wa
//!
//! Handles loading and validation of wa.toml configuration files.
//!
//! # Schema Overview
//!
//! The configuration is structured into sections:
//! - `general`: Log level, workspace/data directory
//! - `ingest`: Poll interval, concurrency, gap detection
//! - `storage`: DB path, retention, flush intervals
//! - `patterns`: Enabled packs, per-pack overrides
//! - `workflows`: Enable/disable, allowlist/denylist, concurrency
//! - `safety`: Capability gates, rate limits, approval, redaction, reservations
//! - `metrics`: Enable, bind address
//!
//! # Forward Compatibility
//!
//! All sections use `#[serde(default)]` to allow missing fields.
//! Unknown fields are ignored to support forward compatibility.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Main Config
// =============================================================================

/// Main configuration structure for wa
///
/// This struct represents the complete wa.toml configuration file.
/// All sections are optional with sensible defaults.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    /// General settings (log level, data directory)
    pub general: GeneralConfig,

    /// Ingest settings (polling, gap detection)
    pub ingest: IngestConfig,

    /// Storage settings (database, retention)
    pub storage: StorageConfig,

    /// Pattern detection settings
    pub patterns: PatternsConfig,

    /// Workflow execution settings
    pub workflows: WorkflowsConfig,

    /// Safety and policy settings
    pub safety: SafetyConfig,

    /// Metrics/telemetry settings
    pub metrics: MetricsConfig,
}

// =============================================================================
// General Config
// =============================================================================

/// General configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// Log level: trace, debug, info, warn, error
    pub log_level: String,

    /// Data directory path (supports ~ expansion)
    /// Default: ~/.local/share/wa (Linux) or ~/Library/Application Support/wa (macOS)
    pub data_dir: String,

    /// Workspace identifier (optional, for multi-workspace setups)
    pub workspace: Option<String>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            data_dir: default_data_dir(),
            workspace: None,
        }
    }
}

fn default_data_dir() -> String {
    // XDG on Linux, ~/Library/Application Support on macOS
    #[cfg(target_os = "macos")]
    {
        "~/Library/Application Support/wa".to_string()
    }
    #[cfg(not(target_os = "macos"))]
    {
        "~/.local/share/wa".to_string()
    }
}

// =============================================================================
// Ingest Config
// =============================================================================

/// Ingest pipeline configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IngestConfig {
    /// Base poll interval in milliseconds
    /// Used when panes are idle; adaptive polling may reduce this when active
    pub poll_interval_ms: u64,

    /// Minimum poll interval when active (adaptive polling lower bound)
    pub min_poll_interval_ms: u64,

    /// Maximum concurrent pane captures
    pub max_concurrent_captures: u32,

    /// Backpressure threshold: pause ingest if storage queue exceeds this
    pub backpressure_threshold: u32,

    /// Enable gap detection (explicit discontinuity tracking)
    pub gap_detection: bool,

    /// Gap detection threshold: if captured text changes by more than this
    /// percentage without overlap, record a gap
    pub gap_detection_threshold_percent: u32,

    /// Maximum segment size in bytes before forced split
    pub max_segment_bytes: u32,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 200,
            min_poll_interval_ms: 50,
            max_concurrent_captures: 10,
            backpressure_threshold: 1000,
            gap_detection: true,
            gap_detection_threshold_percent: 50,
            max_segment_bytes: 65536, // 64KB
        }
    }
}

// =============================================================================
// Storage Config
// =============================================================================

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Database file path (relative to data_dir if not absolute)
    pub db_path: String,

    /// Retention period in days (0 = no retention, keep forever)
    pub retention_days: u32,

    /// Size-based retention in megabytes (0 = no size limit)
    pub retention_max_mb: u32,

    /// Checkpoint/flush interval in seconds
    pub checkpoint_interval_secs: u32,

    /// Writer queue size (bounded for backpressure)
    pub writer_queue_size: u32,

    /// Read pool size (concurrent read connections)
    pub read_pool_size: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: "wa.db".to_string(),
            retention_days: 30,
            retention_max_mb: 0, // No size limit by default
            checkpoint_interval_secs: 60,
            writer_queue_size: 10000,
            read_pool_size: 4,
        }
    }
}

// =============================================================================
// Patterns Config
// =============================================================================

/// Pattern detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PatternsConfig {
    /// Enabled pattern packs (order matters for overrides)
    /// Format: "builtin:<name>" or "file:<path>"
    pub packs: Vec<String>,

    /// Per-pack configuration overrides
    /// Key: pack name, Value: pack-specific settings
    pub pack_overrides: HashMap<String, PackOverride>,

    /// Enable quick-reject optimization (memchr-based pre-filtering)
    pub quick_reject_enabled: bool,
}

impl Default for PatternsConfig {
    fn default() -> Self {
        Self {
            packs: vec![
                "builtin:core".to_string(),
                "builtin:codex".to_string(),
                "builtin:claude_code".to_string(),
                "builtin:gemini".to_string(),
            ],
            pack_overrides: HashMap::new(),
            quick_reject_enabled: true,
        }
    }
}

/// Per-pack configuration override
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PackOverride {
    /// Disable specific rules by ID
    pub disabled_rules: Vec<String>,

    /// Override severity for specific rules
    pub severity_overrides: HashMap<String, String>,

    /// Additional pack-specific settings (extensible)
    pub extra: HashMap<String, toml::Value>,
}

// =============================================================================
// Workflows Config
// =============================================================================

/// Workflow execution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkflowsConfig {
    /// Enabled workflows (by name)
    pub enabled: Vec<String>,

    /// Workflows that can auto-run on event detection
    pub auto_run_allowlist: Vec<String>,

    /// Workflows that are blocked from auto-running
    pub auto_run_denylist: Vec<String>,

    /// Maximum concurrent workflow executions
    pub max_concurrent: u32,

    /// Default step timeout in milliseconds
    pub default_step_timeout_ms: u64,

    /// Enable step-level audit logging
    pub audit_steps: bool,
}

impl Default for WorkflowsConfig {
    fn default() -> Self {
        Self {
            enabled: vec![
                "handle_compaction".to_string(),
                "handle_usage_limits".to_string(),
            ],
            auto_run_allowlist: vec!["handle_compaction".to_string()],
            auto_run_denylist: Vec::new(),
            max_concurrent: 3,
            default_step_timeout_ms: 30_000, // 30 seconds
            audit_steps: true,
        }
    }
}

// =============================================================================
// Safety Config
// =============================================================================

/// Safety and policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SafetyConfig {
    /// Rate limit: maximum sends per pane per minute
    pub rate_limit_per_pane: u32,

    /// Rate limit: maximum total sends per minute
    pub rate_limit_global: u32,

    /// Require prompt to be detected before allowing send
    pub require_prompt_active: bool,

    /// Block sends to alt-screen applications (vim, less, etc.)
    pub block_alt_screen: bool,

    /// Capability gating rules
    pub capabilities: CapabilityConfig,

    /// Approval (allow-once) settings
    pub approval: ApprovalConfig,

    /// Redaction settings for sensitive data
    pub redaction: RedactionConfig,

    /// Pane reservation defaults
    pub reservations: ReservationConfig,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            rate_limit_per_pane: 30,
            rate_limit_global: 100,
            require_prompt_active: true,
            block_alt_screen: true,
            capabilities: CapabilityConfig::default(),
            approval: ApprovalConfig::default(),
            redaction: RedactionConfig::default(),
            reservations: ReservationConfig::default(),
        }
    }
}

/// Capability gating configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)] // These are independent capability flags
pub struct CapabilityConfig {
    /// Allow sending control characters (Ctrl-C, Ctrl-D, etc.)
    pub allow_control_chars: bool,

    /// Allow sending to panes without detected agent
    pub allow_non_agent_panes: bool,

    /// Allow sending arbitrary text (vs. only workflow-generated)
    pub allow_arbitrary_text: bool,

    /// Require explicit confirmation for dangerous patterns
    pub confirm_dangerous_patterns: bool,
}

impl Default for CapabilityConfig {
    fn default() -> Self {
        Self {
            allow_control_chars: true,
            allow_non_agent_panes: false,
            allow_arbitrary_text: true,
            confirm_dangerous_patterns: true,
        }
    }
}

/// Approval (allow-once) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApprovalConfig {
    /// Token expiry time in seconds
    pub token_expiry_secs: u64,

    /// Maximum active approval tokens
    pub max_active_tokens: u32,

    /// Require re-approval after workflow failure
    pub require_reapproval_on_failure: bool,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            token_expiry_secs: 86400, // 24 hours
            max_active_tokens: 100,
            require_reapproval_on_failure: true,
        }
    }
}

/// Redaction configuration for sensitive data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RedactionConfig {
    /// Enable automatic redaction of detected secrets
    pub enabled: bool,

    /// Patterns to redact (regex)
    pub patterns: Vec<String>,

    /// Placeholder text for redacted content
    pub placeholder: String,

    /// Redact in audit logs
    pub redact_audit: bool,

    /// Redact in stored segments
    pub redact_segments: bool,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            patterns: vec![
                // API keys (common formats)
                r#"(?i)(api[_-]?key|apikey)[=:]\s*['\"]?[\w-]{20,}"#.to_string(),
                // Bearer tokens
                r"(?i)bearer\s+[\w-]{20,}".to_string(),
                // AWS credentials
                r#"(?i)(aws[_-]?secret|aws[_-]?access)[=:]\s*['\"]?[\w/+=]{20,}"#.to_string(),
            ],
            placeholder: "[REDACTED]".to_string(),
            redact_audit: true,
            redact_segments: false, // Only redact in audit by default
        }
    }
}

/// Pane reservation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReservationConfig {
    /// Default reservation TTL in seconds
    pub default_ttl_secs: u64,

    /// Maximum reservation TTL in seconds
    pub max_ttl_secs: u64,

    /// Conflict behavior: "deny", "queue", "force" (with warning)
    pub conflict_behavior: String,

    /// Auto-release on workflow completion
    pub auto_release_on_complete: bool,
}

impl Default for ReservationConfig {
    fn default() -> Self {
        Self {
            default_ttl_secs: 300,   // 5 minutes
            max_ttl_secs: 3600,      // 1 hour
            conflict_behavior: "deny".to_string(),
            auto_release_on_complete: true,
        }
    }
}

// =============================================================================
// Metrics Config
// =============================================================================

/// Metrics/telemetry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// Enable metrics endpoint
    pub enabled: bool,

    /// Bind address for metrics server (e.g., "127.0.0.1:9090")
    pub bind: String,

    /// Metrics prefix for all exported metrics
    pub prefix: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:9090".to_string(),
            prefix: "wa".to_string(),
        }
    }
}

// =============================================================================
// Config Loading
// =============================================================================

impl Config {
    /// Load configuration from default locations
    ///
    /// Search order:
    /// 1. ./wa.toml (current directory)
    /// 2. $XDG_CONFIG_HOME/wa/wa.toml or ~/.config/wa/wa.toml
    /// 3. Default values
    pub fn load() -> crate::Result<Self> {
        // Check current directory first
        let cwd_config = std::path::Path::new("wa.toml");
        if cwd_config.exists() {
            return Self::load_from(cwd_config);
        }

        // Check XDG config directory
        let config_dir = dirs_config_path();
        if let Some(ref dir) = config_dir {
            let config_path = dir.join("wa.toml");
            if config_path.exists() {
                return Self::load_from(&config_path);
            }
        }

        // Return defaults
        Ok(Self::default())
    }

    /// Load configuration from a specific path
    pub fn load_from(path: &std::path::Path) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::error::ConfigError::ReadFailed(path.display().to_string(), e.to_string()))?;

        Self::from_toml(&content)
    }

    /// Parse configuration from TOML string
    pub fn from_toml(content: &str) -> crate::Result<Self> {
        toml::from_str(content)
            .map_err(|e| crate::error::ConfigError::ParseFailed(e.to_string()).into())
    }

    /// Serialize configuration to TOML string
    pub fn to_toml(&self) -> crate::Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| crate::error::ConfigError::SerializeFailed(e.to_string()).into())
    }

    /// Get the effective data directory (with ~ expansion)
    #[must_use]
    pub fn effective_data_dir(&self) -> std::path::PathBuf {
        expand_tilde(&self.general.data_dir)
    }

    /// Get the effective database path
    #[must_use]
    pub fn effective_db_path(&self) -> std::path::PathBuf {
        let db_path = std::path::Path::new(&self.storage.db_path);
        if db_path.is_absolute() {
            db_path.to_path_buf()
        } else {
            self.effective_data_dir().join(db_path)
        }
    }
}

/// Get the config directory path (XDG on Linux, Library on macOS)
fn dirs_config_path() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().map(|h| h.join("Library").join("Application Support").join("wa"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::env::var("XDG_CONFIG_HOME")
            .ok()
            .map(std::path::PathBuf::from)
            .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
            .map(|p| p.join("wa"))
    }
}

/// Expand ~ to home directory
fn expand_tilde(path: &str) -> std::path::PathBuf {
    if let Some(suffix) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(suffix);
        }
    }
    std::path::PathBuf::from(path)
}

// Provide a fallback for dirs crate
mod dirs {
    pub fn home_dir() -> Option<std::path::PathBuf> {
        std::env::var("HOME")
            .ok()
            .map(std::path::PathBuf::from)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = Config::default();
        assert_eq!(config.general.log_level, "info");
        assert_eq!(config.ingest.poll_interval_ms, 200);
        assert!(config.safety.require_prompt_active);
        assert_eq!(config.workflows.max_concurrent, 3);
        assert!(!config.metrics.enabled);
    }

    #[test]
    fn default_config_serializes_to_toml() {
        let config = Config::default();
        let toml = config.to_toml().expect("Failed to serialize");
        assert!(toml.contains("[general]"));
        assert!(toml.contains("[ingest]"));
        assert!(toml.contains("[storage]"));
        assert!(toml.contains("[patterns]"));
        assert!(toml.contains("[workflows]"));
        assert!(toml.contains("[safety]"));
        assert!(toml.contains("[metrics]"));
    }

    #[test]
    fn default_config_roundtrips() {
        let config = Config::default();
        let toml = config.to_toml().expect("Failed to serialize");
        let parsed = Config::from_toml(&toml).expect("Failed to parse");

        assert_eq!(config.general.log_level, parsed.general.log_level);
        assert_eq!(config.ingest.poll_interval_ms, parsed.ingest.poll_interval_ms);
        assert_eq!(config.storage.retention_days, parsed.storage.retention_days);
        assert_eq!(config.workflows.max_concurrent, parsed.workflows.max_concurrent);
        assert_eq!(config.safety.rate_limit_per_pane, parsed.safety.rate_limit_per_pane);
        assert_eq!(config.metrics.enabled, parsed.metrics.enabled);
    }

    #[test]
    fn empty_toml_uses_defaults() {
        let config = Config::from_toml("").expect("Failed to parse empty TOML");
        assert_eq!(config.general.log_level, "info");
        assert_eq!(config.ingest.poll_interval_ms, 200);
    }

    #[test]
    fn partial_toml_uses_defaults_for_missing() {
        let toml = r#"
[general]
log_level = "debug"

[storage]
retention_days = 7
"#;
        let config = Config::from_toml(toml).expect("Failed to parse");

        // Specified values
        assert_eq!(config.general.log_level, "debug");
        assert_eq!(config.storage.retention_days, 7);

        // Defaults for unspecified
        assert_eq!(config.ingest.poll_interval_ms, 200);
        assert_eq!(config.workflows.max_concurrent, 3);
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let toml = r#"
[general]
log_level = "info"
some_future_field = "value"

[unknown_section]
key = "value"
"#;
        // This should not error - unknown fields are silently ignored
        let result = Config::from_toml(toml);
        assert!(result.is_ok());
    }

    #[test]
    fn pack_overrides_work() {
        let toml = r#"
[patterns]
packs = ["builtin:core", "builtin:codex"]

[patterns.pack_overrides.codex]
disabled_rules = ["codex.usage_warning"]
"#;
        let config = Config::from_toml(toml).expect("Failed to parse");

        assert_eq!(config.patterns.packs.len(), 2);
        let codex_override = config.patterns.pack_overrides.get("codex");
        assert!(codex_override.is_some());
        assert_eq!(codex_override.unwrap().disabled_rules, vec!["codex.usage_warning"]);
    }

    #[test]
    fn effective_paths_expand_tilde() {
        let config = Config::default();
        let data_dir = config.effective_data_dir();

        // Should not contain ~
        assert!(!data_dir.to_string_lossy().contains('~'));

        // Should be absolute if HOME is set
        if std::env::var("HOME").is_ok() {
            assert!(data_dir.is_absolute());
        }
    }

    #[test]
    fn effective_db_path_joins_correctly() {
        let mut config = Config::default();
        config.storage.db_path = "test.db".to_string();

        let db_path = config.effective_db_path();
        assert!(db_path.to_string_lossy().ends_with("test.db"));
        assert!(db_path.to_string_lossy().contains("wa"));
    }

    #[test]
    fn absolute_db_path_not_joined() {
        let mut config = Config::default();
        config.storage.db_path = "/custom/path/wa.db".to_string();

        let db_path = config.effective_db_path();
        assert_eq!(db_path.to_string_lossy(), "/custom/path/wa.db");
    }

    #[test]
    fn redaction_patterns_are_valid_regex() {
        let config = Config::default();
        for pattern in &config.safety.redaction.patterns {
            assert!(
                fancy_regex::Regex::new(pattern).is_ok(),
                "Invalid regex pattern: {pattern}"
            );
        }
    }

    #[test]
    fn safety_defaults_are_conservative() {
        let config = Config::default();

        // Should require prompt by default
        assert!(config.safety.require_prompt_active);

        // Should block alt-screen by default
        assert!(config.safety.block_alt_screen);

        // Should not allow non-agent panes by default
        assert!(!config.safety.capabilities.allow_non_agent_panes);

        // Should require confirmation for dangerous patterns
        assert!(config.safety.capabilities.confirm_dangerous_patterns);

        // Redaction should be enabled
        assert!(config.safety.redaction.enabled);
    }
}
