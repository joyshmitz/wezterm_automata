//! MCP server integration for wa (feature-gated).
//!
//! This module provides a thin MCP surface that mirrors robot-mode semantics.

use std::time::Instant;

use fastmcp::ToolHandler;
use fastmcp::prelude::*;
use serde::{Deserialize, Serialize};

use crate::Result;
use crate::config::{Config, PaneFilterConfig};
use crate::error::{Error, WeztermError};
use crate::wezterm::{PaneInfo, WeztermClient};

const MCP_VERSION: &str = "v1";

const MCP_ERR_INVALID_ARGS: &str = "WA-MCP-0001";
const MCP_ERR_CONFIG: &str = "WA-MCP-0003";
const MCP_ERR_WEZTERM: &str = "WA-MCP-0004";
const MCP_ERR_STORAGE: &str = "WA-MCP-0005";
const MCP_ERR_POLICY: &str = "WA-MCP-0006";
const MCP_ERR_PANE_NOT_FOUND: &str = "WA-MCP-0007";
const MCP_ERR_WORKFLOW: &str = "WA-MCP-0008";
const MCP_ERR_TIMEOUT: &str = "WA-MCP-0009";
const MCP_ERR_NOT_IMPLEMENTED: &str = "WA-MCP-0010";

#[derive(Debug, Default, Deserialize)]
struct StateParams {
    domain: Option<String>,
    agent: Option<String>,
    pane_id: Option<u64>,
}

#[derive(Debug, Serialize)]
struct McpEnvelope<T> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
    elapsed_ms: u64,
    version: String,
    now: u64,
    mcp_version: &'static str,
}

impl<T> McpEnvelope<T> {
    fn success(data: T, elapsed_ms: u64) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
            error_code: None,
            hint: None,
            elapsed_ms,
            version: crate::VERSION.to_string(),
            now: now_ms(),
            mcp_version: MCP_VERSION,
        }
    }

    fn error(code: &str, msg: impl Into<String>, hint: Option<String>, elapsed_ms: u64) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(msg.into()),
            error_code: Some(code.to_string()),
            hint,
            elapsed_ms,
            version: crate::VERSION.to_string(),
            now: now_ms(),
            mcp_version: MCP_VERSION,
        }
    }
}

#[derive(Debug, Serialize)]
struct McpPaneState {
    pane_id: u64,
    pane_uuid: Option<String>,
    tab_id: u64,
    window_id: u64,
    domain: String,
    title: Option<String>,
    cwd: Option<String>,
    observed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ignore_reason: Option<String>,
}

impl McpPaneState {
    fn from_pane_info(info: &PaneInfo, filter: &PaneFilterConfig) -> Self {
        let domain = info.inferred_domain();
        let title = info.title.clone().unwrap_or_default();
        let cwd = info.cwd.clone().unwrap_or_default();

        let ignore_reason = filter.check_pane(&domain, &title, &cwd);

        Self {
            pane_id: info.pane_id,
            pane_uuid: None,
            tab_id: info.tab_id,
            window_id: info.window_id,
            domain,
            title: info.title.clone(),
            cwd: info.cwd.clone(),
            observed: ignore_reason.is_none(),
            ignore_reason,
        }
    }
}

/// Build the MCP server with minimal tools/resources.
pub fn build_server(config: &Config) -> Result<Server> {
    let filter = config.ingest.panes.clone();
    let server = Server::new("wezterm-automata", crate::VERSION)
        .instructions("wa MCP server (robot parity). See docs/mcp-api-spec.md.")
        .on_startup(|| -> std::result::Result<(), std::io::Error> {
            tracing::info!("MCP server starting");
            Ok(())
        })
        .on_shutdown(|| {
            tracing::info!("MCP server shutting down");
        })
        .tool(WaStateTool::new(filter))
        .build();

    Ok(server)
}

struct WaStateTool {
    filter: PaneFilterConfig,
}

impl WaStateTool {
    fn new(filter: PaneFilterConfig) -> Self {
        Self { filter }
    }
}

impl ToolHandler for WaStateTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "wa.state".to_string(),
            description: Some("Get current pane states (robot parity)".to_string()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string" },
                    "agent": { "type": "string" },
                    "pane_id": { "type": "integer", "minimum": 0 }
                },
                "additionalProperties": false
            }),
            output_schema: None,
            icon: None,
            version: Some(crate::VERSION.to_string()),
            tags: vec!["wa".to_string(), "robot".to_string()],
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let start = Instant::now();
        let params = if arguments.is_null() {
            StateParams::default()
        } else {
            match serde_json::from_value::<StateParams>(arguments) {
                Ok(params) => params,
                Err(err) => {
                    let envelope = McpEnvelope::<()>::error(
                        MCP_ERR_INVALID_ARGS,
                        format!("Invalid params: {err}"),
                        Some("Expected object with optional domain/agent/pane_id".to_string()),
                        elapsed_ms(start),
                    );
                    return envelope_to_content(envelope);
                }
            }
        };

        if params.agent.is_some() {
            tracing::info!(
                "MCP wa.state agent filter is not yet implemented; returning unfiltered results"
            );
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| McpError::internal_error(format!("Tokio runtime init failed: {e}")))?;

        let result = runtime.block_on(async {
            let wezterm = WeztermClient::new();
            wezterm.list_panes().await
        });

        match result {
            Ok(panes) => {
                let states: Vec<McpPaneState> = panes
                    .iter()
                    .filter(|pane| match params.pane_id {
                        Some(pane_id) => pane.pane_id == pane_id,
                        None => true,
                    })
                    .filter(|pane| match params.domain.as_ref() {
                        Some(domain) => pane.inferred_domain() == *domain,
                        None => true,
                    })
                    .map(|pane| McpPaneState::from_pane_info(pane, &self.filter))
                    .collect();
                let envelope = McpEnvelope::success(states, elapsed_ms(start));
                envelope_to_content(envelope)
            }
            Err(err) => {
                let (code, hint) = map_mcp_error(&err);
                let envelope =
                    McpEnvelope::<()>::error(code, err.to_string(), hint, elapsed_ms(start));
                envelope_to_content(envelope)
            }
        }
    }
}

fn map_mcp_error(error: &Error) -> (&'static str, Option<String>) {
    match error {
        Error::Wezterm(WeztermError::PaneNotFound(_)) => (
            MCP_ERR_PANE_NOT_FOUND,
            Some("Use wa.state to list available panes.".to_string()),
        ),
        Error::Wezterm(WeztermError::Timeout(_)) => (
            MCP_ERR_TIMEOUT,
            Some("Increase timeout or ensure WezTerm is responsive.".to_string()),
        ),
        Error::Wezterm(WeztermError::NotRunning) => {
            (MCP_ERR_WEZTERM, Some("Is WezTerm running?".to_string()))
        }
        Error::Wezterm(WeztermError::CliNotFound) => (
            MCP_ERR_WEZTERM,
            Some("Install WezTerm and ensure it is in PATH.".to_string()),
        ),
        Error::Wezterm(_) => (MCP_ERR_WEZTERM, None),
        Error::Config(_) => (MCP_ERR_CONFIG, None),
        Error::Storage(_) => (MCP_ERR_STORAGE, None),
        Error::Workflow(_) => (MCP_ERR_WORKFLOW, None),
        Error::Policy(_) => (MCP_ERR_POLICY, None),
        _ => (MCP_ERR_NOT_IMPLEMENTED, None),
    }
}

fn envelope_to_content<T: Serialize>(envelope: McpEnvelope<T>) -> McpResult<Vec<Content>> {
    let text = serde_json::to_string(&envelope)
        .map_err(|e| McpError::internal_error(format!("Serialize MCP response: {e}")))?;
    Ok(vec![Content::Text { text }])
}

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |dur| u64::try_from(dur.as_millis()).unwrap_or(u64::MAX))
}
