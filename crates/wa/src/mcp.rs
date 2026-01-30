//! MCP server wiring for wa (feature-gated).

use std::path::Path;

use anyhow::bail;
use fastmcp::StdioTransport;

use wa_core::config::Config;

use super::McpCommands;

pub fn run_mcp(
    command: McpCommands,
    config: &Config,
    _workspace_root: &Path,
) -> anyhow::Result<()> {
    match command {
        McpCommands::Serve { transport } => serve_mcp(&transport, config),
    }
}

fn serve_mcp(transport: &str, config: &Config) -> anyhow::Result<()> {
    if transport != "stdio" {
        bail!("Unsupported transport: {transport}");
    }

    let server = wa_core::mcp::build_server(config)?;
    let transport = StdioTransport::stdio();
    server.run_transport(transport);
}
