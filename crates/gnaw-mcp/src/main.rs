//! gnaw MCP server — a thin async adapter over the shared extraction pipeline.
//! Tools build a GnawConfig and call gnaw_pipeline::run_extraction; the heavy,
//! rayon-backed work goes to spawn_blocking. All logging goes to stderr —
//! stdout is the JSON-RPC channel and any stray write to it corrupts the stream
//! and silently disconnects the client.

use std::path::PathBuf;

use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::Deserialize;

use gnaw_core::configuration::GnawConfig;

#[derive(Clone)]
struct GnawServer {
    /// Allowed root. Every requested repo must canonicalize under this, so a
    /// model-supplied path can't read outside the directory the operator
    /// granted (set via GNAW_MCP_ROOT, default: the server's cwd).
    root: PathBuf,
    #[allow(dead_code)] // read by the #[tool_handler] macro expansion, not directly
    tool_router: rmcp::handler::server::tool::ToolRouter<Self>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ExtractArgs {
    /// Repository path to extract. Must resolve under the server's allowed root.
    repo: String,
    /// Glob patterns to include (added to any in a .gnawconfig at the repo root).
    #[serde(default)]
    include: Vec<String>,
    /// Glob patterns to exclude.
    #[serde(default)]
    exclude: Vec<String>,
    // NOTE: deliberately no `budget` / `query` yet — build_spec hardcodes
    // budget:0 and the ranker is Uniform, so neither is enforced. Add them here
    // only once the pipeline honors a budget and a real ranker is wired, so the
    // tool schema never advertises behavior that doesn't exist.
}

#[tool_router]
impl GnawServer {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            tool_router: Self::tool_router(),
        }
    }

    /// Confine an untrusted repo path to the allowed root: canonicalize, then
    /// strip_prefix to prove containment (same pattern as the stdin source).
    fn confine(&self, repo: &str) -> Result<PathBuf, McpError> {
        let abs = PathBuf::from(repo)
            .canonicalize()
            .map_err(|e| McpError::invalid_params(format!("repo path: {e}"), None))?;
        abs.strip_prefix(&self.root)
            .map_err(|_| McpError::invalid_params("repo escapes the allowed root", None))?;
        Ok(abs)
    }

    fn config_for(&self, args: ExtractArgs) -> Result<GnawConfig, McpError> {
        let path = self.confine(&args.repo)?;
        GnawConfig::builder()
            .path(path)
            .include_patterns(args.include)
            .exclude_patterns(args.exclude)
            .build()
            .map_err(|e| McpError::internal_error(format!("config: {e}"), None))
    }

    #[tool(description = "Extract a repository into an LLM-ready prompt. \
                          Returns the rendered prompt text.")]
    async fn extract(
        &self,
        Parameters(args): Parameters<ExtractArgs>,
    ) -> Result<CallToolResult, McpError> {
        let config = self.config_for(args)?;

        // CPU + rayon work off the async executor thread.
        let rendered = tokio::task::spawn_blocking(move || gnaw_pipeline::run_extraction(&config))
            .await
            .map_err(|e| McpError::internal_error(format!("join: {e}"), None))?
            .map_err(|e| McpError::internal_error(format!("extract: {e}"), None))?;

        Ok(CallToolResult::success(vec![Content::text(rendered.body)]))
    }

    #[tool(description = "Estimate the token count of extracting a repository, \
                          without returning the prompt body.")]
    async fn estimate(
        &self,
        Parameters(args): Parameters<ExtractArgs>,
    ) -> Result<CallToolResult, McpError> {
        let config = self.config_for(args)?;

        // Same path as extract for now — not cheaper yet, just discards the body.
        // A real cheap estimate would be a pre-walk that counts without rendering.
        let rendered = tokio::task::spawn_blocking(move || gnaw_pipeline::run_extraction(&config))
            .await
            .map_err(|e| McpError::internal_error(format!("join: {e}"), None))?
            .map_err(|e| McpError::internal_error(format!("estimate: {e}"), None))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "{} tokens ({})",
            rendered.tally.total, rendered.tally.encoding
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for GnawServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions =
            Some("Turn a codebase into an LLM-ready prompt, optimized to a token budget.".into());
        info
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // stderr ONLY — stdout is the protocol channel.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let root = std::env::var("GNAW_MCP_ROOT")
        .map(PathBuf::from)
        .unwrap_or(std::env::current_dir()?)
        .canonicalize()?;

    tracing::info!(root = %root.display(), "starting gnaw-mcp (stdio)");

    let service = GnawServer::new(root).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
