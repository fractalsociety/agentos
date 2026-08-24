//! Launch the official Codex CLI with the read-only AgentOS MCP bridge.
//!
//! This keeps the model-generated shell inside Codex's normal sandbox while
//! the separately configured MCP process owns the narrow CC-PD socket access.

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(name = "codex-agentos", version, trailing_var_arg = true)]
struct Args {
    /// Official Codex CLI executable.
    #[arg(long, default_value = "codex")]
    codex: PathBuf,

    /// AgentOS MCP server executable. Defaults to the launcher's sibling.
    #[arg(long)]
    mcp: Option<PathBuf>,

    /// Compiled agentctl reference client used only by the MCP process.
    #[arg(long, default_value = "tools/agentctl/agentctl")]
    agentctl: PathBuf,

    /// Live CC-PD Unix socket.
    #[arg(long, default_value = "build/cc_pd.sock")]
    socket: PathBuf,

    /// Emit elapsed time and peak child RSS as one JSON object on stderr.
    #[arg(long)]
    metrics: bool,

    /// Arguments forwarded verbatim to Codex, beginning with `exec`.
    #[arg(required = true, allow_hyphen_values = true)]
    codex_args: Vec<OsString>,
}

fn canonical_file(path: &Path, description: &str) -> Result<PathBuf> {
    let absolute = path
        .canonicalize()
        .with_context(|| format!("{description} not found at {}", path.display()))?;
    if !absolute.is_file() {
        bail!("{description} is not a file: {}", absolute.display());
    }
    Ok(absolute)
}

fn canonical_socket(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("CC-PD socket not found at {}", path.display()))
}

fn default_mcp_path() -> Result<PathBuf> {
    let launcher = std::env::current_exe().context("cannot resolve codex-agentos executable")?;
    let mut name = OsString::from("agentos-mcp");
    if let Some(extension) = launcher.extension() {
        name.push(".");
        name.push(extension);
    }
    Ok(launcher
        .parent()
        .context("codex-agentos executable has no parent directory")?
        .join(name))
}

fn toml_string(value: &OsStr) -> Result<String> {
    let value = value
        .to_str()
        .context("AgentOS integration paths must be valid UTF-8")?;
    serde_json::to_string(value).context("failed to encode AgentOS integration path")
}

fn mcp_config_args(mcp: &Path, agentctl: &Path, socket: &Path) -> Result<Vec<OsString>> {
    let mcp = toml_string(mcp.as_os_str())?;
    let agentctl = toml_string(agentctl.as_os_str())?;
    let socket = toml_string(socket.as_os_str())?;
    let transport_args = format!("[\"--agentctl\",{agentctl},\"--socket\",{socket}]");
    let values = [
        format!("mcp_servers.agentos.command={mcp}"),
        format!("mcp_servers.agentos.args={transport_args}"),
        "mcp_servers.agentos.required=true".to_string(),
        concat!(
            "mcp_servers.agentos.enabled_tools=[",
            "\"agentos_pool_status\",",
            "\"agentos_list_guests\",",
            "\"agentos_guest_status\"]"
        )
        .to_string(),
        "mcp_servers.agentos.default_tools_approval_mode=\"auto\"".to_string(),
    ];
    Ok(values
        .into_iter()
        .flat_map(|value| [OsString::from("-c"), OsString::from(value)])
        .collect())
}

#[cfg(unix)]
fn child_max_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage writes a complete rusage value when it returns zero.
    let result = unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, usage.as_mut_ptr()) };
    if result != 0 {
        return None;
    }
    // SAFETY: a zero return above guarantees initialization.
    let rss = unsafe { usage.assume_init() }.ru_maxrss;
    let rss = u64::try_from(rss).ok()?;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    return Some(rss);
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    return rss.checked_mul(1024);
}

#[cfg(not(unix))]
fn child_max_rss_bytes() -> Option<u64> {
    None
}

fn run() -> Result<i32> {
    let args = Args::parse();
    if args.codex_args.first().and_then(|arg| arg.to_str()) != Some("exec") {
        bail!("forwarded Codex arguments must begin with `exec`");
    }

    let mcp = canonical_file(
        args.mcp.as_deref().unwrap_or(&default_mcp_path()?),
        "agentos-mcp executable",
    )?;
    let agentctl = canonical_file(&args.agentctl, "agentctl executable")?;
    let socket = canonical_socket(&args.socket)?;

    let started = Instant::now();
    let status = Command::new(&args.codex)
        .args(mcp_config_args(&mcp, &agentctl, &socket)?)
        .args(args.codex_args)
        .status()
        .with_context(|| format!("failed to start Codex at {}", args.codex.display()))?;
    if args.metrics {
        eprintln!(
            "AGENTOS_CODEX_METRICS {}",
            serde_json::json!({
                "elapsed_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                "max_rss_bytes": child_max_rss_bytes(),
                "exit_code": status.code()
            })
        );
    }
    Ok(status.code().unwrap_or(1))
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("codex-agentos: {error:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_exposes_only_named_read_only_tools() {
        let args = mcp_config_args(
            Path::new("/opt/agentos-mcp"),
            Path::new("/opt/agentctl"),
            Path::new("/run/cc.sock"),
        )
        .unwrap();
        let rendered = args
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(rendered.contains("agentos_pool_status"));
        assert!(rendered.contains("agentos_list_guests"));
        assert!(rendered.contains("agentos_guest_status"));
        assert!(rendered.contains("--agentctl"));
        assert!(!rendered.contains("raw"));
        assert!(rendered.contains("required=true"));
        assert!(rendered.contains("approval_mode=\"auto\""));
    }

    #[test]
    fn config_toml_escapes_paths() {
        let args = mcp_config_args(
            Path::new("/tmp/Agent \"OS\"/mcp"),
            Path::new("/tmp/agentctl"),
            Path::new("/tmp/control socket"),
        )
        .unwrap();
        assert!(args[1].to_string_lossy().contains("\\\"OS\\\""));
        assert!(args[3].to_string_lossy().contains("control socket"));
    }
}
