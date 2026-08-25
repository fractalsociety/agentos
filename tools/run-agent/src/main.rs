//! `run-agent` — launch the official Codex CLI as a Fractal worker.
//!
//! The launcher owns the provider-neutral session boundary. Codex still runs
//! its native `exec --json` protocol, but the launcher controls its sandbox,
//! workspace, MCP configuration, credentials, redaction, and terminal result.

use anyhow::{bail, Context, Result};
use clap::Parser;
use fractal_worker_compat::{
    apply_peak_rss, enforce_allowed_files, map_terminal_result, parse_version_output, redact_text,
    validate_workspace_input, FileChange, RedactionClass, SecretHandle, SessionEvent,
    SessionEventKind, UsageMetrics, VersionRecord, WorkerManifest, WorkspaceInput,
};
use serde_json::{json, Value};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const WORKER_ID: &str = "codex";
const PROVIDER: &str = "codex";

#[derive(Parser, Debug)]
#[command(
    name = "run-agent",
    version,
    about = "Run the official Codex Fractal worker"
)]
struct Cli {
    /// Fractal worker manifest.
    #[arg(long, default_value = "manifests/workers/codex.toml")]
    manifest: PathBuf,

    /// Official Codex executable. This must resolve to the real CLI.
    #[arg(long, default_value = "codex")]
    codex: PathBuf,

    /// FractalOS MCP bridge executable.
    #[arg(long)]
    mcp: Option<PathBuf>,

    /// Compiled agentctl reference client used only by the MCP bridge.
    #[arg(long, default_value = "tools/agentctl/agentctl")]
    agentctl: PathBuf,

    /// Live CC-PD Unix socket.
    #[arg(long, default_value = "build/cc_pd.sock")]
    socket: PathBuf,

    /// Existing clean isolated Git workspace.
    #[arg(long)]
    workspace: PathBuf,

    /// Workspace-relative path Codex is permitted to change. Repeatable.
    #[arg(long = "allowed-file", required = true)]
    allowed_files: Vec<String>,

    /// Prompt passed as the final positional argument to `codex exec`.
    #[arg(long)]
    prompt: String,

    /// Write redacted native Codex JSONL events to this file.
    #[arg(long)]
    events: Option<PathBuf>,

    /// Write the common Fractal terminal-result envelope to this file.
    #[arg(long)]
    result: Option<PathBuf>,

    /// Emit one structured process metric record on stderr.
    #[arg(long)]
    metrics: bool,
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
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
    let launcher = std::env::current_exe().context("cannot resolve run-agent executable")?;
    let mut name = OsString::from("fractalos-mcp");
    if let Some(extension) = launcher.extension() {
        name.push(".");
        name.push(extension);
    }
    Ok(launcher
        .parent()
        .context("run-agent executable has no parent directory")?
        .join(name))
}

fn toml_string(value: &OsStr) -> Result<String> {
    let value = value
        .to_str()
        .context("FractalOS integration paths must be valid UTF-8")?;
    serde_json::to_string(value).context("failed to encode FractalOS integration path")
}

fn mcp_config_args(mcp: &Path, agentctl: &Path, socket: &Path) -> Result<Vec<OsString>> {
    let mcp = toml_string(mcp.as_os_str())?;
    let agentctl = toml_string(agentctl.as_os_str())?;
    let socket = toml_string(socket.as_os_str())?;
    let transport_args = format!("[\"--agentctl\",{agentctl},\"--socket\",{socket}]");
    let values = [
        format!("mcp_servers.fractalos.command={mcp}"),
        format!("mcp_servers.fractalos.args={transport_args}"),
        "mcp_servers.fractalos.required=true".to_string(),
        concat!(
            "mcp_servers.fractalos.enabled_tools=[",
            "\"fractalos_pool_status\",",
            "\"fractalos_list_guests\",",
            "\"fractalos_guest_status\"]"
        )
        .to_string(),
        "mcp_servers.fractalos.default_tools_approval_mode=\"auto\"".to_string(),
    ];
    Ok(values
        .into_iter()
        .flat_map(|value| [OsString::from("-c"), OsString::from(value)])
        .collect())
}

fn credential_free_command(mut command: Command) -> Command {
    // Version discovery must not load an API credential. Session execution
    // intentionally inherits the caller's ephemeral auth process channel.
    for name in [
        "OPENAI_API_KEY",
        "CODEX_API_KEY",
        "OPENAI_ADMIN_KEY",
        "FRACTAL_CODEX_SECRET_HANDLE",
    ] {
        command.env_remove(name);
    }
    command
}

fn discover_version(codex: &Path, manifest: &WorkerManifest) -> Result<VersionRecord> {
    let preflight_home = std::env::temp_dir().join(format!(
        "fractal-codex-version-{}-{}",
        std::process::id(),
        now_unix_ms()
    ));
    std::fs::create_dir(&preflight_home)
        .context("failed to create ephemeral Codex version-preflight home")?;
    let mut command = Command::new(codex);
    command.args(&manifest.discovery.version_args);
    command.env("CODEX_HOME", &preflight_home);
    let output = match credential_free_command(command).output() {
        Ok(output) => output,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&preflight_home);
            return Err(error).with_context(|| {
                format!(
                    "failed to run credential-free {} preflight",
                    codex.display()
                )
            });
        }
    };
    let _ = std::fs::remove_dir_all(&preflight_home);
    let raw = String::from_utf8_lossy(&output.stdout).to_string();
    let fallback = String::from_utf8_lossy(&output.stderr);
    let raw = if raw.trim().is_empty() {
        fallback.to_string()
    } else {
        raw
    };
    if !output.status.success() {
        let (safe, _) = redact_text(manifest, &fallback);
        bail!(
            "credential-free Codex version preflight failed: {}",
            safe.trim()
        );
    }
    let version = parse_version_output(
        WORKER_ID,
        PROVIDER,
        &manifest.worker.executable.name,
        &raw,
        now_unix_ms(),
    )?;
    if manifest.discovery.expect_semver
        && !version
            .cli_version
            .split(['.', '-', '+'])
            .take(2)
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
    {
        bail!("Codex version preflight did not report a semantic version");
    }
    Ok(version)
}

fn workspace_input(workspace: &Path, allowed_files: &[String]) -> Result<WorkspaceInput> {
    let workspace = workspace
        .canonicalize()
        .with_context(|| format!("workspace not found at {}", workspace.display()))?;
    if !workspace.is_dir() {
        bail!("workspace is not a directory: {}", workspace.display());
    }
    let root = git_output(&workspace, &["rev-parse", "--show-toplevel"])?;
    let root = PathBuf::from(root.trim())
        .canonicalize()
        .context("Git returned an invalid workspace root")?;
    if root != workspace {
        bail!("workspace must be the isolated Git worktree root");
    }
    let status = git_output(&workspace, &["status", "--porcelain"])?;
    if !status.trim().is_empty() {
        bail!("workspace must be clean before Codex starts");
    }
    let root_object_id = git_output(&workspace, &["rev-parse", "HEAD"])?
        .trim()
        .to_string();
    let input = WorkspaceInput {
        workspace_id: format!("codex-{}", std::process::id()),
        root_object_id,
        allowed_files: allowed_files.to_vec(),
        verify_command: None,
    };
    validate_workspace_input(&input).context("invalid isolated workspace input")?;
    Ok(input)
}

fn git_output(workspace: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(args)
        .output()
        .context("failed to invoke Git for workspace validation")?;
    if !output.status.success() {
        bail!("Git workspace validation failed");
    }
    String::from_utf8(output.stdout).context("Git emitted non-UTF-8 workspace data")
}

fn changed_files(workspace: &Path, allowed: &WorkspaceInput) -> Result<Vec<FileChange>> {
    let status = git_output(
        workspace,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    let mut changed = Vec::new();
    for line in status.lines() {
        if line.len() < 4 {
            continue;
        }
        let path = line[3..].trim();
        let path = path.rsplit_once(" -> ").map(|(_, new)| new).unwrap_or(path);
        let bytes = std::fs::metadata(workspace.join(path))
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        changed.push((path.to_string(), bytes));
    }
    enforce_allowed_files(allowed, &changed).context("Codex changed a file outside allowed-files")
}

fn auth_handle(manifest: &WorkerManifest) -> Option<SecretHandle> {
    if let Some(handle) = std::env::var_os(&manifest.auth.handle_env) {
        // This is an opaque broker reference, never a credential. It is kept
        // out of diagnostics and is inherited by the short-lived Codex child.
        return handle.to_str().map(|id| SecretHandle {
            id: id.to_string(),
            purpose: "codex-auth".to_string(),
        });
    }
    ["OPENAI_API_KEY", "CODEX_API_KEY"]
        .iter()
        .any(|name| std::env::var_os(name).is_some())
        .then(|| SecretHandle {
            id: "inherited-process-channel".to_string(),
            purpose: "codex-auth".to_string(),
        })
}

fn redacted_events(
    manifest: &WorkerManifest,
    stdout: &[u8],
) -> Result<(String, Vec<SessionEvent>)> {
    let text = String::from_utf8_lossy(stdout);
    let mut safe_lines = Vec::new();
    let mut events = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let (safe_line, redaction) = redact_text(manifest, line);
        let value: Value = serde_json::from_str(&safe_line)
            .with_context(|| "Codex exec --json emitted a non-JSONL line")?;
        let typ = value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("message");
        let item = value.get("item").and_then(Value::as_object);
        let item_type = item
            .and_then(|item| item.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let (kind, summary) = match (typ, item_type) {
            ("item.completed" | "item.started", "mcp_tool_call") => {
                (SessionEventKind::ToolCall, "mcp_tool_call".to_string())
            }
            ("item.completed" | "item.started", "mcp_tool_result") => {
                (SessionEventKind::ToolResult, "mcp_tool_result".to_string())
            }
            ("item.completed" | "item.started", "file_change") => (
                SessionEventKind::FileEdit,
                item.and_then(|item| item.get("path"))
                    .and_then(Value::as_str)
                    .unwrap_or("file_change")
                    .to_string(),
            ),
            ("item.completed" | "item.started", "agent_message") => (
                SessionEventKind::Message,
                item.and_then(|item| item.get("text"))
                    .and_then(Value::as_str)
                    .unwrap_or("agent_message")
                    .to_string(),
            ),
            ("turn.completed", _) => (SessionEventKind::Usage, "usage".to_string()),
            ("error", _) => (
                SessionEventKind::Error,
                value
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("error")
                    .to_string(),
            ),
            ("thread.started" | "turn.started" | "item.started", _) => {
                (SessionEventKind::Status, typ.to_string())
            }
            _ => (SessionEventKind::Message, typ.to_string()),
        };
        let summary = redact_text(manifest, &summary).0;
        events.push(SessionEvent {
            sequence: events.len() as u64,
            kind,
            summary,
            redaction,
            payload_json: Some(safe_line.clone()),
        });
        safe_lines.push(safe_line);
    }
    Ok((
        safe_lines.join("\n") + if safe_lines.is_empty() { "" } else { "\n" },
        events,
    ))
}

fn usage_from_events(events: &[SessionEvent]) -> UsageMetrics {
    let mut usage = UsageMetrics::default();
    for event in events {
        if event.kind != SessionEventKind::Usage {
            continue;
        }
        let Some(raw) = &event.payload_json else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(raw) else {
            continue;
        };
        let value = value.get("usage").unwrap_or(&value);
        usage.input_tokens = value
            .get("input_tokens")
            .or_else(|| value.get("prompt_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(usage.input_tokens);
        usage.output_tokens = value
            .get("output_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(usage.output_tokens);
        usage.cached_tokens = value
            .get("cached_input_tokens")
            .or_else(|| value.get("cached_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(usage.cached_tokens);
    }
    usage
}

#[cfg(unix)]
fn child_max_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage writes a complete rusage value when it returns zero.
    if unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: a zero return above guarantees initialization.
    let rss = u64::try_from(unsafe { usage.assume_init() }.ru_maxrss).ok()?;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    return Some(rss);
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    rss.checked_mul(1024)
}

#[cfg(not(unix))]
fn child_max_rss_bytes() -> Option<u64> {
    None
}

fn terminal_error(
    manifest: &WorkerManifest,
    message: String,
) -> fractal_worker_compat::TerminalResult {
    let (message, _) = redact_text(manifest, &message);
    fractal_worker_compat::TerminalResult {
        schema: manifest.terminal_result.schema.clone(),
        session_id: format!("codex-launcher-error-{}", std::process::id()),
        worker_id: WORKER_ID.to_string(),
        provider: PROVIDER.to_string(),
        state: fractal_worker_compat::SessionState::Failed,
        exit: fractal_worker_compat::ExitClass::LauncherError,
        exit_status: 1,
        version: VersionRecord {
            worker_id: WORKER_ID.to_string(),
            provider: PROVIDER.to_string(),
            protocol_version: fractal_worker_compat::PROTOCOL_VERSION.to_string(),
            cli_name: "codex".to_string(),
            cli_version: "unknown".to_string(),
            discovered_at_unix_ms: now_unix_ms(),
        },
        usage: UsageMetrics::default(),
        events: Vec::new(),
        changed_files: Vec::new(),
        secret_handle: None,
        error_message: Some(message),
    }
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let data = serde_json::to_vec_pretty(value).context("failed to encode terminal result")?;
    std::fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn emit_result(cli: &Cli, result: &fractal_worker_compat::TerminalResult) -> Result<()> {
    if let Some(path) = &cli.result {
        write_json(path, result)?;
    }
    println!(
        "{}",
        serde_json::to_string(result).context("failed to encode result")?
    );
    Ok(())
}

fn run(cli: &Cli, manifest: &WorkerManifest) -> Result<i32> {
    let codex = &cli.codex;
    let mcp = canonical_file(
        cli.mcp.as_deref().unwrap_or(&default_mcp_path()?),
        "fractalos-mcp executable",
    )?;
    let agentctl = canonical_file(&cli.agentctl, "agentctl executable")?;
    let socket = canonical_socket(&cli.socket)?;
    let workspace = workspace_input(&cli.workspace, &cli.allowed_files)?;
    let version = discover_version(codex, manifest)?;
    let handle = auth_handle(manifest);
    let started = Instant::now();

    let mut command = Command::new(codex);
    command
        .args(mcp_config_args(&mcp, &agentctl, &socket)?)
        .args(&manifest.session.launch_args)
        .arg(&manifest.session.workspace_path_arg)
        .arg(&cli.workspace)
        .arg(&cli.prompt);
    let output: Output = command
        .output()
        .with_context(|| format!("failed to start official Codex at {}", codex.display()))?;
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let max_rss = child_max_rss_bytes().unwrap_or(0);

    let (safe_events, mut events) =
        redacted_events(manifest, &output.stdout).context("failed to normalize Codex JSONL")?;
    if let Some(path) = &cli.events {
        std::fs::write(path, safe_events)
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
    let exit_status = output.status.code().unwrap_or(1);
    let terminal_kind = if output.status.success() {
        "success"
    } else if output.status.code() == Some(130) {
        "cancelled"
    } else {
        "failure"
    };
    events.push(SessionEvent {
        sequence: events.len() as u64,
        kind: SessionEventKind::Terminal,
        summary: terminal_kind.to_string(),
        redaction: RedactionClass::None,
        payload_json: Some(
            json!({"type":"terminal","subtype":terminal_kind,"exit_code":exit_status}).to_string(),
        ),
    });
    let mut usage = usage_from_events(&events);
    apply_peak_rss(&mut usage, max_rss);
    usage.wall_time_ms = elapsed_ms;
    let changed = changed_files(&cli.workspace, &workspace);
    let (result, code) = match changed {
        Ok(changed) => {
            let result = map_terminal_result(
                manifest,
                &workspace.workspace_id,
                version,
                events,
                changed,
                usage,
                handle,
            );
            (result, exit_status)
        }
        Err(error) => {
            let (message, _) = redact_text(manifest, &error.to_string());
            let result = fractal_worker_compat::TerminalResult {
                schema: manifest.terminal_result.schema.clone(),
                session_id: workspace.workspace_id,
                worker_id: WORKER_ID.to_string(),
                provider: PROVIDER.to_string(),
                state: fractal_worker_compat::SessionState::Failed,
                exit: fractal_worker_compat::ExitClass::PolicyDenied,
                exit_status: 1,
                version,
                usage,
                events,
                changed_files: Vec::new(),
                secret_handle: handle,
                error_message: Some(message),
            };
            (result, 1)
        }
    };
    emit_result(cli, &result)?;
    if cli.metrics {
        eprintln!(
            "FRACTALOS_CODEX_METRICS {}",
            serde_json::json!({
                "elapsed_ms": elapsed_ms,
                "max_rss_bytes": max_rss,
                "exit_code": code,
                "input_tokens": result.usage.input_tokens,
                "cached_tokens": result.usage.cached_tokens,
                "output_tokens": result.usage.output_tokens,
            })
        );
    }
    Ok(code)
}

fn main() {
    let cli = Cli::parse();
    let manifest = match WorkerManifest::load(&cli.manifest) {
        Ok(manifest) => manifest,
        Err(error) => {
            eprintln!("run-agent: invalid worker manifest: {error}");
            std::process::exit(1);
        }
    };
    if manifest.worker.id != WORKER_ID || manifest.worker.provider != PROVIDER {
        eprintln!("run-agent: manifest is not the Codex worker profile");
        std::process::exit(1);
    }
    match run(&cli, &manifest) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            let result = terminal_error(&manifest, error.to_string());
            if let Err(write_error) = emit_result(&cli, &result) {
                eprintln!("run-agent: {write_error:#}");
            }
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_config_contains_only_the_read_only_allowlist() {
        let args = mcp_config_args(
            Path::new("/opt/fractalos-mcp"),
            Path::new("/opt/agentctl"),
            Path::new("/run/cc.sock"),
        )
        .unwrap();
        let rendered = args
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(rendered.contains("fractalos_pool_status"));
        assert!(rendered.contains("fractalos_list_guests"));
        assert!(rendered.contains("fractalos_guest_status"));
        assert!(!rendered.contains("fractalos_run_native_task"));
        assert!(!rendered.contains("raw"));
        assert!(rendered.contains("required=true"));
    }

    #[test]
    fn codex_command_policy_is_fixed_by_manifest() {
        let manifest = WorkerManifest::load(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../manifests/workers/codex.toml"),
        )
        .unwrap();
        assert_eq!(manifest.session.launch_args[0], "exec");
        assert!(manifest.session.launch_args.contains(&"--json".to_string()));
        assert!(manifest
            .session
            .launch_args
            .contains(&"--ephemeral".to_string()));
        assert!(manifest
            .session
            .launch_args
            .windows(2)
            .any(|window| window == ["--sandbox", "workspace-write"]));
    }

    #[test]
    fn version_preflight_removes_credentials_from_the_child_environment() {
        let mut command = Command::new("codex");
        command.env("OPENAI_API_KEY", "canary");
        let debug = format!("{:?}", credential_free_command(command));
        assert!(!debug.contains("canary"));
    }
}
