//! Fractal worker compatibility helpers for `fractal-worker/v1`.

mod claude;
mod cursor;

pub use claude::ClaudeLauncher;
pub use cursor::{CursorLauncher, OpenSessionOpts};

use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const TERMINAL_RESULT_SCHEMA: &str = "fractal.worker.terminal-result.v1";
pub const PROTOCOL_VERSION: &str = "fractal-worker/v1";

#[derive(Debug, Error)]
pub enum CompatError {
    #[error("{0}")]
    Message(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("launcher not implemented: {0}")]
    LauncherNotImplemented(String),
}

pub type Result<T> = std::result::Result<T, CompatError>;

fn err(msg: impl Into<String>) -> CompatError {
    CompatError::Message(msg.into())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Codex,
    Cursor,
    Claude,
    Hermes,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Pending,
    Running,
    Cancelling,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExitClass {
    Success,
    Failure,
    Cancelled,
    ResourceLimit,
    PolicyDenied,
    LauncherError,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClass {
    None,
    Credential,
    PersonalRecord,
    AbsolutePath,
    Environment,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SessionEventKind {
    Version,
    Status,
    Message,
    ToolCall,
    ToolResult,
    FileEdit,
    Usage,
    Cancellation,
    Error,
    Terminal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionRecord {
    pub worker_id: String,
    pub provider: String,
    pub protocol_version: String,
    pub cli_name: String,
    pub cli_version: String,
    pub discovered_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceInput {
    pub workspace_id: String,
    pub root_object_id: String,
    pub allowed_files: Vec<String>,
    pub verify_command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretHandle {
    pub id: String,
    pub purpose: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct UsageMetrics {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_tokens: u64,
    pub peak_rss_bytes: u64,
    pub wall_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileChange {
    pub path: String,
    pub bytes_written: u64,
    pub within_allowlist: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionEvent {
    pub sequence: u64,
    pub kind: SessionEventKind,
    pub summary: String,
    pub redaction: RedactionClass,
    pub payload_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CancelRequest {
    pub session_id: String,
    pub reason: String,
    pub deadline_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TerminalResult {
    pub schema: String,
    pub session_id: String,
    pub worker_id: String,
    pub provider: String,
    pub state: SessionState,
    pub exit: ExitClass,
    pub exit_status: i32,
    pub version: VersionRecord,
    pub usage: UsageMetrics,
    pub events: Vec<SessionEvent>,
    pub changed_files: Vec<FileChange>,
    pub secret_handle: Option<SecretHandle>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkerManifest {
    pub worker: WorkerSection,
    pub discovery: DiscoverySection,
    pub session: SessionSection,
    pub auth: AuthSection,
    pub limits: LimitsSection,
    pub policy: PolicySection,
    pub redaction: RedactionSection,
    pub terminal_result: TerminalResultSection,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkerSection {
    pub id: String,
    pub provider: String,
    pub protocol: String,
    pub protocol_wit: String,
    pub description: String,
    pub executable: ExecutableRoute,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExecutableRoute {
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoverySection {
    pub version_args: Vec<String>,
    pub expect_semver: bool,
    pub requires_real_version_preflight: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionSection {
    pub stream_format: String,
    pub native_output_format: String,
    pub launch_args: Vec<String>,
    pub requires_isolated_git_workspace: bool,
    pub workspace_path_arg: String,
    pub prompt_arg_mode: String,
    pub allowed_file_enforcement: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthSection {
    pub mode: String,
    pub handle_env: String,
    pub inherit_process_channel: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsSection {
    pub max_rss_bytes: u64,
    pub default_deadline_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicySection {
    pub grant_shell: bool,
    pub grant_network: bool,
    pub grant_filesystem: bool,
    pub grant_environment: bool,
    pub allow_absolute_workspace_paths: bool,
    pub allow_path_parent_segments: bool,
    pub persist_credentials: bool,
    pub log_credentials: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedactionSection {
    pub credential_patterns: Vec<String>,
    pub personal_record_patterns: Vec<String>,
    pub absolute_path_patterns: Vec<String>,
    pub replacement: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TerminalResultSection {
    pub schema: String,
    pub map_exit_zero_to: String,
    pub map_cancel_signal_to: String,
    pub include_peak_rss: bool,
    pub include_usage_tokens: bool,
}

impl WorkerManifest {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let manifest: Self = toml::from_str(&text)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.worker.protocol != PROTOCOL_VERSION {
            return Err(err(format!(
                "unsupported protocol {}",
                self.worker.protocol
            )));
        }
        if self.worker.executable.kind != "path-lookup" {
            return Err(err("executable.kind must be path-lookup"));
        }
        if self.worker.executable.name.contains('/') || self.worker.executable.name.contains('\\') {
            return Err(err("executable.name must be a bare command"));
        }
        if self.policy.grant_shell
            || self.policy.grant_network
            || self.policy.grant_filesystem
            || self.policy.grant_environment
        {
            return Err(err("worker manifest must grant no ambient authority"));
        }
        if self.auth.mode != "opaque-secret-handle" {
            return Err(err("auth.mode must be opaque-secret-handle"));
        }
        Ok(())
    }

    pub fn grants_no_authority(&self) -> bool {
        !self.policy.grant_shell
            && !self.policy.grant_network
            && !self.policy.grant_filesystem
            && !self.policy.grant_environment
            && !self.policy.persist_credentials
            && !self.policy.log_credentials
    }
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

pub fn cursor_manifest_path() -> PathBuf {
    repo_root().join("manifests/workers/cursor.toml")
}

pub fn claude_manifest_path() -> PathBuf {
    repo_root().join("manifests/workers/claude.toml")
}

pub fn worker_wit_path() -> PathBuf {
    repo_root().join("interfaces/wit/fractal-worker-v1/worker.wit")
}

pub fn cursor_fixture_dir() -> PathBuf {
    repo_root().join("tests/fixtures/cursor-worker")
}

pub fn scan_manifest_safety(text: &str) -> Result<()> {
    let lowered = text.to_lowercase();
    let redaction_idx = text.find("[redaction]").unwrap_or(usize::MAX);
    for needle in ["sk-", "bearer ", "password =", "token ="] {
        if let Some(idx) = lowered.find(needle) {
            if idx < redaction_idx {
                return Err(err(format!(
                    "manifest embeds forbidden material near `{needle}`"
                )));
            }
        }
    }
    // Personal home paths are only legal inside [redaction] pattern lists.
    for needle in ["/users/", "/home/"] {
        if let Some(idx) = lowered.find(needle) {
            if idx < redaction_idx {
                return Err(err(format!(
                    "manifest embeds personal path near `{needle}`"
                )));
            }
        }
    }
    Ok(())
}

pub fn validate_workspace_input(ws: &WorkspaceInput) -> Result<()> {
    if ws.workspace_id.trim().is_empty() {
        return Err(err("workspace_id must be non-empty"));
    }
    if ws.allowed_files.is_empty() {
        return Err(err("allowed_files must not be empty"));
    }
    for path in &ws.allowed_files {
        validate_relative_path(path)?;
    }
    Ok(())
}

pub fn validate_relative_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(err("path must be non-empty"));
    }
    if path.starts_with('/') || path.contains("..") {
        return Err(err(format!("path escapes isolated workspace: {path}")));
    }
    Ok(())
}

pub fn parse_version_output(
    worker_id: &str,
    provider: &str,
    cli_name: &str,
    raw: &str,
    discovered_at_unix_ms: u64,
) -> Result<VersionRecord> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(err("empty version output"));
    }
    let cli_version = trimmed
        .split_whitespace()
        .find(|tok| tok.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .unwrap_or(trimmed)
        .trim_matches(|c| c == 'v' || c == ',' || c == ';')
        .to_string();
    Ok(VersionRecord {
        worker_id: worker_id.to_string(),
        provider: provider.to_string(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        cli_name: cli_name.to_string(),
        cli_version,
        discovered_at_unix_ms,
    })
}

pub fn normalize_jsonl_events(jsonl: &str) -> Result<Vec<SessionEvent>> {
    let mut events = Vec::new();
    for (idx, line) in jsonl.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)?;
        let typ = value
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(format!("jsonl line {idx} missing type")))?;
        let (kind, summary) = match typ {
            "status" => (
                SessionEventKind::Status,
                value
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("status")
                    .to_string(),
            ),
            "assistant" | "message" => (
                SessionEventKind::Message,
                value
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            ),
            "tool_call" => {
                let path = value.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if path.is_empty() {
                    (
                        SessionEventKind::ToolCall,
                        value
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("tool")
                            .to_string(),
                    )
                } else {
                    (SessionEventKind::FileEdit, path.to_string())
                }
            }
            "tool_result" => (
                SessionEventKind::ToolResult,
                value
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("tool_result")
                    .to_string(),
            ),
            "usage" => (SessionEventKind::Usage, "usage".into()),
            "cancellation" => (
                SessionEventKind::Cancellation,
                value
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("cancelled")
                    .to_string(),
            ),
            "result" | "terminal" => (
                SessionEventKind::Terminal,
                value
                    .get("subtype")
                    .and_then(|v| v.as_str())
                    .unwrap_or("terminal")
                    .to_string(),
            ),
            "error" => (
                SessionEventKind::Error,
                value
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("error")
                    .to_string(),
            ),
            "version" => (
                SessionEventKind::Version,
                value
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("version")
                    .to_string(),
            ),
            other => return Err(err(format!("unknown jsonl event type: {other}"))),
        };
        events.push(SessionEvent {
            sequence: events.len() as u64,
            kind,
            summary,
            redaction: RedactionClass::None,
            payload_json: Some(line.to_string()),
        });
    }
    Ok(events)
}

pub fn extract_usage(events: &[SessionEvent]) -> UsageMetrics {
    let mut usage = UsageMetrics::default();
    for ev in events {
        if ev.kind != SessionEventKind::Usage {
            continue;
        }
        if let Some(raw) = &ev.payload_json {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
                usage.input_tokens = v.get("input_tokens").and_then(|x| x.as_u64()).unwrap_or(0);
                usage.output_tokens = v.get("output_tokens").and_then(|x| x.as_u64()).unwrap_or(0);
                usage.cached_tokens = v.get("cached_tokens").and_then(|x| x.as_u64()).unwrap_or(0);
                usage.peak_rss_bytes = v
                    .get("peak_rss_bytes")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(usage.peak_rss_bytes);
            }
        }
    }
    usage
}

pub fn extract_exit(events: &[SessionEvent]) -> (ExitClass, i32, SessionState) {
    for ev in events.iter().rev() {
        if ev.kind != SessionEventKind::Terminal && ev.kind != SessionEventKind::Cancellation {
            continue;
        }
        if let Some(raw) = &ev.payload_json {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
                let code = v.get("exit_code").and_then(|x| x.as_i64()).unwrap_or(1) as i32;
                let subtype = v.get("subtype").and_then(|x| x.as_str()).unwrap_or("");
                if ev.kind == SessionEventKind::Cancellation
                    || subtype == "cancelled"
                    || code == 130
                {
                    return (ExitClass::Cancelled, code, SessionState::Cancelled);
                }
                if code == 0 || subtype == "success" {
                    return (ExitClass::Success, code, SessionState::Completed);
                }
                return (ExitClass::Failure, code, SessionState::Failed);
            }
        }
        if ev.kind == SessionEventKind::Cancellation {
            return (ExitClass::Cancelled, 130, SessionState::Cancelled);
        }
    }
    (ExitClass::Failure, 1, SessionState::Failed)
}

pub fn collect_changed_paths(events: &[SessionEvent]) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    for ev in events {
        if ev.kind != SessionEventKind::FileEdit && ev.kind != SessionEventKind::ToolCall {
            continue;
        }
        if let Some(raw) = &ev.payload_json {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
                if let Some(path) = v.get("path").and_then(|x| x.as_str()) {
                    let bytes = v.get("bytes").and_then(|x| x.as_u64()).unwrap_or(0);
                    out.push((path.to_string(), bytes));
                }
            }
        }
    }
    out
}

pub fn enforce_allowed_files(
    workspace: &WorkspaceInput,
    changed: &[(String, u64)],
) -> Result<Vec<FileChange>> {
    let mut changes = Vec::new();
    for (path, bytes) in changed {
        validate_relative_path(path)?;
        let allowed = workspace.allowed_files.iter().any(|a| a == path);
        changes.push(FileChange {
            path: path.clone(),
            bytes_written: *bytes,
            within_allowlist: allowed,
        });
        if !allowed {
            return Err(err(format!(
                "policy-denied: path `{path}` is outside allowed-files"
            )));
        }
    }
    Ok(changes)
}

pub fn redact_text(manifest: &WorkerManifest, input: &str) -> (String, RedactionClass) {
    let mut out = input.to_string();
    let mut class = RedactionClass::None;
    let repl = manifest.redaction.replacement.as_str();

    let mut apply = |patterns: &[String], next: RedactionClass| {
        for pat in patterns {
            if let Ok(re) = Regex::new(pat) {
                if re.is_match(&out) {
                    if class == RedactionClass::None {
                        class = next;
                    }
                    out = re.replace_all(&out, repl).into_owned();
                }
            }
        }
    };

    apply(
        &manifest.redaction.credential_patterns,
        RedactionClass::Credential,
    );
    apply(
        &manifest.redaction.personal_record_patterns,
        RedactionClass::PersonalRecord,
    );
    apply(
        &manifest.redaction.absolute_path_patterns,
        RedactionClass::AbsolutePath,
    );
    (out, class)
}

pub fn apply_peak_rss(usage: &mut UsageMetrics, peak_rss_bytes: u64) {
    usage.peak_rss_bytes = peak_rss_bytes;
}

pub fn map_terminal_result(
    manifest: &WorkerManifest,
    session_id: &str,
    version: VersionRecord,
    events: Vec<SessionEvent>,
    changed_files: Vec<FileChange>,
    mut usage: UsageMetrics,
    secret_handle: Option<SecretHandle>,
) -> TerminalResult {
    let (exit, exit_status, state) = extract_exit(&events);
    if !manifest.terminal_result.include_peak_rss {
        usage.peak_rss_bytes = 0;
    }
    if !manifest.terminal_result.include_usage_tokens {
        usage.input_tokens = 0;
        usage.output_tokens = 0;
        usage.cached_tokens = 0;
    }
    TerminalResult {
        schema: manifest.terminal_result.schema.clone(),
        session_id: session_id.to_string(),
        worker_id: manifest.worker.id.clone(),
        provider: manifest.worker.provider.clone(),
        state,
        exit,
        exit_status,
        version,
        usage,
        events,
        changed_files,
        secret_handle,
        error_message: None,
    }
}
