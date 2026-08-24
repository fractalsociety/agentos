//! Cursor CLI compatibility adapter for `fractal-worker/v1`.
//!
//! Loads `manifests/workers/cursor.toml`, runs real version preflight, launches
//! the official Cursor CLI inside a temporary isolated Git workspace, normalizes
//! streaming output, propagates cancellation/deadlines, measures peak RSS, and
//! rejects out-of-allowlist file changes. Credentials cross the boundary only as
//! opaque handles; values are never logged.

use crate::{
    apply_peak_rss, collect_changed_paths, enforce_allowed_files, err, extract_usage,
    map_terminal_result, normalize_jsonl_events, parse_version_output, redact_text,
    validate_workspace_input, CancelRequest, CompatError, ExitClass, RedactionClass, Result,
    SecretHandle, SessionEvent, SessionEventKind, SessionState, TerminalResult, UsageMetrics,
    VersionRecord, WorkerManifest, WorkspaceInput,
};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Options for a live or replay Cursor session.
#[derive(Debug, Clone, Default)]
pub struct OpenSessionOpts {
    pub secret: Option<SecretHandle>,
    pub deadline_unix_ms: Option<u64>,
    pub cancel: Option<Arc<AtomicBool>>,
    /// When set, do not spawn the CLI; normalize this JSONL as the session stream.
    pub replay_jsonl: Option<String>,
    /// Peak RSS override used with replay (bytes).
    pub replay_peak_rss_bytes: Option<u64>,
    /// Optional seed directory whose allowed files are copied into the isolated tree.
    pub seed_dir: Option<PathBuf>,
}

/// Live Cursor launcher behind the Fractal worker boundary.
pub struct CursorLauncher;

impl CursorLauncher {
    /// Resolve the Cursor executable via path-lookup (never a path embedded in the manifest).
    pub fn resolve_executable(manifest: &WorkerManifest) -> Result<PathBuf> {
        let mut candidates = vec![manifest.worker.executable.name.clone()];
        candidates.extend(manifest.worker.executable.aliases.iter().cloned());
        for name in candidates {
            if name.contains('/') || name.contains('\\') {
                return Err(err("executable name must be bare (path-lookup only)"));
            }
            if let Ok(path) = which(&name) {
                return Ok(path);
            }
        }
        Err(err(format!(
            "cursor CLI not found on PATH (tried {} and aliases)",
            manifest.worker.executable.name
        )))
    }

    /// Real CLI version preflight using manifest `discovery.version_args`.
    pub fn discover_version_live(manifest: &WorkerManifest) -> Result<VersionRecord> {
        let exe = Self::resolve_executable(manifest)?;
        let output = Command::new(&exe)
            .args(&manifest.discovery.version_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(err(format!(
                "cursor version preflight failed (status {:?}): {}",
                output.status.code(),
                redact_text(manifest, &stderr).0
            )));
        }
        let raw = String::from_utf8_lossy(&output.stdout);
        let now = unix_now_ms();
        parse_version_output(
            &manifest.worker.id,
            &manifest.worker.provider,
            &manifest.worker.executable.name,
            &raw,
            now,
        )
    }

    /// Open a live session (or replay when `opts.replay_jsonl` is set).
    pub fn open_session_live(
        manifest: &WorkerManifest,
        workspace: &WorkspaceInput,
        prompt: &str,
    ) -> Result<TerminalResult> {
        Self::open_session(manifest, workspace, prompt, OpenSessionOpts::default())
    }

    pub fn open_session(
        manifest: &WorkerManifest,
        workspace: &WorkspaceInput,
        prompt: &str,
        opts: OpenSessionOpts,
    ) -> Result<TerminalResult> {
        validate_workspace_input(workspace)?;
        if !manifest.grants_no_authority() {
            return Err(err("refusing to launch: manifest grants ambient authority"));
        }

        let version = if opts.replay_jsonl.is_some() {
            parse_version_output(
                &manifest.worker.id,
                &manifest.worker.provider,
                &manifest.worker.executable.name,
                "0.0.0-replay",
                unix_now_ms(),
            )?
        } else {
            Self::discover_version_live(manifest)?
        };

        let isolated =
            materialize_isolated_workspace("fractal-cursor", workspace, opts.seed_dir.as_deref())?;
        let session_id = format!("cursor-{}", workspace.workspace_id);
        let secret = opts.secret.clone().or_else(secret_handle_from_env);

        let (raw_stream, peak_rss, cancelled) = if let Some(jsonl) = &opts.replay_jsonl {
            let peak = opts.replay_peak_rss_bytes.unwrap_or(0);
            (jsonl.clone(), peak, false)
        } else {
            Self::spawn_and_collect(
                manifest,
                &isolated,
                prompt,
                &secret,
                opts.deadline_unix_ms,
                opts.cancel.clone(),
            )?
        };

        let (redacted_stream, _) = redact_text(manifest, &raw_stream);
        let mut events = normalize_cursor_stream(&redacted_stream)?;
        if cancelled {
            ensure_cancel_terminal(&mut events);
        }

        let mut usage = extract_usage(&events);
        apply_peak_rss(&mut usage, peak_rss);
        if peak_rss > manifest.limits.max_rss_bytes {
            return Ok(resource_limit_result(
                manifest,
                &session_id,
                version,
                events,
                usage,
                secret,
                peak_rss,
            ));
        }

        let mut changed = collect_changed_paths(&events);
        let diff_paths = git_changed_paths(&isolated)?;
        for p in diff_paths {
            if !changed.iter().any(|(c, _)| c == &p) {
                let bytes = file_size_in(&isolated, &p).unwrap_or(0);
                changed.push((p, bytes));
            }
        }

        let files = match enforce_allowed_files(workspace, &changed) {
            Ok(f) => f,
            Err(e) => {
                let mut result = map_terminal_result(
                    manifest,
                    &session_id,
                    version,
                    events,
                    vec![],
                    usage,
                    secret,
                );
                result.state = SessionState::Failed;
                result.exit = ExitClass::PolicyDenied;
                result.exit_status = 78;
                result.error_message = Some(e.to_string());
                return Ok(result);
            }
        };

        let mut result =
            map_terminal_result(manifest, &session_id, version, events, files, usage, secret);
        // Redact any residual summaries
        for ev in &mut result.events {
            let (summary, class) = redact_text(manifest, &ev.summary);
            ev.summary = summary;
            if class != RedactionClass::None {
                ev.redaction = class;
            }
        }
        Ok(result)
    }

    /// Propagate cancellation into a running session flag and build a cancel envelope helper.
    pub fn request_cancel(flag: &AtomicBool, request: &CancelRequest) -> CancelRequest {
        flag.store(true, Ordering::SeqCst);
        request.clone()
    }

    fn spawn_and_collect(
        manifest: &WorkerManifest,
        workspace_root: &Path,
        prompt: &str,
        secret: &Option<SecretHandle>,
        deadline_unix_ms: Option<u64>,
        cancel: Option<Arc<AtomicBool>>,
    ) -> Result<(String, u64, bool)> {
        let exe = Self::resolve_executable(manifest)?;
        let deadline_ms = deadline_unix_ms
            .map(|abs| abs.saturating_sub(unix_now_ms()))
            .unwrap_or(manifest.limits.default_deadline_ms);
        let deadline = Instant::now() + Duration::from_millis(deadline_ms.max(1));

        let mut args: Vec<String> = manifest.session.launch_args.clone();
        args.push(manifest.session.workspace_path_arg.clone());
        args.push(workspace_root.to_string_lossy().into_owned());
        // Prefer stream-json when manifest asked for jsonl semantics.
        if let Some(idx) = args.iter().position(|a| a == "json") {
            if manifest.session.stream_format == "jsonl" {
                args[idx] = "stream-json".into();
            }
        }
        if manifest.session.prompt_arg_mode == "positional" {
            args.push(prompt.to_string());
        }

        let mut cmd = Command::new(&exe);
        cmd.args(&args)
            .current_dir(workspace_root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());
        apply_sanitized_env(&mut cmd, manifest, secret);

        let mut child = cmd.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| err("missing child stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| err("missing child stderr"))?;

        let peak = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let peak_bg = Arc::clone(&peak);
        let pid = child.id();
        let monitor = thread::spawn(move || monitor_peak_rss(pid, peak_bg, deadline));

        let reader = thread::spawn(move || {
            let mut out = String::new();
            let mut buf = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match buf.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => out.push_str(&line),
                    Err(_) => break,
                }
            }
            let mut err_buf = String::new();
            let _ = BufReader::new(stderr).read_to_string(&mut err_buf);
            if !err_buf.is_empty() {
                out.push_str(&err_buf);
            }
            out
        });

        let mut cancelled = false;
        loop {
            if cancel.as_ref().is_some_and(|c| c.load(Ordering::SeqCst))
                || Instant::now() >= deadline
            {
                cancelled = true;
                let _ = terminate_child(&mut child);
                break;
            }
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(e) => return Err(e.into()),
            }
        }
        let _ = child.wait();
        let _ = monitor.join();
        let raw = reader.join().unwrap_or_default();
        let peak_rss = peak.load(Ordering::SeqCst);
        Ok((raw, peak_rss, cancelled))
    }
}

fn secret_handle_from_env() -> Option<SecretHandle> {
    let id = std::env::var("FRACTAL_CURSOR_SECRET_HANDLE").ok()?;
    if id.is_empty() {
        return None;
    }
    Some(SecretHandle {
        id,
        purpose: "cli-auth".into(),
    })
}

fn apply_sanitized_env(
    cmd: &mut Command,
    manifest: &WorkerManifest,
    secret: &Option<SecretHandle>,
) {
    cmd.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    if let Some(tmpdir) = std::env::var_os("TMPDIR") {
        cmd.env("TMPDIR", tmpdir);
    }
    if let Some(lang) = std::env::var_os("LANG") {
        cmd.env("LANG", lang);
    }
    if let Some(h) = secret {
        cmd.env(&manifest.auth.handle_env, &h.id);
    } else if let Ok(id) = std::env::var(&manifest.auth.handle_env) {
        cmd.env(&manifest.auth.handle_env, id);
    }
    // Inherited auth channel only — values are never read into logs.
    if manifest.auth.inherit_process_channel {
        for key in [
            "HOME",
            "USER",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "CURSOR_API_KEY",
            "CURSOR_AUTH_TOKEN",
        ] {
            if let Some(v) = std::env::var_os(key) {
                cmd.env(key, v);
            }
        }
    }
}

pub(crate) fn materialize_isolated_workspace(
    prefix: &str,
    workspace: &WorkspaceInput,
    seed_dir: Option<&Path>,
) -> Result<PathBuf> {
    static WORKSPACE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = WORKSPACE_SEQ.fetch_add(1, Ordering::SeqCst);
    let base = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}-{}-{}",
        sanitize_id(&workspace.workspace_id),
        std::process::id(),
        seq,
        unix_now_ms()
    ));
    std::fs::create_dir_all(&base)?;
    run_git(&base, &["init", "-q"])?;
    run_git(&base, &["config", "user.name", "Fractal Worker"])?;
    run_git(&base, &["config", "user.email", "fractal-worker@invalid"])?;

    for rel in &workspace.allowed_files {
        crate::validate_relative_path(rel)?;
        let dest = base.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if let Some(seed) = seed_dir {
            let src = seed.join(rel);
            if src.is_file() {
                std::fs::copy(&src, &dest)?;
            } else {
                std::fs::write(&dest, b"")?;
            }
        } else {
            std::fs::write(&dest, b"")?;
        }
    }
    run_git(&base, &["add", "-A"])?;
    run_git(&base, &["commit", "-qm", "fractal-baseline"])?;
    Ok(base)
}

pub(crate) fn run_git(cwd: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(err(format!("git {:?} failed", args)));
    }
    Ok(())
}

pub(crate) fn git_changed_paths(cwd: &Path) -> Result<Vec<String>> {
    let output = Command::new("git")
        .args(["diff", "--name-only", "HEAD"])
        .current_dir(cwd)
        .output()?;
    let mut paths = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let p = line.trim();
        if !p.is_empty() {
            paths.push(p.to_string());
        }
    }
    let untracked = Command::new("git")
        .args(["ls-files", "--others", "--exclude-standard"])
        .current_dir(cwd)
        .output()?;
    for line in String::from_utf8_lossy(&untracked.stdout).lines() {
        let p = line.trim();
        if !p.is_empty() && !paths.iter().any(|x| x == p) {
            paths.push(p.to_string());
        }
    }
    Ok(paths)
}

pub(crate) fn file_size_in(root: &Path, rel: &str) -> Result<u64> {
    Ok(std::fs::metadata(root.join(rel))
        .map(|m| m.len())
        .unwrap_or(0))
}

fn normalize_cursor_stream(raw: &str) -> Result<Vec<SessionEvent>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(vec![SessionEvent {
            sequence: 0,
            kind: SessionEventKind::Status,
            summary: "empty-stream".into(),
            redaction: RedactionClass::None,
            payload_json: None,
        }]);
    }
    // Prefer JSONL; if a single JSON object, wrap as one line.
    if trimmed.starts_with('{') && !trimmed.contains('\n') {
        return normalize_jsonl_events(trimmed);
    }
    match normalize_jsonl_events(raw) {
        Ok(events) => Ok(events),
        Err(_) => {
            // Fallback: treat non-JSONL stdout as a single message + success terminal.
            let mut events = vec![SessionEvent {
                sequence: 0,
                kind: SessionEventKind::Message,
                summary: trimmed.chars().take(200).collect(),
                redaction: RedactionClass::None,
                payload_json: Some(
                    serde_json::json!({"type":"assistant","text":trimmed}).to_string(),
                ),
            }];
            events.push(SessionEvent {
                sequence: 1,
                kind: SessionEventKind::Terminal,
                summary: "success".into(),
                redaction: RedactionClass::None,
                payload_json: Some(
                    "{\"type\":\"result\",\"subtype\":\"success\",\"exit_code\":0}".into(),
                ),
            });
            Ok(events)
        }
    }
}

pub(crate) fn ensure_cancel_terminal(events: &mut Vec<SessionEvent>) {
    if events
        .iter()
        .any(|e| e.kind == SessionEventKind::Cancellation)
    {
        return;
    }
    events.push(SessionEvent {
        sequence: events.len() as u64,
        kind: SessionEventKind::Cancellation,
        summary: "cancelled".into(),
        redaction: RedactionClass::None,
        payload_json: Some("{\"type\":\"cancellation\",\"reason\":\"deadline-or-cancel\"}".into()),
    });
    events.push(SessionEvent {
        sequence: events.len() as u64,
        kind: SessionEventKind::Terminal,
        summary: "cancelled".into(),
        redaction: RedactionClass::None,
        payload_json: Some(
            "{\"type\":\"result\",\"subtype\":\"cancelled\",\"exit_code\":130}".into(),
        ),
    });
}

pub(crate) fn resource_limit_result(
    manifest: &WorkerManifest,
    session_id: &str,
    version: VersionRecord,
    events: Vec<SessionEvent>,
    usage: UsageMetrics,
    secret: Option<SecretHandle>,
    peak: u64,
) -> TerminalResult {
    let mut result =
        map_terminal_result(manifest, session_id, version, events, vec![], usage, secret);
    result.state = SessionState::Failed;
    result.exit = ExitClass::ResourceLimit;
    result.exit_status = 137;
    result.error_message = Some(format!(
        "peak RSS {peak} exceeds limit {}",
        manifest.limits.max_rss_bytes
    ));
    result
}

pub(crate) fn monitor_peak_rss(
    pid: u32,
    peak: Arc<std::sync::atomic::AtomicU64>,
    deadline: Instant,
) {
    while Instant::now() < deadline {
        if let Some(rss) = sample_rss_bytes(pid) {
            peak.fetch_max(rss, Ordering::SeqCst);
        } else {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn sample_rss_bytes(pid: u32) -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("ps")
            .args(["-o", "rss=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let kb: u64 = text.trim().parse().ok()?;
        Some(kb.saturating_mul(1024))
    }
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmHWM:") {
                let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
                return Some(kb.saturating_mul(1024));
            }
        }
        return None;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
}

pub(crate) fn terminate_child(child: &mut Child) -> Result<()> {
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

fn which(name: &str) -> Result<PathBuf> {
    which_env_override("FRACTAL_CURSOR_EXECUTABLE", name)
}

pub(crate) fn which_env_override(env_var: &str, name: &str) -> Result<PathBuf> {
    if let Ok(path) = std::env::var(env_var) {
        let p = PathBuf::from(&path);
        if p.is_file() {
            return Ok(p);
        }
    }
    let output = Command::new("which").arg(name).output()?;
    if !output.status.success() {
        return Err(CompatError::Message(format!("{name} not found")));
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        return Err(err(format!("{name} not found")));
    }
    Ok(PathBuf::from(path))
}

pub(crate) fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect()
}

#[cfg(test)]
mod local_tests {
    use super::*;
    use crate::cursor_manifest_path;

    #[test]
    fn replay_session_maps_fixture_without_launcher_stub() {
        let manifest = WorkerManifest::load(cursor_manifest_path()).unwrap();
        let ws = WorkspaceInput {
            workspace_id: "unit".into(),
            root_object_id: "root".into(),
            allowed_files: vec!["src/health.c".into()],
            verify_command: None,
        };
        let jsonl =
            std::fs::read_to_string(crate::cursor_fixture_dir().join("session.jsonl")).unwrap();
        let result = CursorLauncher::open_session(
            &manifest,
            &ws,
            "noop",
            OpenSessionOpts {
                replay_jsonl: Some(jsonl),
                replay_peak_rss_bytes: Some(1024 * 1024),
                secret: Some(SecretHandle {
                    id: "handle:test".into(),
                    purpose: "cli-auth".into(),
                }),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(result.schema, crate::TERMINAL_RESULT_SCHEMA);
        assert_eq!(result.exit, ExitClass::Success);
        assert_eq!(result.usage.peak_rss_bytes, 1024 * 1024);
        assert!(result
            .changed_files
            .iter()
            .all(|f| f.path == "src/health.c"));
    }
}
