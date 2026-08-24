//! Claude CLI compatibility adapter for `fractal-worker/v1`.
//!
//! Loads `manifests/workers/claude.toml`, performs real CLI version preflight
//! (`claude --version`, semver expected — stubs rejected), launches the Claude
//! CLI only inside a temporary isolated Git workspace, translates the native
//! `claude-stream-json` output into shared Fractal session events and a common
//! terminal result, propagates cancellation and deadlines, measures peak RSS,
//! and rejects out-of-allowlist file changes post-run via Git diff. Credentials
//! cross the boundary only as opaque handles; values are never logged and all
//! output is deterministically redacted using the manifest patterns.

use crate::cursor::{
    ensure_cancel_terminal, file_size_in, git_changed_paths, materialize_isolated_workspace,
    monitor_peak_rss, resource_limit_result, terminate_child, unix_now_ms, which_env_override,
};
use crate::{
    apply_peak_rss, collect_changed_paths, enforce_allowed_files, err, extract_usage,
    map_terminal_result, normalize_jsonl_events, parse_version_output, redact_text,
    validate_workspace_input, CancelRequest, ExitClass, OpenSessionOpts, RedactionClass, Result,
    SecretHandle, SessionEvent, SessionState, TerminalResult, VersionRecord, WorkerManifest,
    WorkspaceInput,
};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Live Claude launcher behind the Fractal worker boundary.
pub struct ClaudeLauncher;

impl ClaudeLauncher {
    /// Resolve the Claude executable via path-lookup (never a path embedded in the manifest).
    pub fn resolve_executable(manifest: &WorkerManifest) -> Result<PathBuf> {
        let mut candidates = vec![manifest.worker.executable.name.clone()];
        candidates.extend(manifest.worker.executable.aliases.iter().cloned());
        for name in candidates {
            if name.contains('/') || name.contains('\\') {
                return Err(err("executable name must be bare (path-lookup only)"));
            }
            if let Ok(path) = which_env_override("FRACTAL_CLAUDE_EXECUTABLE", &name) {
                return Ok(path);
            }
        }
        Err(err(format!(
            "claude CLI not found on PATH (tried {} and aliases)",
            manifest.worker.executable.name
        )))
    }

    /// Real CLI version preflight using manifest `discovery.version_args`.
    /// Refuses empty, non-semver, or stubbed output.
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
                "claude version preflight failed (status {:?}): {}",
                output.status.code(),
                redact_text(manifest, &stderr).0
            )));
        }
        let raw = String::from_utf8_lossy(&output.stdout);
        let version = parse_version_output(
            &manifest.worker.id,
            &manifest.worker.provider,
            &manifest.worker.executable.name,
            &raw,
            unix_now_ms(),
        )?;
        if manifest.discovery.expect_semver
            && !version
                .cli_version
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
        {
            return Err(err(format!(
                "claude version preflight got non-semver output: {}",
                redact_text(manifest, &raw).0
            )));
        }
        Ok(version)
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

        // Every session executes only inside a fresh isolated Git worktree.
        let isolated =
            materialize_isolated_workspace("fractal-claude", workspace, opts.seed_dir.as_deref())?;
        let session_id = format!("claude-{}", workspace.workspace_id);
        let secret = opts.secret.clone().or_else(secret_handle_from_env);

        let (raw_stream, peak_rss, cancelled, child_exit, wall_ms) =
            if let Some(jsonl) = &opts.replay_jsonl {
                let peak = opts.replay_peak_rss_bytes.unwrap_or(0);
                (jsonl.clone(), peak, false, 0, 0)
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

        // Deterministic redaction of the raw stream before any normalization.
        let (redacted_stream, _) = redact_text(manifest, &raw_stream);
        let mut events = translate_claude_stream(&isolated, &redacted_stream, child_exit)?;
        if cancelled {
            ensure_cancel_terminal(&mut events);
        }

        let mut usage = extract_usage(&events);
        usage.wall_time_ms = wall_ms;
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
        // Post-run diff: catch edits the stream never reported.
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
        // Redact any residual summaries.
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
    ) -> Result<(String, u64, bool, i32, u64)> {
        let started = Instant::now();
        let exe = Self::resolve_executable(manifest)?;
        let deadline_ms = deadline_unix_ms
            .map(|abs| abs.saturating_sub(unix_now_ms()))
            .unwrap_or(manifest.limits.default_deadline_ms);
        let deadline = Instant::now() + Duration::from_millis(deadline_ms.max(1));

        let mut args: Vec<String> = manifest.session.launch_args.clone();
        args.push(manifest.session.workspace_path_arg.clone());
        args.push(workspace_root.to_string_lossy().into_owned());
        if manifest.session.prompt_arg_mode == "positional" {
            args.push(prompt.to_string());
        }

        let stdin_mode = if manifest.session.prompt_arg_mode == "stdin" {
            Stdio::piped()
        } else {
            Stdio::null()
        };
        let mut cmd = Command::new(&exe);
        cmd.args(&args)
            .current_dir(workspace_root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(stdin_mode);
        apply_sanitized_env(&mut cmd, manifest, secret);

        let mut child = cmd.spawn()?;
        if manifest.session.prompt_arg_mode == "stdin" {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(prompt.as_bytes());
                let _ = stdin.flush();
                drop(stdin);
            }
        }
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
        let exit_status = child.wait()?;
        let wall_ms = started.elapsed().as_millis() as u64;
        let _ = monitor.join();
        let raw = reader.join().unwrap_or_default();
        let peak_rss = peak.load(Ordering::SeqCst);
        let child_exit = if cancelled {
            130
        } else {
            exit_status.code().unwrap_or(1)
        };
        Ok((raw, peak_rss, cancelled, child_exit, wall_ms))
    }
}

fn secret_handle_from_env() -> Option<SecretHandle> {
    let id = std::env::var("FRACTAL_CLAUDE_SECRET_HANDLE").ok()?;
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
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
        ] {
            if let Some(v) = std::env::var_os(key) {
                cmd.env(key, v);
            }
        }
    }
}

/// Relativize a tool-reported path against the isolated workspace root so
/// allowlist enforcement sees workspace-relative paths only. Absolute paths
/// outside the root are left intact and denied by enforcement.
fn relativize(root: &Path, file_path: &str) -> String {
    let p = Path::new(file_path);
    if p.is_absolute() {
        if let Ok(rel) = p.strip_prefix(root) {
            return rel.to_string_lossy().replace('\\', "/");
        }
        return file_path.to_string();
    }
    file_path.to_string()
}

/// Translate native `claude-stream-json` output into the shared Fractal JSONL
/// event dialect. Non-JSON lines become error events; a stream with no JSON at
/// all degrades to a single message plus a terminal using `fallback_exit`.
fn translate_claude_stream(
    root: &Path,
    raw: &str,
    fallback_exit: i32,
) -> Result<Vec<SessionEvent>> {
    let mut lines_out: Vec<String> = Vec::new();
    let mut json_seen = false;
    let mut tool_names: HashMap<String, String> = HashMap::new();

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            let msg: String = line.chars().take(300).collect();
            lines_out.push(serde_json::json!({"type": "error", "message": msg}).to_string());
            continue;
        };
        json_seen = true;
        let typ = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match typ {
            "system" => {
                let subtype = v
                    .get("subtype")
                    .and_then(|s| s.as_str())
                    .unwrap_or("system");
                lines_out
                    .push(serde_json::json!({"type": "status", "message": subtype}).to_string());
            }
            "assistant" | "user" => {
                let message = v.get("message").cloned().unwrap_or(serde_json::Value::Null);
                if let Some(text) = message.get("content").and_then(|c| c.as_str()) {
                    if typ == "assistant" {
                        lines_out.push(
                            serde_json::json!({"type": "assistant", "text": text}).to_string(),
                        );
                    }
                    continue;
                }
                let Some(blocks) = message.get("content").and_then(|c| c.as_array()) else {
                    continue;
                };
                for block in blocks {
                    let block_type = block.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    match block_type {
                        "text" if typ == "assistant" => {
                            let text = block.get("text").and_then(|t| t.as_str()).unwrap_or("");
                            lines_out.push(
                                serde_json::json!({"type": "assistant", "text": text}).to_string(),
                            );
                        }
                        "tool_use" => {
                            let name = block.get("name").and_then(|n| n.as_str()).unwrap_or("tool");
                            if let Some(id) = block.get("id").and_then(|i| i.as_str()) {
                                tool_names.insert(id.to_string(), name.to_string());
                            }
                            let input = block
                                .get("input")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null);
                            if let Some(file_path) = input.get("file_path").and_then(|f| f.as_str())
                            {
                                let rel = relativize(root, file_path);
                                let bytes = input
                                    .get("new_string")
                                    .and_then(|n| n.as_str())
                                    .map(|s| s.len() as u64)
                                    .unwrap_or(0);
                                lines_out.push(
                                    serde_json::json!({
                                        "type": "tool_call",
                                        "name": name,
                                        "path": rel,
                                        "bytes": bytes,
                                    })
                                    .to_string(),
                                );
                            } else {
                                lines_out.push(
                                    serde_json::json!({"type": "tool_call", "name": name})
                                        .to_string(),
                                );
                            }
                        }
                        "tool_result" => {
                            let name = block
                                .get("tool_use_id")
                                .and_then(|i| i.as_str())
                                .and_then(|i| tool_names.get(i))
                                .cloned()
                                .unwrap_or_else(|| "tool_result".into());
                            let ok = !block
                                .get("is_error")
                                .and_then(|e| e.as_bool())
                                .unwrap_or(false);
                            lines_out.push(
                                serde_json::json!({
                                    "type": "tool_result",
                                    "name": name,
                                    "ok": ok,
                                })
                                .to_string(),
                            );
                        }
                        _ => {}
                    }
                }
            }
            "result" => {
                if let Some(usage) = v.get("usage") {
                    lines_out.push(
                        serde_json::json!({
                            "type": "usage",
                            "input_tokens": usage.get("input_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
                            "output_tokens": usage.get("output_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
                            "cached_tokens": usage
                                .get("cache_read_input_tokens")
                                .and_then(|x| x.as_u64())
                                .unwrap_or(0),
                        })
                        .to_string(),
                    );
                }
                let subtype = v
                    .get("subtype")
                    .and_then(|s| s.as_str())
                    .unwrap_or("success");
                let is_error = v.get("is_error").and_then(|e| e.as_bool()).unwrap_or(false);
                let exit_code = if is_error || subtype.starts_with("error") {
                    1
                } else {
                    0
                };
                lines_out.push(
                    serde_json::json!({
                        "type": "result",
                        "subtype": subtype,
                        "exit_code": exit_code,
                    })
                    .to_string(),
                );
            }
            "error" => {
                let msg = v
                    .get("message")
                    .or_else(|| v.get("error"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("error");
                let msg: String = msg.chars().take(300).collect();
                lines_out.push(serde_json::json!({"type": "error", "message": msg}).to_string());
            }
            other => {
                lines_out.push(serde_json::json!({"type": "status", "message": other}).to_string());
            }
        }
    }

    if !json_seen {
        let text: String = raw.trim().chars().take(200).collect();
        lines_out.push(serde_json::json!({"type": "assistant", "text": text}).to_string());
        let subtype = if fallback_exit == 0 {
            "success"
        } else {
            "failure"
        };
        lines_out.push(
            serde_json::json!({
                "type": "result",
                "subtype": subtype,
                "exit_code": fallback_exit,
            })
            .to_string(),
        );
    }

    normalize_jsonl_events(&lines_out.join("\n"))
}

#[cfg(test)]
mod local_tests {
    use super::*;
    use crate::claude_manifest_path;
    use crate::{OpenSessionOpts, SecretHandle, SessionEventKind};

    fn manifest() -> WorkerManifest {
        WorkerManifest::load(claude_manifest_path()).unwrap()
    }

    fn ws() -> WorkspaceInput {
        WorkspaceInput {
            workspace_id: "claude-unit".into(),
            root_object_id: "root".into(),
            allowed_files: vec!["src/health.c".into()],
            verify_command: None,
        }
    }

    const NATIVE_STREAM: &str = concat!(
        r#"{"type":"system","subtype":"init","session_id":"s1"}"#,
        "\n",
        r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Editing the file."}]}}"#,
        "\n",
        r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Edit","input":{"file_path":"src/health.c","old_string":"return -1;","new_string":"return 0;"}}]}}"#,
        "\n",
        r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"ok"}]}}"#,
        "\n",
        r#"{"type":"result","subtype":"success","is_error":false,"usage":{"input_tokens":25,"output_tokens":70,"cache_read_input_tokens":8}}"#,
        "\n",
    );

    #[test]
    fn replay_maps_native_claude_stream_json_to_fractal_result() {
        let result = ClaudeLauncher::open_session(
            &manifest(),
            &ws(),
            "fix health",
            OpenSessionOpts {
                replay_jsonl: Some(NATIVE_STREAM.into()),
                replay_peak_rss_bytes: Some(2 * 1024 * 1024),
                secret: Some(SecretHandle {
                    id: "handle:claude-test".into(),
                    purpose: "cli-auth".into(),
                }),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(result.schema, crate::TERMINAL_RESULT_SCHEMA);
        assert_eq!(result.provider, "claude");
        assert_eq!(result.exit, ExitClass::Success);
        assert_eq!(result.state, SessionState::Completed);
        assert_eq!(result.usage.input_tokens, 25);
        assert_eq!(result.usage.output_tokens, 70);
        assert_eq!(result.usage.cached_tokens, 8);
        assert_eq!(result.usage.peak_rss_bytes, 2 * 1024 * 1024);
        assert!(result
            .changed_files
            .iter()
            .any(|f| f.path == "src/health.c" && f.within_allowlist));
        assert_eq!(
            result.secret_handle.as_ref().map(|h| h.id.as_str()),
            Some("handle:claude-test")
        );
        assert!(result
            .events
            .iter()
            .any(|e| e.kind == SessionEventKind::ToolResult && e.summary == "Edit"));
    }

    #[test]
    fn absolute_tool_paths_inside_workspace_relativize_outside_denied() {
        let root = Path::new("/tmp/fractal-claude-x");
        assert_eq!(
            relativize(root, "/tmp/fractal-claude-x/src/health.c"),
            "src/health.c"
        );
        assert_eq!(
            relativize(root, "/etc/passwd"),
            "/etc/passwd",
            "paths outside the isolated root must stay absolute so enforcement denies them"
        );
        assert_eq!(relativize(root, "src/health.c"), "src/health.c");
    }

    #[test]
    fn edit_outside_allowlist_is_policy_denied() {
        let mut outside = String::new();
        for line in NATIVE_STREAM.lines() {
            if line.contains("src/health.c") {
                outside.push_str(&line.replace("src/health.c", "README.md"));
            } else {
                outside.push_str(line);
            }
            outside.push('\n');
        }
        let result = ClaudeLauncher::open_session(
            &manifest(),
            &ws(),
            "noop",
            OpenSessionOpts {
                replay_jsonl: Some(outside),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(result.exit, ExitClass::PolicyDenied);
        assert_eq!(result.exit_status, 78);
        assert!(result
            .error_message
            .as_deref()
            .unwrap_or_default()
            .contains("policy-denied"));
    }

    #[test]
    fn peak_rss_over_limit_maps_to_resource_limit() {
        let result = ClaudeLauncher::open_session(
            &manifest(),
            &ws(),
            "noop",
            OpenSessionOpts {
                replay_jsonl: Some(NATIVE_STREAM.into()),
                replay_peak_rss_bytes: Some(157286401),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(result.exit, ExitClass::ResourceLimit);
        assert_eq!(result.exit_status, 137);
    }

    #[test]
    fn credentials_and_paths_are_redacted_in_translated_events() {
        let leak = concat!(
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"used token=sk-live-canary-value at /Users/alice/secret"}]}}"#,
            "\n",
            r#"{"type":"result","subtype":"success","is_error":false}"#,
            "\n",
        );
        let result = ClaudeLauncher::open_session(
            &manifest(),
            &ws(),
            "noop",
            OpenSessionOpts {
                replay_jsonl: Some(leak.into()),
                ..Default::default()
            },
        )
        .unwrap();
        let blob = serde_json::to_string(&result).unwrap();
        assert!(!blob.contains("sk-live-canary-value"));
        assert!(!blob.contains("/Users/alice"));
        assert!(blob.contains("[REDACTED]"));
    }

    #[test]
    fn non_json_stream_falls_back_to_message_and_child_exit() {
        let events = translate_claude_stream(Path::new("/w"), "plain stdout noise", 0).unwrap();
        assert_eq!(events.last().unwrap().kind, SessionEventKind::Terminal);
        let (_, code, state) = crate::extract_exit(&events);
        assert_eq!((code, state), (0, SessionState::Completed));

        let events = translate_claude_stream(Path::new("/w"), "boom", 1).unwrap();
        let (_, code, state) = crate::extract_exit(&events);
        assert_eq!((code, state), (1, SessionState::Failed));
    }

    #[test]
    fn error_result_subtype_maps_to_failure() {
        let stream = concat!(
            r#"{"type":"result","subtype":"error_during_execution","is_error":true}"#,
            "\n",
        );
        let events = translate_claude_stream(Path::new("/w"), stream, 0).unwrap();
        let (exit, code, state) = crate::extract_exit(&events);
        assert_eq!(
            (exit, code, state),
            (ExitClass::Failure, 1, SessionState::Failed)
        );
    }
}
