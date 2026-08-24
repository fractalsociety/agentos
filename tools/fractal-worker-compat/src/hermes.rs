//! Hermes CLI compatibility adapter for `fractal-worker/v1`.
//!
//! Loads `manifests/workers/hermes.toml`, performs real CLI version preflight
//! (`hermes --version`, semver expected — stubs rejected), launches the Hermes
//! CLI only inside a temporary isolated Git workspace, normalizes native
//! `hermes-jsonl` output into shared Fractal session events and a common
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
    SecretHandle, SessionEvent, SessionEventKind, SessionState, TerminalResult, VersionRecord,
    WorkerManifest, WorkspaceInput,
};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Live Hermes launcher behind the Fractal worker boundary.
pub struct HermesLauncher;

impl HermesLauncher {
    /// Resolve the Hermes executable via path-lookup (never a path embedded in the manifest).
    pub fn resolve_executable(manifest: &WorkerManifest) -> Result<PathBuf> {
        let mut candidates = vec![manifest.worker.executable.name.clone()];
        candidates.extend(manifest.worker.executable.aliases.iter().cloned());
        for name in candidates {
            if name.contains('/') || name.contains('\\') {
                return Err(err("executable name must be bare (path-lookup only)"));
            }
            if let Ok(path) = which_env_override("FRACTAL_HERMES_EXECUTABLE", &name) {
                return Ok(path);
            }
        }
        Err(err(format!(
            "hermes CLI not found on PATH (tried {} and aliases)",
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
                "hermes version preflight failed (status {:?}): {}",
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
        let lower = version.cli_version.to_ascii_lowercase();
        if lower.contains("stub") || lower.contains("fake") {
            return Err(err("hermes version preflight returned a stub identity"));
        }
        if manifest.discovery.expect_semver
            && !version
                .cli_version
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
        {
            return Err(err(format!(
                "hermes version preflight got non-semver output: {}",
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
        if !manifest.session.requires_isolated_git_workspace {
            return Err(err("refusing to launch: isolated Git workspace required"));
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
            materialize_isolated_workspace("fractal-hermes", workspace, opts.seed_dir.as_deref())?;
        let session_id = format!("hermes-{}", workspace.workspace_id);
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

        // Normalize first so broad manifest regexes cannot corrupt JSON quoting;
        // every normalized event is deterministically redacted before return.
        let mut events = normalize_hermes_stream(&isolated, &raw_stream, child_exit)?;
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
            if let Some(payload) = &ev.payload_json {
                let (payload, payload_class) = redact_text(manifest, payload);
                ev.payload_json = Some(payload);
                if payload_class != RedactionClass::None {
                    ev.redaction = payload_class;
                }
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
    let id = std::env::var("FRACTAL_HERMES_SECRET_HANDLE").ok()?;
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
    // Inherited auth channel only: the Fractal boundary passes only an opaque
    // handle. Raw API keys/tokens are deliberately not copied into the child.
    if manifest.auth.inherit_process_channel {
        for key in [
            "HOME",
            "USER",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "HERMES_CONFIG",
            "HERMES_PROFILE",
        ] {
            if let Some(v) = std::env::var_os(key) {
                cmd.env(key, v);
            }
        }
    }
}

fn normalize_hermes_stream(
    _root: &Path,
    raw: &str,
    fallback_exit: i32,
) -> Result<Vec<SessionEvent>> {
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
    match normalize_jsonl_events(trimmed) {
        Ok(mut events) => {
            if !events.iter().any(|e| e.kind == SessionEventKind::Terminal) {
                let subtype = if fallback_exit == 0 {
                    "success"
                } else {
                    "failure"
                };
                events.push(SessionEvent {
                    sequence: events.len() as u64,
                    kind: SessionEventKind::Terminal,
                    summary: subtype.into(),
                    redaction: RedactionClass::None,
                    payload_json: Some(
                        serde_json::json!({
                            "type": "result",
                            "subtype": subtype,
                            "exit_code": fallback_exit,
                        })
                        .to_string(),
                    ),
                });
            }
            Ok(events)
        }
        Err(_) => {
            let text: String = trimmed.chars().take(300).collect();
            let subtype = if fallback_exit == 0 {
                "success"
            } else {
                "failure"
            };
            Ok(vec![
                SessionEvent {
                    sequence: 0,
                    kind: SessionEventKind::Message,
                    summary: text.clone(),
                    redaction: RedactionClass::None,
                    payload_json: Some(
                        serde_json::json!({"type":"assistant","text":text}).to_string(),
                    ),
                },
                SessionEvent {
                    sequence: 1,
                    kind: SessionEventKind::Terminal,
                    summary: subtype.into(),
                    redaction: RedactionClass::None,
                    payload_json: Some(
                        serde_json::json!({
                            "type":"result",
                            "subtype":subtype,
                            "exit_code":fallback_exit,
                        })
                        .to_string(),
                    ),
                },
            ])
        }
    }
}

#[cfg(test)]
mod local_tests {
    use super::*;
    use crate::hermes_manifest_path;

    fn manifest() -> WorkerManifest {
        WorkerManifest::load(hermes_manifest_path()).unwrap()
    }

    fn ws() -> WorkspaceInput {
        WorkspaceInput {
            workspace_id: "hermes-unit".into(),
            root_object_id: "root".into(),
            allowed_files: vec!["src/health.c".into()],
            verify_command: None,
        }
    }

    const HERMES_JSONL: &str = concat!(
        r#"{"type":"status","message":"started"}"#,
        "\n",
        r#"{"type":"assistant","text":"Editing src/lib.rs token=sk-CANARY"}"#,
        "\n",
        r#"{"type":"tool_call","name":"edit","path":"src/health.c","bytes":28}"#,
        "\n",
        r#"{"type":"usage","input_tokens":5,"output_tokens":7,"cached_tokens":2}"#,
        "\n",
        r#"{"type":"result","subtype":"success","exit_code":0}"#,
        "\n",
    );
    #[test]
    fn replay_maps_native_hermes_jsonl_to_fractal_result() {
        let result = HermesLauncher::open_session(
            &manifest(),
            &ws(),
            "fix health",
            OpenSessionOpts {
                replay_jsonl: Some(HERMES_JSONL.into()),
                replay_peak_rss_bytes: Some(3 * 1024 * 1024),
                secret: Some(SecretHandle {
                    id: "handle:hermes-test".into(),
                    purpose: "cli-auth".into(),
                }),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(result.provider, "hermes");
        assert_eq!(result.exit, ExitClass::Success);
        assert_eq!(result.state, SessionState::Completed);
        assert_eq!(result.usage.input_tokens, 5);
        assert_eq!(result.usage.output_tokens, 7);
        assert_eq!(result.usage.cached_tokens, 2);
        assert_eq!(result.usage.peak_rss_bytes, 3 * 1024 * 1024);
        assert!(result
            .changed_files
            .iter()
            .any(|f| f.path == "src/health.c" && f.within_allowlist));
        let blob = serde_json::to_string(&result).unwrap();
        assert!(!blob.contains("sk-CANARY"));
        assert_eq!(
            result.secret_handle.as_ref().map(|h| h.id.as_str()),
            Some("handle:hermes-test")
        );
    }

    #[test]
    fn replay_denies_file_edits_outside_allowlist() {
        let result = HermesLauncher::open_session(
            &manifest(),
            &ws(),
            "noop",
            OpenSessionOpts {
                replay_jsonl: Some(HERMES_JSONL.replace("src/health.c", "README.md")),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(result.exit, ExitClass::PolicyDenied);
        assert_eq!(result.exit_status, 78);
    }

    #[test]
    fn peak_rss_over_limit_maps_to_resource_limit() {
        let result = HermesLauncher::open_session(
            &manifest(),
            &ws(),
            "noop",
            OpenSessionOpts {
                replay_jsonl: Some(HERMES_JSONL.into()),
                replay_peak_rss_bytes: Some(157286401),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(result.exit, ExitClass::ResourceLimit);
        assert_eq!(result.exit_status, 137);
    }
}
