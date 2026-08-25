use fractal_worker_compat::{
    apply_peak_rss, collect_changed_paths, enforce_allowed_files, extract_usage,
    map_terminal_result, normalize_jsonl_events, parse_version_output, redact_text,
    scan_manifest_safety, validate_workspace_input, worker_wit_path, CancelRequest, ExitClass,
    RedactionClass, SecretHandle, SessionEvent, SessionEventKind, SessionState, UsageMetrics,
    VersionRecord, WorkerManifest, WorkspaceInput, TERMINAL_RESULT_SCHEMA,
};
use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn manifest_path(worker: &str) -> PathBuf {
    repo_root().join(format!("manifests/workers/{worker}.toml"))
}

fn load_manifest(worker: &str) -> WorkerManifest {
    WorkerManifest::load(manifest_path(worker)).expect("worker manifest must load")
}

fn assert_worker_wit_contract() {
    let wit = fs::read_to_string(worker_wit_path()).expect("read worker.wit");
    for needle in [
        "package fractal:worker@1.0.0;",
        "record version-record",
        "record workspace-input",
        "record session-event",
        "record terminal-result",
        "record usage-metrics",
        "peak-rss-bytes",
        "secret-handle",
        "discover-version",
        "open-session",
        "next-event",
        "cancel",
        "collect-terminal",
        "enforce-allowed-files",
        "redact-text",
        "world fractal-worker-v1",
    ] {
        assert!(
            wit.contains(needle),
            "worker.wit missing required fragment: {needle}"
        );
    }
}

fn valid_workspace() -> WorkspaceInput {
    WorkspaceInput {
        workspace_id: "ws-fixture-1".into(),
        root_object_id: "a".repeat(64),
        allowed_files: vec!["src/lib.rs".into()],
        verify_command: None,
    }
}

fn fixture_version(worker: &str, raw: &str) -> VersionRecord {
    parse_version_output(worker, worker, worker, raw, 1_700_000_000_000).expect("parse version")
}

fn canonical_jsonl() -> &'static str {
    "{\"type\":\"status\",\"message\":\"started\"}\n\
{\"type\":\"assistant\",\"text\":\"editing src/lib.rs\"}\n\
{\"type\":\"tool_call\",\"name\":\"edit\",\"path\":\"src/lib.rs\",\"bytes\":12}\n\
{\"type\":\"usage\",\"input_tokens\":10,\"output_tokens\":5,\"cached_tokens\":0}\n\
{\"type\":\"result\",\"subtype\":\"success\",\"exit_code\":0}\n"
}

fn terminal_result_for(
    worker: &str,
    native_version: &str,
) -> fractal_worker_compat::TerminalResult {
    let manifest = load_manifest(worker);
    let events = normalize_jsonl_events(canonical_jsonl()).expect("normalize events");
    let mut usage = extract_usage(&events);
    apply_peak_rss(&mut usage, 64 * 1024 * 1024);
    let changed = collect_changed_paths(&events);
    let files = enforce_allowed_files(&valid_workspace(), &changed).expect("allowed files");
    map_terminal_result(
        &manifest,
        "sess-fixture-1",
        fixture_version(worker, native_version),
        events,
        files,
        usage,
        Some(SecretHandle {
            id: format!("handle:{worker}-opaque-test"),
            purpose: "cli-auth".into(),
        }),
    )
}

fn semantic_projection(
    result: &fractal_worker_compat::TerminalResult,
) -> (SessionState, ExitClass, i32, Vec<String>, UsageMetrics) {
    (
        result.state.clone(),
        result.exit.clone(),
        result.exit_status,
        result
            .changed_files
            .iter()
            .map(|f| f.path.clone())
            .collect(),
        result.usage.clone(),
    )
}

fn preflight_version_record(worker: &str, manifest: &WorkerManifest, raw: &str) -> VersionRecord {
    assert!(manifest.discovery.requires_real_version_preflight);
    assert!(manifest.discovery.expect_semver);
    let version = parse_version_output(
        &manifest.worker.id,
        &manifest.worker.provider,
        &manifest.worker.executable.name,
        raw,
        1_700_000_000_000,
    )
    .expect("parse non-stub CLI version output");
    assert_eq!(version.worker_id, worker);
    assert_eq!(version.provider, worker);
    assert_eq!(version.cli_name, worker);
    assert!(!version.cli_version.trim().is_empty());
    assert!(!version.cli_version.to_ascii_lowercase().contains("stub"));
    version
}

#[test]
fn claude_manifest_loads_without_shell_network_filesystem_authority_or_secrets() {
    assert_worker_wit_contract();
    let text = fs::read_to_string(manifest_path("claude")).expect("read manifest");
    scan_manifest_safety(&text).expect("manifest safety scan");
    assert!(text.contains("native_output_format = \"claude-stream-json\""));
    let m = load_manifest("claude");
    assert_eq!(m.worker.id, "claude");
    assert_eq!(m.worker.provider, "claude");
    assert_eq!(m.worker.protocol, "fractal-worker/v1");
    assert_eq!(m.worker.executable.name, "claude");
    assert!(m.grants_no_authority());
    assert!(!m.policy.grant_shell);
    assert!(!m.policy.grant_network);
    assert!(!m.policy.grant_filesystem);
    assert_eq!(m.auth.mode, "opaque-secret-handle");
    assert_eq!(m.terminal_result.schema, TERMINAL_RESULT_SCHEMA);
}

#[test]
fn claude_manifest_requires_real_version_preflight_and_accepts_non_stub_cli_identity() {
    let manifest = load_manifest("claude");
    let version = preflight_version_record("claude", &manifest, "Claude Code 1.2.3");
    assert_eq!(version.cli_version, "1.2.3");
}

#[test]
fn claude_version_output_parser_records_real_cli_identity() {
    let version = fixture_version("claude", "Claude Code 1.2.3");
    assert_eq!(version.worker_id, "claude");
    assert_eq!(version.cli_name, "claude");
    assert_eq!(version.cli_version, "1.2.3");
}

#[test]
fn claude_isolated_repository_input_rejects_absolute_and_parent_paths() {
    let mut ws = valid_workspace();
    validate_workspace_input(&ws).expect("valid isolated workspace input");
    ws.allowed_files = vec!["/tmp/evil.rs".into()];
    assert!(validate_workspace_input(&ws).is_err());
    ws.allowed_files = vec!["../outside.rs".into()];
    assert!(validate_workspace_input(&ws).is_err());
}

#[test]
fn claude_stream_json_normalizes_to_shared_fractal_events() {
    let events = normalize_jsonl_events(canonical_jsonl())
        .expect("normalize Claude stream-json adapter JSONL");
    assert!(events.iter().any(|e| e.kind == SessionEventKind::Status));
    assert!(events.iter().any(|e| e.kind == SessionEventKind::FileEdit));
    assert!(events.iter().any(|e| e.kind == SessionEventKind::Usage));
    assert!(events.iter().any(|e| e.kind == SessionEventKind::Terminal));
    for (i, ev) in events.iter().enumerate() {
        assert_eq!(ev.sequence, i as u64);
    }
}

#[test]
fn claude_cancellation_maps_to_terminal_cancelled_status() {
    let mut cancelled =
        normalize_jsonl_events("{\"type\":\"status\",\"message\":\"running\"}\n").unwrap();
    let cancel = CancelRequest {
        session_id: "sess-cancel".into(),
        reason: "user-cancel".into(),
        deadline_unix_ms: None,
    };
    cancelled.push(SessionEvent {
        sequence: cancelled.len() as u64,
        kind: SessionEventKind::Cancellation,
        summary: cancel.reason,
        redaction: RedactionClass::None,
        payload_json: Some("{\"type\":\"cancellation\",\"reason\":\"user-cancel\"}".into()),
    });
    cancelled.push(SessionEvent {
        sequence: cancelled.len() as u64,
        kind: SessionEventKind::Terminal,
        summary: "cancelled".into(),
        redaction: RedactionClass::None,
        payload_json: Some(
            "{\"type\":\"result\",\"subtype\":\"cancelled\",\"exit_code\":130}".into(),
        ),
    });
    let manifest = load_manifest("claude");
    let result = map_terminal_result(
        &manifest,
        "sess-cancel",
        fixture_version("claude", "1.2.3"),
        cancelled,
        vec![],
        UsageMetrics::default(),
        None,
    );
    assert_eq!(result.state, SessionState::Cancelled);
    assert_eq!(result.exit, ExitClass::Cancelled);
    assert_eq!(result.exit_status, 130);
}

#[test]
fn claude_terminal_status_peak_rss_and_allowed_files_enter_result() {
    let result = terminal_result_for("claude", "Claude Code 1.2.3");
    assert_eq!(result.state, SessionState::Completed);
    assert_eq!(result.exit, ExitClass::Success);
    assert_eq!(result.exit_status, 0);
    assert_eq!(result.usage.peak_rss_bytes, 64 * 1024 * 1024);
    assert_eq!(result.changed_files[0].path, "src/lib.rs");
    assert!(result.changed_files[0].within_allowlist);
}

#[test]
fn claude_allowed_file_enforcement_rejects_out_of_scope_edits() {
    let denied = enforce_allowed_files(&valid_workspace(), &[("README.md".into(), 4)]);
    assert!(format!("{}", denied.unwrap_err()).contains("policy-denied"));
}

#[test]
fn claude_opaque_secret_handling_redacts_values_but_preserves_handle() {
    let manifest = load_manifest("claude");
    let canary = "token=sk-live-secret-canary-do-not-leak /Users/alice/private";
    let (redacted, class) = redact_text(&manifest, canary);
    assert!(!redacted.contains("sk-live-secret-canary-do-not-leak"));
    assert_ne!(class, RedactionClass::None);
    let result = terminal_result_for("claude", "1.2.3");
    assert_eq!(
        result.secret_handle.as_ref().map(|h| h.id.as_str()),
        Some("handle:claude-opaque-test")
    );
}

#[test]
fn claude_result_semantics_match_hermes_despite_different_cli_output_format() {
    let claude = terminal_result_for("claude", "Claude Code 1.2.3");
    let hermes = terminal_result_for("hermes", "hermes 0.1.0");
    assert_eq!(semantic_projection(&claude), semantic_projection(&hermes));
}
