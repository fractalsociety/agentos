//! Cursor compatibility contract tests for fractal-worker/v1.

use fractal_worker_compat::{
    apply_peak_rss, assess_provider_readiness, collect_changed_paths, cursor_fixture_dir,
    cursor_manifest_path, enforce_allowed_files, extract_usage, map_terminal_result,
    normalize_jsonl_events, parse_version_output, redact_text, scan_manifest_safety,
    validate_workspace_input, worker_wit_path, CompatError, CursorLauncher, ExitClass,
    LiveEnvProbe, OpenSessionOpts, ProviderProofClass, SecretHandle, SessionEventKind,
    SessionState, WorkerManifest, WorkspaceInput, TERMINAL_RESULT_SCHEMA,
};
use std::collections::HashMap;
use std::fs;

fn load_manifest() -> WorkerManifest {
    WorkerManifest::load(cursor_manifest_path()).expect("cursor.toml must load")
}

#[test]
fn cursor_worker_wit_declares_provider_neutral_session_surface() {
    let wit = fs::read_to_string(worker_wit_path()).expect("read worker.wit");
    for required in [
        "package fractal:worker@1.0.0",
        "interface worker",
        "enum provider-kind",
        "cursor,",
        "record version-record",
        "record workspace-input",
        "record secret-handle",
        "record session-event",
        "record terminal-result",
        "peak-rss-bytes: u64",
        "resource session",
        "discover-version: func",
        "open-session: func",
        "cancel: func",
        "enforce-allowed-files: func",
        "redact-text: func",
        "enum provider-proof-class",
        "record provider-readiness-report",
        "record remote-session-handle",
        "assess-provider-readiness: func",
        "world fractal-worker-v1",
    ] {
        assert!(wit.contains(required), "worker.wit missing `{required}`");
    }
}

#[test]
fn cursor_manifest_describes_executable_route_without_authority_or_secrets() {
    let text = fs::read_to_string(cursor_manifest_path()).unwrap();
    scan_manifest_safety(&text).unwrap();
    let m = load_manifest();
    assert_eq!(m.worker.id, "cursor");
    assert_eq!(m.worker.provider, "cursor");
    assert_eq!(m.worker.protocol, "fractal-worker/v1");
    assert_eq!(m.worker.executable.kind, "path-lookup");
    assert_eq!(m.worker.executable.name, "cursor");
    assert!(!m.worker.executable.name.contains('/'));
    assert!(m.grants_no_authority());
    assert_eq!(m.auth.mode, "opaque-secret-handle");
    assert_eq!(m.terminal_result.schema, TERMINAL_RESULT_SCHEMA);
    assert!(m.discovery.requires_real_version_preflight);
    assert_eq!(m.session.stream_format, "jsonl");
}

#[test]
fn cursor_version_discovery_parses_fixture_output() {
    let raw = fs::read_to_string(cursor_fixture_dir().join("version.txt")).unwrap();
    let version = parse_version_output("cursor", "cursor", "cursor", &raw, 1).unwrap();
    assert_eq!(version.cli_version, "0.46.0");
    assert_eq!(version.protocol_version, "fractal-worker/v1");
}

#[test]
fn cursor_isolated_workspace_input_rejects_escapes() {
    let mut ws = WorkspaceInput {
        workspace_id: "ws-1".into(),
        root_object_id: "root".into(),
        allowed_files: vec!["src/health.c".into()],
        verify_command: Some("make test".into()),
    };
    validate_workspace_input(&ws).unwrap();
    ws.allowed_files = vec!["/tmp/x.c".into()];
    assert!(validate_workspace_input(&ws).is_err());
    ws.allowed_files = vec!["../out.c".into()];
    assert!(validate_workspace_input(&ws).is_err());
}

#[test]
fn cursor_jsonl_event_normalization() {
    let jsonl = fs::read_to_string(cursor_fixture_dir().join("session.jsonl")).unwrap();
    let events = normalize_jsonl_events(&jsonl).unwrap();
    assert!(events.iter().any(|e| e.kind == SessionEventKind::Status));
    assert!(events.iter().any(|e| e.kind == SessionEventKind::FileEdit));
    assert!(events.iter().any(|e| e.kind == SessionEventKind::Usage));
    assert!(events.iter().any(|e| e.kind == SessionEventKind::Terminal));
}

#[test]
fn cursor_cancellation_maps_into_terminal_envelope() {
    let m = load_manifest();
    let jsonl = fs::read_to_string(cursor_fixture_dir().join("cancel.jsonl")).unwrap();
    let events = normalize_jsonl_events(&jsonl).unwrap();
    let version = parse_version_output("cursor", "cursor", "cursor", "0.46.0", 0).unwrap();
    let result = map_terminal_result(
        &m,
        "sess-cancel-1",
        version,
        events,
        vec![],
        Default::default(),
        None,
    );
    assert_eq!(result.state, SessionState::Cancelled);
    assert_eq!(result.exit, ExitClass::Cancelled);
    assert_eq!(result.exit_status, 130);
}

#[test]
fn cursor_exit_status_and_peak_rss_enter_terminal_result() {
    let m = load_manifest();
    let jsonl = fs::read_to_string(cursor_fixture_dir().join("session.jsonl")).unwrap();
    let events = normalize_jsonl_events(&jsonl).unwrap();
    let mut usage = extract_usage(&events);
    apply_peak_rss(&mut usage, 64 * 1024 * 1024);
    let ws = WorkspaceInput {
        workspace_id: "ws-1".into(),
        root_object_id: "root".into(),
        allowed_files: vec!["src/health.c".into()],
        verify_command: None,
    };
    let files = enforce_allowed_files(&ws, &collect_changed_paths(&events)).unwrap();
    let version = parse_version_output("cursor", "cursor", "cursor", "0.46.0", 0).unwrap();
    let result = map_terminal_result(
        &m,
        "sess-fixture-1",
        version,
        events,
        files,
        usage,
        Some(SecretHandle {
            id: "cursor-cli-auth".into(),
            purpose: "cli-auth".into(),
        }),
    );
    assert_eq!(result.schema, TERMINAL_RESULT_SCHEMA);
    assert_eq!(result.exit, ExitClass::Success);
    assert_eq!(result.exit_status, 0);
    assert_eq!(result.usage.peak_rss_bytes, 64 * 1024 * 1024);
    assert_eq!(result.usage.input_tokens, 120);
    let encoded = serde_json::to_value(&result).unwrap();
    assert_eq!(
        encoded.get("schema").and_then(|v| v.as_str()),
        Some(TERMINAL_RESULT_SCHEMA)
    );
}

#[test]
fn cursor_allowed_file_enforcement_rejects_out_of_scope_edits() {
    let ws = WorkspaceInput {
        workspace_id: "ws-1".into(),
        root_object_id: "root".into(),
        allowed_files: vec!["src/health.c".into()],
        verify_command: None,
    };
    enforce_allowed_files(&ws, &[("src/health.c".into(), 1)]).unwrap();
    assert!(enforce_allowed_files(&ws, &[("README.md".into(), 1)]).is_err());
    assert!(enforce_allowed_files(&ws, &[("../x".into(), 1)]).is_err());
}

#[test]
fn cursor_credential_redaction_strips_canaries() {
    let m = load_manifest();
    let canary = fs::read_to_string(cursor_fixture_dir().join("canary_secrets.txt")).unwrap();
    let (redacted, class) = redact_text(&m, &canary);
    assert!(!redacted.contains("sk-CANARYCURSORSECRETVALUE999"));
    assert!(!redacted.contains("sk-CANARYBEARERTOKEN888"));
    assert!(!redacted.contains("sk-CANARYENVKEY777"));
    assert!(!redacted.contains("/Users/someone"));
    assert!(redacted.contains("[REDACTED]"));
    assert_ne!(class, fractal_worker_compat::RedactionClass::None);
}

#[test]
fn cursor_adapter_is_wired_and_runs_fixture_session() {
    let m = load_manifest();
    match CursorLauncher::discover_version_live(&m) {
        Ok(v) => {
            assert_eq!(v.provider, "cursor");
            assert_eq!(v.protocol_version, "fractal-worker/v1");
            assert!(!v.cli_version.is_empty());
            assert!(!v.cli_version.contains("stub"));
        }
        Err(CompatError::LauncherNotImplemented(_)) => {
            panic!("Cursor adapter must not return LauncherNotImplemented")
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("not found") || msg.contains("failed") || msg.contains("preflight"),
                "unexpected discover error: {msg}"
            );
        }
    }

    let ws = WorkspaceInput {
        workspace_id: "ws-fixture".into(),
        root_object_id: "root".into(),
        allowed_files: vec!["src/health.c".into()],
        verify_command: None,
    };
    let jsonl = fs::read_to_string(cursor_fixture_dir().join("session.jsonl")).unwrap();
    let result = CursorLauncher::open_session(
        &m,
        &ws,
        "fixture-prompt",
        OpenSessionOpts {
            replay_jsonl: Some(jsonl),
            replay_peak_rss_bytes: Some(32 * 1024 * 1024),
            secret: Some(SecretHandle {
                id: "cursor-cli-auth".into(),
                purpose: "cli-auth".into(),
            }),
            ..Default::default()
        },
    )
    .expect("fixture session must succeed");
    assert_eq!(result.schema, TERMINAL_RESULT_SCHEMA);
    assert_eq!(result.exit, ExitClass::Success);
    assert_eq!(result.usage.peak_rss_bytes, 32 * 1024 * 1024);
    assert_eq!(result.changed_files.len(), 1);
    assert_eq!(result.changed_files[0].path, "src/health.c");
    assert!(result.changed_files[0].within_allowlist);
    assert_eq!(
        result.secret_handle.as_ref().map(|h| h.id.as_str()),
        Some("cursor-cli-auth")
    );

    let deny_jsonl = concat!(
        "{\"type\":\"status\",\"message\":\"bad\"}\n",
        "{\"type\":\"tool_call\",\"name\":\"write\",\"path\":\"README.md\",\"bytes\":1}\n",
        "{\"type\":\"result\",\"subtype\":\"success\",\"exit_code\":0}\n"
    );
    let denied = CursorLauncher::open_session(
        &m,
        &ws,
        "deny",
        OpenSessionOpts {
            replay_jsonl: Some(deny_jsonl.into()),
            replay_peak_rss_bytes: Some(1024),
            ..Default::default()
        },
    )
    .expect("policy denial returns a terminal envelope");
    assert_eq!(denied.exit, ExitClass::PolicyDenied);
}

#[test]
fn cursor_empty_version_and_malformed_jsonl_are_rejected() {
    assert!(parse_version_output("cursor", "cursor", "cursor", "   ", 1).is_err());
    assert!(normalize_jsonl_events("{\"no_type\":true}\n").is_err());
    assert!(normalize_jsonl_events("not-json\n").is_err());
}

#[test]
fn cursor_undeclared_effects_rejected_and_adapter_mints_no_capabilities() {
    let m = load_manifest();
    assert!(m.grants_no_authority());
    assert!(!m.policy.grant_shell);
    assert!(!m.policy.grant_network);
    assert!(!m.policy.grant_filesystem);
    assert!(!m.policy.grant_environment);
    assert!(!m.policy.persist_credentials);

    let mut bad = m.clone();
    bad.policy.grant_shell = true;
    assert!(!bad.grants_no_authority());
    assert!(bad.validate().is_err());

    let mut net = m.clone();
    net.policy.grant_network = true;
    assert!(net.validate().is_err());
}

#[test]
fn cursor_malformed_terminal_envelope_missing_schema_is_detectable() {
    let m = load_manifest();
    let jsonl = fs::read_to_string(cursor_fixture_dir().join("session.jsonl")).unwrap();
    let events = normalize_jsonl_events(&jsonl).unwrap();
    let version = parse_version_output("cursor", "cursor", "cursor", "0.46.0", 0).unwrap();
    let mut result = map_terminal_result(
        &m,
        "sess-schema",
        version,
        events,
        vec![],
        Default::default(),
        None,
    );
    assert_eq!(result.schema, TERMINAL_RESULT_SCHEMA);
    result.schema = String::new();
    let encoded = serde_json::to_value(&result).unwrap();
    assert!(
        encoded
            .get("schema")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .is_empty(),
        "empty schema must be visible to validators"
    );
    assert_ne!(
        encoded.get("schema").and_then(|v| v.as_str()),
        Some(TERMINAL_RESULT_SCHEMA)
    );
}

struct MapEnv {
    vars: HashMap<&'static str, String>,
    paths: HashMap<&'static str, bool>,
}

impl LiveEnvProbe for MapEnv {
    fn var(&self, key: &str) -> Option<String> {
        self.vars.get(key).cloned()
    }
    fn executable_exists(&self, _name: &str) -> bool {
        false
    }
    fn path_executable(&self, path: &str) -> bool {
        self.paths.get(path).copied().unwrap_or(false)
    }
    fn now_unix_ms(&self) -> u64 {
        1
    }
}

#[test]
fn cursor_live_without_cli_reports_blocked_external_not_success() {
    let env = MapEnv {
        vars: HashMap::from([
            ("FRACTAL_CURSOR_LIVE", "1".into()),
            // no executable, no secret → blocked_external
        ]),
        paths: HashMap::new(),
    };
    let report = assess_provider_readiness(&env);
    let cursor = report
        .providers
        .iter()
        .find(|p| p.provider == "cursor")
        .expect("cursor row");
    assert_eq!(cursor.proof_class, ProviderProofClass::BlockedExternal);
    assert!(!cursor.claims_live_product);
    assert!(cursor.live_requested);
    assert!(!cursor.executable_resolved);
    assert!(
        cursor.blocker.as_deref().unwrap_or("").contains("executable")
            || cursor
                .blocker
                .as_deref()
                .unwrap_or("")
                .contains("FRACTAL_CURSOR_SECRET_HANDLE"),
        "blocker must name missing prerequisite: {:?}",
        cursor.blocker
    );

    // Without live flag → host fixture, never a fake live success.
    let fixture_env = MapEnv {
        vars: HashMap::new(),
        paths: HashMap::new(),
    };
    let fixture = assess_provider_readiness(&fixture_env)
        .providers
        .into_iter()
        .find(|p| p.provider == "cursor")
        .unwrap();
    assert_eq!(fixture.proof_class, ProviderProofClass::HostFixture);
    assert!(!fixture.claims_live_product);
}
