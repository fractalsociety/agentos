//! L2 host proof for remote Fractal worker sessions (fos-gz0.14.13).
//!
//! Covers common envelope acceptance across providers, grant denial before
//! local dispatch, disconnect/reconnect without duplicate committed effects,
//! and live-vs-blocked provider readiness evidence.

use fractal_mesh_gateway::{GatewayConfig, MeshGateway};
use fractal_worker_compat::{
    assess_provider_readiness, sample_envelope, valid_grant, ExitClass, GrantAuthority,
    LiveEnvProbe, ProviderKind, ProviderProofClass, RemoteSessionEnvelope, RemoteSessionError,
    RemoteWorkerSessionHost, SessionState, PROVIDER_READINESS_SCHEMA, TERMINAL_RESULT_SCHEMA,
};
use std::collections::HashMap;

fn host_with_peer(peer: &str) -> RemoteWorkerSessionHost {
    let gateway = MeshGateway::new(GatewayConfig::default());
    gateway
        .connect_peer(peer, "conn-1", "direct")
        .expect("connect peer");
    RemoteWorkerSessionHost::new(gateway, peer, GrantAuthority::default())
}

#[test]
fn all_providers_accept_common_remote_envelope() {
    let peer = "peer-workers";
    let mut host = host_with_peer(peer);
    let auth = GrantAuthority::default();

    for provider in [
        ProviderKind::Codex,
        ProviderKind::Cursor,
        ProviderKind::Claude,
        ProviderKind::Hermes,
    ] {
        let session = format!("sess-{}", provider_slug(provider));
        let envelope = sample_envelope(provider, &auth, &session, "effect-1");
        let outcome = host.dispatch(&envelope, None).expect("dispatch");
        assert!(outcome.committed);
        assert_eq!(outcome.terminal.schema, TERMINAL_RESULT_SCHEMA);
        assert_eq!(outcome.terminal.provider, provider_slug(provider));
        assert_eq!(outcome.terminal.state, SessionState::Completed);
        assert_eq!(outcome.terminal.exit, ExitClass::Success);
        assert_eq!(outcome.terminal.version.protocol_version, "fractal-worker/v1");
        assert!(
            outcome
                .terminal
                .changed_files
                .iter()
                .all(|f| f.within_allowlist),
            "isolation must keep edits inside allowlist"
        );
        assert!(
            outcome
                .terminal
                .events
                .iter()
                .all(|e| e
                    .payload_json
                    .as_deref()
                    .map(|p| !p.contains("sk-"))
                    .unwrap_or(true)),
            "events must not embed credential canaries"
        );
        assert_eq!(outcome.handle.session_id, session);
        assert!(!outcome.handle.resume_token.is_empty());
    }
}

#[test]
fn reconnect_preserves_handles_and_avoids_duplicate_effects() {
    let peer = "peer-reconnect";
    let mut host = host_with_peer(peer);
    let auth = GrantAuthority::default();
    let envelope = sample_envelope(ProviderKind::Cursor, &auth, "sess-reconnect", "effect-a");

    let first = host.dispatch(&envelope, None).expect("initial dispatch");
    assert!(first.committed);
    assert_eq!(first.events_appended, first.terminal.events.len() as u64);
    let lineage_len = host.event_lineage("sess-reconnect").len();
    assert!(lineage_len > 0);
    let resume = first.handle.resume_token.clone();
    let task_seq = first.handle.next_task_sequence;
    let event_seq = first.handle.next_event_sequence;

    host.disconnect_peer().expect("disconnect");
    host.reconnect_peer("conn-2", "relay").expect("reconnect");

    let second = host
        .dispatch(&envelope, Some(resume.clone()))
        .expect("resumed dispatch");
    assert!(
        !second.committed,
        "committed effect must not re-dispatch after reconnect"
    );
    assert_eq!(second.events_appended, 0);
    assert_eq!(second.handle.session_id, "sess-reconnect");
    assert_eq!(
        host.event_lineage("sess-reconnect").len(),
        lineage_len,
        "event lineage must be preserved"
    );
    assert!(host.is_committed("sess-reconnect", "effect-a"));
    // Cursor advanced during first commit; resume must not invent a lower sequence.
    assert!(second.handle.next_task_sequence >= task_seq);
    assert!(second.handle.next_event_sequence >= event_seq);
    assert!(!second.handle.resume_token.is_empty());
}

#[test]
fn grant_denials_happen_before_local_dispatch() {
    let peer = "peer-deny";
    let mut host = host_with_peer(peer);
    let auth = GrantAuthority::default();

    let cases: Vec<(&str, Box<dyn Fn(&mut RemoteSessionEnvelope)>)> = vec![
        (
            "wrong audience",
            Box::new(|env| {
                env.grant.audience_node = [0xEE; 32];
            }),
        ),
        (
            "expired grant",
            Box::new(|env| {
                env.grant.expiry_unix_ms = 1;
            }),
        ),
        (
            "stale epoch",
            Box::new(|env| {
                env.grant.authority_epoch = 0;
            }),
        ),
        (
            "fabricated grant",
            Box::new(|env| {
                if let Some(byte) = env.grant.signature.get_mut(0) {
                    *byte = 0x00;
                }
            }),
        ),
        (
            "unauthorized object",
            Box::new(|env| {
                env.requested_object = Some([0xFF; 32]);
            }),
        ),
        (
            "expired lease",
            Box::new(|env| {
                if let Some(lease) = env.lease.as_mut() {
                    lease.expires_unix_ms = 1;
                }
            }),
        ),
    ];

    for (label, mutate) in cases {
        let mut envelope = sample_envelope(
            ProviderKind::Hermes,
            &auth,
            &format!("sess-deny-{label}"),
            "effect-deny",
        );
        mutate(&mut envelope);
        let err = host
            .dispatch(&envelope, None)
            .expect_err(&format!("expected denial for {label}"));
        match label {
            "wrong audience" => assert_eq!(err, RemoteSessionError::WrongAudience),
            "expired grant" => assert_eq!(err, RemoteSessionError::ExpiredGrant),
            "stale epoch" => assert_eq!(err, RemoteSessionError::StaleEpoch),
            "fabricated grant" => assert_eq!(err, RemoteSessionError::FabricatedGrant),
            "unauthorized object" => assert_eq!(err, RemoteSessionError::UnauthorizedObject),
            "expired lease" => assert_eq!(err, RemoteSessionError::ExpiredLease),
            _ => unreachable!(),
        }
        assert!(
            !host.is_committed(&envelope.session_id, "effect-deny"),
            "denied grant must not commit an effect ({label})"
        );
        assert!(
            host.event_lineage(&envelope.session_id).is_empty(),
            "denied grant must not append events ({label})"
        );
    }

    // Control: a valid grant still dispatches after the denial battery.
    let ok = sample_envelope(ProviderKind::Hermes, &auth, "sess-deny-ok", "effect-ok");
    let outcome = host.dispatch(&ok, None).expect("valid grant still works");
    assert!(outcome.committed);
    let _ = valid_grant(&auth);
}

fn provider_slug(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::Codex => "codex",
        ProviderKind::Cursor => "cursor",
        ProviderKind::Claude => "claude",
        ProviderKind::Hermes => "hermes",
    }
}

struct MapEnv {
    vars: HashMap<&'static str, String>,
    executables: HashMap<&'static str, bool>,
    paths: HashMap<&'static str, bool>,
}

impl LiveEnvProbe for MapEnv {
    fn var(&self, key: &str) -> Option<String> {
        self.vars.get(key).cloned()
    }

    fn executable_exists(&self, name: &str) -> bool {
        self.executables.get(name).copied().unwrap_or(false)
    }

    fn path_executable(&self, path: &str) -> bool {
        self.paths.get(path).copied().unwrap_or(false)
    }

    fn now_unix_ms(&self) -> u64 {
        1_700_000_000_000
    }
}

#[test]
fn readiness_report_distinguishes_fixture_live_and_blocked() {
    let env = MapEnv {
        vars: HashMap::from([
            ("FRACTAL_CODEX_LIVE", "1".into()),
            ("FRACTAL_CODEX_EXECUTABLE", "/opt/codex".into()),
            ("FRACTAL_CODEX_SECRET_HANDLE", "handle:codex".into()),
            ("FRACTAL_CURSOR_LIVE", "1".into()),
            // cursor live requested but secret missing → blocked
            ("FRACTAL_CURSOR_EXECUTABLE", "/opt/cursor".into()),
            ("FRACTAL_CLAUDE_LIVE", "0".into()),
            // hermes: no live flag → host fixture
        ]),
        executables: HashMap::new(),
        paths: HashMap::from([
            ("/opt/codex", true),
            ("/opt/cursor", true),
        ]),
    };

    let report = assess_provider_readiness(&env);
    assert_eq!(report.schema, PROVIDER_READINESS_SCHEMA);
    assert_eq!(report.protocol_version, "fractal-worker/v1");
    assert_eq!(report.providers.len(), 4);

    let by: HashMap<_, _> = report
        .providers
        .iter()
        .map(|p| (p.provider.as_str(), p))
        .collect();

    let codex = by["codex"];
    assert_eq!(codex.proof_class, ProviderProofClass::LiveConfigured);
    assert!(codex.claims_live_product);
    assert!(codex.blocker.is_none());

    let cursor = by["cursor"];
    assert_eq!(cursor.proof_class, ProviderProofClass::BlockedExternal);
    assert!(!cursor.claims_live_product);
    assert!(
        cursor
            .blocker
            .as_deref()
            .unwrap_or("")
            .contains("FRACTAL_CURSOR_SECRET_HANDLE"),
        "blocked cursor must name the missing secret: {:?}",
        cursor.blocker
    );

    let claude = by["claude"];
    assert_eq!(claude.proof_class, ProviderProofClass::HostFixture);
    assert!(!claude.claims_live_product);
    assert!(!claude.live_requested);

    let hermes = by["hermes"];
    assert_eq!(hermes.proof_class, ProviderProofClass::HostFixture);
    assert!(!hermes.claims_live_product);

    // Fixture path must never be mixed into a live product claim set.
    assert!(report
        .providers
        .iter()
        .filter(|p| p.proof_class == ProviderProofClass::HostFixture)
        .all(|p| !p.claims_live_product));
}
