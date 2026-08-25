//! Remote Fractal worker sessions over MeshGateway.
//!
//! Host-level (L2) fence: audience-bound grants and execution leases are
//! validated before any provider adapter runs. Transport uses MeshGateway
//! resumable sessions; providers share one typed envelope and terminal result.

use crate::{
    ExitClass, ProviderKind, RedactionClass, SecretHandle, SessionEvent, SessionEventKind,
    SessionState, TerminalResult, UsageMetrics, VersionRecord, WorkspaceInput,
    TERMINAL_RESULT_SCHEMA, PROTOCOL_VERSION,
};
use fractal_mesh_gateway::{
    CancelRequest, GatewayError, MeshGateway, SessionStatus, TaskRequest,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

pub const WORKER_INTERFACE_LABEL: &str = "fractal-worker/v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RemoteSessionError {
    #[error("wrong audience")]
    WrongAudience,
    #[error("expired grant")]
    ExpiredGrant,
    #[error("expired lease")]
    ExpiredLease,
    #[error("stale authority or revocation epoch")]
    StaleEpoch,
    #[error("fabricated grant signature")]
    FabricatedGrant,
    #[error("unauthorized object range")]
    UnauthorizedObject,
    #[error("policy denied before local dispatch")]
    PolicyDenied,
    #[error("unknown provider adapter")]
    UnknownProvider,
    #[error("duplicate committed effect")]
    DuplicateEffect,
    #[error("mesh gateway: {0}")]
    Gateway(String),
    #[error("{0}")]
    Message(String),
}

impl From<GatewayError> for RemoteSessionError {
    fn from(value: GatewayError) -> Self {
        RemoteSessionError::Gateway(value.to_string())
    }
}

pub type RemoteResult<T> = Result<T, RemoteSessionError>;

/// Host mirror of `mesh_remote_grant_t` (see `remote_grant.h`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRemoteGrant {
    pub issuer: [u8; 32],
    pub subject_node: [u8; 32],
    pub subject_agent: [u8; 32],
    pub audience_node: [u8; 32],
    pub space_id: [u8; 32],
    pub interface_hash: [u8; 32],
    pub object_scope: [u8; 32],
    pub operation_mask: u64,
    pub scope_flags: u32,
    pub effect_class: u32,
    pub budget_units: u64,
    pub expiry_unix_ms: u64,
    pub authority_epoch: u64,
    pub revocation_epoch: u64,
    pub nonce: [u8; 32],
    /// Host-proof marker: first byte `0xA5` means valid under the test verifier.
    /// Stored as Vec because serde does not support `[u8; 64]` without extras.
    pub signature: Vec<u8>,
}

/// Host mirror of `mesh_execution_lease_t`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostExecutionLease {
    pub lease_id: u64,
    pub fence_epoch: u64,
    pub expires_unix_ms: u64,
    pub authority_epoch: u64,
    pub revocation_epoch: u64,
    pub holder_node: [u8; 32],
    pub subject_agent: [u8; 32],
    pub space_id: [u8; 32],
    pub nonce: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantAuthority {
    pub local_node: [u8; 32],
    pub expected_space: [u8; 32],
    pub expected_interface: [u8; 32],
    pub authority_epoch: u64,
    pub revocation_epoch: u64,
    pub now_unix_ms: u64,
    pub valid_signature_marker: u8,
}

impl Default for GrantAuthority {
    fn default() -> Self {
        Self {
            local_node: [0x11; 32],
            expected_space: [0x22; 32],
            expected_interface: interface_hash_bytes(),
            authority_epoch: 4,
            revocation_epoch: 9,
            now_unix_ms: 1_000,
            valid_signature_marker: 0xA5,
        }
    }
}

pub fn interface_hash_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    let label = WORKER_INTERFACE_LABEL.as_bytes();
    let n = label.len().min(32);
    out[..n].copy_from_slice(&label[..n]);
    out
}

pub fn validate_remote_grant(
    grant: &HostRemoteGrant,
    lease: Option<&HostExecutionLease>,
    requested_object: Option<&[u8; 32]>,
    auth: &GrantAuthority,
) -> RemoteResult<()> {
    if grant.signature.first().copied() != Some(auth.valid_signature_marker) {
        return Err(RemoteSessionError::FabricatedGrant);
    }
    if grant.audience_node != auth.local_node {
        return Err(RemoteSessionError::WrongAudience);
    }
    if grant.expiry_unix_ms <= auth.now_unix_ms {
        return Err(RemoteSessionError::ExpiredGrant);
    }
    if grant.authority_epoch != auth.authority_epoch
        || grant.revocation_epoch != auth.revocation_epoch
    {
        return Err(RemoteSessionError::StaleEpoch);
    }
    if grant.space_id != auth.expected_space || grant.interface_hash != auth.expected_interface {
        return Err(RemoteSessionError::PolicyDenied);
    }
    if let Some(object) = requested_object {
        if *object != grant.object_scope {
            return Err(RemoteSessionError::UnauthorizedObject);
        }
    }
    if let Some(lease) = lease {
        if lease.signature.first().copied() != Some(auth.valid_signature_marker) {
            return Err(RemoteSessionError::FabricatedGrant);
        }
        if lease.expires_unix_ms <= auth.now_unix_ms {
            return Err(RemoteSessionError::ExpiredLease);
        }
        if lease.authority_epoch != auth.authority_epoch
            || lease.revocation_epoch != auth.revocation_epoch
        {
            return Err(RemoteSessionError::StaleEpoch);
        }
        if lease.holder_node != auth.local_node {
            return Err(RemoteSessionError::WrongAudience);
        }
    }
    Ok(())
}

/// Common remote session envelope accepted by every provider adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSessionEnvelope {
    pub session_id: String,
    pub provider: ProviderKind,
    pub workspace: WorkspaceInput,
    pub prompt: String,
    pub secret: Option<SecretHandle>,
    pub grant: HostRemoteGrant,
    pub lease: Option<HostExecutionLease>,
    pub requested_object: Option<[u8; 32]>,
    /// Stable effect id for exactly-once commit across reconnect.
    pub effect_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSessionHandle {
    pub peer: String,
    pub session_id: String,
    pub resume_token: Vec<u8>,
    pub next_task_sequence: u64,
    pub next_event_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDispatchOutcome {
    pub handle: RemoteSessionHandle,
    pub terminal: TerminalResult,
    pub events_appended: u64,
    pub committed: bool,
}

pub trait ProviderAdapter: Send + Sync {
    fn provider(&self) -> ProviderKind;
    fn run_isolated(&self, envelope: &RemoteSessionEnvelope) -> RemoteResult<TerminalResult>;
}

/// Fixture adapter used for L2 host proof (no live CLI).
#[derive(Debug, Clone)]
pub struct FixtureAdapter {
    provider: ProviderKind,
    worker_id: String,
    cli_name: String,
    cli_version: String,
}

impl FixtureAdapter {
    pub fn new(provider: ProviderKind) -> Self {
        let (worker_id, cli_name, cli_version) = match provider {
            ProviderKind::Codex => ("codex", "codex", "0.42.0"),
            ProviderKind::Cursor => ("cursor", "cursor", "0.46.0"),
            ProviderKind::Claude => ("claude", "claude", "1.0.0"),
            ProviderKind::Hermes => ("hermes", "hermes", "0.3.0"),
        };
        Self {
            provider,
            worker_id: worker_id.into(),
            cli_name: cli_name.into(),
            cli_version: cli_version.into(),
        }
    }
}

impl ProviderAdapter for FixtureAdapter {
    fn provider(&self) -> ProviderKind {
        self.provider
    }

    fn run_isolated(&self, envelope: &RemoteSessionEnvelope) -> RemoteResult<TerminalResult> {
        if envelope.provider != self.provider {
            return Err(RemoteSessionError::UnknownProvider);
        }
        crate::validate_workspace_input(&envelope.workspace)
            .map_err(|e| RemoteSessionError::Message(e.to_string()))?;

        let provider_name = match self.provider {
            ProviderKind::Codex => "codex",
            ProviderKind::Cursor => "cursor",
            ProviderKind::Claude => "claude",
            ProviderKind::Hermes => "hermes",
        };
        let version = VersionRecord {
            worker_id: self.worker_id.clone(),
            provider: provider_name.into(),
            protocol_version: PROTOCOL_VERSION.into(),
            cli_name: self.cli_name.clone(),
            cli_version: self.cli_version.clone(),
            discovered_at_unix_ms: 1,
        };

        let mut events = vec![
            SessionEvent {
                sequence: 0,
                kind: SessionEventKind::Version,
                summary: version.cli_version.clone(),
                redaction: RedactionClass::None,
                payload_json: Some(format!(
                    r#"{{"type":"version","version":"{}"}}"#,
                    version.cli_version
                )),
            },
            SessionEvent {
                sequence: 1,
                kind: SessionEventKind::Status,
                summary: "running".into(),
                redaction: RedactionClass::None,
                payload_json: Some(r#"{"type":"status","message":"running"}"#.into()),
            },
            SessionEvent {
                sequence: 2,
                kind: SessionEventKind::FileEdit,
                summary: envelope
                    .workspace
                    .allowed_files
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "src/health.c".into()),
                redaction: RedactionClass::None,
                payload_json: Some(format!(
                    r#"{{"type":"tool_call","path":"{}","bytes":32}}"#,
                    envelope
                        .workspace
                        .allowed_files
                        .first()
                        .map(String::as_str)
                        .unwrap_or("src/health.c")
                )),
            },
            SessionEvent {
                sequence: 3,
                kind: SessionEventKind::Terminal,
                summary: "success".into(),
                redaction: RedactionClass::None,
                payload_json: Some(r#"{"type":"result","subtype":"success","exit_code":0}"#.into()),
            },
        ];

        // Ensure secret values never appear in event payloads.
        if let Some(secret) = &envelope.secret {
            for ev in &mut events {
                if let Some(payload) = &ev.payload_json {
                    if payload.contains(&secret.id) {
                        return Err(RemoteSessionError::Message(
                            "secret handle leaked into event payload".into(),
                        ));
                    }
                }
            }
        }

        let changed = crate::collect_changed_paths(&events);
        let changed_files = crate::enforce_allowed_files(&envelope.workspace, &changed)
            .map_err(|e| RemoteSessionError::Message(e.to_string()))?;

        Ok(TerminalResult {
            schema: TERMINAL_RESULT_SCHEMA.into(),
            session_id: envelope.session_id.clone(),
            worker_id: self.worker_id.clone(),
            provider: provider_name.into(),
            state: SessionState::Completed,
            exit: ExitClass::Success,
            exit_status: 0,
            version,
            usage: UsageMetrics {
                input_tokens: 1,
                output_tokens: 1,
                cached_tokens: 0,
                peak_rss_bytes: 8 * 1024 * 1024,
                wall_time_ms: 10,
            },
            events,
            changed_files,
            secret_handle: envelope.secret.clone(),
            error_message: None,
        })
    }
}

pub struct RemoteWorkerSessionHost {
    gateway: MeshGateway,
    peer: String,
    authority: GrantAuthority,
    adapters: HashMap<ProviderKind, Box<dyn ProviderAdapter>>,
    /// Exactly-once ledger of committed effect ids per session.
    committed: HashSet<(String, String)>,
    /// Event lineage retained across reconnect for each session.
    event_lineage: HashMap<String, Vec<SessionEvent>>,
}

impl RemoteWorkerSessionHost {
    pub fn new(gateway: MeshGateway, peer: impl Into<String>, authority: GrantAuthority) -> Self {
        let mut adapters: HashMap<ProviderKind, Box<dyn ProviderAdapter>> = HashMap::new();
        for provider in [
            ProviderKind::Codex,
            ProviderKind::Cursor,
            ProviderKind::Claude,
            ProviderKind::Hermes,
        ] {
            adapters.insert(provider, Box::new(FixtureAdapter::new(provider)));
        }
        Self {
            gateway,
            peer: peer.into(),
            authority,
            adapters,
            committed: HashSet::new(),
            event_lineage: HashMap::new(),
        }
    }

    pub fn gateway(&self) -> &MeshGateway {
        &self.gateway
    }

    pub fn authority_mut(&mut self) -> &mut GrantAuthority {
        &mut self.authority
    }

    pub fn event_lineage(&self, session_id: &str) -> &[SessionEvent] {
        self.event_lineage
            .get(session_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn is_committed(&self, session_id: &str, effect_id: &str) -> bool {
        self.committed
            .contains(&(session_id.to_string(), effect_id.to_string()))
    }

    fn handle_from_status(&self, status: SessionStatus) -> RemoteSessionHandle {
        RemoteSessionHandle {
            peer: self.peer.clone(),
            session_id: status.session,
            resume_token: status.resume_token,
            next_task_sequence: status.next_task_sequence,
            next_event_sequence: status.next_event_sequence,
        }
    }

    /// Open or resume a mesh session, then dispatch only after grant validation.
    pub fn dispatch(
        &mut self,
        envelope: &RemoteSessionEnvelope,
        resume_token: Option<Vec<u8>>,
    ) -> RemoteResult<RemoteDispatchOutcome> {
        validate_remote_grant(
            &envelope.grant,
            envelope.lease.as_ref(),
            envelope.requested_object.as_ref(),
            &self.authority,
        )?;

        let effect_key = (envelope.session_id.clone(), envelope.effect_id.clone());
        if self.committed.contains(&effect_key) {
            // Reconnect after a committed effect: preserve lineage, do not re-run.
            let status = if let Some(token) = resume_token.as_ref() {
                self.gateway
                    .resume(&self.peer, &envelope.session_id, token)?
            } else {
                self.gateway
                    .session_status(&self.peer, &envelope.session_id)?
            };
            let lineage = self
                .event_lineage
                .get(&envelope.session_id)
                .cloned()
                .unwrap_or_default();
            let terminal = TerminalResult {
                schema: TERMINAL_RESULT_SCHEMA.into(),
                session_id: envelope.session_id.clone(),
                worker_id: envelope.provider_name().into(),
                provider: envelope.provider_name().into(),
                state: SessionState::Completed,
                exit: ExitClass::Success,
                exit_status: 0,
                version: VersionRecord {
                    worker_id: envelope.provider_name().into(),
                    provider: envelope.provider_name().into(),
                    protocol_version: PROTOCOL_VERSION.into(),
                    cli_name: envelope.provider_name().into(),
                    cli_version: "replay".into(),
                    discovered_at_unix_ms: 1,
                },
                usage: UsageMetrics::default(),
                events: lineage,
                changed_files: vec![],
                secret_handle: envelope.secret.clone(),
                error_message: Some("effect already committed; replayed without re-dispatch".into()),
            };
            return Ok(RemoteDispatchOutcome {
                handle: self.handle_from_status(status),
                terminal,
                events_appended: 0,
                committed: false,
            });
        }

        let _status = self.gateway.open_task(
            &self.peer,
            TaskRequest {
                session: envelope.session_id.clone(),
                payload: serde_json::to_vec(envelope).map_err(|e| {
                    RemoteSessionError::Message(format!("envelope encode failed: {e}"))
                })?,
                resume_token,
            },
        )?;

        let adapter = self
            .adapters
            .get(&envelope.provider)
            .ok_or(RemoteSessionError::UnknownProvider)?;
        let terminal = adapter.run_isolated(envelope)?;

        // Append events onto the mesh event stream and retain lineage.
        let mut appended = 0u64;
        for event in &terminal.events {
            let bytes = serde_json::to_vec(event).map_err(|e| {
                RemoteSessionError::Message(format!("event encode failed: {e}"))
            })?;
            let frame = self
                .gateway
                .submit_event(&self.peer, &envelope.session_id, bytes)?;
            let _ = self.gateway.release_sent(&self.peer, frame.payload.len());
            appended += 1;
        }
        self.event_lineage
            .entry(envelope.session_id.clone())
            .or_default()
            .extend(terminal.events.clone());
        self.committed.insert(effect_key);

        let status = self
            .gateway
            .session_status(&self.peer, &envelope.session_id)?;
        Ok(RemoteDispatchOutcome {
            handle: self.handle_from_status(status),
            terminal,
            events_appended: appended,
            committed: true,
        })
    }

    pub fn cancel(
        &self,
        session_id: &str,
        reason: &str,
    ) -> RemoteResult<SessionStatus> {
        Ok(self.gateway.cancel_request(
            &self.peer,
            CancelRequest {
                session: session_id.into(),
                reason: reason.into(),
                deadline_unix_ms: None,
            },
        )?)
    }

    pub fn disconnect_peer(&self) -> RemoteResult<()> {
        Ok(self.gateway.disconnect_peer(&self.peer)?)
    }

    pub fn reconnect_peer(&self, connection_id: &str, path: &str) -> RemoteResult<()> {
        Ok(self
            .gateway
            .connect_peer(&self.peer, connection_id, path)?)
    }
}

impl RemoteSessionEnvelope {
    pub fn provider_name(&self) -> &'static str {
        match self.provider {
            ProviderKind::Codex => "codex",
            ProviderKind::Cursor => "cursor",
            ProviderKind::Claude => "claude",
            ProviderKind::Hermes => "hermes",
        }
    }
}

pub fn valid_grant(auth: &GrantAuthority) -> HostRemoteGrant {
    let mut signature = vec![0u8; 64];
    signature[0] = auth.valid_signature_marker;
    HostRemoteGrant {
        issuer: [0x70; 32],
        subject_node: [0x33; 32],
        subject_agent: [0x44; 32],
        audience_node: auth.local_node,
        space_id: auth.expected_space,
        interface_hash: auth.expected_interface,
        object_scope: [0x55; 32],
        operation_mask: 1,
        scope_flags: 1,
        effect_class: 1,
        budget_units: 10,
        expiry_unix_ms: auth.now_unix_ms.saturating_add(1_000),
        authority_epoch: auth.authority_epoch,
        revocation_epoch: auth.revocation_epoch,
        nonce: [0x91; 32],
        signature,
    }
}

pub fn valid_lease(auth: &GrantAuthority) -> HostExecutionLease {
    let mut signature = vec![0u8; 64];
    signature[0] = auth.valid_signature_marker;
    HostExecutionLease {
        lease_id: 7,
        fence_epoch: 1,
        expires_unix_ms: auth.now_unix_ms.saturating_add(1_000),
        authority_epoch: auth.authority_epoch,
        revocation_epoch: auth.revocation_epoch,
        holder_node: auth.local_node,
        subject_agent: [0x44; 32],
        space_id: auth.expected_space,
        nonce: [0x92; 32],
        signature,
    }
}

pub fn sample_envelope(
    provider: ProviderKind,
    auth: &GrantAuthority,
    session_id: &str,
    effect_id: &str,
) -> RemoteSessionEnvelope {
    let grant = valid_grant(auth);
    RemoteSessionEnvelope {
        session_id: session_id.into(),
        provider,
        workspace: WorkspaceInput {
            workspace_id: format!("ws-{}", provider_slug(provider)),
            root_object_id: "root".into(),
            allowed_files: vec!["src/health.c".into()],
            verify_command: Some("make test".into()),
        },
        prompt: "fix health check".into(),
        secret: Some(SecretHandle {
            id: "handle:test".into(),
            purpose: "worker-auth".into(),
        }),
        grant: grant.clone(),
        lease: Some(valid_lease(auth)),
        requested_object: Some(grant.object_scope),
        effect_id: effect_id.into(),
    }
}

fn provider_slug(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::Codex => "codex",
        ProviderKind::Cursor => "cursor",
        ProviderKind::Claude => "claude",
        ProviderKind::Hermes => "hermes",
    }
}

/// How a provider may be claimed in evidence — fixture never equals live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProofClass {
    /// L2 host/fixture path only. Must not be reported as live product proof.
    HostFixture,
    /// Live CLI path is configured (flag + executable + opaque secret handle).
    LiveConfigured,
    /// Live was requested or assessed but an external prerequisite is missing.
    BlockedExternal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderReadiness {
    pub provider: String,
    pub proof_class: ProviderProofClass,
    pub live_env_flag: String,
    pub live_requested: bool,
    pub executable_resolved: bool,
    pub secret_handle_present: bool,
    pub claims_live_product: bool,
    pub blocker: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderReadinessReport {
    pub schema: String,
    pub protocol_version: String,
    pub generated_at_unix_ms: u64,
    pub providers: Vec<ProviderReadiness>,
}

pub const PROVIDER_READINESS_SCHEMA: &str = "fractal.worker.provider-readiness.v1";

/// Environment probe so tests can inject live/blocked configurations.
pub trait LiveEnvProbe: Send + Sync {
    fn var(&self, key: &str) -> Option<String>;
    fn executable_exists(&self, name: &str) -> bool;
    fn path_executable(&self, path: &str) -> bool;
    fn now_unix_ms(&self) -> u64;
}

/// Process environment + PATH lookup for host/e2e use.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessLiveEnv;

impl LiveEnvProbe for ProcessLiveEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    fn executable_exists(&self, name: &str) -> bool {
        which_on_path(name).is_some()
    }

    fn path_executable(&self, path: &str) -> bool {
        let p = std::path::Path::new(path);
        p.is_file()
            && std::fs::metadata(p)
                .map(|m| {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        m.permissions().mode() & 0o111 != 0
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = m;
                        true
                    }
                })
                .unwrap_or(false)
    }

    fn now_unix_ms(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

fn which_on_path(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

struct ProviderLiveKeys {
    provider: ProviderKind,
    live_flag: &'static str,
    executable_override: &'static str,
    secret_handle: &'static str,
    default_cli: &'static str,
}

const PROVIDER_LIVE_KEYS: &[ProviderLiveKeys] = &[
    ProviderLiveKeys {
        provider: ProviderKind::Codex,
        live_flag: "FRACTAL_CODEX_LIVE",
        executable_override: "FRACTAL_CODEX_EXECUTABLE",
        secret_handle: "FRACTAL_CODEX_SECRET_HANDLE",
        default_cli: "codex",
    },
    ProviderLiveKeys {
        provider: ProviderKind::Cursor,
        live_flag: "FRACTAL_CURSOR_LIVE",
        executable_override: "FRACTAL_CURSOR_EXECUTABLE",
        secret_handle: "FRACTAL_CURSOR_SECRET_HANDLE",
        default_cli: "cursor",
    },
    ProviderLiveKeys {
        provider: ProviderKind::Claude,
        live_flag: "FRACTAL_CLAUDE_LIVE",
        executable_override: "FRACTAL_CLAUDE_EXECUTABLE",
        secret_handle: "FRACTAL_CLAUDE_SECRET_HANDLE",
        default_cli: "claude",
    },
    ProviderLiveKeys {
        provider: ProviderKind::Hermes,
        live_flag: "FRACTAL_HERMES_LIVE",
        executable_override: "FRACTAL_HERMES_EXECUTABLE",
        secret_handle: "FRACTAL_HERMES_SECRET_HANDLE",
        default_cli: "hermes",
    },
];

fn env_truthy(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn assess_one(keys: &ProviderLiveKeys, env: &dyn LiveEnvProbe) -> ProviderReadiness {
    let live_requested = env
        .var(keys.live_flag)
        .as_deref()
        .map(env_truthy)
        .unwrap_or(false);
    let secret_handle_present = env
        .var(keys.secret_handle)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    let executable_resolved = if let Some(path) = env.var(keys.executable_override) {
        !path.trim().is_empty() && env.path_executable(path.trim())
    } else {
        env.executable_exists(keys.default_cli)
    };

    if !live_requested {
        return ProviderReadiness {
            provider: provider_slug(keys.provider).into(),
            proof_class: ProviderProofClass::HostFixture,
            live_env_flag: keys.live_flag.into(),
            live_requested: false,
            executable_resolved,
            secret_handle_present,
            claims_live_product: false,
            blocker: None,
        };
    }

    let mut missing = Vec::new();
    if !executable_resolved {
        missing.push(format!(
            "executable missing (set {} or install {})",
            keys.executable_override, keys.default_cli
        ));
    }
    if !secret_handle_present {
        missing.push(format!("{} unset", keys.secret_handle));
    }

    if missing.is_empty() {
        ProviderReadiness {
            provider: provider_slug(keys.provider).into(),
            proof_class: ProviderProofClass::LiveConfigured,
            live_env_flag: keys.live_flag.into(),
            live_requested: true,
            executable_resolved: true,
            secret_handle_present: true,
            claims_live_product: true,
            blocker: None,
        }
    } else {
        ProviderReadiness {
            provider: provider_slug(keys.provider).into(),
            proof_class: ProviderProofClass::BlockedExternal,
            live_env_flag: keys.live_flag.into(),
            live_requested: true,
            executable_resolved,
            secret_handle_present,
            claims_live_product: false,
            blocker: Some(missing.join("; ")),
        }
    }
}

/// Assess live vs blocked vs host-fixture for all four providers.
///
/// Host fixture proof never sets `claims_live_product`. Live product claims
/// require the live env flag plus resolved CLI and opaque secret handle.
pub fn assess_provider_readiness(env: &dyn LiveEnvProbe) -> ProviderReadinessReport {
    ProviderReadinessReport {
        schema: PROVIDER_READINESS_SCHEMA.into(),
        protocol_version: PROTOCOL_VERSION.into(),
        generated_at_unix_ms: env.now_unix_ms(),
        providers: PROVIDER_LIVE_KEYS
            .iter()
            .map(|keys| assess_one(keys, env))
            .collect(),
    }
}

pub fn assess_provider_readiness_from_process() -> ProviderReadinessReport {
    assess_provider_readiness(&ProcessLiveEnv)
}
