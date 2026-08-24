//! Bounded Fractal mesh transport.
//!
//! The semantic protocol is deliberately independent of Quinn. Reliable task
//! frames use bidirectional streams, events and objects use unidirectional
//! streams, and only [`FrameType::Hint`] may be sent as a QUIC datagram. The
//! [`MeshGateway`] is the one process-wide service; it keeps at most one
//! connection for each active peer and never turns a Headscale attribute into
//! AgentOS authority.

use quinn::{Connection, Endpoint, ServerConfig};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

pub const ALPN: &[u8] = b"fractalos-agent/1";
pub const MAGIC: u32 = 0x314d_5346; // FSM1
pub const SCHEMA_VERSION: u16 = 1;
pub const HEADER_BYTES: usize = 64;
pub const MAX_PAYLOAD: usize = 64 * 1024;
pub const MAX_INFLIGHT_FRAMES: u32 = 64;
pub const MAX_INFLIGHT_BYTES: u64 = 1024 * 1024;
pub const MAX_PEER_BYTES: u64 = 4 * MAX_INFLIGHT_BYTES;
pub const MAX_RESUMABLE_PEERS: usize = 64;
pub const MAX_REPLAY_STREAMS: usize = MAX_INFLIGHT_FRAMES as usize * 2;
pub const MAX_SESSIONS_PER_PEER: usize = 256;
pub const MAX_DISCOVERED_PEERS: usize = 256;
pub const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(15);
const MAX_FRAME_BYTES: usize = HEADER_BYTES + MAX_PAYLOAD;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[repr(u8)]
pub enum FrameType {
    Task = 1,
    Event = 2,
    Object = 3,
    Control = 4,
    Hint = 5,
}

impl FrameType {
    pub fn from_byte(value: u8) -> Result<Self, FrameError> {
        match value {
            1 => Ok(Self::Task),
            2 => Ok(Self::Event),
            3 => Ok(Self::Object),
            4 => Ok(Self::Control),
            5 => Ok(Self::Hint),
            _ => Err(FrameError::BadFrameType(value)),
        }
    }

    pub fn is_datagram_only(self) -> bool {
        self == Self::Hint
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub frame_type: FrameType,
    pub flags: u8,
    pub stream_id: u32,
    pub session_hash: u64,
    pub path_epoch: u64,
    pub sequence: u64,
    pub manifest_bytes: u32,
    pub payload_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame is shorter than the fixed header")]
    MalformedLength,
    #[error("frame has the wrong magic")]
    BadMagic,
    #[error("frame has an unsupported schema")]
    BadSchema,
    #[error("frame has an unsupported type {0}")]
    BadFrameType(u8),
    #[error("a semantic frame was supplied as a datagram")]
    SemanticDatagram,
    #[error("a disposable hint was supplied on a reliable stream")]
    DatagramRequired,
    #[error("frame manifest is larger than its payload")]
    BadManifestLength,
    #[error("frame exceeds the configured payload limit")]
    PayloadTooLarge,
}

fn put_u16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn get_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn get_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}
fn get_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
        bytes[at + 4],
        bytes[at + 5],
        bytes[at + 6],
        bytes[at + 7],
    ])
}

impl Frame {
    pub fn new(frame_type: FrameType, sequence: u64, payload: Vec<u8>) -> Result<Self, FrameError> {
        Self::with_metadata(frame_type, sequence, 0, 0, 0, payload)
    }

    pub fn with_metadata(
        frame_type: FrameType,
        sequence: u64,
        stream_id: u32,
        session_hash: u64,
        path_epoch: u64,
        payload: Vec<u8>,
    ) -> Result<Self, FrameError> {
        if payload.len() > MAX_PAYLOAD {
            return Err(FrameError::PayloadTooLarge);
        }
        Ok(Self {
            header: FrameHeader {
                frame_type,
                flags: 0,
                stream_id,
                session_hash,
                path_epoch,
                sequence,
                manifest_bytes: 0,
                payload_bytes: payload.len() as u32,
            },
            payload,
        })
    }

    pub fn with_manifest(mut self, manifest: &[u8]) -> Result<Self, FrameError> {
        if manifest.len() > self.payload.len() {
            return Err(FrameError::BadManifestLength);
        }
        self.header.manifest_bytes = manifest.len() as u32;
        Ok(self)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; HEADER_BYTES + self.payload.len()];
        put_u32(&mut out, 0, MAGIC);
        put_u16(&mut out, 4, SCHEMA_VERSION);
        out[6] = self.header.frame_type as u8;
        out[7] = self.header.flags;
        put_u32(&mut out, 8, HEADER_BYTES as u32);
        put_u32(&mut out, 12, self.payload.len() as u32);
        put_u32(&mut out, 16, self.header.stream_id);
        put_u64(&mut out, 24, self.header.session_hash);
        put_u64(&mut out, 32, self.header.sequence);
        put_u64(&mut out, 40, self.header.path_epoch);
        put_u32(&mut out, 48, self.header.manifest_bytes);
        out[HEADER_BYTES..].copy_from_slice(&self.payload);
        out
    }

    pub fn wire_len(&self) -> usize {
        HEADER_BYTES + self.payload.len()
    }

    pub fn decode(bytes: &[u8], datagram: bool) -> Result<Self, FrameError> {
        if bytes.len() < HEADER_BYTES {
            return Err(FrameError::MalformedLength);
        }
        if get_u32(bytes, 0) != MAGIC {
            return Err(FrameError::BadMagic);
        }
        if get_u16(bytes, 4) != SCHEMA_VERSION {
            return Err(FrameError::BadSchema);
        }
        let frame_type = FrameType::from_byte(bytes[6])?;
        if datagram && !frame_type.is_datagram_only() {
            return Err(FrameError::SemanticDatagram);
        }
        if !datagram && frame_type.is_datagram_only() {
            return Err(FrameError::DatagramRequired);
        }
        let header_bytes = get_u32(bytes, 8) as usize;
        let payload_bytes = get_u32(bytes, 12) as usize;
        let total = header_bytes
            .checked_add(payload_bytes)
            .ok_or(FrameError::MalformedLength)?;
        if header_bytes != HEADER_BYTES || payload_bytes > MAX_PAYLOAD || total != bytes.len() {
            return Err(FrameError::MalformedLength);
        }
        let manifest_bytes = get_u32(bytes, 48);
        if manifest_bytes as usize > payload_bytes {
            return Err(FrameError::BadManifestLength);
        }
        Ok(Self {
            header: FrameHeader {
                frame_type,
                flags: bytes[7],
                stream_id: get_u32(bytes, 16),
                session_hash: get_u64(bytes, 24),
                path_epoch: get_u64(bytes, 40),
                sequence: get_u64(bytes, 32),
                manifest_bytes,
                payload_bytes: payload_bytes as u32,
            },
            payload: bytes[HEADER_BYTES..].to_vec(),
        })
    }

    pub fn manifest(&self) -> &[u8] {
        &self.payload[..self.header.manifest_bytes as usize]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub session: String,
    pub stream: FrameType,
    pub object: Option<[u8; 32]>,
    pub total_bytes: u64,
    pub chunk_size: u32,
    pub resume_token: Vec<u8>,
}

impl Manifest {
    /// Encode a canonical CBOR map. Keys are emitted in bytewise canonical
    /// order and integers use their shortest representation, so equal values
    /// always have equal bytes on every host.
    pub fn encode_cbor(&self) -> Result<Vec<u8>, ManifestError> {
        if self.session.len() > 255 || self.resume_token.len() > 255 {
            return Err(ManifestError::FieldTooLarge);
        }
        let mut out = Vec::with_capacity(128 + self.session.len() + self.resume_token.len());
        cbor_map_len(&mut out, 6);
        cbor_text(&mut out, "stream");
        cbor_uint(&mut out, self.stream as u64);
        cbor_text(&mut out, "object-id");
        match self.object {
            Some(object) => cbor_bytes(&mut out, &object),
            None => out.push(0xf6),
        }
        cbor_text(&mut out, "chunk-size");
        cbor_uint(&mut out, self.chunk_size as u64);
        cbor_text(&mut out, "session-id");
        cbor_text(&mut out, &self.session);
        cbor_text(&mut out, "total-bytes");
        cbor_uint(&mut out, self.total_bytes);
        cbor_text(&mut out, "resume-token");
        cbor_bytes(&mut out, &self.resume_token);
        Ok(out)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ManifestError {
    #[error("manifest field exceeds its bounded wire size")]
    FieldTooLarge,
}

fn cbor_map_len(out: &mut Vec<u8>, len: u8) {
    out.push(0xa0 | len);
}
fn cbor_uint(out: &mut Vec<u8>, value: u64) {
    if value <= 23 {
        out.push(value as u8);
    } else if value <= u8::MAX as u64 {
        out.extend_from_slice(&[0x18, value as u8]);
    } else if value <= u16::MAX as u64 {
        out.push(0x19);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        out.push(0x1a);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(0x1b);
        out.extend_from_slice(&value.to_be_bytes());
    }
}
fn cbor_text(out: &mut Vec<u8>, text: &str) {
    cbor_bytes_header(out, 3, text.len());
    out.extend_from_slice(text.as_bytes());
}
fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    cbor_bytes_header(out, 2, bytes.len());
    out.extend_from_slice(bytes);
}
fn cbor_bytes_header(out: &mut Vec<u8>, major: u8, len: usize) {
    let major = major << 5;
    if len <= 23 {
        out.push(major | len as u8);
    } else if len <= u8::MAX as usize {
        out.extend_from_slice(&[major | 24, len as u8]);
    } else {
        out.push(major | 25);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_payload_bytes: usize,
    pub max_inflight_frames: u32,
    pub max_inflight_bytes: u64,
    pub max_peer_bytes: u64,
    pub keepalive: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_payload_bytes: MAX_PAYLOAD,
            max_inflight_frames: MAX_INFLIGHT_FRAMES,
            max_inflight_bytes: MAX_INFLIGHT_BYTES,
            max_peer_bytes: MAX_PEER_BYTES,
            keepalive: DEFAULT_KEEPALIVE,
        }
    }
}

impl Limits {
    pub fn keepalive_seconds(&self) -> u32 {
        self.keepalive.as_secs().min(u32::MAX as u64) as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowWindow {
    pub frames_in_flight: u32,
    pub bytes_in_flight: u64,
    limits: Limits,
}

impl FlowWindow {
    pub fn new(limits: Limits) -> Self {
        Self {
            frames_in_flight: 0,
            bytes_in_flight: 0,
            limits,
        }
    }

    pub fn allows(&self, frame_bytes: usize) -> bool {
        frame_bytes <= self.limits.max_payload_bytes.min(MAX_PAYLOAD)
            && self.frames_in_flight < self.limits.max_inflight_frames
            && (frame_bytes as u64)
                <= self
                    .limits
                    .max_inflight_bytes
                    .saturating_sub(self.bytes_in_flight)
    }

    pub fn reserve(&mut self, frame_bytes: usize) -> Result<(), GatewayError> {
        if !self.allows(frame_bytes) {
            return Err(GatewayError::FlowControlExceeded);
        }
        self.frames_in_flight += 1;
        self.bytes_in_flight += frame_bytes as u64;
        Ok(())
    }

    pub fn release(&mut self, frame_bytes: usize) {
        self.frames_in_flight = self.frames_in_flight.saturating_sub(1);
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(frame_bytes as u64);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Pending,
    Running,
    Cancelling,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStatus {
    pub session: String,
    pub state: SessionState,
    pub next_task_sequence: u64,
    pub next_event_sequence: u64,
    pub next_object_sequence: u64,
    pub resume_token: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRequest {
    pub session: String,
    pub payload: Vec<u8>,
    pub resume_token: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelRequest {
    pub session: String,
    pub reason: String,
    pub deadline_unix_ms: Option<u64>,
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("peer already has an active connection")]
    DuplicatePeerConnection,
    #[error("peer is not connected")]
    UnknownPeer,
    #[error("session already exists")]
    DuplicateSession,
    #[error("session does not exist")]
    UnknownSession,
    #[error("session is no longer accepting task data")]
    SessionNotActive,
    #[error("replayed or duplicate sequence")]
    DuplicateSequence,
    #[error("frame sequence is outside the bounded receive window")]
    SequenceWindowExceeded,
    #[error("frame belongs to an older migrated path")]
    StalePathEpoch,
    #[error("peer has reached the bounded stream limit")]
    StreamLimitExceeded,
    #[error("peer has reached the bounded session limit")]
    SessionLimitExceeded,
    #[error("frame type is not valid for this QUIC stream direction")]
    InvalidStreamKind,
    #[error("flow-control limit exceeded")]
    FlowControlExceeded,
    #[error("peer memory limit exceeded")]
    PeerMemoryExceeded,
    #[error("resume token is invalid or stale")]
    InvalidResumeToken,
    #[error("invalid peer identity: {0}")]
    InvalidPeer(String),
    #[error("invalid session identity: {0}")]
    InvalidSession(String),
    #[error("QUIC: {0}")]
    Quic(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
struct ReplayBuffer {
    next: u64,
    pending: BTreeMap<u64, Frame>,
    seen: BTreeSet<u64>,
}

impl ReplayBuffer {
    fn new() -> Self {
        Self {
            next: 1,
            pending: BTreeMap::new(),
            seen: BTreeSet::new(),
        }
    }

    fn accept(&mut self, frame: Frame) -> Result<Vec<Frame>, GatewayError> {
        let sequence = frame.header.sequence;
        if sequence < self.next || self.seen.contains(&sequence) {
            return Err(GatewayError::DuplicateSequence);
        }
        if sequence > self.next.saturating_add(MAX_INFLIGHT_FRAMES as u64) {
            return Err(GatewayError::SequenceWindowExceeded);
        }
        self.seen.insert(sequence);
        self.pending.insert(sequence, frame);
        let mut ready = Vec::new();
        while let Some(frame) = self.pending.remove(&self.next) {
            ready.push(frame);
            self.next += 1;
        }
        // Keep the duplicate set bounded even if a peer sends a long stream.
        let floor = self.next.saturating_sub(MAX_INFLIGHT_FRAMES as u64);
        self.seen.retain(|sequence| *sequence >= floor);
        Ok(ready)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeToken(Vec<u8>);

impl ResumeToken {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn mint(secret: &[u8; 32], peer: &str, session: &str, status: &SessionStatus) -> Self {
        let mut body = Vec::with_capacity(64 + peer.len() + session.len());
        body.push(1);
        body.push(peer.len() as u8);
        body.extend_from_slice(peer.as_bytes());
        body.push(session.len() as u8);
        body.extend_from_slice(session.as_bytes());
        body.extend_from_slice(&status.next_task_sequence.to_le_bytes());
        body.extend_from_slice(&status.next_event_sequence.to_le_bytes());
        body.extend_from_slice(&status.next_object_sequence.to_le_bytes());
        let mut mac = Sha256::new();
        mac.update(secret);
        mac.update(&body);
        body.extend_from_slice(&mac.finalize());
        Self(body)
    }

    fn validate(&self, secret: &[u8; 32], peer: &str, session: &str) -> Option<(u64, u64, u64)> {
        let bytes = &self.0;
        if bytes.len() < 1 + 1 + 1 + 24 + 32 || bytes[0] != 1 {
            return None;
        }
        let peer_len = bytes[1] as usize;
        let peer_end = 2usize.checked_add(peer_len)?;
        if bytes.len() < peer_end + 1 {
            return None;
        }
        if bytes.get(2..peer_end)? != peer.as_bytes() {
            return None;
        }
        let session_len = bytes[peer_end] as usize;
        let session_start = peer_end + 1;
        let session_end = session_start.checked_add(session_len)?;
        let numbers_end = session_end.checked_add(24)?;
        let mac_start = numbers_end;
        if bytes.len() != mac_start + 32
            || bytes.get(session_start..session_end)? != session.as_bytes()
        {
            return None;
        }
        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(&bytes[..mac_start]);
        if hasher.finalize().as_slice() != &bytes[mac_start..] {
            return None;
        }
        Some((
            u64::from_le_bytes(bytes[session_end..session_end + 8].try_into().ok()?),
            u64::from_le_bytes(bytes[session_end + 8..session_end + 16].try_into().ok()?),
            u64::from_le_bytes(bytes[session_end + 16..numbers_end].try_into().ok()?),
        ))
    }
}

#[derive(Debug, Clone)]
struct Session {
    state: SessionState,
    next_task: u64,
    next_event: u64,
    next_object: u64,
    cancelled_reason: Option<String>,
}

impl Session {
    fn new() -> Self {
        Self {
            state: SessionState::Pending,
            next_task: 1,
            next_event: 1,
            next_object: 1,
            cancelled_reason: None,
        }
    }
}

#[derive(Debug)]
struct PeerState {
    connection_id: String,
    path: String,
    path_epoch: u64,
    last_activity: Instant,
    window: FlowWindow,
    memory_bytes: u64,
    sessions: HashMap<String, Session>,
    replay: HashMap<u32, ReplayBuffer>,
}

#[derive(Debug)]
struct GatewayInner {
    peers: HashMap<String, PeerState>,
    resumable: BTreeMap<String, HashMap<String, Session>>,
    advertisements: Vec<PeerAdvertisement>,
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub limits: Limits,
    pub resume_secret: [u8; 32],
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            resume_secret: [0x42; 32],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAdvertisement {
    pub peer: String,
    pub node_id: Option<String>,
    pub node_key: Option<String>,
    pub endpoints: Vec<String>,
    pub tags: Vec<String>,
}

/// The singleton gateway state. Construct exactly one instance in the service
/// binary and share its clone with the QUIC accept loop; a peer may be attached
/// only once until its connection is explicitly disconnected.
#[derive(Clone)]
pub struct MeshGateway {
    config: GatewayConfig,
    inner: Arc<Mutex<GatewayInner>>,
}

impl MeshGateway {
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            config,
            inner: Arc::new(Mutex::new(GatewayInner {
                peers: HashMap::new(),
                resumable: BTreeMap::new(),
                advertisements: Vec::new(),
            })),
        }
    }

    pub fn limits(&self) -> Limits {
        self.config.limits
    }

    pub fn set_discovery(&self, advertisements: Vec<PeerAdvertisement>) {
        let mut advertisements: Vec<_> = advertisements
            .into_iter()
            .filter(|advertisement| {
                !advertisement.peer.is_empty() && advertisement.peer.len() <= 255
            })
            .map(|mut advertisement| {
                advertisement.node_id = advertisement.node_id.filter(|value| value.len() <= 255);
                advertisement.node_key = advertisement.node_key.filter(|value| value.len() <= 255);
                advertisement
                    .endpoints
                    .retain(|value| !value.is_empty() && value.len() <= 255);
                advertisement
                    .tags
                    .retain(|value| !value.is_empty() && value.len() <= 255);
                advertisement.endpoints.truncate(64);
                advertisement.tags.truncate(64);
                advertisement
            })
            .collect();
        advertisements.sort_by(|left, right| left.peer.cmp(&right.peer));
        advertisements.dedup_by(|left, right| left.peer == right.peer);
        advertisements.truncate(MAX_DISCOVERED_PEERS);
        self.inner
            .lock()
            .expect("gateway mutex poisoned")
            .advertisements = advertisements;
    }

    pub fn discovered_peers(&self) -> Vec<PeerAdvertisement> {
        self.inner
            .lock()
            .expect("gateway mutex poisoned")
            .advertisements
            .clone()
    }

    pub fn discover_peers(&self) -> Vec<PeerAdvertisement> {
        self.discovered_peers()
    }

    pub fn connect_peer(
        &self,
        peer: &str,
        connection_id: &str,
        path: &str,
    ) -> Result<(), GatewayError> {
        if peer.is_empty() || peer.len() > 255 {
            return Err(GatewayError::InvalidPeer(peer.into()));
        }
        if connection_id.len() > 255 || path.len() > 255 {
            return Err(GatewayError::InvalidPeer(
                "connection metadata too large".into(),
            ));
        }
        let mut inner = self.inner.lock().expect("gateway mutex poisoned");
        if inner.peers.contains_key(peer) {
            return Err(GatewayError::DuplicatePeerConnection);
        }
        let sessions = inner.resumable.remove(peer).unwrap_or_default();
        inner.peers.insert(
            peer.into(),
            PeerState {
                connection_id: connection_id.into(),
                path: path.into(),
                path_epoch: 0,
                last_activity: Instant::now(),
                window: FlowWindow::new(self.config.limits),
                memory_bytes: 0,
                sessions,
                replay: HashMap::new(),
            },
        );
        Ok(())
    }

    pub fn disconnect_peer(&self, peer: &str) -> Result<(), GatewayError> {
        let mut inner = self.inner.lock().expect("gateway mutex poisoned");
        let state = inner.peers.remove(peer).ok_or(GatewayError::UnknownPeer)?;
        if inner.resumable.len() >= MAX_RESUMABLE_PEERS {
            if let Some(oldest) = inner.resumable.keys().next().cloned() {
                inner.resumable.remove(&oldest);
            }
        }
        inner.resumable.insert(peer.into(), state.sessions);
        Ok(())
    }

    pub fn observe_path(&self, peer: &str, path: &str) -> Result<u64, GatewayError> {
        if path.len() > 255 {
            return Err(GatewayError::InvalidPeer("path too large".into()));
        }
        let mut inner = self.inner.lock().expect("gateway mutex poisoned");
        let state = inner.peers.get_mut(peer).ok_or(GatewayError::UnknownPeer)?;
        if state.path != path {
            state.path = path.into();
            state.path_epoch = state.path_epoch.saturating_add(1);
        }
        state.last_activity = Instant::now();
        Ok(state.path_epoch)
    }

    pub fn open_session(&self, peer: &str, session: &str) -> Result<SessionStatus, GatewayError> {
        validate_session(session)?;
        let mut inner = self.inner.lock().expect("gateway mutex poisoned");
        let state = inner.peers.get_mut(peer).ok_or(GatewayError::UnknownPeer)?;
        if state.sessions.contains_key(session) {
            return Err(GatewayError::DuplicateSession);
        }
        if state.sessions.len() >= MAX_SESSIONS_PER_PEER {
            return Err(GatewayError::SessionLimitExceeded);
        }
        state.sessions.insert(session.into(), Session::new());
        Ok(status_for(
            &self.config.resume_secret,
            peer,
            session,
            state.sessions.get(session).unwrap(),
        ))
    }

    /// Implements mesh.open-task as one bounded state transition. A supplied
    /// token resumes the prior session cursor before the task is sequenced;
    /// without one, the session must be new.
    pub fn open_task(
        &self,
        peer: &str,
        request: TaskRequest,
    ) -> Result<SessionStatus, GatewayError> {
        validate_session(&request.session)?;
        if let Some(token) = request.resume_token.as_deref() {
            self.resume(peer, &request.session, token)?;
        } else {
            self.open_session(peer, &request.session)?;
        }
        self.submit_task(peer, &request.session, request.payload)?;
        self.session_status(peer, &request.session)
    }

    pub fn session_status(&self, peer: &str, session: &str) -> Result<SessionStatus, GatewayError> {
        let inner = self.inner.lock().expect("gateway mutex poisoned");
        let state = inner.peers.get(peer).ok_or(GatewayError::UnknownPeer)?;
        let session_state = state
            .sessions
            .get(session)
            .ok_or(GatewayError::UnknownSession)?;
        Ok(status_for(
            &self.config.resume_secret,
            peer,
            session,
            session_state,
        ))
    }

    pub fn submit_task(
        &self,
        peer: &str,
        session: &str,
        payload: Vec<u8>,
    ) -> Result<Frame, GatewayError> {
        let mut inner = self.inner.lock().expect("gateway mutex poisoned");
        let state = inner.peers.get_mut(peer).ok_or(GatewayError::UnknownPeer)?;
        let session_state = state
            .sessions
            .get_mut(session)
            .ok_or(GatewayError::UnknownSession)?;
        if matches!(
            session_state.state,
            SessionState::Cancelling
                | SessionState::Completed
                | SessionState::Failed
                | SessionState::Cancelled
        ) {
            return Err(GatewayError::SessionNotActive);
        }
        let payload_len = payload.len();
        if payload_len > self.config.limits.max_payload_bytes {
            return Err(GatewayError::FlowControlExceeded);
        }
        state.window.reserve(payload_len)?;
        let Some(new_memory) = state.memory_bytes.checked_add(payload_len as u64) else {
            state.window.release(payload_len);
            return Err(GatewayError::PeerMemoryExceeded);
        };
        if new_memory > self.config.limits.max_peer_bytes {
            state.window.release(payload_len);
            return Err(GatewayError::PeerMemoryExceeded);
        }
        state.memory_bytes = new_memory;
        session_state.state = SessionState::Running;
        let sequence = session_state.next_task;
        session_state.next_task += 1;
        state.last_activity = Instant::now();
        Frame::with_metadata(
            FrameType::Task,
            sequence,
            0,
            hash_id(session),
            state.path_epoch,
            payload,
        )
        .map_err(|_| {
            state.window.release(payload_len);
            state.memory_bytes = state.memory_bytes.saturating_sub(payload_len as u64);
            GatewayError::FlowControlExceeded
        })
    }

    pub fn submit_event(
        &self,
        peer: &str,
        session: &str,
        payload: Vec<u8>,
    ) -> Result<Frame, GatewayError> {
        self.submit_stream_frame(peer, session, FrameType::Event, payload)
    }

    pub fn submit_object(
        &self,
        peer: &str,
        session: &str,
        payload: Vec<u8>,
    ) -> Result<Frame, GatewayError> {
        self.submit_stream_frame(peer, session, FrameType::Object, payload)
    }

    fn submit_stream_frame(
        &self,
        peer: &str,
        session: &str,
        frame_type: FrameType,
        payload: Vec<u8>,
    ) -> Result<Frame, GatewayError> {
        let mut inner = self.inner.lock().expect("gateway mutex poisoned");
        let state = inner.peers.get_mut(peer).ok_or(GatewayError::UnknownPeer)?;
        let session_state = state
            .sessions
            .get_mut(session)
            .ok_or(GatewayError::UnknownSession)?;
        if matches!(
            session_state.state,
            SessionState::Completed | SessionState::Failed | SessionState::Cancelled
        ) {
            return Err(GatewayError::SessionNotActive);
        }
        let payload_len = payload.len();
        if payload_len > self.config.limits.max_payload_bytes {
            return Err(GatewayError::FlowControlExceeded);
        }
        state.window.reserve(payload_len)?;
        let Some(new_memory) = state.memory_bytes.checked_add(payload_len as u64) else {
            state.window.release(payload_len);
            return Err(GatewayError::PeerMemoryExceeded);
        };
        if new_memory > self.config.limits.max_peer_bytes {
            state.window.release(payload_len);
            return Err(GatewayError::PeerMemoryExceeded);
        }
        state.memory_bytes = new_memory;
        let (stream_id, sequence) = match frame_type {
            FrameType::Event => {
                let sequence = session_state.next_event;
                session_state.next_event += 1;
                (1, sequence)
            }
            FrameType::Object => {
                let sequence = session_state.next_object;
                session_state.next_object += 1;
                (2, sequence)
            }
            _ => {
                state.window.release(payload_len);
                state.memory_bytes = state.memory_bytes.saturating_sub(payload_len as u64);
                return Err(GatewayError::InvalidStreamKind);
            }
        };
        state.last_activity = Instant::now();
        Frame::with_metadata(
            frame_type,
            sequence,
            stream_id,
            hash_id(session),
            state.path_epoch,
            payload,
        )
        .map_err(|_| {
            state.window.release(payload_len);
            state.memory_bytes = state.memory_bytes.saturating_sub(payload_len as u64);
            GatewayError::FlowControlExceeded
        })
    }

    /// Release the flow-control reservation after a frame returned by one of
    /// the submit methods has been handed to Quinn. The reservation is kept
    /// until this explicit acknowledgement so a slow peer cannot grow an
    /// unbounded application queue.
    pub fn release_sent(&self, peer: &str, bytes: usize) -> Result<(), GatewayError> {
        self.release_received(peer, bytes)
    }

    pub fn receive(&self, peer: &str, frame: Frame) -> Result<Vec<Frame>, GatewayError> {
        let mut inner = self.inner.lock().expect("gateway mutex poisoned");
        let state = inner.peers.get_mut(peer).ok_or(GatewayError::UnknownPeer)?;
        if frame.header.frame_type.is_datagram_only() {
            return Err(GatewayError::InvalidStreamKind);
        }
        if frame.header.path_epoch < state.path_epoch {
            return Err(GatewayError::StalePathEpoch);
        }
        let bytes = frame.payload.len();
        state.window.reserve(bytes)?;
        let Some(new_memory) = state.memory_bytes.checked_add(bytes as u64) else {
            state.window.release(bytes);
            return Err(GatewayError::PeerMemoryExceeded);
        };
        if new_memory > self.config.limits.max_peer_bytes {
            state.window.release(bytes);
            return Err(GatewayError::PeerMemoryExceeded);
        }
        if !state.replay.contains_key(&frame.header.stream_id)
            && state.replay.len() >= MAX_REPLAY_STREAMS
        {
            state.window.release(bytes);
            return Err(GatewayError::StreamLimitExceeded);
        }
        let stream = state
            .replay
            .entry(frame.header.stream_id)
            .or_insert_with(ReplayBuffer::new);
        match stream.accept(frame) {
            Ok(frames) => {
                state.memory_bytes = new_memory;
                state.last_activity = Instant::now();
                Ok(frames)
            }
            Err(error) => {
                state.window.release(bytes);
                Err(error)
            }
        }
    }

    pub fn release_received(&self, peer: &str, bytes: usize) -> Result<(), GatewayError> {
        let mut inner = self.inner.lock().expect("gateway mutex poisoned");
        let state = inner.peers.get_mut(peer).ok_or(GatewayError::UnknownPeer)?;
        state.window.release(bytes);
        state.memory_bytes = state.memory_bytes.saturating_sub(bytes as u64);
        Ok(())
    }

    pub fn cancel(
        &self,
        peer: &str,
        session: &str,
        reason: &str,
    ) -> Result<SessionStatus, GatewayError> {
        let mut inner = self.inner.lock().expect("gateway mutex poisoned");
        let state = inner.peers.get_mut(peer).ok_or(GatewayError::UnknownPeer)?;
        let session_state = state
            .sessions
            .get_mut(session)
            .ok_or(GatewayError::UnknownSession)?;
        session_state.state = SessionState::Cancelling;
        session_state.cancelled_reason = Some(reason.chars().take(256).collect());
        Ok(status_for(
            &self.config.resume_secret,
            peer,
            session,
            session_state,
        ))
    }

    pub fn cancel_request(
        &self,
        peer: &str,
        request: CancelRequest,
    ) -> Result<SessionStatus, GatewayError> {
        // A deadline is carried by the WIT contract for the policy layer. The
        // transport records cancellation immediately; deadline enforcement is
        // intentionally owned by the task service rather than QUIC.
        self.cancel(peer, &request.session, &request.reason)
    }

    pub fn mark_cancelled(&self, peer: &str, session: &str) -> Result<SessionStatus, GatewayError> {
        let mut inner = self.inner.lock().expect("gateway mutex poisoned");
        let state = inner.peers.get_mut(peer).ok_or(GatewayError::UnknownPeer)?;
        let session_state = state
            .sessions
            .get_mut(session)
            .ok_or(GatewayError::UnknownSession)?;
        session_state.state = SessionState::Cancelled;
        Ok(status_for(
            &self.config.resume_secret,
            peer,
            session,
            session_state,
        ))
    }

    pub fn resume(
        &self,
        peer: &str,
        session: &str,
        token: &[u8],
    ) -> Result<SessionStatus, GatewayError> {
        let mut inner = self.inner.lock().expect("gateway mutex poisoned");
        let state = inner.peers.get_mut(peer).ok_or(GatewayError::UnknownPeer)?;
        let session_state = state
            .sessions
            .get_mut(session)
            .ok_or(GatewayError::UnknownSession)?;
        let Some((task, event, object)) =
            ResumeToken(token.to_vec()).validate(&self.config.resume_secret, peer, session)
        else {
            return Err(GatewayError::InvalidResumeToken);
        };
        if task < session_state.next_task
            || event < session_state.next_event
            || object < session_state.next_object
        {
            return Err(GatewayError::InvalidResumeToken);
        }
        session_state.next_task = task;
        session_state.next_event = event;
        session_state.next_object = object;
        Ok(status_for(
            &self.config.resume_secret,
            peer,
            session,
            session_state,
        ))
    }

    pub fn keepalive_due(&self, peer: &str, now: Instant) -> Result<bool, GatewayError> {
        let inner = self.inner.lock().expect("gateway mutex poisoned");
        let state = inner.peers.get(peer).ok_or(GatewayError::UnknownPeer)?;
        Ok(now.saturating_duration_since(state.last_activity) >= self.config.limits.keepalive)
    }

    pub fn peer_memory(&self, peer: &str) -> Result<u64, GatewayError> {
        self.inner
            .lock()
            .expect("gateway mutex poisoned")
            .peers
            .get(peer)
            .map(|state| state.memory_bytes)
            .ok_or(GatewayError::UnknownPeer)
    }

    pub fn peer_connection_id(&self, peer: &str) -> Result<String, GatewayError> {
        self.inner
            .lock()
            .expect("gateway mutex poisoned")
            .peers
            .get(peer)
            .map(|state| state.connection_id.clone())
            .ok_or(GatewayError::UnknownPeer)
    }
}

fn status_for(secret: &[u8; 32], peer: &str, session: &str, state: &Session) -> SessionStatus {
    let mut status = SessionStatus {
        session: session.into(),
        state: state.state,
        next_task_sequence: state.next_task,
        next_event_sequence: state.next_event,
        next_object_sequence: state.next_object,
        resume_token: Vec::new(),
    };
    status.resume_token = ResumeToken::mint(secret, peer, session, &status).0;
    status
}

fn validate_session(session: &str) -> Result<(), GatewayError> {
    if session.is_empty() || session.len() > 255 {
        return Err(GatewayError::InvalidSession(
            session.chars().take(64).collect(),
        ));
    }
    Ok(())
}

fn hash_id(value: &str) -> u64 {
    let digest = Sha256::digest(value.as_bytes());
    u64::from_le_bytes(digest[..8].try_into().expect("sha256 has eight bytes"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureEvent {
    Delivered(Frame),
    Dropped(Frame),
    Disconnected,
}

/// Deterministic host-only transport fixture. It models bounded buffering,
/// loss, duplication, reordering, and disconnects without opening sockets.
#[derive(Debug)]
pub struct InMemoryTransport {
    capacity_bytes: usize,
    queued_bytes: usize,
    queue: VecDeque<Frame>,
    disconnected: bool,
}

impl InMemoryTransport {
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            capacity_bytes,
            queued_bytes: 0,
            queue: VecDeque::new(),
            disconnected: false,
        }
    }

    pub fn send(&mut self, frame: Frame) -> Result<(), GatewayError> {
        let size = frame.payload.len();
        if self.disconnected {
            return Err(GatewayError::UnknownPeer);
        }
        if self.queued_bytes.saturating_add(size) > self.capacity_bytes
            || self.queue.len() >= self.capacity_bytes.max(1)
        {
            return Err(GatewayError::PeerMemoryExceeded);
        }
        self.queued_bytes += size;
        self.queue.push_back(frame);
        Ok(())
    }

    pub fn duplicate_front(&mut self) -> Result<(), GatewayError> {
        let Some(frame) = self.queue.front().cloned() else {
            return Err(GatewayError::UnknownPeer);
        };
        self.send(frame)
    }

    pub fn drop_front(&mut self) -> Option<FixtureEvent> {
        let frame = self.queue.pop_front()?;
        self.queued_bytes = self.queued_bytes.saturating_sub(frame.payload.len());
        Some(FixtureEvent::Dropped(frame))
    }

    pub fn reorder(&mut self) {
        if self.queue.len() > 1 {
            let last = self.queue.pop_back().expect("queue length checked");
            self.queue.push_front(last);
        }
    }

    pub fn disconnect(&mut self) {
        self.disconnected = true;
    }

    pub fn deliver(&mut self) -> Option<FixtureEvent> {
        if self.disconnected {
            return Some(FixtureEvent::Disconnected);
        }
        let frame = self.queue.pop_front()?;
        self.queued_bytes = self.queued_bytes.saturating_sub(frame.payload.len());
        Some(FixtureEvent::Delivered(frame))
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }
    pub fn queued_frames(&self) -> usize {
        self.queue.len()
    }
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("Headscale discovery JSON must contain an array of nodes")]
    InvalidNodes,
    #[error("Headscale discovery returned too many nodes")]
    TooManyPeers,
    #[error("Headscale discovery contains an oversized field")]
    FieldTooLarge,
    #[error("Headscale discovery JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Headscale discovery I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// Reads the atomic `netcap-state.json` emitted by the existing
/// mesh-controller route. This is deliberately a discovery adapter only: tags,
/// node keys, and selected netcaps are returned as metadata and are not used
/// to mint capabilities or authorize a session.
pub struct HeadscaleDiscovery {
    state_path: std::path::PathBuf,
}

impl HeadscaleDiscovery {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            state_path: path.into(),
        }
    }

    pub fn load(&self) -> Result<Vec<PeerAdvertisement>, DiscoveryError> {
        self.load_bytes(&std::fs::read(&self.state_path)?)
    }

    pub fn load_bytes(&self, bytes: &[u8]) -> Result<Vec<PeerAdvertisement>, DiscoveryError> {
        let root: Value = serde_json::from_slice(bytes)?;
        let nodes: &[Value] = match root.get("nodes") {
            Some(Value::Array(nodes)) => nodes.as_slice(),
            // Headscale emits null for an empty node collection.
            Some(Value::Null) => &[],
            _ => return Err(DiscoveryError::InvalidNodes),
        };
        if nodes.len() > MAX_DISCOVERED_PEERS {
            return Err(DiscoveryError::TooManyPeers);
        }
        let mut peers = Vec::with_capacity(nodes.len());
        for node in nodes {
            let peer = node
                .get("node_id")
                .or_else(|| node.get("nodeId"))
                .filter(|value| !value.is_null())
                .map(value_string)
                .or_else(|| node.get("name").and_then(Value::as_str).map(str::to_owned));
            let Some(peer) = peer else {
                continue;
            };
            if peer.is_empty() || peer.len() > 255 {
                return Err(DiscoveryError::FieldTooLarge);
            }
            let node_id = node
                .get("node_id")
                .or_else(|| node.get("nodeId"))
                .filter(|value| !value.is_null())
                .map(value_string);
            let node_key = node
                .get("node_key")
                .or_else(|| node.get("nodeKey"))
                .filter(|value| !value.is_null())
                .map(value_string);
            if node_id.as_ref().is_some_and(|value| value.len() > 255)
                || node_key.as_ref().is_some_and(|value| value.len() > 255)
            {
                return Err(DiscoveryError::FieldTooLarge);
            }
            let strings = |keys: &[&str]| {
                keys.iter()
                    .find_map(|key| node.get(key).and_then(Value::as_array))
                    .map(|items| {
                        items
                            .iter()
                            .take(64)
                            .filter_map(Value::as_str)
                            .filter(|value| !value.is_empty() && value.len() <= 255)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default()
            };
            peers.push(PeerAdvertisement {
                peer,
                node_id,
                node_key,
                endpoints: strings(&["endpoints", "addresses"]),
                tags: strings(&["authenticated_tags", "tags"]),
            });
        }
        peers.sort_by(|left, right| left.peer.cmp(&right.peer));
        Ok(peers)
    }
}

fn value_string(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

/// Quinn integration. The endpoint is supplied by the process so certificate
/// and private-key policy stays outside the semantic session state.
pub struct QuicService {
    endpoint: Endpoint,
    gateway: MeshGateway,
}

impl QuicService {
    pub fn new(endpoint: Endpoint, gateway: MeshGateway) -> Self {
        Self { endpoint, gateway }
    }

    pub async fn run(self, peer: String) -> Result<(), GatewayError> {
        while let Some(incoming) = self.endpoint.accept().await {
            let connection = incoming
                .await
                .map_err(|error| GatewayError::Quic(error.to_string()))?;
            let gateway = self.gateway.clone();
            let peer = peer.clone();
            tokio::spawn(async move {
                let connection_id = connection.remote_address().to_string();
                if gateway
                    .connect_peer(&peer, &connection_id, &connection_id)
                    .is_err()
                {
                    connection.close(quinn::VarInt::from_u32(1), b"duplicate peer");
                    return;
                }
                let _ = serve_connection(gateway.clone(), peer.clone(), connection).await;
                let _ = gateway.disconnect_peer(&peer);
            });
        }
        Ok(())
    }
}

async fn serve_connection(
    gateway: MeshGateway,
    peer: String,
    connection: Connection,
) -> Result<(), GatewayError> {
    loop {
        tokio::select! {
            result = connection.accept_bi() => {
                let (send, receive) = result.map_err(|error| GatewayError::Quic(error.to_string()))?;
                let gateway = gateway.clone();
                let peer = peer.clone();
                let connection = connection.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_bi(gateway, peer, connection.clone(), send, receive).await {
                        connection.close(quinn::VarInt::from_u32(2), error.to_string().as_bytes());
                    }
                });
            }
            result = connection.accept_uni() => {
                let receive = result.map_err(|error| GatewayError::Quic(error.to_string()))?;
                let gateway = gateway.clone();
                let peer = peer.clone();
                let connection = connection.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_uni(gateway, peer, connection.clone(), receive).await {
                        connection.close(quinn::VarInt::from_u32(3), error.to_string().as_bytes());
                    }
                });
            }
            result = connection.read_datagram() => {
                let bytes = result.map_err(|error| GatewayError::Quic(error.to_string()))?;
                gateway.observe_path(&peer, &connection.remote_address().to_string())?;
                // Datagrams are disposable hints only; they never enter
                // replay, flow, or session state.
                if bytes.len() <= MAX_FRAME_BYTES {
                    let _ = Frame::decode(&bytes, true);
                }
            }
        }
    }
}

async fn handle_bi(
    gateway: MeshGateway,
    peer: String,
    connection: Connection,
    mut send: quinn::SendStream,
    mut receive: quinn::RecvStream,
) -> Result<(), GatewayError> {
    gateway.observe_path(&peer, &connection.remote_address().to_string())?;
    let bytes = receive
        .read_to_end(MAX_FRAME_BYTES + 4)
        .await
        .map_err(|error| GatewayError::Quic(error.to_string()))?;
    let frame = decode_record(&bytes)?;
    if !matches!(
        frame.header.frame_type,
        FrameType::Task | FrameType::Control
    ) {
        return Err(GatewayError::InvalidStreamKind);
    }
    let ready = gateway.receive(&peer, frame)?;
    for frame in ready {
        let frame_bytes = frame.payload.len();
        let encoded = encode_record(&frame);
        send.write_all(&encoded)
            .await
            .map_err(|error| GatewayError::Quic(error.to_string()))?;
        gateway.release_received(&peer, frame_bytes)?;
    }
    send.finish()
        .map_err(|error| GatewayError::Quic(error.to_string()))?;
    Ok(())
}

async fn handle_uni(
    gateway: MeshGateway,
    peer: String,
    connection: Connection,
    mut receive: quinn::RecvStream,
) -> Result<(), GatewayError> {
    gateway.observe_path(&peer, &connection.remote_address().to_string())?;
    let bytes = receive
        .read_to_end(MAX_FRAME_BYTES + 4)
        .await
        .map_err(|error| GatewayError::Quic(error.to_string()))?;
    let frame = decode_record(&bytes)?;
    if !matches!(
        frame.header.frame_type,
        FrameType::Event | FrameType::Object
    ) {
        return Err(GatewayError::InvalidStreamKind);
    }
    for frame in gateway.receive(&peer, frame)? {
        gateway.release_received(&peer, frame.payload.len())?;
    }
    Ok(())
}

fn encode_record(frame: &Frame) -> Vec<u8> {
    let encoded = frame.encode();
    let mut record = Vec::with_capacity(4 + encoded.len());
    record.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
    record.extend_from_slice(&encoded);
    record
}

fn decode_record(bytes: &[u8]) -> Result<Frame, GatewayError> {
    if bytes.len() < 4 {
        return Err(GatewayError::FlowControlExceeded);
    }
    let length = u32::from_le_bytes(bytes[..4].try_into().expect("four bytes checked")) as usize;
    let Some(record_bytes) = length.checked_add(4) else {
        return Err(GatewayError::FlowControlExceeded);
    };
    if length > MAX_FRAME_BYTES || record_bytes != bytes.len() {
        return Err(GatewayError::FlowControlExceeded);
    }
    Frame::decode(&bytes[4..], false).map_err(|_| GatewayError::FlowControlExceeded)
}

/// Build a server configuration with the mandatory ALPN. Callers should use
/// their provisioned certificate in production; this helper is for local
/// deterministic fixtures and development service startup.
pub fn server_config(
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<ServerConfig, GatewayError> {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|error| GatewayError::Quic(error.to_string()))?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|error| GatewayError::Quic(error.to_string()))?;
    Ok(ServerConfig::with_crypto(Arc::new(quic_tls)))
}

pub fn development_server_config() -> Result<ServerConfig, GatewayError> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .map_err(|error| GatewayError::Quic(error.to_string()))?;
    let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        certified.key_pair.serialize_der(),
    ));
    server_config(cert, key)
}

pub async fn bind_development_gateway(
    bind: SocketAddr,
    gateway: MeshGateway,
) -> Result<QuicService, GatewayError> {
    let mut config = development_server_config()?;
    if let Some(transport) = Arc::get_mut(&mut config.transport) {
        transport
            .keep_alive_interval(Some(gateway.limits().keepalive))
            .max_concurrent_bidi_streams(quinn::VarInt::from_u32(MAX_INFLIGHT_FRAMES))
            .max_concurrent_uni_streams(quinn::VarInt::from_u32(MAX_INFLIGHT_FRAMES))
            .datagram_receive_buffer_size(Some(MAX_PAYLOAD));
    }
    let endpoint = Endpoint::server(config, bind)?;
    Ok(QuicService::new(endpoint, gateway))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_is_fixed_width_and_round_trips() {
        let frame = Frame::with_metadata(FrameType::Task, 7, 3, 9, 2, vec![1, 2, 3]).unwrap();
        assert_eq!(frame.encode().len(), HEADER_BYTES + 3);
        assert_eq!(Frame::decode(&frame.encode(), false).unwrap(), frame);
    }

    #[test]
    fn manifests_are_deterministic_cbor() {
        let manifest = Manifest {
            session: "s".into(),
            stream: FrameType::Object,
            object: None,
            total_bytes: 9,
            chunk_size: 4,
            resume_token: vec![1, 2],
        };
        assert_eq!(
            manifest.encode_cbor().unwrap(),
            manifest.encode_cbor().unwrap()
        );
        assert_eq!(manifest.encode_cbor().unwrap()[0], 0xa6);
    }

    #[test]
    fn reorder_is_buffered_and_duplicates_rejected() {
        let mut replay = ReplayBuffer::new();
        let two = Frame::new(FrameType::Event, 2, vec![]).unwrap();
        let one = Frame::new(FrameType::Event, 1, vec![]).unwrap();
        assert!(replay.accept(two).unwrap().is_empty());
        assert_eq!(replay.accept(one).unwrap().len(), 2);
        assert!(matches!(
            replay.accept(Frame::new(FrameType::Event, 2, vec![]).unwrap()),
            Err(GatewayError::DuplicateSequence)
        ));
    }

    #[test]
    fn fixture_is_bounded() {
        let mut transport = InMemoryTransport::new(2);
        assert!(transport
            .send(Frame::new(FrameType::Hint, 1, vec![1, 2]).unwrap())
            .is_ok());
        assert!(matches!(
            transport.send(Frame::new(FrameType::Hint, 2, vec![3]).unwrap()),
            Err(GatewayError::PeerMemoryExceeded)
        ));
    }

    #[test]
    fn disconnect_reconnect_and_path_migration_preserve_resume_state() {
        let gateway = MeshGateway::new(GatewayConfig::default());
        gateway
            .connect_peer("peer-a", "conn-1", "10.0.0.1:8443")
            .unwrap();
        let opened = gateway.open_session("peer-a", "session-a").unwrap();
        let task = gateway.submit_task("peer-a", "session-a", vec![7]).unwrap();
        assert_eq!(task.header.sequence, 1);
        assert_eq!(gateway.observe_path("peer-a", "10.0.0.2:8443").unwrap(), 1);
        let current = gateway.session_status("peer-a", "session-a").unwrap();
        gateway.disconnect_peer("peer-a").unwrap();
        gateway
            .connect_peer("peer-a", "conn-2", "10.0.0.2:8443")
            .unwrap();
        let resumed = gateway
            .resume("peer-a", "session-a", &current.resume_token)
            .unwrap();
        assert_eq!(resumed.next_task_sequence, 2);
        assert_ne!(opened.resume_token, current.resume_token);
        assert_eq!(gateway.peer_connection_id("peer-a").unwrap(), "conn-2");
    }

    #[test]
    fn cancellation_stops_new_tasks_but_keeps_status_explicit() {
        let gateway = MeshGateway::new(GatewayConfig::default());
        gateway.connect_peer("peer-a", "conn", "path").unwrap();
        gateway.open_session("peer-a", "session-a").unwrap();
        let status = gateway
            .cancel("peer-a", "session-a", "user request")
            .unwrap();
        assert_eq!(status.state, SessionState::Cancelling);
        assert!(matches!(
            gateway.submit_task("peer-a", "session-a", vec![]),
            Err(GatewayError::SessionNotActive)
        ));
        let status = gateway.mark_cancelled("peer-a", "session-a").unwrap();
        assert_eq!(status.state, SessionState::Cancelled);
    }

    #[test]
    fn headscale_empty_and_string_node_ids_are_discovery_only() {
        let discovery = HeadscaleDiscovery::new("unused");
        assert!(discovery
            .load_bytes(br#"{"schema":1,"nodes":null}"#)
            .unwrap()
            .is_empty());
        let peers = discovery
            .load_bytes(br#"{"nodes":[{"node_id":"node-7","node_key":"key","authenticated_tags":["tag:agent"]}]}"#)
            .unwrap();
        assert_eq!(peers[0].peer, "node-7");
        assert_eq!(peers[0].tags, vec!["tag:agent"]);
    }
}
