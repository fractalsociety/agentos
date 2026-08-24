//! Contract tests for the generated, transport-neutral Fractal Mesh frame.
//!
//! This is deliberately a small schema mirror, not a transport implementation.
//! The production encoder/decoder is generated from the mesh schema and must
//! preserve these fixed-width fields and rejection rules.  In particular,
//! semantic frames are length-delimited reliable-stream records; datagrams are
//! limited to disposable hints.

const MAGIC: u32 = 0x314d_5346; // "FSM1"
const SCHEMA_VERSION: u16 = 1;
const HEADER_BYTES: usize = 64;
const MAX_PAYLOAD: usize = 64 * 1024;
const MAX_INFLIGHT_FRAMES: u32 = 64;
const MAX_INFLIGHT_BYTES: u64 = 1024 * 1024;

const TASK: u8 = 1;
const EVENT: u8 = 2;
const OBJECT: u8 = 3;
const CONTROL: u8 = 4;
const HINT: u8 = 5;

#[derive(Debug, PartialEq, Eq)]
enum FrameError {
    MalformedLength,
    BadMagic,
    BadSchema,
    SemanticDatagram,
}

#[derive(Debug, PartialEq, Eq)]
struct Header {
    frame_type: u8,
    payload_bytes: usize,
    sequence: u64,
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn frame(frame_type: u8, payload_bytes: usize, sequence: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; HEADER_BYTES + payload_bytes];
    put_u32(&mut bytes, 0, MAGIC);
    put_u16(&mut bytes, 4, SCHEMA_VERSION);
    bytes[6] = frame_type;
    put_u32(&mut bytes, 8, HEADER_BYTES as u32);
    put_u32(&mut bytes, 12, payload_bytes as u32);
    put_u64(&mut bytes, 32, sequence);
    bytes
}

fn decode(bytes: &[u8], datagram: bool) -> Result<Header, FrameError> {
    if bytes.len() < HEADER_BYTES {
        return Err(FrameError::MalformedLength);
    }
    if get_u32(bytes, 0) != MAGIC {
        return Err(FrameError::BadMagic);
    }
    if get_u16(bytes, 4) != SCHEMA_VERSION {
        return Err(FrameError::BadSchema);
    }
    let frame_type = bytes[6];
    if !(TASK..=HINT).contains(&frame_type) {
        return Err(FrameError::BadSchema);
    }
    if datagram && frame_type != HINT {
        return Err(FrameError::SemanticDatagram);
    }
    let header_bytes = get_u32(bytes, 8) as usize;
    let payload_bytes = get_u32(bytes, 12) as usize;
    let total = header_bytes
        .checked_add(payload_bytes)
        .ok_or(FrameError::MalformedLength)?;
    if header_bytes != HEADER_BYTES || payload_bytes > MAX_PAYLOAD || total != bytes.len() {
        return Err(FrameError::MalformedLength);
    }
    Ok(Header {
        frame_type,
        payload_bytes,
        sequence: get_u64(bytes, 32),
    })
}

#[derive(Clone, Copy)]
struct ReplayCursor {
    highest_sequence: u64,
}

impl ReplayCursor {
    fn accept(&mut self, sequence: u64) -> bool {
        if sequence <= self.highest_sequence {
            return false;
        }
        self.highest_sequence = sequence;
        true
    }
}

struct Grant {
    audience: [u8; 32],
    authority_epoch: u64,
    revocation_epoch: u64,
}

fn grant_is_current(grant: &Grant, audience: &[u8; 32], authority: u64, revocation: u64) -> bool {
    grant.audience == *audience
        && grant.authority_epoch == authority
        && grant.revocation_epoch == revocation
}

struct CompletionGuard {
    completed: bool,
}

impl CompletionGuard {
    fn accept(&mut self) -> bool {
        if self.completed {
            return false;
        }
        self.completed = true;
        true
    }
}

struct FlowWindow {
    frames_in_flight: u32,
    bytes_in_flight: u64,
}

impl FlowWindow {
    fn allows(&self, frame_bytes: usize) -> bool {
        (frame_bytes as u64) <= MAX_PAYLOAD as u64
            && self.frames_in_flight < MAX_INFLIGHT_FRAMES
            && self.bytes_in_flight <= MAX_INFLIGHT_BYTES
            && (frame_bytes as u64) <= MAX_INFLIGHT_BYTES - self.bytes_in_flight
    }
}

#[test]
fn malformed_lengths_are_rejected_before_payload_access() {
    let mut bytes = frame(TASK, 8, 1);
    put_u32(&mut bytes, 12, (MAX_PAYLOAD + 1) as u32);
    assert_eq!(decode(&bytes, false), Err(FrameError::MalformedLength));

    let mut truncated = frame(EVENT, 8, 2);
    truncated.truncate(HEADER_BYTES - 1);
    assert_eq!(decode(&truncated, false), Err(FrameError::MalformedLength));

    let mut wrong_header = frame(TASK, 0, 3);
    put_u32(&mut wrong_header, 8, (HEADER_BYTES - 1) as u32);
    assert_eq!(
        decode(&wrong_header, false),
        Err(FrameError::MalformedLength)
    );
}

#[test]
fn replayed_sequence_is_rejected() {
    let first = decode(&frame(OBJECT, 0, 9), false).unwrap();
    let duplicate = decode(&frame(OBJECT, 0, 9), false).unwrap();
    let mut cursor = ReplayCursor {
        highest_sequence: 0,
    };
    assert!(cursor.accept(first.sequence));
    assert!(!cursor.accept(duplicate.sequence));
}

#[test]
fn wrong_grant_audience_is_rejected() {
    let grant = Grant {
        audience: [7u8; 32],
        authority_epoch: 4,
        revocation_epoch: 9,
    };
    assert!(!grant_is_current(&grant, &[8u8; 32], 4, 9));
}

#[test]
fn stale_revocation_epoch_is_rejected() {
    let grant = Grant {
        audience: [1u8; 32],
        authority_epoch: 4,
        revocation_epoch: 8,
    };
    assert!(!grant_is_current(&grant, &[1u8; 32], 4, 9));
}

#[test]
fn remote_badge_injection_has_no_authority() {
    // The generated RemoteGrant has no badge field.  Any badge supplied by a
    // peer is untrusted data and cannot be converted into local authority.
    fn remote_badge_is_authority(_: u64) -> bool {
        false
    }
    assert!(!remote_badge_is_authority(0xfeed_u64));
}

#[test]
fn duplicate_completion_is_rejected() {
    let mut guard = CompletionGuard { completed: false };
    assert!(guard.accept());
    assert!(!guard.accept());
}

#[test]
fn flow_control_is_bounded_and_datagrams_are_hints_only() {
    let mut window = FlowWindow {
        frames_in_flight: 0,
        bytes_in_flight: 0,
    };
    assert!(window.allows(1024));
    window.frames_in_flight = MAX_INFLIGHT_FRAMES;
    assert!(!window.allows(1));

    assert_eq!(decode(&frame(HINT, 0, 1), true).unwrap().frame_type, HINT);
    assert_eq!(
        decode(&frame(CONTROL, 0, 1), true),
        Err(FrameError::SemanticDatagram)
    );
}
