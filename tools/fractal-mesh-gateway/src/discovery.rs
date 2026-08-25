//! Headscale netcap discovery and signed Fractal service advertisements.
//!
//! Tailnet / Headscale fields are connectivity metadata only. They never mint
//! Agent ISA authority. A `deny` or missing NetCap rejects mesh eligibility.

use sha2::{Digest, Sha512};
use std::path::PathBuf;
use thiserror::Error;

use crate::{value_string, GatewayError, MAX_DISCOVERED_PEERS};

/// Matches `MESH_ADVERTISEMENT_SIGNATURE_DOMAIN` in remote_grant.h.
pub const SERVICE_AD_SIGNATURE_DOMAIN: &[u8] = b"fractalos/fractal-service-ad/1";
pub const SERVICE_ID_BYTES: usize = 32;
pub const NODE_ID_BYTES: usize = 32;
pub const INTERFACE_HASH_BYTES: usize = 32;
pub const ENDPOINT_BYTES: usize = 64;
pub const SIGNATURE_BYTES: usize = 64;
pub const SERVICE_AD_SIGNING_BYTES: usize = 184;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPathKind {
    /// Direct WireGuard UDP between peers.
    Direct,
    /// Configured peer relay (not DERP).
    Relay,
    /// DERP / connectivity fallback.
    Derp,
    /// Path class not yet observed.
    Unknown,
}

impl ConnectionPathKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
            Self::Derp => "derp",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPathState {
    pub peer: String,
    pub path: String,
    pub kind: ConnectionPathKind,
    pub path_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAdvertisement {
    pub peer: String,
    pub node_id: Option<String>,
    pub node_key: Option<String>,
    /// MagicDNS / given name from Headscale (`name` in netcap-state).
    pub magic_dns: Option<String>,
    pub endpoints: Vec<String>,
    pub tags: Vec<String>,
    pub selected_tag: Option<String>,
    /// Reconciled NetCap label (`mesh-agent`, `mesh-control`, `deny`, …).
    pub netcap: String,
    pub agent_endpoint_ports: Vec<u16>,
    /// True when NetCap permits MeshGateway transport (not `deny` / empty).
    pub policy_allowed: bool,
}

impl PeerAdvertisement {
    pub fn is_mesh_eligible(&self) -> bool {
        self.policy_allowed
            && !self.peer.is_empty()
            && !self.agent_endpoint_ports.is_empty()
    }
}

/// Signed Fractal service advertisement (discovery only — grants no call right).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAdvertisement {
    pub service_id: [u8; SERVICE_ID_BYTES],
    pub provider_node: [u8; NODE_ID_BYTES],
    pub interface_hash: [u8; INTERFACE_HASH_BYTES],
    pub endpoint: [u8; ENDPOINT_BYTES],
    pub required_capability: u64,
    pub health_epoch: u64,
    pub expiry_unix_ms: u64,
    pub signature: [u8; SIGNATURE_BYTES],
}

impl ServiceAdvertisement {
    pub fn signing_bytes(&self) -> [u8; SERVICE_AD_SIGNING_BYTES] {
        let mut out = [0u8; SERVICE_AD_SIGNING_BYTES];
        let mut offset = 0usize;
        out[offset..offset + SERVICE_ID_BYTES].copy_from_slice(&self.service_id);
        offset += SERVICE_ID_BYTES;
        out[offset..offset + NODE_ID_BYTES].copy_from_slice(&self.provider_node);
        offset += NODE_ID_BYTES;
        out[offset..offset + INTERFACE_HASH_BYTES].copy_from_slice(&self.interface_hash);
        offset += INTERFACE_HASH_BYTES;
        out[offset..offset + ENDPOINT_BYTES].copy_from_slice(&self.endpoint);
        offset += ENDPOINT_BYTES;
        out[offset..offset + 8].copy_from_slice(&self.required_capability.to_le_bytes());
        offset += 8;
        out[offset..offset + 8].copy_from_slice(&self.health_epoch.to_le_bytes());
        offset += 8;
        out[offset..offset + 8].copy_from_slice(&self.expiry_unix_ms.to_le_bytes());
        debug_assert_eq!(offset + 8, SERVICE_AD_SIGNING_BYTES);
        out
    }

    /// Host-proof signature: SHA-512(domain || 0x00 || signing_bytes || secret).
    /// Production AuthServer will replace this with the contract Ed25519 verifier.
    pub fn sign(&mut self, secret: &[u8; 32]) {
        self.signature = sign_service_ad(&self.signing_bytes(), secret);
    }

    pub fn verify(&self, secret: &[u8; 32]) -> bool {
        verify_service_ad(&self.signing_bytes(), secret, &self.signature)
    }
}

pub fn sign_service_ad(signing_bytes: &[u8; SERVICE_AD_SIGNING_BYTES], secret: &[u8; 32]) -> [u8; SIGNATURE_BYTES] {
    let mut hasher = Sha512::new();
    hasher.update(SERVICE_AD_SIGNATURE_DOMAIN);
    hasher.update([0u8]);
    hasher.update(signing_bytes);
    hasher.update(secret);
    let digest = hasher.finalize();
    let mut signature = [0u8; SIGNATURE_BYTES];
    signature.copy_from_slice(&digest);
    signature
}

pub fn verify_service_ad(
    signing_bytes: &[u8; SERVICE_AD_SIGNING_BYTES],
    secret: &[u8; 32],
    signature: &[u8; SIGNATURE_BYTES],
) -> bool {
    sign_service_ad(signing_bytes, secret) == *signature
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("Headscale discovery JSON must contain an array of nodes")]
    InvalidNodes,
    #[error("Headscale discovery returned too many nodes")]
    TooManyPeers,
    #[error("Headscale discovery contains an oversized field")]
    FieldTooLarge,
    #[error("Headscale discovery missing deny-by-default NetCap policy for a node")]
    MissingPolicy,
    #[error("Headscale discovery JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Headscale discovery I/O: {0}")]
    Io(#[from] std::io::Error),
}

impl From<DiscoveryError> for GatewayError {
    fn from(value: DiscoveryError) -> Self {
        GatewayError::Discovery(value.to_string())
    }
}

/// Reads the atomic `netcap-state.json` emitted by the mesh-controller route.
pub struct HeadscaleDiscovery {
    state_path: PathBuf,
}

impl HeadscaleDiscovery {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            state_path: path.into(),
        }
    }

    pub fn load(&self) -> Result<Vec<PeerAdvertisement>, DiscoveryError> {
        self.load_bytes(&std::fs::read(&self.state_path)?)
    }

    pub fn load_bytes(&self, bytes: &[u8]) -> Result<Vec<PeerAdvertisement>, DiscoveryError> {
        let root: serde_json::Value = serde_json::from_slice(bytes)?;
        let nodes: &[serde_json::Value] = match root.get("nodes") {
            Some(serde_json::Value::Array(nodes)) => nodes.as_slice(),
            Some(serde_json::Value::Null) => &[],
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
                .or_else(|| node.get("name").and_then(serde_json::Value::as_str).map(str::to_owned));
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
            let magic_dns = node
                .get("name")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 255)
                .map(str::to_owned);
            let selected_tag = node
                .get("selected_tag")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 255)
                .map(str::to_owned);
            if node_id.as_ref().is_some_and(|value| value.len() > 255)
                || node_key.as_ref().is_some_and(|value| value.len() > 255)
            {
                return Err(DiscoveryError::FieldTooLarge);
            }
            let netcap = match node.get("netcap").and_then(serde_json::Value::as_str) {
                Some(value) if !value.is_empty() && value.len() <= 255 => value.to_owned(),
                Some(_) => return Err(DiscoveryError::FieldTooLarge),
                None => return Err(DiscoveryError::MissingPolicy),
            };
            let agent_endpoint_ports = node
                .get("agent_endpoint_ports")
                .and_then(serde_json::Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .take(64)
                        .filter_map(|value| {
                            value
                                .as_u64()
                                .and_then(|port| u16::try_from(port).ok())
                                .filter(|port| *port != 0)
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let strings = |keys: &[&str]| {
                keys.iter()
                    .find_map(|key| node.get(key).and_then(serde_json::Value::as_array))
                    .map(|items| {
                        items
                            .iter()
                            .take(64)
                            .filter_map(serde_json::Value::as_str)
                            .filter(|value| !value.is_empty() && value.len() <= 255)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let policy_allowed = netcap != "deny";
            peers.push(PeerAdvertisement {
                peer,
                node_id,
                node_key,
                magic_dns,
                endpoints: strings(&["endpoints", "addresses"]),
                tags: strings(&["authenticated_tags", "tags"]),
                selected_tag,
                netcap,
                agent_endpoint_ports,
                policy_allowed,
            });
        }
        peers.sort_by(|left, right| left.peer.cmp(&right.peer));
        Ok(peers)
    }
}

pub fn mesh_eligible_peers(advertisements: &[PeerAdvertisement]) -> Vec<PeerAdvertisement> {
    advertisements
        .iter()
        .filter(|peer| peer.is_mesh_eligible())
        .cloned()
        .collect()
}
