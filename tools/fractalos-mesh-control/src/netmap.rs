//! Packed `OP_WG_APPLY_NETMAP` encoder (matches `wg_net.h` layout).

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

pub const WG_NETMAP_VERSION: u32 = 1;
pub const WG_KEY_LEN: usize = 32;
pub const WG_NETMAP_PEER_BYTES: usize = 48;
pub const WG_NETMAP_HEADER_BYTES: usize = 8;
pub const WG_MAX_PEERS: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub name: Option<String>,
    /// 64-char hex node/WireGuard public key.
    pub node_key_hex: String,
    /// Allowed IP as host-endian u32 matching wg_net tests (BE wire value).
    pub allowed_ip: u32,
    pub endpoint_ip: u32,
    pub endpoint_port: u16,
}

fn decode_hex_key(hex_str: &str) -> Result<[u8; WG_KEY_LEN]> {
    let s = hex_str
        .trim()
        .strip_prefix("nodekey:")
        .unwrap_or(hex_str.trim());
    let bytes = hex::decode(s)?;
    if bytes.len() != WG_KEY_LEN {
        bail!("node key length {} != 32", bytes.len());
    }
    let mut out = [0u8; WG_KEY_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn encode_nodes_to_netmap(peers: &[PeerRecord]) -> Result<Vec<u8>> {
    if peers.len() > WG_MAX_PEERS {
        bail!("peer count {} exceeds WG_MAX_PEERS", peers.len());
    }
    let mut out =
        Vec::with_capacity(WG_NETMAP_HEADER_BYTES + peers.len() * WG_NETMAP_PEER_BYTES);
    out.extend_from_slice(&WG_NETMAP_VERSION.to_le_bytes());
    out.extend_from_slice(&(peers.len() as u32).to_le_bytes());
    for p in peers {
        let key = decode_hex_key(&p.node_key_hex)?;
        out.extend_from_slice(&key);
        out.extend_from_slice(&p.endpoint_ip.to_le_bytes());
        out.extend_from_slice(&p.endpoint_port.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&p.allowed_ip.to_le_bytes());
        let mask: u32 = if p.allowed_ip != 0 { 0xffff_ffff } else { 0 };
        out.extend_from_slice(&mask.to_le_bytes());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_one_peer() {
        let peers = [PeerRecord {
            name: Some("a".into()),
            node_key_hex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                .into(),
            allowed_ip: u32::from_be_bytes([100, 64, 0, 1]),
            endpoint_ip: u32::from_be_bytes([10, 0, 0, 1]),
            endpoint_port: 51820,
        }];
        let blob = encode_nodes_to_netmap(&peers).unwrap();
        assert_eq!(blob.len(), 8 + 48);
        assert_eq!(&blob[0..4], &1u32.to_le_bytes());
        assert_eq!(blob[8], 0x01);
    }
}
