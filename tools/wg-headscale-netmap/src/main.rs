//! Host tool: Headscale node JSON → packed `OP_WG_APPLY_NETMAP` blob.
//!
//! Does **not** implement Tailscale Noise (ts2021) login. It consumes an
//! already-authorized Headscale node list (fixture or REST `/api/v1/node`)
//! and emits the freestanding packed netmap `wg_net` applies.

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

const WG_NETMAP_VERSION: u32 = 1;
const WG_KEY_LEN: usize = 32;
const WG_NETMAP_PEER_BYTES: usize = 48;
const WG_NETMAP_HEADER_BYTES: usize = 8;
const WG_MAX_PEERS: usize = 16;

#[derive(Parser, Debug)]
#[command(name = "wg-headscale-netmap")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Encode a Headscale-style nodes JSON document to a packed netmap.
    Encode {
        /// Input JSON path (`-` = stdin).
        #[arg(long, default_value = "-")]
        input: String,
        /// Output path (`-` = stdout).
        #[arg(long, default_value = "-")]
        output: String,
    },
    /// Fetch `/api/v1/node` from a live Headscale and encode the netmap.
    Fetch {
        #[arg(long, env = "FRACTALOS_HEADSCALE_URL")]
        url: String,
        #[arg(long, env = "FRACTALOS_HEADSCALE_TOKEN_FILE")]
        token_file: PathBuf,
        #[arg(long, default_value = "-")]
        output: String,
    },
}

#[derive(Debug, Deserialize)]
struct NodeList {
    #[serde(default)]
    nodes: Vec<Node>,
}

#[derive(Debug, Deserialize)]
struct Node {
    #[serde(default, alias = "nodeKey", alias = "node_key")]
    node_key: Option<String>,
    #[serde(default, alias = "ipAddresses", alias = "ip_addresses")]
    ip_addresses: Vec<String>,
    #[serde(default)]
    endpoints: Vec<String>,
    #[serde(default)]
    name: Option<String>,
}

fn decode_key(raw: &str) -> Result<[u8; WG_KEY_LEN]> {
    let s = raw.trim();
    if let Ok(bytes) = hex::decode(s) {
        if bytes.len() == WG_KEY_LEN {
            let mut out = [0u8; WG_KEY_LEN];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
    }
    let engine = base64::engine::general_purpose::STANDARD;
    if let Ok(bytes) = engine.decode(s) {
        if bytes.len() == WG_KEY_LEN {
            let mut out = [0u8; WG_KEY_LEN];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
    }
    // Tailscale node keys are often `nodekey:` prefixed hex.
    let stripped = s
        .strip_prefix("nodekey:")
        .or_else(|| s.strip_prefix("nodeKey:"))
        .unwrap_or(s);
    let bytes = hex::decode(stripped).context("node key is not hex/base64")?;
    if bytes.len() != WG_KEY_LEN {
        bail!("node key length {} != 32", bytes.len());
    }
    let mut out = [0u8; WG_KEY_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_ipv4(s: &str) -> Option<u32> {
    let parts: Vec<_> = s.trim().split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut o = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        o[i] = p.parse().ok()?;
    }
    Some(u32::from_be_bytes(o))
}

fn parse_endpoint(s: &str) -> Option<(u32, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let ip = parse_ipv4(host)?;
    let port: u16 = port.parse().ok()?;
    Some((ip, port))
}

fn encode_netmap(nodes: &[Node]) -> Result<Vec<u8>> {
    if nodes.len() > WG_MAX_PEERS {
        bail!("peer count {} exceeds WG_MAX_PEERS", nodes.len());
    }
    let mut out =
        Vec::with_capacity(WG_NETMAP_HEADER_BYTES + nodes.len() * WG_NETMAP_PEER_BYTES);
    out.extend_from_slice(&WG_NETMAP_VERSION.to_le_bytes());
    out.extend_from_slice(&(nodes.len() as u32).to_le_bytes());

    for (idx, node) in nodes.iter().enumerate() {
        let key_raw = node
            .node_key
            .as_deref()
            .with_context(|| format!("node[{idx}] missing nodeKey"))?;
        let key = decode_key(key_raw)?;
        let mut endpoint_ip = 0u32;
        let mut endpoint_port = 0u16;
        for ep in &node.endpoints {
            if let Some((ip, port)) = parse_endpoint(ep) {
                endpoint_ip = ip;
                endpoint_port = port;
                break;
            }
        }
        let allowed_ip = node
            .ip_addresses
            .iter()
            .find_map(|s| parse_ipv4(s))
            .unwrap_or(0);
        let allowed_mask: u32 = if allowed_ip != 0 { 0xffff_ffff } else { 0 };

        out.extend_from_slice(&key);
        out.extend_from_slice(&endpoint_ip.to_le_bytes());
        out.extend_from_slice(&endpoint_port.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&allowed_ip.to_le_bytes());
        out.extend_from_slice(&allowed_mask.to_le_bytes());
        let _ = &node.name;
    }
    Ok(out)
}

fn read_input(path: &str) -> Result<String> {
    if path == "-" {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        Ok(fs::read_to_string(path)?)
    }
}

fn write_output(path: &str, bytes: &[u8]) -> Result<()> {
    if path == "-" {
        io::stdout().write_all(bytes)?;
    } else {
        fs::write(path, bytes)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Encode { input, output } => {
            let text = read_input(&input)?;
            let list: NodeList = serde_json::from_str(&text).context("parse nodes JSON")?;
            let blob = encode_netmap(&list.nodes)?;
            write_output(&output, &blob)?;
            eprintln!(
                "encoded {} peers ({} bytes)",
                list.nodes.len(),
                blob.len()
            );
        }
        Cmd::Fetch {
            url,
            token_file,
            output,
        } => {
            let token = fs::read_to_string(&token_file)
                .with_context(|| format!("read token {}", token_file.display()))?
                .trim()
                .to_string();
            if token.is_empty() {
                bail!("empty Headscale API token");
            }
            let base = url.trim_end_matches('/');
            let endpoint = format!("{base}/api/v1/node");
            let body: serde_json::Value = ureq::get(&endpoint)
                .set("Authorization", &format!("Bearer {token}"))
                .set("Accept", "application/json")
                .call()
                .context("Headscale /api/v1/node")?
                .into_json()
                .context("decode Headscale JSON")?;
            let list: NodeList = serde_json::from_value(body).context("map to NodeList")?;
            let blob = encode_netmap(&list.nodes)?;
            write_output(&output, &blob)?;
            eprintln!(
                "fetched {} peers from {base} ({} bytes)",
                list.nodes.len(),
                blob.len()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_two_peers_from_fixture_shape() {
        let json = r#"{
          "nodes": [
            {
              "name": "a",
              "nodeKey": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
              "ipAddresses": ["100.64.0.1"],
              "endpoints": ["10.0.0.1:41641"]
            },
            {
              "name": "b",
              "node_key": "nodekey:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
              "ip_addresses": ["100.64.0.2"],
              "endpoints": ["10.0.0.2:51820"]
            }
          ]
        }"#;
        let list: NodeList = serde_json::from_str(json).unwrap();
        let blob = encode_netmap(&list.nodes).unwrap();
        assert_eq!(blob.len(), 8 + 2 * 48);
        assert_eq!(&blob[0..4], &1u32.to_le_bytes());
        assert_eq!(&blob[4..8], &2u32.to_le_bytes());
        assert_eq!(blob[8], 0x01);
        let ip = u32::from_le_bytes(blob[8 + 32..8 + 36].try_into().unwrap());
        assert_eq!(ip, u32::from_be_bytes([10, 0, 0, 1]));
        let port = u16::from_le_bytes(blob[8 + 36..8 + 38].try_into().unwrap());
        assert_eq!(port, 41641);
    }
}
