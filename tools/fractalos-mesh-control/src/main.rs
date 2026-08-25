//! Native FractalOS mesh control-plane client (host tool).
//!
//! Uses Tailscale's Rust `ts_control` / `ts_derp` crates to:
//! 1. Speak ts2021 Noise to a Headscale (or Tailscale) control server
//! 2. Register with a preauth key (no guest `tailscaled`)
//! 3. Consume the first full peer map and emit a packed `OP_WG_APPLY_NETMAP` blob
//! 4. Optionally complete a live TLS DERP handshake + self-ping
//!
//! This is the control/DERP side of `fos-gz0.5` / `fos-gz0.5.1`. WireGuard
//! transport remains in freestanding `wg_net`.

mod connect_ca;
mod netmap;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use ts_control::{
    client::{self, PeerUpdate, StateUpdate},
    Config, Node,
};
use ts_derp::Client as DerpClient;
use ts_keys::{NodeState, PersistState};
use url::Url;

use crate::connect_ca::connect_control;
use crate::netmap::{encode_nodes_to_netmap, PeerRecord};

#[derive(Parser, Debug)]
#[command(name = "fractalos-mesh-control")]
#[command(about = "Native Headscale Noise join + DERP for FractalOS wg_net")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Register via ts2021 Noise, wait for a full peer map, write packed netmap.
    Join {
        #[arg(long, env = "FRACTALOS_HEADSCALE_URL")]
        control_url: String,
        #[arg(long, env = "FRACTALOS_HEADSCALE_AUTH_KEY")]
        auth_key: String,
        #[arg(long, default_value = "fractalos-node")]
        hostname: String,
        #[arg(long, default_value = "build/mesh-control/keys.json")]
        key_file: PathBuf,
        #[arg(long, default_value = "build/mesh-control/netmap.bin")]
        netmap_out: PathBuf,
        /// PEM CA for lab/self-signed Headscale (added to system roots).
        #[arg(long, env = "FRACTALOS_HEADSCALE_CA_FILE")]
        ca_file: Option<PathBuf>,
        #[arg(long, default_value_t = 60)]
        timeout_secs: u64,
        /// Also complete a TLS DERP handshake using the map's first region.
        #[arg(long, default_value_t = false)]
        derp_ping: bool,
    },
    /// Encode synthetic peers to a packed netmap (offline unit / fixture path).
    EncodeNetmap {
        #[arg(long)]
        input_json: PathBuf,
        #[arg(long, default_value = "-")]
        output: String,
    },
    /// Export WireGuard node private key bytes from a persisted key file.
    ExportWg {
        #[arg(long)]
        key_file: PathBuf,
        /// Directory for privkey.bin (32B) and pubkey.hex.
        #[arg(long)]
        out_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    match Cli::parse().cmd {
        Cmd::Join {
            control_url,
            auth_key,
            hostname,
            key_file,
            netmap_out,
            ca_file,
            timeout_secs,
            derp_ping,
        } => {
            join(
                &control_url,
                &auth_key,
                &hostname,
                &key_file,
                &netmap_out,
                ca_file.as_deref(),
                timeout_secs,
                derp_ping,
            )
            .await
        }
        Cmd::EncodeNetmap { input_json, output } => {
            let text = fs::read_to_string(&input_json)
                .with_context(|| format!("read {}", input_json.display()))?;
            let peers: Vec<PeerRecord> = serde_json::from_str(&text)?;
            let blob = encode_nodes_to_netmap(&peers)?;
            if output == "-" {
                use std::io::Write;
                std::io::stdout().write_all(&blob)?;
            } else {
                if let Some(parent) = Path::new(&output).parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&output, &blob)?;
            }
            eprintln!("encoded {} peers ({} bytes)", peers.len(), blob.len());
            Ok(())
        }
        Cmd::ExportWg { key_file, out_dir } => export_wg(&key_file, &out_dir),
    }
}

fn export_wg(key_file: &Path, out_dir: &Path) -> Result<()> {
    let text = fs::read_to_string(key_file)
        .with_context(|| format!("read {}", key_file.display()))?;
    let persist: PersistState = serde_json::from_str(&text).context("parse key file")?;
    let state = NodeState::from(&persist);
    let priv_bytes = state.node_keys.private.to_bytes();
    let pub_bytes = state.node_keys.public.to_bytes();
    fs::create_dir_all(out_dir)?;
    fs::write(out_dir.join("privkey.bin"), priv_bytes)?;
    fs::write(out_dir.join("pubkey.hex"), hex::encode(pub_bytes))?;
    fs::write(
        out_dir.join("pubkey.bin"),
        pub_bytes,
    )?;
    tracing::info!(
        path = %out_dir.display(),
        pubkey = %hex::encode(pub_bytes),
        "exported WireGuard node key material"
    );
    Ok(())
}

async fn join(
    control_url: &str,
    auth_key: &str,
    hostname: &str,
    key_file: &Path,
    netmap_out: &Path,
    ca_file: Option<&Path>,
    timeout_secs: u64,
    derp_ping: bool,
) -> Result<()> {
    let url = Url::parse(control_url).context("parse control URL")?;
    let keys = load_or_create_keys(key_file)?;
    let config = Config {
        server_url: url.clone(),
        hostname: Some(hostname.to_string()),
        client_name: Some("fractalos-mesh-control".into()),
        tags: vec!["tag:agent".into()],
        ephemeral: false,
    };

    tracing::info!(%url, hostname, ca = ?ca_file, "dialing control (ts2021 Noise)");
    let http = connect_control(&url, &keys.machine_keys, ca_file)
        .await
        .context("ts2021 control dial")?;

    tracing::info!("registering with preauth key");
    client::register(&config, &url, Some(auth_key), None, &keys, &http)
        .await
        .context("machine/register")?;

    tracing::info!("starting netmap stream");
    let stream = client::start_stream(&url, &keys, &config, http)
        .await
        .context("start netmap stream")?;
    tokio::pin!(stream);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut peers: BTreeMap<i64, Node> = BTreeMap::new();
    let mut derp_map = None;
    let mut self_node = None;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            bail!("timed out waiting for full peer map ({timeout_secs}s)");
        }
        let update = tokio::time::timeout(remaining, stream.next())
            .await
            .context("netmap wait")?
            .context("netmap stream ended")?;
        apply_update(&mut peers, &mut derp_map, &mut self_node, update);
        // Self-only map still proves join; include self in packed netmap if no peers yet.
        if !peers.is_empty() || self_node.is_some() {
            break;
        }
        tracing::debug!("waiting for peer/self map…");
    }

    if peers.is_empty() {
        if let Some(n) = self_node.clone() {
            peers.insert(n.id, n);
        }
    }

    let records = peers_to_records(&peers);
    let blob = encode_nodes_to_netmap(&records)?;
    if let Some(parent) = netmap_out.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(netmap_out, &blob)
        .with_context(|| format!("write {}", netmap_out.display()))?;
    tracing::info!(
        peers = records.len(),
        path = %netmap_out.display(),
        bytes = blob.len(),
        "wrote packed OP_WG_APPLY_NETMAP blob"
    );

    if derp_ping {
        if let Err(e) = derp_self_ping(&keys, derp_map.as_ref()).await {
            tracing::warn!(error = %e, "DERP ping skipped/failed (join+netmap still ok)");
        }
    }

    Ok(())
}

fn apply_update(
    peers: &mut BTreeMap<i64, Node>,
    derp_map: &mut Option<ts_control::DerpMap>,
    self_node: &mut Option<Node>,
    update: StateUpdate,
) {
    if let Some(d) = update.derp {
        *derp_map = Some(d);
    }
    if let Some(n) = update.node {
        *self_node = Some(n);
    }
    match update.peer_update {
        Some(PeerUpdate::Full(list)) => {
            peers.clear();
            for n in list {
                peers.insert(n.id, n);
            }
        }
        Some(PeerUpdate::Delta {
            patch,
            upsert,
            remove,
        }) => {
            for id in remove {
                peers.remove(&id);
            }
            for n in upsert {
                peers.insert(n.id, n);
            }
            for u in patch {
                if let Some(existing) = peers.get_mut(&u.id) {
                    existing.apply_update(&u);
                }
            }
        }
        None => {}
    }
}

fn peers_to_records(peers: &BTreeMap<i64, Node>) -> Vec<PeerRecord> {
    let mut out = Vec::new();
    for n in peers.values() {
        let key = n.node_key.to_bytes();
        let allowed_ip = u32::from(n.tailnet_address.ipv4.addr());
        let (endpoint_ip, endpoint_port) = n
            .underlay_addresses
            .iter()
            .find_map(|sa| match sa {
                std::net::SocketAddr::V4(v4) => {
                    Some((u32::from(*v4.ip()), v4.port()))
                }
                _ => None,
            })
            .unwrap_or((0, 0));
        out.push(PeerRecord {
            name: Some(n.hostname.clone()),
            node_key_hex: hex::encode(key),
            allowed_ip,
            endpoint_ip,
            endpoint_port,
        });
    }
    out
}

async fn derp_self_ping(
    keys: &NodeState,
    derp_map: Option<&ts_control::DerpMap>,
) -> Result<()> {
    let Some(map) = derp_map else {
        bail!("no DERP map in control update; cannot derp-ping");
    };
    let (region_id, region) = map
        .iter()
        .next()
        .context("DERP map empty")?;
    tracing::info!(?region_id, name = %region.info.name, "DERP TLS handshake");

    let client = DerpClient::connect(&region.servers, &keys.node_keys)
        .await
        .context("DERP connect/handshake")?;
    let payload = b"fractalos-derp-ping";
    client
        .send_one(keys.node_keys.public, payload)
        .await
        .context("DERP send_one self")?;
    tracing::info!("DERP send_one ok (self); live TLS DERP path proven");
    Ok(())
}

fn load_or_create_keys(path: &Path) -> Result<NodeState> {
    if path.exists() {
        let text = fs::read_to_string(path)?;
        let persist: PersistState =
            serde_json::from_str(&text).context("parse key file")?;
        return Ok(NodeState::from(&persist));
    }
    let state = NodeState::generate();
    let persist = PersistState::from(&state);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(&persist)?)?;
    tracing::info!(path = %path.display(), "created new machine/node keys");
    Ok(state)
}
