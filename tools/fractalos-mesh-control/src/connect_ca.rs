//! Control dial with optional custom CA (lab Headscale self-signed certs).

use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use ts_capabilityversion::CapabilityVersion;
use ts_control::client::{
    read_challenge_packet, upgrade_ts2021, CONTROL_PROTOCOL_VERSION,
};
use ts_control_noise::Handshake;
use ts_http_util::{BytesBody, ClientExt, EmptyBody, Http2, ResponseExt};
use ts_keys::{MachineKeyPair, MachinePublicKey};
use url::Url;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ControlPublicKeys {
    public_key: MachinePublicKey,
}

fn load_roots(ca_file: Option<&Path>) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_file {
        let pem = std::fs::read(path).with_context(|| format!("read CA {}", path.display()))?;
        let mut cursor = std::io::Cursor::new(pem);
        for cert in rustls_pemfile::certs(&mut cursor) {
            let cert = cert.context("parse CA PEM")?;
            roots
                .add(cert)
                .map_err(|e| anyhow::anyhow!("add CA: {e}"))?;
        }
    }
    Ok(roots)
}

async fn tls_connect(
    url: &Url,
    ca_file: Option<&Path>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let host = url.host_str().context("control URL missing host")?;
    let port = url.port_or_known_default().context("control URL missing port")?;
    let tcp = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("tcp connect {host}:{port}"))?;
    let roots = load_roots(ca_file)?;
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string()).context("server name")?;
    connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake")
}

async fn fetch_control_key_with_ca(
    control_url: &Url,
    ca_file: Option<&Path>,
) -> Result<MachinePublicKey> {
    let mut key_url = control_url.join("/key")?;
    key_url
        .query_pairs_mut()
        .extend_pairs([("v", CapabilityVersion::CURRENT.to_string())]);
    let tls = tls_connect(&key_url, ca_file).await?;
    let h1 = ts_http_util::http1::connect::<EmptyBody>(tls)
        .await
        .context("http1 for /key")?;
    let response = h1.get(&key_url, None).await.context("GET /key")?;
    if !response.status().is_success() {
        bail!("GET /key failed: {}", response.status());
    }
    let body = response.collect_bytes().await.context("read /key body")?;
    let keys: ControlPublicKeys = serde_json::from_slice(&body).context("parse /key JSON")?;
    Ok(keys.public_key)
}

/// Dial Headscale/Tailscale control with optional extra CA, complete ts2021 Noise.
pub async fn connect_control(
    control_url: &Url,
    machine_keys: &MachineKeyPair,
    ca_file: Option<&Path>,
) -> Result<Http2<BytesBody>> {
    match control_url.scheme() {
        "https" => {}
        "http" => bail!("http control URLs are not supported for Noise join"),
        other => bail!("unsupported control URL scheme: {other}"),
    }

    let control_public_key = fetch_control_key_with_ca(control_url, ca_file).await?;
    let tls = tls_connect(control_url, ca_file).await?;
    let h1 = ts_http_util::http1::connect::<EmptyBody>(tls)
        .await
        .context("http1 for /ts2021")?;

    let (handshake, init_msg) = Handshake::initialize(
        &CONTROL_PROTOCOL_VERSION,
        machine_keys,
        &control_public_key,
        CapabilityVersion::CURRENT,
    );

    let conn = upgrade_ts2021(control_url, &init_msg, handshake, machine_keys, h1)
        .await
        .context("upgrade /ts2021")?;
    let conn = read_challenge_packet(conn)
        .await
        .context("control challenge")?;
    let h2 = ts_http_util::http2::connect(conn)
        .await
        .context("http2 over Noise")?;
    Ok(h2)
}
