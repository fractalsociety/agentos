use fractal_mesh_gateway::{bind_development_gateway, GatewayConfig, MeshGateway};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind: SocketAddr = std::env::var("FRACTAL_MESH_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8443".to_owned())
        .parse()?;
    let gateway = MeshGateway::new(GatewayConfig::default());
    let service = bind_development_gateway(bind, gateway.clone()).await?;
    let peer = std::env::var("FRACTAL_MESH_PEER").unwrap_or_else(|_| "headscale-peer".to_owned());
    service.run(peer).await?;
    Ok(())
}
