# Private agent mesh

FractalOS packages Headscale as a FreeBSD `mesh-controller` guest role. Headscale
is the coordination plane; standard Tailscale clients provide the WireGuard
data plane. Every enrolled device receives an authenticated tailnet identity,
which `fractalos-headscale-policy-sync` reconciles into a deny-by-default NetCap
state file.

## Build and validate the controller

```bash
# Static role, agentctl, permission, and policy reconciliation checks.
make test-agentctl-mesh

# Download the pinned, checksummed Headscale release and validate its real
# config parser, TLS listener, SQLite database, policy, REST API, and enrollment.
make validate-headscale-role

# Also enroll two standard Tailscale containers and invoke agent-a:8443 from
# agent-b through the resulting WireGuard tailnet.
FRACTALOS_TAILSCALE_E2E=1 make validate-headscale-role

# Full fos-gz0.14.19 vertical-slice gate (host suites + Docker two-client mesh
# + topology + live reconnect cut ~30s). Success → proof_class=live_vertical_slice.
./tests/e2e/run_two_device_live_local.sh

# After two physical/VM Tailscale clients are enrolled on a durable controller:
FRACTALOS_HEADSCALE_URL=https://mesh.fractalos.internal:8080 \
FRACTALOS_HEADSCALE_TOKEN_FILE=/var/db/fractalos-secrets/headscale/api.token \
./tests/e2e/run_two_device_physical.sh

# Native FractalOS path (fos-gz0.5): convert Headscale node JSON to packed
# OP_WG_APPLY_NETMAP (host proof; live join without tailscaled still open).
./tests/e2e/test_wg_native_netmap_feed.sh

# Produce a FreeBSD disk whose first boot installs the role.
make bootstrap-guest OS=freebsd15

# Boot that disk, wait for first-boot provisioning, and verify the protected
# secrets, Headscale service/version, reconciled NetCaps, and TLS health check.
make e2e-mesh-freebsd
```

The controller defaults to `https://mesh.fractalos.internal:8080`. Publish that
name in DNS before enrolling devices. The first boot generates a private TLS
key and a one-year self-signed certificate under
`/var/db/fractalos-secrets/headscale`. For a durable deployment, replace those
files with a certificate issued by a CA already trusted by every joining
device. Otherwise, install `tls.crt` into each device's operating-system trust
store before running Tailscale.

## Enroll a device

On a trusted controller host, create a short-lived, single-use enrollment key:

```bash
export FRACTALOS_HEADSCALE_URL=https://mesh.fractalos.internal:8080
export FRACTALOS_HEADSCALE_TOKEN_FILE=/var/db/fractalos-secrets/headscale/api.token
agentctl mesh enroll-key --ttl-seconds 600
```

The command returns structured JSON. Extract `result.preAuthKey.key`, then use
the unmodified Tailscale client on the device:

```bash
tailscale up \
  --login-server=https://mesh.fractalos.internal:8080 \
  --auth-key='hskey-auth-…'
```

Enrollment keys assign `tag:agent`. The shipped Headscale policy permits agent
devices to contact only port 8443 on other `tag:agent` devices. Controller
administrators can reach controller ports 443, 8080, and 8443. No allow-all
rule is present.

## Operate the mesh

All management commands emit JSON and exit:

```bash
agentctl mesh status
agentctl mesh nodes
agentctl mesh users
agentctl mesh expire-node NODE_ID
```

Headscale keeps SQLite state in `/var/db/headscale` with WAL enabled. TLS,
Noise, and API secrets remain in `/var/db/fractalos-secrets/headscale` with mode
0700/0600. The reconciliation job atomically writes
`/var/db/headscale/netcap-state.json`; unrecognized or untagged identities map
to the `deny` NetCap.

The embedded DERP configuration is present but disabled by default. Enable it
only after publishing a reachable TLS endpoint and opening its STUN/DERP ports.

## Native FractalOS data-plane status

`net_pd` owns the VirtIO-net MMIO/IRQ path. `wg_net` implements WireGuard
`Noise_IKpsk2`, transport AEAD, replay windows, packed Headscale-style netmap
apply (roam without session wipe), cookie replies, entropy-backed ephemeral
keys, DERP frame wrap/unwrap, per-peer direct-vs-DERP path mode, and timer-tick
rekey. Host suites cover sessions, netmap/rekey, cookies, entropy, DERP, and
multi-peer dataplane traffic (`test_wg_dataplane`).

`tools/wg-headscale-netmap` converts a Headscale `/api/v1/node` listing (or a
fixture JSON) into the packed blob consumed by `OP_WG_APPLY_NETMAP`:

```bash
cargo run -p wg-headscale-netmap -- encode \
  --input tests/fixtures/headscale_nodes.json --output /tmp/netmap.bin

# Optional live controller (API token; does not replace Noise login):
cargo run -p wg-headscale-netmap -- fetch \
  --url "$FRACTALOS_HEADSCALE_URL" \
  --token-file "$FRACTALOS_HEADSCALE_TOKEN_FILE" \
  --output /tmp/netmap.bin
```

**Native join status:** Proven on host against pinned Headscale via
`tests/e2e/test_mesh_control_live_join.sh` (ts2021 Noise register, packed
netmap, TLS DERP). Evidence:
`build/evidence/gz0.5-native-headscale-join.json`.

**Two-node native mesh:** Proven on host (`fos-gz0.15`) — two processes each
running `wg_net` (`tests/host/wg_fractalos_node.c`) join Headscale via
`fractalos-mesh-control`, apply peer netmaps, and exchange authenticated
WireGuard transport over a localhost UDP underlay. Evidence:
`build/evidence/two-fractalos-native-mesh.json`.

```bash
# Offline packed-netmap encode + unit tests
./tests/e2e/test_mesh_control_join.sh

# Full live close gate (downloads pinned Headscale, self-signed CA, join):
./tests/e2e/test_mesh_control_live_join.sh

# Two FractalOS-native nodes + Headscale data-plane mesh:
./tests/e2e/test_two_fractalos_native_mesh.sh

# Against an existing controller:
FRACTALOS_MESH_CONTROL_LIVE=1 \
FRACTALOS_HEADSCALE_URL=https://mesh.example:8080 \
FRACTALOS_HEADSCALE_AUTH_KEY='hskey-auth-…' \
FRACTALOS_HEADSCALE_CA_FILE=/path/to/tls.crt \
  ./tests/e2e/test_mesh_control_join.sh
```

Pass `--ca-file` (or `FRACTALOS_HEADSCALE_CA_FILE`) when the controller uses a
private CA. Public WebPKI roots are always included.

Tailnet identity remains connectivity metadata. Neither a successful Noise
session nor a Headscale tag creates ModelCap, ToolCap, MemoryCap, ExecCap, or a
worker NetCap; those must still be independently minted into the relevant
seL4 CSpace.
