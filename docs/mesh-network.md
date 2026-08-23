# Private agent mesh

agentOS packages Headscale as a FreeBSD `mesh-controller` guest role. Headscale
is the coordination plane; standard Tailscale clients provide the WireGuard
data plane. Every enrolled device receives an authenticated tailnet identity,
which `agentos-headscale-policy-sync` reconciles into a deny-by-default NetCap
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
AGENTOS_TAILSCALE_E2E=1 make validate-headscale-role

# Produce a FreeBSD disk whose first boot installs the role.
make bootstrap-guest OS=freebsd15

# Boot that disk, wait for first-boot provisioning, and verify the protected
# secrets, Headscale service/version, reconciled NetCaps, and TLS health check.
make e2e-mesh-freebsd
```

The controller defaults to `https://mesh.agentos.internal:8080`. Publish that
name in DNS before enrolling devices. The first boot generates a private TLS
key and a one-year self-signed certificate under
`/var/db/agentos-secrets/headscale`. For a durable deployment, replace those
files with a certificate issued by a CA already trusted by every joining
device. Otherwise, install `tls.crt` into each device's operating-system trust
store before running Tailscale.

## Enroll a device

On a trusted controller host, create a short-lived, single-use enrollment key:

```bash
export AGENTOS_HEADSCALE_URL=https://mesh.agentos.internal:8080
export AGENTOS_HEADSCALE_TOKEN_FILE=/var/db/agentos-secrets/headscale/api.token
agentctl mesh enroll-key --ttl-seconds 600
```

The command returns structured JSON. Extract `result.preAuthKey.key`, then use
the unmodified Tailscale client on the device:

```bash
tailscale up \
  --login-server=https://mesh.agentos.internal:8080 \
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
Noise, and API secrets remain in `/var/db/agentos-secrets/headscale` with mode
0700/0600. The reconciliation job atomically writes
`/var/db/headscale/netcap-state.json`; unrecognized or untagged identities map
to the `deny` NetCap.

The embedded DERP configuration is present but disabled by default. Enable it
only after publishing a reachable TLS endpoint and opening its STUN/DERP ports.
