#!/usr/bin/env python3
"""Host-side invariants for the FreeBSD Headscale controller role."""

import json
import os
import pathlib
import stat
import subprocess
import tempfile


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    repo = pathlib.Path(__file__).resolve().parents[1]
    role = repo / "guest/roles/mesh-controller"
    files = role / "files"

    manifest = json.loads((role / "manifest.json").read_text())
    require(manifest["headscale_version"] == "0.29.3", "release must stay pinned")
    require(len(manifest["source_sha256"]) == 64, "source checksum missing")
    require(len(manifest["freebsd_amd64_sha256"]) == 64, "FreeBSD checksum missing")
    require(len(manifest["validation_assets"]) == 4, "host validation assets incomplete")

    config = (files / "config.yaml").read_text()
    require("server_url: https://mesh.fractalos.internal:8080" in config,
            "advertised and listening Headscale ports must agree")
    require("randomize_client_port" not in config, "removed v0.29 key present")
    require("write_ahead_log: true" in config, "SQLite WAL must be enabled")
    require("/var/db/fractalos-secrets/headscale" in config, "secret path missing")

    policy = (files / "policy.hujson").read_text()
    require('"randomizeClientPort": true' in policy, "WireGuard port policy missing")
    require('"tag:agent:8443"' in policy, "agent endpoint grant missing")
    require('"dst": ["*"]' not in policy, "broad destination grant is forbidden")

    install = (role / "install.sh").read_text()
    require("-g headscale -m 0640" in install, "Headscale cannot read role config")
    require("subjectAltName = DNS:mesh.fractalos.internal" in install,
            "generated TLS certificate needs a SAN")
    require("users create agent-admin" in install and "users create agents" in install,
            "required policy identities are not provisioned")
    require("releases/download/v${VERSION}/headscale_${VERSION}.tar.gz" in install,
            "source build must use the checksummed release archive")
    require('cd "$WORK_DIR/source"' in install,
            "release source archive has no versioned top-level directory")
    require("ln -s /usr/local/bin/python3.11 /usr/local/bin/python3" in install,
            "FreeBSD python311 needs an unversioned python3 entry point")
    require("#!/usr/local/bin/python3.11" in install,
            "installed policy sync must not depend on the rc/cron PATH")
    require("fractalos-headscale-policy-sync || true" not in install,
            "first boot must not hide NetCap reconciliation failures")
    require("headscale_ready=0" in install and "management socket did not become ready" in install,
            "controller provisioning must wait for the Headscale management socket")

    firstboot = (files / "fractalos_mesh_firstboot.rc").read_text()
    require("installed=0" in firstboot and 'if [ "$installed" -ne 1 ]' in firstboot,
            "first boot must propagate controller installation failures")
    require("fractalos-mesh-firstboot.log" in firstboot and 'attempt=$((attempt + 1))' in firstboot,
            "first boot must log and retry transient installation failures")

    bootstrap = (repo / "tools/bootstrap-guest.sh").read_text()
    freebsd = bootstrap[bootstrap.index("bootstrap_freebsd15()") :]
    nixos = bootstrap[bootstrap.index("bootstrap_nixos()") : bootstrap.index("bootstrap_freebsd15()")]
    require('file=\\$role,readonly=on,media=cdrom' in freebsd,
            "FreeBSD installer does not attach the controller role")
    require('file=\\$role,readonly=on,media=cdrom' not in nixos,
            "controller role leaked into an unrelated installer")
    require("cc73a14d4b1cfada880b78deb0b94ae0f439167418c32a6708f68f79563cb50c" in freebsd,
            "FreeBSD installer ISO is not checksum-pinned")

    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = pathlib.Path(tmp_name)
        fake = tmp / "headscale"
        fake.write_text("""#!/bin/sh
cat <<'EOF'
{"nodes":[
 {"id":"1","nodeKey":"nodekey:a","name":"alpha","validTags":["tag:agent"]},
 {"id":"2","nodeKey":"nodekey:b","name":"beta","forcedTags":["tag:unknown"]},
 {"id":"3","node_key":"nodekey:c","given_name":"control","valid_tags":["tag:mesh-controller"]}
]}
EOF
""")
        fake.chmod(0o755)
        output = tmp / "netcap-state.json"
        env = os.environ.copy()
        env.update({
            "FRACTALOS_HEADSCALE_BIN": str(fake),
            "FRACTALOS_HEADSCALE_CONFIG": str(tmp / "config.yaml"),
            "FRACTALOS_NETCAP_MAP": str(files / "netcap-map.json"),
            "FRACTALOS_NETCAP_STATE": str(output),
        })
        subprocess.run([str(files / "policy-sync.py")], check=True, env=env)
        state = json.loads(output.read_text())
        by_name = {node["name"]: node for node in state["nodes"]}
        require(by_name["alpha"]["netcap"] == "mesh-agent", "agent tag not mapped")
        require(by_name["beta"]["netcap"] == "deny", "unknown tag was not denied")
        require(by_name["control"]["netcap"] == "mesh-control", "controller tag not mapped")
        require(stat.S_IMODE(output.stat().st_mode) == 0o640, "NetCap state mode is not 0640")

        fake.write_text("#!/bin/sh\nprintf '%s\\n' '{\"nodes\":null}'\n")
        fake.chmod(0o755)
        subprocess.run([str(files / "policy-sync.py")], check=True, env=env)
        state = json.loads(output.read_text())
        require(state == {"schema": 1, "nodes": []},
                "Headscale null node collection must produce empty NetCap state")

    print("[PASS] mesh-controller role security and reconciliation invariants")


if __name__ == "__main__":
    main()
