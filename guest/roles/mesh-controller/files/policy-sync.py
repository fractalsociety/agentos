#!/usr/bin/env python3
"""Reconcile authenticated Headscale node tags into deny-by-default NetCaps."""

import json
import os
import pathlib
import subprocess
import tempfile

CONFIG = os.environ.get("FRACTALOS_HEADSCALE_CONFIG", "/usr/local/etc/headscale/config.yaml")
HEADSCALE = os.environ.get("FRACTALOS_HEADSCALE_BIN", "/usr/local/sbin/headscale")
MAP = pathlib.Path(os.environ.get(
    "FRACTALOS_NETCAP_MAP", "/usr/local/etc/headscale/netcap-map.json"))
OUTPUT = pathlib.Path(os.environ.get(
    "FRACTALOS_NETCAP_STATE", "/var/db/headscale/netcap-state.json"))


def main():
    policy = json.loads(MAP.read_text(encoding="utf-8"))
    raw = subprocess.check_output([
        HEADSCALE, "-c", CONFIG,
        "nodes", "list", "--output", "json",
    ], text=True)
    decoded = json.loads(raw)
    nodes = decoded.get("nodes") if isinstance(decoded, dict) else decoded
    # Headscale encodes an empty collection as {"nodes": null}.
    if nodes is None:
        nodes = []
    if not isinstance(nodes, list):
        raise ValueError("headscale nodes response must be a list or null")
    decisions = []
    for node in nodes:
        # Headscale 0.29's canonical Node.tags field is the definitive identity
        # for tagged nodes. It is distinct from untrusted Hostinfo.RequestTags.
        tags = node.get("tags")
        if tags is None:  # compatibility with pre-0.29 administrative output
            valid_tags = node.get("validTags") or node.get("valid_tags") or []
            forced_tags = node.get("forcedTags") or node.get("forced_tags") or []
            tags = valid_tags + forced_tags
        tags = sorted(set(tags))
        selected = policy["default"]
        selected_tag = None
        for tag in sorted(tags):
            if tag in policy.get("tags", {}):
                selected = policy["tags"][tag]
                selected_tag = tag
                break
        decisions.append({
            "node_id": node.get("id"),
            "node_key": node.get("nodeKey") or node.get("node_key"),
            "name": node.get("name") or node.get("givenName") or node.get("given_name"),
            "authenticated_tags": tags,
            "selected_tag": selected_tag,
            "netcap": selected["netcap"],
            "agent_endpoint_ports": selected["agent_endpoint_ports"],
        })
    state = {"schema": 1, "nodes": decisions}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="netcap-state.", dir=str(OUTPUT.parent))
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(state, stream, separators=(",", ":"), sort_keys=True)
        stream.write("\n")
    os.chmod(temporary, 0o640)
    os.replace(temporary, OUTPUT)


if __name__ == "__main__":
    main()
