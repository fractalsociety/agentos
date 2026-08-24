#!/usr/bin/env python3
"""Hermetic modern MCP stdio server used by the native target gate."""

from __future__ import annotations

import json
import sys

PROTOCOL = "2026-07-28"
LEGACY_PROTOCOL = "2025-11-25"


def send(message: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> int:
    legacy = "--legacy" in sys.argv[1:]
    for raw in sys.stdin:
        try:
            request = json.loads(raw)
            method = request["method"]
            request_id = request.get("id")
            params = request.get("params") or {}
            if request_id is None and method == "notifications/initialized":
                continue
            if method == "server/discover" and legacy:
                send({
                    "jsonrpc": "2.0", "id": request_id,
                    "error": {"code": -32601, "message": "method not found"},
                })
                continue
            if method == "server/discover":
                result = {
                    "resultType": "complete",
                    "supportedVersions": [PROTOCOL],
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "agentos-fixture", "version": "1"},
                }
            elif method == "initialize" and legacy:
                result = {
                    "protocolVersion": LEGACY_PROTOCOL,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "agentos-legacy-fixture", "version": "1"},
                }
            elif method == "tools/list":
                result = {
                    "resultType": "complete",
                    "tools": [{
                        "name": "fixture_echo",
                        "description": "Echo a message through a real MCP server",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"message": {"type": "string"}},
                            "required": ["message"],
                            "additionalProperties": False,
                        },
                    }],
                    "ttlMs": 60000,
                    "cacheScope": "public",
                }
            elif method == "tools/call" and params.get("name") == "fixture_echo":
                arguments = params.get("arguments") or {}
                result = {
                    "resultType": "complete",
                    "content": [{"type": "text", "text": arguments.get("message", "")}],
                    "structuredContent": {"echo": arguments.get("message", "")},
                    "isError": False,
                }
            else:
                send({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": "method or tool not found"},
                })
                continue
            send({"jsonrpc": "2.0", "id": request_id, "result": result})
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            send({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": f"invalid request: {exc}"},
            })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
