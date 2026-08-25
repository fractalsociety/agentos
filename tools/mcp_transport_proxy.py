#!/usr/bin/env python3
"""Bridge FractalOS's private MCP console to one shared MCP stdio server."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import selectors
import socket
import struct
import subprocess
import sys
import time
from typing import Any

MAGIC = 0x504D4741
VERSION = 1
PROTOCOL = "2026-07-28"
LEGACY_PROTOCOL = "2025-11-25"
REQUEST_LIST = 1
REQUEST_INVOKE = 2
STATUS_OK = 0
STATUS_INVALID = 1
STATUS_NOT_FOUND = 2
STATUS_DENIED = 4
STATUS_PROVIDER_DOWN = 6
STATUS_TOO_LARGE = 7
REQUEST_HEADER = struct.Struct("<IIIIIII")
RESPONSE_HEADER = struct.Struct("<IIII")
TOOL_NAME = re.compile(r"^[A-Za-z0-9_.:/-]{1,123}$")
MAX_INPUT = 16 * 1024
MAX_OUTPUT = 16 * 1024


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("MCP transport closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def connect_with_retry(path: str, timeout: float) -> socket.socket:
    deadline = time.monotonic() + timeout
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(path)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
            time.sleep(0.05)
    raise OSError(f"timed out connecting to {path}: {last_error}")


def request_meta(protocol: str) -> dict[str, object]:
    return {
        "io.modelcontextprotocol/protocolVersion": protocol,
        "io.modelcontextprotocol/clientInfo": {
            "name": "fractalos-mcp-transport",
            "version": "1",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }


class McpStdioClient:
    def __init__(
        self, argv: list[str], timeout: float = 30.0,
        server_env: dict[str, str] | None = None,
    ) -> None:
        if not argv or any(not isinstance(item, str) or not item for item in argv):
            raise ValueError("MCP server argv must be a non-empty string array")
        self.argv = argv
        self.timeout = timeout
        self.server_env = server_env or {}
        self.process: subprocess.Popen[bytes] | None = None
        self.next_id = 1
        self.protocol = PROTOCOL
        self.modern = True
        self.tools: dict[str, dict[str, Any]] = {}

    def start(self) -> None:
        self._spawn()
        probe = self._rpc(
            "server/discover", {}, protocol=PROTOCOL,
            response_timeout=min(self.timeout, 2.0), allow_timeout=True,
        )
        supported = probe.get("supportedVersions") if probe else None
        if isinstance(supported, list) and PROTOCOL in supported:
            self.protocol = PROTOCOL
            self.modern = True
        else:
            self.close()
            self._spawn()
            initialized = self._rpc("initialize", {
                "protocolVersion": LEGACY_PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "fractalos-mcp-transport", "version": "1"},
            }, protocol=None)
            selected = initialized.get("protocolVersion")
            if not isinstance(selected, str):
                raise RuntimeError("legacy MCP server did not negotiate a version")
            self.protocol = selected
            self.modern = False
            self._notify("notifications/initialized", {})
        self.refresh_tools()

    def _spawn(self) -> None:
        env = {
            key: os.environ[key]
            for key in ("PATH", "LANG", "LC_ALL", "TMPDIR")
            if key in os.environ
        }
        env.update(self.server_env)
        self.process = subprocess.Popen(
            self.argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            env=env,
        )

    def close(self) -> None:
        process = self.process
        self.process = None
        if process is None:
            return
        if process.stdin:
            process.stdin.close()
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if process.stdout:
            process.stdout.close()

    def _send(self, message: dict[str, object]) -> None:
        if self.process is None or self.process.stdin is None:
            raise RuntimeError("MCP server is not running")
        encoded = json.dumps(message, separators=(",", ":")).encode() + b"\n"
        self.process.stdin.write(encoded)
        self.process.stdin.flush()

    def _read_response(self, request_id: int, timeout: float) -> dict[str, Any]:
        if self.process is None or self.process.stdout is None:
            raise RuntimeError("MCP server is not running")
        selector = selectors.DefaultSelector()
        selector.register(self.process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                events = selector.select(max(0.0, deadline - time.monotonic()))
                if not events:
                    break
                raw = self.process.stdout.readline(MAX_OUTPUT + 1)
                if not raw:
                    raise EOFError("MCP server closed stdout")
                if len(raw) > MAX_OUTPUT or not raw.endswith(b"\n"):
                    raise ValueError("MCP response exceeds framing limit")
                message = json.loads(raw)
                if message.get("id") != request_id:
                    # Current MCP permits related notifications while a request
                    # is in flight. This bridge has no subscription authority,
                    # so it ignores bounded notifications and waits for its ID.
                    if "id" not in message:
                        continue
                    raise ValueError("MCP response ID mismatch")
                if "error" in message:
                    raise RuntimeError(f"MCP JSON-RPC error: {message['error']}")
                result = message.get("result")
                if not isinstance(result, dict):
                    raise ValueError("MCP result is not an object")
                return result
        finally:
            selector.close()
        raise TimeoutError("MCP server response timed out")

    def _rpc(
        self,
        method: str,
        params: dict[str, object],
        *,
        protocol: str | None | object = ...,
        response_timeout: float | None = None,
        allow_timeout: bool = False,
    ) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        actual_protocol = self.protocol if protocol is ... else protocol
        body_params = dict(params)
        if isinstance(actual_protocol, str):
            body_params["_meta"] = request_meta(actual_protocol)
        self._send({
            "jsonrpc": "2.0", "id": request_id,
            "method": method, "params": body_params,
        })
        try:
            return self._read_response(
                request_id,
                self.timeout if response_timeout is None else response_timeout,
            )
        except (RuntimeError, TimeoutError) as exc:
            if allow_timeout:
                return {}
            raise exc

    def _notify(self, method: str, params: dict[str, object]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def refresh_tools(self) -> dict[str, dict[str, Any]]:
        result = self._rpc("tools/list", {})
        raw_tools = result.get("tools")
        if not isinstance(raw_tools, list):
            raise ValueError("MCP tools/list omitted tools array")
        tools: dict[str, dict[str, Any]] = {}
        for raw in raw_tools:
            if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
                raise ValueError("MCP tool descriptor is invalid")
            name = raw["name"]
            if not TOOL_NAME.fullmatch(name):
                raise ValueError(f"MCP tool name is unsafe: {name!r}")
            public_name = "mcp." + name
            descriptor: dict[str, Any] = {"name": public_name}
            for key in ("title", "description", "inputSchema", "outputSchema", "annotations"):
                if key in raw:
                    descriptor[key] = raw[key]
            tools[public_name] = descriptor
        self.tools = tools
        return tools

    def list_payload(self) -> bytes:
        tools = self.refresh_tools()
        return json.dumps(
            {"tools": list(tools.values())}, separators=(",", ":"),
        ).encode()

    def invoke(self, public_name: str, input_bytes: bytes) -> bytes:
        if public_name not in self.tools:
            self.refresh_tools()
        descriptor = self.tools.get(public_name)
        if descriptor is None:
            raise KeyError(public_name)
        arguments = json.loads(input_bytes or b"{}")
        if not isinstance(arguments, dict):
            raise ValueError("MCP tool arguments must be a JSON object")
        result = self._rpc("tools/call", {
            "name": public_name[4:],
            "arguments": arguments,
        })
        return json.dumps(result, separators=(",", ":")).encode()


def parse_server_argv(raw: str | None) -> list[str]:
    if raw is None:
        return [sys.executable, str(pathlib.Path(__file__).with_name("mcp_fixture_server.py"))]
    value = json.loads(raw)
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ValueError("--server-command-json must be a non-empty JSON string array")
    return value


def parse_server_env(raw: str | None) -> dict[str, str]:
    if raw is None:
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and key
        and key.replace("_", "A").isalnum()
        and isinstance(item, str)
        for key, item in value.items()
    ):
        raise ValueError("--server-env-json must be a JSON string map")
    return value


def serve(sock: socket.socket, client: McpStdioClient, trace: bool = False) -> None:
    while True:
        raw = recv_exact(sock, REQUEST_HEADER.size)
        magic, version, operation, name_len, input_len, output_cap, tag = \
            REQUEST_HEADER.unpack(raw)
        if magic != MAGIC or version != VERSION:
            raise ValueError("invalid FractalOS MCP transport header")
        if not 4 <= name_len < 128 or input_len > MAX_INPUT \
                or not 0 < output_cap <= MAX_OUTPUT:
            raise ValueError("FractalOS MCP transport bounds violation")
        name_raw = recv_exact(sock, name_len)
        input_bytes = recv_exact(sock, input_len)
        status = STATUS_PROVIDER_DOWN
        output = b""
        try:
            name = name_raw.decode("utf-8")
            if operation == REQUEST_LIST and name == "mcp.tools.list":
                output = client.list_payload()
                status = STATUS_OK
            elif operation == REQUEST_INVOKE and name.startswith("mcp."):
                output = client.invoke(name, input_bytes)
                status = STATUS_OK
            else:
                status = STATUS_INVALID
        except KeyError:
            status = STATUS_NOT_FOUND
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            status = STATUS_INVALID
        except (EOFError, OSError, RuntimeError, TimeoutError):
            status = STATUS_PROVIDER_DOWN
        if len(output) >= output_cap or len(output) > MAX_OUTPUT:
            status, output = STATUS_TOO_LARGE, b""
        if trace:
            print(
                f"[mcp-transport-proxy] op={operation} name={name_raw!r} "
                f"status={status} output={len(output)}",
                file=sys.stderr,
            )
        sock.sendall(RESPONSE_HEADER.pack(MAGIC, status, len(output), tag))
        if output:
            sock.sendall(output)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True, help="QEMU MCP console Unix socket")
    parser.add_argument(
        "--server-command-json",
        help="administrator-selected MCP stdio server argv as a JSON array",
    )
    parser.add_argument(
        "--server-env-json",
        help="explicit environment passed only to the MCP server as a JSON map",
    )
    parser.add_argument("--connect-timeout", type=float, default=30.0)
    parser.add_argument("--request-timeout", type=float, default=30.0)
    parser.add_argument("--trace", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client: McpStdioClient | None = None
    try:
        argv = parse_server_argv(args.server_command_json)
        server_env = parse_server_env(args.server_env_json)
        client = McpStdioClient(argv, args.request_timeout, server_env)
        client.start()
        sock = connect_with_retry(args.socket, args.connect_timeout)
        print(f"[mcp-transport-proxy] connected to {args.socket}", file=sys.stderr)
        with sock:
            serve(sock, client, args.trace)
    except (EOFError, OSError, RuntimeError, TimeoutError, ValueError) as exc:
        print(f"[mcp-transport-proxy] stopped: {exc}", file=sys.stderr)
        return 1
    finally:
        if client is not None:
            client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
