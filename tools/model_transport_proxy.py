#!/usr/bin/env python3
"""Bridge AgentOS's dedicated VirtIO model console to the local model bridge."""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
import urllib.error
import urllib.request

MAGIC = 0x4D544741
VERSION = 1
HEADER = struct.Struct("<IIII")
MAX_BODY = 1024 * 1024


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("model transport closed")
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


def post_bridge(url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read(MAX_BODY + 1)
            if len(payload) > MAX_BODY:
                raise ValueError("model bridge response too large")
            return response.status, payload
    except urllib.error.HTTPError as exc:
        payload = exc.read(MAX_BODY + 1)
        if len(payload) > MAX_BODY:
            payload = b""
        return exc.code, payload


def serve(sock: socket.socket, bridge_url: str, timeout: float, trace: bool = False) -> None:
    while True:
        raw = recv_exact(sock, HEADER.size)
        magic, version, body_len, response_cap = HEADER.unpack(raw)
        if magic != MAGIC or version != VERSION:
            raise ValueError("invalid AgentOS model transport header")
        if not 0 < body_len <= MAX_BODY or response_cap > MAX_BODY:
            raise ValueError("AgentOS model transport bounds violation")
        body = recv_exact(sock, body_len)
        if trace:
            print(
                "[model-transport-proxy] request="
                + body[:4096].decode("utf-8", errors="replace"),
                file=sys.stderr,
            )
        try:
            status, response = post_bridge(bridge_url, body, timeout)
            if len(response) > response_cap:
                response = b""
                transport_status = 1
            else:
                transport_status = 0
            if trace:
                print(
                    "[model-transport-proxy] response="
                    + response[:4096].decode("utf-8", errors="replace"),
                    file=sys.stderr,
                )
        except (OSError, ValueError, urllib.error.URLError) as exc:
            print(f"[model-transport-proxy] bridge error: {exc}", file=sys.stderr)
            status, response, transport_status = 0, b"", 1
        sock.sendall(HEADER.pack(MAGIC, status, len(response), transport_status))
        if response:
            sock.sendall(response)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True, help="QEMU model console Unix socket")
    parser.add_argument(
        "--bridge-url",
        default="http://127.0.0.1:8790/v1/chat/completions",
    )
    parser.add_argument("--connect-timeout", type=float, default=30.0)
    parser.add_argument("--request-timeout", type=float, default=180.0)
    parser.add_argument("--trace", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        sock = connect_with_retry(args.socket, args.connect_timeout)
        print(f"[model-transport-proxy] connected to {args.socket}", file=sys.stderr)
        with sock:
            serve(sock, args.bridge_url, args.request_timeout, args.trace)
    except (EOFError, OSError, ValueError) as exc:
        print(f"[model-transport-proxy] stopped: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
