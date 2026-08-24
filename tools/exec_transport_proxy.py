#!/usr/bin/env python3
"""Run immutable AgentOS ExecSvc profiles from a dedicated VirtIO console."""

from __future__ import annotations

import argparse
import os
import pathlib
import resource
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable

MAGIC = 0x45584741
VERSION = 1
PROFILE_C11_COMPILE = 1
REQUEST_HEADER = struct.Struct("<IIIIII")
RESPONSE_HEADER = struct.Struct("<IIiII")
SOURCE_MAX = 24 * 1024
OUTPUT_MAX = 16 * 1024


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("exec transport closed")
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


def _resource_limits() -> None:
    limits = [
        (resource.RLIMIT_CPU, 3),
        (resource.RLIMIT_FSIZE, 1024 * 1024),
        (resource.RLIMIT_NOFILE, 32),
    ]
    # Darwin reserves a large virtual address range before exec; Linux does
    # not. The stricter 256 MiB address-space ceiling is therefore applied on
    # the production host while macOS development still receives a 2 GiB cap.
    if hasattr(resource, "RLIMIT_AS"):
        limits.append((resource.RLIMIT_AS,
                       2 * 1024 * 1024 * 1024 if sys.platform == "darwin"
                       else 256 * 1024 * 1024))
    for kind, requested in limits:
        _, hard = resource.getrlimit(kind)
        soft = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
        resource.setrlimit(kind, (soft, hard))


def _has_forbidden_preprocessor(source: bytes) -> bool:
    # This first profile intentionally supports translation-unit-only C. A
    # byte-level deny is conservative but closes comment, digraph, trigraph,
    # escaped-newline, macro, and absolute-path variants of file directives.
    return (b"#" in source or b"%:" in source or b"??=" in source
            or b"_Pragma" in source or b"__pragma" in source)


def run_c11_compile(source: bytes, compiler: str, timeout: float) -> tuple[int, bytes]:
    if b"\x00" in source:
        return 2, b"source contains NUL byte\n"
    if _has_forbidden_preprocessor(source):
        return 2, b"preprocessor directives are disabled by this profile\n"
    argv = [
        compiler,
        "-x", "c", "-std=c11", "-fsyntax-only", "-nostdinc",
        "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-",
    ]
    with tempfile.TemporaryDirectory(prefix="agentos-exec-") as work:
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
        try:
            completed = subprocess.run(
                argv,
                input=source,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=work,
                env=env,
                timeout=timeout,
                check=False,
                preexec_fn=_resource_limits if sys.platform.startswith("linux") else None,
            )
        except subprocess.TimeoutExpired:
            return 124, b"compile profile timed out\n"
    return completed.returncode, completed.stdout[:OUTPUT_MAX]


Runner = Callable[[int, bytes, int], tuple[int, int, bytes]]


def make_runner(compiler: str, timeout: float) -> Runner:
    def run(profile: int, source: bytes, output_capacity: int) -> tuple[int, int, bytes]:
        if profile != PROFILE_C11_COMPILE:
            return 3, -1, b""
        exit_code, output = run_c11_compile(source, compiler, timeout)
        if not output and exit_code == 0:
            output = b"compile: ok\n"
        if len(output) > output_capacity:
            return 4, -1, b""
        return 0, exit_code, output

    return run


def serve(sock: socket.socket, runner: Runner, trace: bool = False) -> None:
    while True:
        raw = recv_exact(sock, REQUEST_HEADER.size)
        magic, version, profile, source_len, output_cap, request_tag = REQUEST_HEADER.unpack(raw)
        if magic != MAGIC or version != VERSION:
            raise ValueError("invalid AgentOS exec transport header")
        if not 0 < source_len <= SOURCE_MAX or not 0 < output_cap <= OUTPUT_MAX:
            raise ValueError("AgentOS exec transport bounds violation")
        source = recv_exact(sock, source_len)
        if trace:
            print(
                f"[exec-transport-proxy] profile={profile} tag={request_tag} "
                f"source_bytes={source_len}",
                file=sys.stderr,
            )
        try:
            status, exit_code, output = runner(profile, source, output_cap)
        except (OSError, ValueError) as exc:
            print(f"[exec-transport-proxy] profile error: {exc}", file=sys.stderr)
            status, exit_code, output = 4, -1, b""
        if len(output) > output_cap:
            status, exit_code, output = 4, -1, b""
        sock.sendall(RESPONSE_HEADER.pack(MAGIC, status, exit_code, len(output), request_tag))
        if output:
            sock.sendall(output)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True, help="QEMU exec console Unix socket")
    parser.add_argument("--compiler", default=shutil.which("clang") or "clang")
    parser.add_argument("--connect-timeout", type=float, default=30.0)
    parser.add_argument("--profile-timeout", type=float, default=10.0)
    parser.add_argument("--trace", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    compiler = str(pathlib.Path(args.compiler).resolve())
    if not os.path.isfile(compiler) or not os.access(compiler, os.X_OK):
        print(f"[exec-transport-proxy] compiler is not executable: {compiler}", file=sys.stderr)
        return 2
    try:
        sock = connect_with_retry(args.socket, args.connect_timeout)
        print(f"[exec-transport-proxy] connected to {args.socket}", file=sys.stderr)
        with sock:
            serve(sock, make_runner(compiler, args.profile_timeout), args.trace)
    except (EOFError, OSError, ValueError) as exc:
        print(f"[exec-transport-proxy] stopped: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
