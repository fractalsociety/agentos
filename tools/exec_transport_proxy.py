#!/usr/bin/env python3
"""Run immutable AgentOS ExecSvc profiles from a dedicated VirtIO console."""

from __future__ import annotations

import argparse
import io
import os
import pathlib
import resource
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Callable

MAGIC = 0x45584741
VERSION = 1
PROFILE_C11_COMPILE = 1
PROFILE_AGENTOS_REPO_TEST = 2
REQUEST_HEADER = struct.Struct("<IIIIII")
RESPONSE_HEADER = struct.Struct("<IIiII")
REPO_BUNDLE_HEADER = struct.Struct("<IIII")
REPO_BUNDLE_MAGIC = 0x50524741
REPO_BUNDLE_VERSION = 1
REPO_PATH_MAX = 256
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


def parse_repo_bundle(payload: bytes) -> tuple[pathlib.PurePosixPath, bytes]:
    if len(payload) < REPO_BUNDLE_HEADER.size:
        raise ValueError("repository bundle is truncated")
    magic, version, path_len, content_len = REPO_BUNDLE_HEADER.unpack_from(payload)
    if magic != REPO_BUNDLE_MAGIC or version != REPO_BUNDLE_VERSION:
        raise ValueError("repository bundle header is invalid")
    if not 0 < path_len <= REPO_PATH_MAX:
        raise ValueError("repository path length is invalid")
    if content_len > SOURCE_MAX - REPO_BUNDLE_HEADER.size - path_len:
        raise ValueError("repository overlay content is too large")
    if len(payload) != REPO_BUNDLE_HEADER.size + path_len + content_len:
        raise ValueError("repository bundle length is invalid")
    raw_path = payload[REPO_BUNDLE_HEADER.size:REPO_BUNDLE_HEADER.size + path_len]
    if b"\x00" in raw_path:
        raise ValueError("repository path contains NUL")
    try:
        path = pathlib.PurePosixPath(raw_path.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("repository path is not UTF-8") from exc
    if path.is_absolute() or not path.parts or any(
        part in ("", ".", "..") for part in path.parts
    ) or path.parts[0] == ".git":
        raise ValueError("repository path escapes the managed workspace")
    content = payload[REPO_BUNDLE_HEADER.size + path_len:]
    return path, content


def _extract_git_snapshot(repository_root: pathlib.Path,
                          destination: pathlib.Path,
                          timeout: float) -> None:
    archived = subprocess.run(
        ["git", "-C", str(repository_root), "archive", "--format=tar", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if archived.returncode != 0:
        raise ValueError("administrator repository snapshot failed")
    with tarfile.open(fileobj=io.BytesIO(archived.stdout), mode="r:") as archive:
        for member in archive.getmembers():
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or any(part == ".." for part in path.parts):
                raise ValueError("repository snapshot contains an unsafe path")
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise ValueError("repository snapshot contains a non-regular file")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("repository snapshot extraction failed")
            with target.open("wb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(member.mode & 0o777)


def _sandboxed_repo_argv(workspace: pathlib.Path,
                         test_runner: str) -> list[str]:
    command = [test_runner, "test"]
    if sys.platform == "darwin":
        quoted = str(workspace).replace('"', '\\"')
        policy = (
            '(version 1) (deny default) (allow process*) (allow file-read*) '
            f'(allow file-write* (literal "/dev/null") (subpath "{quoted}")) '
            '(allow sysctl-read) (allow mach-lookup) (deny network*)'
        )
        return ["/usr/bin/sandbox-exec", "-p", policy, *command]
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        raise ValueError("managed repository tests require bubblewrap on Linux")
    return [
        bwrap, "--die-with-parent", "--new-session", "--unshare-all",
        "--ro-bind", "/", "/", "--bind", str(workspace), str(workspace),
        "--tmpfs", "/tmp", "--proc", "/proc", "--dev", "/dev",
        "--chdir", str(workspace), *command,
    ]


def run_agentos_repo_test(payload: bytes, repository_root: str | None,
                          test_runner: str, timeout: float) -> tuple[int, bytes]:
    path, content = parse_repo_bundle(payload)
    if repository_root is None:
        raise ValueError("managed repository root is not configured")
    root = pathlib.Path(repository_root).resolve()
    if not root.is_dir() or not (root / ".git").exists():
        raise ValueError("managed repository root is not a Git worktree")
    with tempfile.TemporaryDirectory(prefix="agentos-repo-") as temporary:
        workspace = pathlib.Path(temporary).resolve()
        _extract_git_snapshot(root, workspace, min(timeout, 30.0))
        initialized = subprocess.run(
            ["git", "init", "-q", str(workspace)], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=min(timeout, 10.0), check=False,
        )
        if initialized.returncode != 0:
            raise ValueError("managed workspace initialization failed")
        overlay = workspace.joinpath(*path.parts)
        overlay.parent.mkdir(parents=True, exist_ok=True)
        if overlay.exists() and not overlay.is_file():
            raise ValueError("repository overlay target is not a regular file")
        overlay.write_bytes(content)
        sandbox_tmp = workspace / "tmp"
        sandbox_tmp.mkdir()
        env = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C", "LC_ALL": "C", "HOME": str(workspace),
            "TMPDIR": str(sandbox_tmp),
            "AGENTOS_REPO_AGENT_TASK": "1",
        }
        try:
            completed = subprocess.run(
                _sandboxed_repo_argv(workspace, test_runner),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                cwd=workspace, env=env, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return 124, b"managed repository tests timed out\n"
    if completed.returncode == 0:
        return 0, b"repository tests: ok\n"
    output = completed.stdout[-OUTPUT_MAX:]
    return completed.returncode, output or b"repository tests failed\n"


Runner = Callable[[int, bytes, int], tuple[int, int, bytes]]


def make_runner(compiler: str, timeout: float,
                repository_root: str | None = None,
                test_runner: str | None = None,
                repository_timeout: float = 180.0) -> Runner:
    def run(profile: int, source: bytes, output_capacity: int) -> tuple[int, int, bytes]:
        if profile == PROFILE_C11_COMPILE:
            exit_code, output = run_c11_compile(source, compiler, timeout)
        elif profile == PROFILE_AGENTOS_REPO_TEST:
            if test_runner is None:
                return 3, -1, b""
            try:
                exit_code, output = run_agentos_repo_test(
                    source, repository_root, test_runner, repository_timeout)
            except ValueError as exc:
                exit_code, output = 2, (str(exc) + "\n").encode()
        else:
            return 3, -1, b""
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
    parser.add_argument("--repository-root")
    parser.add_argument("--repository-timeout", type=float, default=180.0)
    parser.add_argument("--test-runner",
                        help="administrator-built xtask binary")
    parser.add_argument("--trace", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    compiler = str(pathlib.Path(args.compiler).resolve())
    if not os.path.isfile(compiler) or not os.access(compiler, os.X_OK):
        print(f"[exec-transport-proxy] compiler is not executable: {compiler}", file=sys.stderr)
        return 2
    test_runner_arg = args.test_runner
    if test_runner_arg is None and args.repository_root is not None:
        test_runner_arg = str(
            pathlib.Path(args.repository_root) / "target/debug/xtask"
        )
    test_runner = (str(pathlib.Path(test_runner_arg).resolve())
                   if test_runner_arg is not None else None)
    if test_runner is not None and (
        not os.path.isfile(test_runner) or not os.access(test_runner, os.X_OK)
    ):
        print(f"[exec-transport-proxy] test runner is not executable: {test_runner}",
              file=sys.stderr)
        return 2
    try:
        sock = connect_with_retry(args.socket, args.connect_timeout)
        print(f"[exec-transport-proxy] connected to {args.socket}", file=sys.stderr)
        with sock:
            serve(sock, make_runner(
                compiler, args.profile_timeout, args.repository_root, test_runner,
                args.repository_timeout), args.trace)
    except (EOFError, OSError, ValueError) as exc:
        print(f"[exec-transport-proxy] stopped: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
