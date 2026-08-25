#!/usr/bin/env python3
"""Build, boot, and run one real capability-native FractalOS coding task."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / "build" / "qemu_virt_aarch64"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    prompt = parser.add_mutually_exclusive_group(required=True)
    prompt.add_argument("--prompt")
    prompt.add_argument("--prompt-file", type=pathlib.Path)
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--agentctl", type=pathlib.Path,
                        default=ROOT / "tools" / "agentctl" / "agentctl")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--max-steps", type=int, default=24)
    parser.add_argument("--required-caps", type=lambda value: int(value, 0),
                        default=13,
                        help="declaration only; default Model+Memory+Exec (13)")
    parser.add_argument("--no-require-test", action="store_false",
                        dest="require_test", default=True)
    parser.add_argument("--boot-timeout", type=float, default=120.0)
    parser.add_argument("--task-timeout", type=float, default=600.0)
    parser.add_argument("--trace", action="store_true")
    return parser.parse_args()


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def process(argv: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
    return subprocess.Popen(argv, start_new_session=True, **kwargs)


def stop(child: subprocess.Popen[bytes] | None) -> None:
    if child is None or child.poll() is not None:
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
        child.wait(timeout=3)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def process_snapshot(child: subprocess.Popen[bytes]) -> tuple[int, float]:
    """Return whole-QEMU RSS bytes and point-in-time CPU percentage."""
    if child.poll() is not None:
        return (0, 0.0)
    snapshot = subprocess.run(
        ["ps", "-o", "rss=", "-o", "%cpu=", "-p", str(child.pid)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    fields = snapshot.stdout.split()
    if len(fields) != 2:
        return (0, 0.0)
    try:
        return (int(fields[0]) * 1024, float(fields[1]))
    except ValueError:
        return (0, 0.0)


def wait_bridge(port: int, child: subprocess.Popen[bytes], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    url = f"http://127.0.0.1:{port}/healthz"
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError(f"model bridge exited with {child.returncode}")
        try:
            with urllib.request.urlopen(url, timeout=0.5) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("model bridge did not become ready")


def qemu_argv(sockets: pathlib.Path) -> list[str]:
    def console(bus: int, stem: str, name: str) -> list[str]:
        path = sockets / f"{stem}.sock"
        return [
            "-chardev", f"socket,id={stem}_char,path={path},server=on,wait=off",
            "-device", f"virtio-serial-device,bus=virtio-mmio-bus.{bus},id=vser_{stem}",
            "-device", f"virtconsole,bus=vser_{stem}.0,chardev={stem}_char,name={name}",
        ]

    argv = [
        "qemu-system-aarch64", "-machine",
        "virt,virtualization=on,highmem=off,secure=off", "-cpu", "cortex-a57",
        "-m", "2G", "-display", "none", "-monitor", "none", "-serial", "stdio",
        "-global", "virtio-mmio.force-legacy=off",
        "-netdev", "user,id=fractalos_net",
        "-device",
        "virtio-net-device,netdev=fractalos_net,bus=virtio-mmio-bus.0,ctrl_vq=off,ctrl_rx=off,ctrl_vlan=off,guest_announce=off,mq=off,ctrl_mac_addr=off,ctrl_guest_offloads=off",
    ]
    argv += console(2, "cc", "cc.0")
    argv += console(3, "model", "model.0")
    argv += console(8, "exec", "exec.0")
    argv += console(16, "mcp", "mcp.0")
    argv += [
        "-device", f"loader,file={BUILD / 'loader.elf'},cpu-num=0",
        "-device", f"loader,file={BUILD / 'fractalos.img'},addr=0x48000000",
    ]
    return argv


def read_serial(child: subprocess.Popen[bytes], ready: threading.Event,
                trace: bool) -> None:
    assert child.stdout is not None
    marker = b"FractalOS boot complete"
    pending = b""
    for chunk in iter(lambda: child.stdout.read(256), b""):
        if trace:
            sys.stderr.buffer.write(chunk)
            sys.stderr.buffer.flush()
        pending = (pending + chunk)[-4096:]
        if marker in pending:
            ready.set()


def checked_prompt(args: argparse.Namespace) -> str:
    if args.prompt is not None:
        prompt = args.prompt
    else:
        prompt = args.prompt_file.read_text(encoding="utf-8")
    encoded = prompt.encode("utf-8")
    if not 0 < len(encoded) <= 4076:
        raise ValueError("prompt must encode to 1..4076 UTF-8 bytes")
    return prompt


def main() -> int:
    args = parse_args()
    prompt = checked_prompt(args)
    if not 1 <= args.max_steps <= 128:
        raise ValueError("--max-steps must be in 1..128")
    if args.required_caps & ~31:
        raise ValueError("--required-caps contains unknown bits")

    if not args.no_build:
        subprocess.run(
            ["make", "build", "BOARD=qemu_virt_aarch64", "GUEST_OS=none"],
            cwd=ROOT, check=True,
        )
        subprocess.run(["make", "-C", "tools/agentctl", "all"],
                       cwd=ROOT, check=True)
    for required in (BUILD / "loader.elf", BUILD / "fractalos.img", args.agentctl):
        if not pathlib.Path(required).is_file():
            raise FileNotFoundError(required)

    login = subprocess.run([args.codex, "login", "status"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if login.returncode != 0:
        sys.stderr.buffer.write(login.stdout)
        raise RuntimeError("official Codex CLI is not authenticated")

    children: list[subprocess.Popen[bytes]] = []
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="fractalos-native-") as temporary:
        temp = pathlib.Path(temporary)
        port = free_tcp_port()
        bridge = process(
            [sys.executable, str(ROOT / "tools/model_bridge.py"),
             "--port", str(port), "--codex-cli", args.codex],
            stdout=subprocess.DEVNULL,
        )
        children.append(bridge)
        try:
            wait_bridge(port, bridge, 15.0)
            qemu = process(qemu_argv(temp), stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
            children.append(qemu)
            trace_flag = ["--trace"] if args.trace else []
            children.append(process(
                [sys.executable, str(ROOT / "tools/model_transport_proxy.py"),
                 "--socket", str(temp / "model.sock"), "--bridge-url",
                 f"http://127.0.0.1:{port}/v1/chat/completions", *trace_flag],
                stdout=subprocess.DEVNULL,
            ))
            children.append(process(
                [sys.executable, str(ROOT / "tools/exec_transport_proxy.py"),
                 "--socket", str(temp / "exec.sock"), "--repository-root",
                 str(ROOT), *trace_flag], stdout=subprocess.DEVNULL,
            ))
            children.append(process(
                [sys.executable, str(ROOT / "tools/mcp_transport_proxy.py"),
                 "--socket", str(temp / "mcp.sock"), *trace_flag],
                stdout=subprocess.DEVNULL,
            ))

            ready = threading.Event()
            reader = threading.Thread(target=read_serial,
                                      args=(qemu, ready, args.trace), daemon=True)
            reader.start()
            if not ready.wait(args.boot_timeout):
                raise TimeoutError("FractalOS did not reach its truthful ready marker")

            command = [
                str(args.agentctl), "--socket", str(temp / "cc.sock"),
                "--batch", "agent-run", "--caps", str(args.required_caps),
                "--max-steps", str(args.max_steps),
            ]
            if args.require_test:
                command.append("--require-test")
            command.append(prompt)
            completed = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       timeout=args.task_timeout)
            if completed.stderr:
                sys.stderr.buffer.write(completed.stderr)
            if completed.stdout:
                sys.stdout.buffer.write(completed.stdout)
                sys.stdout.buffer.flush()
            elapsed_ms = int((time.monotonic() - started) * 1000)
            qemu_rss_bytes, qemu_cpu_percent = process_snapshot(qemu)
            print("FRACTALOS_NATIVE_RUN " + json.dumps({
                "elapsed_ms": elapsed_ms,
                "exit_code": completed.returncode,
                "required_caps": args.required_caps,
                "max_steps": args.max_steps,
                "qemu_rss_bytes": qemu_rss_bytes,
                "qemu_cpu_percent_at_completion": qemu_cpu_percent,
            }, separators=(",", ":")), file=sys.stderr)
            return completed.returncode
        finally:
            for child in reversed(children):
                stop(child)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, OSError, RuntimeError, TimeoutError,
            ValueError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as error:
        print(f"run-native-agent: {error}", file=sys.stderr)
        raise SystemExit(1)
