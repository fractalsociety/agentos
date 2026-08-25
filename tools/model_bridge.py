#!/usr/bin/env python3
"""Bounded host bridge from FractalOS ModelSvc to an OpenAI-compatible API."""

from __future__ import annotations

import argparse
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_REQUEST_BYTES = 1 * 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


def rewrite_request(body: bytes, model_override: str | None) -> bytes:
    if len(body) > MAX_REQUEST_BYTES:
        raise ValueError("request too large")
    value = json.loads(body)
    if not isinstance(value, dict) or not isinstance(value.get("messages"), list):
        raise ValueError("expected an OpenAI-compatible chat request")
    if model_override:
        value["model"] = model_override
    value.pop("temperature_scale", None)
    temperature = value.get("temperature")
    if isinstance(temperature, int) and temperature > 2:
        value["temperature"] = temperature / 1000.0
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def render_codex_prompt(body: bytes) -> str:
    """Render a chat request for a tool-less, shared Codex model process."""
    value = json.loads(body)
    messages = value.get("messages", [])
    rendered = [
        "Act only as the model behind an FractalOS capability-scoped harness.",
        "Do not use shell, files, network tools, or ask questions.",
        "Return only the JSON object requested by the system message.",
        "",
    ]
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        content = message.get("content")
        if isinstance(role, str) and isinstance(content, str):
            rendered.append(f"[{role}]\n{content}\n")
    return "\n".join(rendered)


def codex_cli_completion(body: bytes, executable: str, timeout: float) -> bytes:
    """Run the authenticated official Codex CLI as a shared model backend."""
    prompt = render_codex_prompt(body)
    with tempfile.TemporaryDirectory(prefix="fractalos-model-") as workspace:
        output_path = os.path.join(workspace, "last-message.json")
        command = [
            executable,
            "exec",
            "--ignore-user-config",
            "--ignore-rules",
            "--ephemeral",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--output-last-message",
            output_path,
            "--cd",
            workspace,
            "-",
        ]
        try:
            completed = subprocess.run(
                command,
                input=prompt.encode("utf-8"),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise OSError("Codex CLI timed out") from exc
        if completed.returncode != 0:
            raise OSError(f"Codex CLI exited with status {completed.returncode}")
        with open(output_path, "rb") as output:
            content = output.read(MAX_RESPONSE_BYTES + 1)
        if len(content) > MAX_RESPONSE_BYTES:
            raise ValueError("Codex CLI response too large")
        message = content.decode("utf-8").strip()
        if not message:
            raise ValueError("Codex CLI returned an empty response")
        response = {
            "id": "fractalos-codex-cli",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": message},
                "finish_reason": "stop",
            }],
        }
        return json.dumps(response, separators=(",", ":")).encode("utf-8")


class BridgeHandler(BaseHTTPRequestHandler):
    server_version = "FractalOSModelBridge/1"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("[model-bridge] " + fmt % args + "\n")

    def _reply(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/healthz":
            self._reply(404, b'{"error":"not found"}', "application/json")
            return
        self._reply(200, b'{"status":"ready"}', "application/json")

    def do_POST(self) -> None:  # noqa: N802
        config = self.server.bridge_config  # type: ignore[attr-defined]
        if self.path != "/v1/chat/completions":
            self._reply(404, b'{"error":"not found"}', "application/json")
            return
        try:
            content_length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            content_length = -1
        if content_length < 0 or content_length > MAX_REQUEST_BYTES:
            self._reply(413, b'{"error":"request too large"}', "application/json")
            return
        try:
            body = rewrite_request(self.rfile.read(content_length), config.model)
        except (ValueError, json.JSONDecodeError) as exc:
            response = json.dumps({"error": str(exc)}).encode("utf-8")
            self._reply(400, response, "application/json")
            return

        if config.codex_cli:
            try:
                with config.codex_slots:
                    response = codex_cli_completion(
                        body, config.codex_cli, config.timeout)
                self._reply(200, response, "application/json")
            except (OSError, ValueError, UnicodeError) as exc:
                response = json.dumps(
                    {"error": f"Codex CLI unavailable: {exc}"}).encode("utf-8")
                self._reply(502, response, "application/json")
            return

        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if config.api_key:
            headers["Authorization"] = f"Bearer {config.api_key}"
        request = urllib.request.Request(config.upstream, body, headers, method="POST")
        try:
            context = ssl.create_default_context()
            with urllib.request.urlopen(request, timeout=config.timeout,
                                        context=context) as upstream:
                response = upstream.read(MAX_RESPONSE_BYTES + 1)
                if len(response) > MAX_RESPONSE_BYTES:
                    raise ValueError("upstream response too large")
                self._reply(upstream.status, response,
                            upstream.headers.get("Content-Type", "application/json"))
        except urllib.error.HTTPError as exc:
            response = exc.read(MAX_RESPONSE_BYTES)
            self._reply(exc.code, response,
                        exc.headers.get("Content-Type", "application/json"))
        except (OSError, ValueError) as exc:
            response = json.dumps({"error": f"upstream unavailable: {exc}"}).encode("utf-8")
            self._reply(502, response, "application/json")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument("--upstream", default=os.environ.get(
        "FRACTALOS_MODEL_UPSTREAM", "https://api.openai.com/v1/chat/completions"))
    parser.add_argument("--model", default=os.environ.get("FRACTALOS_MODEL_NAME"))
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--allow-http-upstream", action="store_true")
    parser.add_argument("--codex-cli", nargs="?", const="codex", default=None,
                        help="use the authenticated official Codex CLI as the shared backend")
    parser.add_argument("--codex-max-concurrency", type=int, default=1,
                        help="maximum simultaneous Codex processes (default: 1)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 1 <= args.codex_max_concurrency <= 8:
        print("--codex-max-concurrency must be between 1 and 8", file=sys.stderr)
        return 2
    if (not args.codex_cli and not args.upstream.startswith("https://")
            and not args.allow_http_upstream):
        print("refusing non-HTTPS upstream; use --allow-http-upstream for a trusted local API",
              file=sys.stderr)
        return 2
    args.api_key = os.environ.get("FRACTALOS_MODEL_API_KEY") or os.environ.get(
        "OPENAI_API_KEY")
    if not args.codex_cli and not args.api_key and not args.allow_http_upstream:
        print("set FRACTALOS_MODEL_API_KEY or OPENAI_API_KEY", file=sys.stderr)
        return 2
    server = ThreadingHTTPServer((args.bind, args.port), BridgeHandler)
    args.codex_slots = threading.BoundedSemaphore(args.codex_max_concurrency)
    server.bridge_config = args  # type: ignore[attr-defined]
    backend = f"codex-cli:{args.codex_cli}" if args.codex_cli else args.upstream
    print(f"[model-bridge] listening on {args.bind}:{args.port}; backend={backend}",
          file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
