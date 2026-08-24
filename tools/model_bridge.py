#!/usr/bin/env python3
"""Bounded host bridge from AgentOS ModelSvc to an OpenAI-compatible API."""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
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


class BridgeHandler(BaseHTTPRequestHandler):
    server_version = "AgentOSModelBridge/1"

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
        "AGENTOS_MODEL_UPSTREAM", "https://api.openai.com/v1/chat/completions"))
    parser.add_argument("--model", default=os.environ.get("AGENTOS_MODEL_NAME"))
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--allow-http-upstream", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.upstream.startswith("https://") and not args.allow_http_upstream:
        print("refusing non-HTTPS upstream; use --allow-http-upstream for a trusted local API",
              file=sys.stderr)
        return 2
    args.api_key = os.environ.get("AGENTOS_MODEL_API_KEY") or os.environ.get(
        "OPENAI_API_KEY")
    if not args.api_key and not args.allow_http_upstream:
        print("set AGENTOS_MODEL_API_KEY or OPENAI_API_KEY", file=sys.stderr)
        return 2
    server = ThreadingHTTPServer((args.bind, args.port), BridgeHandler)
    server.bridge_config = args  # type: ignore[attr-defined]
    print(f"[model-bridge] listening on {args.bind}:{args.port}; upstream={args.upstream}",
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
