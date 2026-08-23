#!/usr/bin/env python3
import http.server
import json
import pathlib
import subprocess
import tempfile
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *_args):
        pass

    def reply(self, value):
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        Handler.seen.append(("GET", self.path, self.headers.get("Authorization"), None))
        if self.path == "/health":
            self.reply({"status": "ok"})
        elif self.path == "/api/v1/user":
            self.reply({"users": [{"id": "7", "name": "agents"}]})
        else:
            self.reply({"nodes": [{"id": 1}]})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        payload = json.loads(raw or b"{}")
        Handler.seen.append(("POST", self.path, self.headers.get("Authorization"), payload))
        self.reply({"preAuthKey": {"key": "one-time-test-key"}})


def run(helper, url, token, *args):
    result = subprocess.run(
        [str(helper), "--url", url, "--token-file", str(token), *args],
        check=True, text=True, capture_output=True,
    )
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    return payload


def main():
    repo = pathlib.Path(__file__).resolve().parents[1]
    helper = repo / "tools/agentctl/agentctl-mesh"
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    with tempfile.TemporaryDirectory() as tmp:
        token = pathlib.Path(tmp) / "api.token"
        token.write_text("secret-test-token\n")
        token.chmod(0o600)
        url = f"http://127.0.0.1:{server.server_port}"
        run(helper, url, token, "status")
        run(helper, url, token, "nodes")
        result = run(helper, url, token, "enroll-key", "--ttl-seconds", "600")
        assert result["result"]["preAuthKey"]["key"] == "one-time-test-key"
    server.shutdown()
    assert Handler.seen[0][2] is None
    assert Handler.seen[1][2] == "Bearer secret-test-token"
    assert Handler.seen[2][0:3] == ("GET", "/api/v1/user", "Bearer secret-test-token")
    assert Handler.seen[3][3]["aclTags"] == ["tag:agent"]
    assert Handler.seen[3][3]["user"] == "7"
    print("[PASS] agentctl mesh structured management tests")


if __name__ == "__main__":
    main()
