import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import mcp_transport_proxy as proxy  # noqa: E402


class McpTransportProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = ROOT / "tools" / "mcp_fixture_server.py"
        self.client = proxy.McpStdioClient([sys.executable, str(fixture)], 2.0)
        self.client.start()

    def tearDown(self) -> None:
        self.client.close()

    def test_discovers_namespaced_tool(self) -> None:
        payload = self.client.list_payload()
        self.assertIn(b'"name":"mcp.fixture_echo"', payload)

    def test_invokes_real_stdio_tool(self) -> None:
        payload = self.client.invoke("mcp.fixture_echo", b'{"message":"fractalos-ok"}')
        self.assertIn(b'"text":"fractalos-ok"', payload)
        self.assertIn(b'"echo":"fractalos-ok"', payload)

    def test_unknown_tool_is_not_forwarded(self) -> None:
        with self.assertRaises(KeyError):
            self.client.invoke("mcp.not_registered", b"{}")

    def test_command_requires_json_argv(self) -> None:
        with self.assertRaises(ValueError):
            proxy.parse_server_argv('"sh -c bad"')

    def test_server_environment_is_explicit(self) -> None:
        self.assertEqual(
            proxy.parse_server_env('{"GITHUB_TOKEN":"secret"}'),
            {"GITHUB_TOKEN": "secret"},
        )
        with self.assertRaises(ValueError):
            proxy.parse_server_env('{"BAD-KEY":"value"}')


class LegacyMcpTransportProxyTests(unittest.TestCase):
    def test_falls_back_to_initialize_lifecycle(self) -> None:
        fixture = ROOT / "tools" / "mcp_fixture_server.py"
        client = proxy.McpStdioClient(
            [sys.executable, str(fixture), "--legacy"], 2.0,
        )
        try:
            client.start()
            self.assertFalse(client.modern)
            self.assertEqual(client.protocol, proxy.LEGACY_PROTOCOL)
            self.assertIn("mcp.fixture_echo", client.tools)
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
