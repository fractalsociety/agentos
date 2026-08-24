import importlib.util
import pathlib
import shutil
import socket
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "exec_transport_proxy", ROOT / "tools/exec_transport_proxy.py"
)
PROXY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(PROXY)


class ExecTransportProxyTests(unittest.TestCase):
    @staticmethod
    def repo_bundle(path: bytes, content: bytes) -> bytes:
        return PROXY.REPO_BUNDLE_HEADER.pack(
            PROXY.REPO_BUNDLE_MAGIC, PROXY.REPO_BUNDLE_VERSION,
            len(path), len(content),
        ) + path + content

    def test_wire_round_trip_preserves_profile_and_tag(self):
        left, right = socket.socketpair()
        seen = []

        def runner(profile, source, output_cap):
            seen.append((profile, source, output_cap))
            return 0, 0, b"compile: ok\n"

        def service():
            try:
                PROXY.serve(right, runner)
            except (EOFError, OSError):
                pass

        thread = threading.Thread(target=service, daemon=True)
        thread.start()
        try:
            source = b"int answer(void) { return 42; }\n"
            left.sendall(PROXY.REQUEST_HEADER.pack(
                PROXY.MAGIC, PROXY.VERSION, PROXY.PROFILE_C11_COMPILE,
                len(source), 1024, 77,
            ) + source)
            raw = PROXY.recv_exact(left, PROXY.RESPONSE_HEADER.size)
            self.assertEqual(
                PROXY.RESPONSE_HEADER.unpack(raw),
                (PROXY.MAGIC, 0, 0, len(b"compile: ok\n"), 77),
            )
            self.assertEqual(PROXY.recv_exact(left, len(b"compile: ok\n")),
                             b"compile: ok\n")
            self.assertEqual(seen, [(1, source, 1024)])
        finally:
            left.close()
            right.close()
            thread.join(timeout=1.0)

    @unittest.skipUnless(shutil.which("clang"), "clang unavailable")
    def test_real_compile_profile_accepts_valid_and_rejects_invalid_c(self):
        compiler = shutil.which("clang")
        ok, output = PROXY.run_c11_compile(
            b"int answer(void) { return 42; }\n", compiler, 5.0
        )
        self.assertEqual((ok, output), (0, b""))
        bad, diagnostics = PROXY.run_c11_compile(
            b"int answer(void) { return ; }\n", compiler, 5.0
        )
        self.assertNotEqual(bad, 0)
        self.assertIn(b"error:", diagnostics)

    @unittest.skipUnless(shutil.which("clang"), "clang unavailable")
    def test_profile_blocks_host_file_includes(self):
        compiler = shutil.which("clang")
        code, output = PROXY.run_c11_compile(b'#include "/etc/passwd"\n', compiler, 5.0)
        self.assertEqual(code, 2)
        self.assertEqual(output, b"preprocessor directives are disabled by this profile\n")
        for bypass in (b'/**/#include "/etc/passwd"\n',
                       b'%:include "/etc/passwd"\n',
                       b'??=include "/etc/passwd"\n',
                       b'_Pragma("GCC dependency /etc/passwd")\n'):
            blocked, _ = PROXY.run_c11_compile(bypass, compiler, 5.0)
            self.assertEqual(blocked, 2)

    def test_repository_bundle_is_bounded_and_cannot_escape_workspace(self):
        content = b"int agentos_repo_answer(void) { return 42; }\n"
        path, decoded = PROXY.parse_repo_bundle(self.repo_bundle(
            b"tests/fixtures/repo_agent/answer.c", content
        ))
        self.assertEqual(str(path), "tests/fixtures/repo_agent/answer.c")
        self.assertEqual(decoded, content)
        for unsafe in (b"/etc/passwd", b"../escape", b"src/../../escape",
                       b".git/config", b"bad\x00path"):
            with self.assertRaises(ValueError):
                PROXY.parse_repo_bundle(self.repo_bundle(unsafe, content))

    @unittest.skipUnless(shutil.which("clang"), "toolchain unavailable")
    def test_repository_profile_fails_closed_without_admin_root(self):
        runner = PROXY.make_runner(
            shutil.which("clang"), 5.0, None, "/nonexistent/xtask", 5.0
        )
        status, exit_code, output = runner(
            PROXY.PROFILE_AGENTOS_REPO_TEST,
            self.repo_bundle(b"src/answer.c", b"int answer(void){return 42;}\n"),
            1024,
        )
        self.assertEqual(status, 0)
        self.assertEqual(exit_code, 2)
        self.assertIn(b"root is not configured", output)


if __name__ == "__main__":
    unittest.main()
