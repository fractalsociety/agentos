import importlib.util
import pathlib
import socket
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "model_transport_proxy", ROOT / "tools/model_transport_proxy.py"
)
PROXY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(PROXY)


class ModelTransportProxyTests(unittest.TestCase):
    def test_recv_exact_handles_fragmentation(self):
        left, right = socket.socketpair()
        try:
            thread = threading.Thread(
                target=lambda: (right.sendall(b"ab"), right.sendall(b"cdef"))
            )
            thread.start()
            self.assertEqual(PROXY.recv_exact(left, 6), b"abcdef")
            thread.join()
        finally:
            left.close()
            right.close()

    def test_wire_header_matches_native_abi(self):
        encoded = PROXY.HEADER.pack(PROXY.MAGIC, PROXY.VERSION, 123, 456)
        self.assertEqual(len(encoded), 16)
        self.assertEqual(encoded[:4], b"AGTM")
        self.assertEqual(PROXY.HEADER.unpack(encoded), (PROXY.MAGIC, 1, 123, 456))


if __name__ == "__main__":
    unittest.main()
