import socket
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from coordinator.coordinator import invoke_enclave


class InvokeEnclaveProtocolTest(unittest.TestCase):
    def test_invoke_enclave_closes_write_side_before_read(self):
        calls = []

        class FakeSocket:
            def connect(self, addr):
                calls.append(("connect", addr))

            def sendall(self, payload):
                calls.append(("sendall", payload))

            def shutdown(self, how):
                calls.append(("shutdown", how))

            def recv(self, size):
                calls.append(("recv", size))
                return b'{"ok": true, "evidence": {"manifestDigest": "abc"}}'

            def close(self):
                calls.append(("close", None))

        original_af_vsock = getattr(socket, "AF_VSOCK", None)
        original_socket = socket.socket
        try:
            socket.AF_VSOCK = 40
            socket.socket = lambda *args, **kwargs: FakeSocket()
            result = invoke_enclave(16, 5005, {"requestId": "r1"})
        finally:
            if original_af_vsock is None:
                delattr(socket, "AF_VSOCK")
            else:
                socket.AF_VSOCK = original_af_vsock
            socket.socket = original_socket

        self.assertEqual(result, {"manifestDigest": "abc"})
        self.assertIn(("shutdown", socket.SHUT_WR), calls)
        self.assertLess(calls.index(("shutdown", socket.SHUT_WR)), calls.index(("recv", 1024 * 1024)))


if __name__ == "__main__":
    unittest.main()
