"""Optional real SSH server contracts, independent of sing-box interoperability."""
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import unittest

import protocol_runtime as runtime
import protocol_ssh_fixture as ssh_fixture


@unittest.skipUnless(importlib.util.find_spec("paramiko"), "optional pinned Paramiko SSH fixture dependency is not installed")
class SSHFixtureTests(unittest.TestCase):
    def test_fake_auth_pinned_host_key_and_exact_destination_routing(self):
        paramiko = ssh_fixture.paramiko_module()
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "ssh-host-key.pem"
            public_key = ssh_fixture.create_host_key(key_path)
            key = paramiko.RSAKey.from_private_key_file(str(key_path))
            self.assertEqual(public_key, key.get_name() + " " + key.get_base64())
            with runtime.serving(runtime.TCPSink((runtime.LOOPBACK, 0))) as sink:
                with runtime.serving(ssh_fixture.SSHServer(0, [sink.server_address[1]], key_path)) as server:
                    with socket.create_connection(server.server_address, timeout=3) as sock:
                        transport = paramiko.Transport(sock)
                        try:
                            transport.connect(hostkey=key, username=runtime.USERNAME, password=runtime.PASSWORD)
                            channel = transport.open_channel("direct-tcpip", (runtime.BOUNDARY, sink.server_address[1]), (runtime.LOOPBACK, 12345))
                            channel.settimeout(3)
                            channel.sendall(b"ssh-forward\n")
                            self.assertEqual(json.loads(runtime.read_line(channel)),
                                             {"peer": runtime.PROXY_EXIT, "token": "ssh-forward"})
                            with self.assertRaises(paramiko.ChannelException):
                                transport.open_channel("direct-tcpip", (runtime.LOOPBACK, sink.server_address[1]), (runtime.LOOPBACK, 12345))
                            with self.assertRaises(paramiko.ChannelException):
                                transport.open_session()
                        finally:
                            transport.close()

    def test_wrong_password_does_not_authenticate(self):
        paramiko = ssh_fixture.paramiko_module()
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "ssh-host-key.pem"
            ssh_fixture.create_host_key(key_path)
            key = paramiko.RSAKey.from_private_key_file(str(key_path))
            with runtime.serving(ssh_fixture.SSHServer(0, [31337], key_path)) as server:
                with socket.create_connection(server.server_address, timeout=3) as sock:
                    transport = paramiko.Transport(sock)
                    try:
                        with self.assertRaises(paramiko.AuthenticationException):
                            transport.connect(hostkey=key, username=runtime.USERNAME, password="incorrect-test-password")
                    finally:
                        transport.close()


if __name__ == "__main__":
    unittest.main()
