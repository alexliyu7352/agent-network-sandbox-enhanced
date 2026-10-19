#!/usr/bin/env python3
"""Optional loopback SSH server for protocol_runtime.py; never a system SSH server.

Use a private Python environment with these official Python 3.8-compatible pins:
paramiko==3.5.1 cryptography==44.0.3 bcrypt==4.1.3 PyNaCl==1.5.0
cffi==1.17.1 pycparser==2.22

Only the public fake password is accepted. There are no OS accounts, sessions,
commands, file transfer, remote forwarding or non-loopback outbound connections.
Paramiko's ServerInterface direct-tcpip callback authorizes exact fixture ports;
the server alone rewrites 127.0.0.2 to 127.0.0.1 and binds source 127.0.0.3.
API source: https://docs.paramiko.org/en/3.4/api/server.html
"""

import argparse
import json
import logging
import os
from pathlib import Path
import select
import socket
import socketserver
import threading


USERNAME = "matrix-user"
PASSWORD = "public-protocol-matrix-fake-password"
LOOPBACK = "127.0.0.1"
BOUNDARY = "127.0.0.2"
PROXY_EXIT = "127.0.0.3"


def paramiko_module():
    try:
        import paramiko
    except ImportError:
        raise RuntimeError("optional SSH fixture requires paramiko==3.5.1") from None
    if paramiko.__version__ != "3.5.1":
        raise RuntimeError("optional SSH fixture requires paramiko==3.5.1")
    logger = logging.getLogger("paramiko")
    logger.handlers = [logging.NullHandler()]
    logger.propagate = False
    return paramiko


def create_host_key(path):
    key = paramiko_module().RSAKey.generate(2048)
    key.write_private_key_file(str(path))
    Path(path).chmod(0o600)
    return key.get_name() + " " + key.get_base64()


def make_interface(server):
    paramiko = server.paramiko

    class Interface(paramiko.ServerInterface):
        def __init__(self):
            self.destinations = {}

        def get_allowed_auths(self, username):
            return "password"

        def check_auth_password(self, username, password):
            if username == USERNAME and password == PASSWORD:
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_direct_tcpip_request(self, chanid, origin, destination):
            address, port = destination
            if address != BOUNDARY or port not in server.allowed_ports:
                return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            self.destinations[chanid] = port
            return paramiko.OPEN_SUCCEEDED

    return Interface()


class SSHServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, port, allowed_ports, key_path):
        if not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError("invalid local SSH fixture port")
        if not allowed_ports or any(not isinstance(value, int) or not 1 <= value <= 65535 for value in allowed_ports):
            raise ValueError("invalid local SSH fixture destinations")
        self.paramiko = paramiko_module()
        self.key = self.paramiko.RSAKey.from_private_key_file(str(key_path))
        self.allowed_ports = set(allowed_ports)
        self.transports = set()
        self.lock = threading.Lock()
        super().__init__((LOOPBACK, port), SSHHandler)

    def server_close(self):
        with self.lock:
            transports = list(self.transports)
        for transport in transports:
            transport.close()
        super().server_close()


class SSHHandler(socketserver.BaseRequestHandler):
    def handle(self):
        paramiko = self.server.paramiko
        transport = paramiko.Transport(self.request)
        transport.add_server_key(self.server.key)
        interface = make_interface(self.server)
        with self.server.lock:
            self.server.transports.add(transport)
        try:
            transport.start_server(server=interface)
            while transport.is_active():
                channel = transport.accept(timeout=0.2)
                if channel is None:
                    continue
                port = interface.destinations.pop(channel.get_id(), None)
                if port is None:
                    channel.close()
                    continue
                threading.Thread(target=forward_channel, args=(channel, port), daemon=True).start()
        except (OSError, EOFError, paramiko.SSHException):
            pass
        finally:
            transport.close()
            with self.server.lock:
                self.server.transports.discard(transport)


def forward_channel(channel, port):
    # All destinations came through the exact allowlist. Neither the channel's
    # original host nor the origin address is used as a socket destination.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target:
            target.settimeout(3)
            target.bind((PROXY_EXIT, 0))
            target.connect((LOOPBACK, port))
            while not channel.closed:
                readable, _, _ = select.select([channel, target], [], [], 0.2)
                for endpoint in readable:
                    payload = endpoint.recv(65536)
                    if not payload:
                        return
                    (target if endpoint is channel else channel).sendall(payload)
    except (OSError, EOFError):
        pass
    finally:
        channel.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    config = json.loads(args.config.read_text())
    if set(config) != {"fixture", "listen_port", "allowed_ports", "host_key_path"} or config["fixture"] != "paramiko-3.5.1":
        raise ValueError("invalid private SSH fixture configuration")
    with SSHServer(config["listen_port"], config["allowed_ports"], config["host_key_path"]) as server:
        print("protocol-ssh started", flush=True)
        server.serve_forever(poll_interval=0.05)


if __name__ == "__main__":
    main()
