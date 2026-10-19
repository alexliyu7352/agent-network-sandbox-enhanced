#!/usr/bin/env python3
"""Real pinned-core loopback protocol matrix; never a host-firewall acceptance test.

Each case compiles the production managed policy, then replaces only its TUN,
interface binding and resolver boundary for an unprivileged local fixture.
Proxy servers alone rewrite 127.0.0.2 destinations to local sinks and use source
127.0.0.3. Canary listeners on the original destinations detect direct fallback.
No public endpoint, real credential, system firewall or route is used.

Primary schema sources: SagerNet/sing-box at af6e64c3b69e6132ebaee0e1a3d24e93903f6709,
option/{simple,hysteria,hysteria2,tuic,shadowsocks,trojan,vmess,vless,anytls,snell,naive}.go
and protocol/{socks,naive}/inbound.go (both wrap their router with UoT).
Shared DNS wire/fixture helpers come from this repository's test_dns_runtime.py.
"""

import argparse
import copy
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

import test_dns_runtime as dns_fixture


ROOT = Path(__file__).resolve().parents[1]
REVISION = "af6e64c3b69e6132ebaee0e1a3d24e93903f6709"
LOOPBACK = "127.0.0.1"
BOUNDARY = "127.0.0.2"
PROXY_EXIT = "127.0.0.3"
SERVER_NAME = "protocol.test"
PASSWORD = "public-protocol-matrix-fake-password"
USERNAME = "matrix-user"
UUID = "00000000-0000-4000-8000-000000000001"
TIMEOUT = 3.0
EXPERIMENTAL_CASES = ("snell4", "hysteria-port-hopping")
BLOCKED = {
    "ssh": "The pinned core has no SSH server inbound; a separately managed SSH fixture is required.",
    "snell4": "Opt-in snell4 tests a v4 client against the native v5 server; compatibility is not part of the default verified matrix.",
    "shadowtls": "A local cover TLS server and protocol injection chain need a dedicated fixture.",
    "hysteria1-port-hopping": "Opt-in hysteria-port-hopping requires actual observed rotation; not part of the default verified matrix.",
}


class CaseFailure(Exception):
    """Only static stage codes may be emitted; core/configuration logs stay private."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise CaseFailure(code)


def validate_version(text):
    require(re.search(r"\bsing-box(?:\s+version)?\s+1\.14\.2(?:\s|$)", text) is not None,
            "pinned-version-required")
    require(REVISION in text, "pinned-revision-required")


def case_names():
    names = ["hysteria", "hysteria2", "tuic", "tuic-over-stream", "shadowsocks",
             "shadowsocks-uot", "shadowsocks-mux", "anytls", "http", "https",
             "socks4-tcp", "socks4a-tcp", "socks5-tcp", "socks5-uot", "naive",
             "naive-quic", "naive-uot", "snell6"]
    for kind in ("trojan", "vmess", "vless"):
        names.append(kind)
        names.extend(kind + "-" + transport for transport in ("http", "ws", "grpc", "httpupgrade", "quic"))
    return names + ["selector-trojan", "selector-hysteria2", "urltest", "detour", "hysteria2-port-hopping"]


def is_hopping_case(name):
    return name in {"hysteria2-port-hopping", "hysteria-port-hopping"}


def transport_options(kind):
    result = {"type": kind}
    if kind in {"http", "ws", "httpupgrade"}:
        result["path"] = "/matrix"
    if kind == "grpc":
        result["service_name"] = "matrix"
    return result


def protocol_pair(name, tag, port, certificate, cert_path, key_path):
    kind = name.split("-", 1)[0]
    if name == "https":
        kind = "http"
    if name.startswith("socks"):
        kind = "socks"
    if name in {"snell4", "snell6"}:
        kind = "snell"
    outbound = {"type": kind, "tag": tag, "server": LOOPBACK, "server_port": port}
    inbound = {"type": kind, "tag": tag + "-in", "listen": LOOPBACK, "listen_port": port}
    if kind in {"hysteria", "hysteria2", "tuic", "trojan", "anytls", "naive"} or name == "https":
        outbound["tls"] = {"enabled": True, "server_name": SERVER_NAME, "certificate": [certificate]}
        inbound["tls"] = {"enabled": True, "certificate_path": cert_path, "key_path": key_path}
    if kind == "hysteria":
        outbound.update(auth_str=PASSWORD, up_mbps=100, down_mbps=100)
        inbound.update(up_mbps=100, down_mbps=100, users=[{"name": USERNAME, "auth_str": PASSWORD}])
    elif kind in {"hysteria2", "trojan", "anytls"}:
        outbound["password"] = PASSWORD
        inbound["users"] = [{"name": USERNAME, "password": PASSWORD}]
    elif kind == "tuic":
        outbound.update(uuid=UUID, password=PASSWORD)
        inbound["users"] = [{"name": USERNAME, "uuid": UUID, "password": PASSWORD}]
        if name.endswith("over-stream"):
            outbound["udp_over_stream"] = True
    elif kind == "shadowsocks":
        outbound.update(method="chacha20-ietf-poly1305", password=PASSWORD)
        inbound.update(method="chacha20-ietf-poly1305", password=PASSWORD)
        if name.endswith("uot"):
            outbound["udp_over_tcp"] = True
        elif name.endswith("mux"):
            outbound["multiplex"] = {"enabled": True, "protocol": "smux"}
            inbound["multiplex"] = {"enabled": True}
    elif kind in {"vmess", "vless"}:
        outbound["uuid"] = UUID
        inbound["users"] = [{"name": USERNAME, "uuid": UUID}]
        if kind == "vmess":
            outbound["security"] = "auto"
    elif kind in {"http", "naive"}:
        outbound.update(username=USERNAME, password=PASSWORD)
        inbound["users"] = [{"username": USERNAME, "password": PASSWORD}]
        if kind == "naive":
            outbound["quic"] = name == "naive-quic"
            inbound["network"] = "udp" if outbound["quic"] else "tcp"
            if name == "naive-uot":
                outbound["udp_over_tcp"] = True
    elif kind == "socks":
        version = name.split("-", 1)[0][5:]
        outbound["version"] = version
        if name.endswith("uot"):
            outbound["udp_over_tcp"] = True
        else:
            outbound["network"] = "tcp"
        # SOCKS4 has no password authentication. The listener remains loopback.
        if version == "5":
            outbound.update(username=USERNAME, password=PASSWORD)
            inbound["users"] = [{"username": USERNAME, "password": PASSWORD}]
    elif kind == "snell":
        # The pinned core's option/snell.go exposes client versions 4/6 and
        # server versions 5/6. Using the real server schema is an interoperability
        # experiment, not an assumption that the version numbers are aliases.
        outbound.update(version=4 if name == "snell4" else 6, psk=PASSWORD)
        inbound.update(version=5 if name == "snell4" else 6, psk=PASSWORD)
        if name == "snell4":
            outbound["obfs_mode"] = "none"
            inbound["obfs_mode"] = "none"
    if kind in {"trojan", "vmess", "vless"} and "-" in name:
        transport = name.split("-", 1)[1]
        outbound["transport"] = transport_options(transport)
        inbound["transport"] = transport_options(transport)
        if transport == "quic" and "tls" not in outbound:
            outbound["tls"] = {"enabled": True, "server_name": SERVER_NAME, "certificate": [certificate]}
            inbound["tls"] = {"enabled": True, "certificate_path": cert_path, "key_path": key_path}
    return outbound, inbound


def compile_config(source, mode):
    result = subprocess.run(["jq", "-ceS", "--arg", "mode", mode, "-f", str(ROOT / "gateway-policy.jq")],
                            input=json.dumps(source), text=True, capture_output=True, timeout=10)
    require(result.returncode == 0, "managed-policy-" + mode)
    return json.loads(result.stdout)


def build_configs(name, original, ports, certificate, cert_path, key_path):
    require(name in case_names() or name in EXPERIMENTAL_CASES, "unknown-case")
    source = copy.deepcopy(original)
    source["log"] = {"level": "info", "timestamp": False}
    extra_ports = []
    if name in {"selector-trojan", "selector-hysteria2", "urltest"}:
        a, a_in = protocol_pair("trojan", "a", ports["proxy"], certificate, cert_path, key_path)
        b, b_in = protocol_pair("hysteria2", "b", ports["proxy2"], certificate, cert_path, key_path)
        group = {"type": "urltest" if name == "urltest" else "selector", "tag": "proxy", "outbounds": ["a", "b"]}
        if name == "urltest":
            group.update(url="http://" + BOUNDARY + ":" + str(ports["tcp"]) + "/", interval="1m")
        else:
            group["default"] = "a" if name.endswith("trojan") else "b"
        outbounds, inbounds = [group, a, b], [a_in, b_in]
    elif name == "detour":
        inner, inner_in = protocol_pair("trojan", "proxy", ports["proxy"], certificate, cert_path, key_path)
        carrier, carrier_in = protocol_pair("hysteria2", "carrier", ports["proxy2"], certificate, cert_path, key_path)
        inner.update(server=BOUNDARY, detour="carrier")
        outbounds, inbounds = [inner, carrier], [inner_in, carrier_in]
        extra_ports.append(ports["proxy"])
    else:
        outbound, inbound = protocol_pair(name, "proxy", ports["proxy"], certificate, cert_path, key_path)
        if is_hopping_case(name):
            outbound.pop("server_port")
            outbound["server_ports"] = [str(ports["hop" + str(index)]) + ":" + str(ports["hop" + str(index)])
                                        for index in range(8)]
            outbound["hop_interval"] = "5s"
            # Pinned sing-quic hysteria/client.go passes this interval to the
            # same NewHopConn with intervalMax=0; no Hy2-only field is added.
        outbounds, inbounds = [outbound], [inbound]
    source["outbounds"] = outbounds
    policy = compile_config(source, "policy")
    client = compile_config(source, "effective")
    for outbound in client["outbounds"]:
        outbound.pop("bind_interface", None)
    client["inbounds"] = [
        {"type": "direct", "tag": "tcp-in", "listen": LOOPBACK, "listen_port": ports["ingress_tcp"],
         "network": "tcp", "override_address": BOUNDARY, "override_port": ports["tcp"]},
        {"type": "direct", "tag": "udp-in", "listen": LOOPBACK, "listen_port": ports["ingress_udp"],
         "network": "udp", "override_address": BOUNDARY, "override_port": ports["udp"]},
        {"type": "direct", "tag": "tun-in", "listen": LOOPBACK, "listen_port": ports["ingress_dns"],
         "override_address": "1.1.1.1", "override_port": 53},
    ]
    resolver = client["dns"]["servers"][0]
    resolver.update(server=BOUNDARY, server_port=ports["dns"])
    if resolver["type"] == "https":
        resolver["tls"]["certificate"] = [certificate]
    server = {
        "log": {"level": "info", "timestamp": False}, "inbounds": inbounds,
        "outbounds": [{"type": "direct", "tag": "sink", "inet4_bind_address": PROXY_EXIT}],
        "route": {"rules": [
            {"ip_cidr": [BOUNDARY + "/32"], "port": [ports["tcp"], ports["udp"], ports["dns"]] + extra_ports,
             "action": "route", "outbound": "sink", "override_address": LOOPBACK},
            {"action": "reject"},
        ]},
    }
    return source, client, server, policy


class TCPSink(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address):
        super().__init__(address, TCPHandler)
        self.seen = []
        self.connections = []


class TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        # Record acceptance before waiting for a line: TLS/DNS can stall without
        # sending one, and that must still trip a direct-fallback canary.
        self.server.connections.append(self.client_address[0])
        self.request.settimeout(60)
        try:
            while True:
                message = self.rfile.readline(4096)
                if not message:
                    return
                self.server.seen.append((self.client_address[0], message))
                if message.startswith((b"GET ", b"HEAD ")):
                    while self.rfile.readline(4096) not in {b"\r\n", b"\n", b""}:
                        pass
                    self.wfile.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    return
                self.wfile.write(json.dumps({"peer": self.client_address[0], "token": message.decode().strip()}).encode() + b"\n")
        except (OSError, ValueError):
            return


class UDPSink(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address):
        super().__init__(address, UDPHandler)
        self.seen = []


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        message, sock = self.request
        self.server.seen.append((self.client_address[0], message))
        # Canary listeners also record arbitrary DNS/TLS bytes without logging them.
        response = {"peer": self.client_address[0], "token": message.decode(errors="replace").strip()}
        sock.sendto(json.dumps(response).encode() + b"\n", self.client_address)


class MultiportRelay:
    """One client/QUIC session, many destination ports, one stable backend peer.

    The pinned sing-quic hysteria/hop.go creates a new connected UDP socket at
    each hop. This fixture collapses those local source addresses onto one UDP
    socket, so all ports really reach the same live QUIC connection. It records
    received traffic; configured ports alone never count as a successful hop.
    """

    def __init__(self, ports, backend_port):
        self.frontends = []
        self.backend = None
        self.thread = None
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.seen_ports = set()
        try:
            for port in ports:
                frontend = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.frontends.append(frontend)
                frontend.bind((LOOPBACK, port))
            self.backend = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.backend.bind((LOOPBACK, 0))
            self.backend.connect((LOOPBACK, backend_port))
            self.ports = [item.getsockname()[1] for item in self.frontends]
            self.thread = threading.Thread(target=self._serve, daemon=True)
            self.thread.start()
        except BaseException:
            self.close()
            raise

    @property
    def observed_ports(self):
        with self.lock:
            return sorted(self.seen_ports)

    def _serve(self):
        current = None
        while not self.stop.is_set():
            readable, _, _ = select.select(self.frontends + [self.backend], [], [], 0.03)
            for sock in readable:
                try:
                    if sock is self.backend:
                        payload = sock.recv(65535)
                        if current is not None:
                            current[0].sendto(payload, current[1])
                    else:
                        payload, address = sock.recvfrom(65535)
                        with self.lock:
                            self.seen_ports.add(sock.getsockname()[1])
                        current = (sock, address)
                        self.backend.send(payload)
                except OSError:
                    # A stopped backend generates local ICMP; no alternate
                    # destination or direct path is introduced on that error.
                    continue

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=2)
        for sock in self.frontends + ([self.backend] if self.backend is not None else []):
            sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


@contextmanager
def serving(server):
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.03}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def read_line(sock):
    result = bytearray()
    while not result.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError()
        result.extend(chunk)
        require(len(result) <= 4096, "oversized-probe-reply")
    return bytes(result)


def tcp_exchange(port, token, existing=None):
    connection = existing or socket.create_connection((LOOPBACK, port), TIMEOUT)
    connection.settimeout(TIMEOUT)
    try:
        connection.sendall(token.encode() + b"\n")
        return json.loads(read_line(connection))
    finally:
        if existing is None:
            connection.close()


def udp_exchange(port, token):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(TIMEOUT)
        connection.sendto(token.encode(), (LOOPBACK, port))
        return json.loads(connection.recv(4096))


def require_unavailable(probe, code):
    try:
        probe()
    except (OSError, EOFError, ValueError, AssertionError):
        return
    raise CaseFailure(code)


def canaries_quiet(canaries):
    return all(not sink.seen and not getattr(sink, "connections", []) for sink in canaries)


def graph_evidence(name, log, ports):
    """Require authenticated forwarding lines, never just listener startup lines.

    These lines are emitted immediately before RouteConnectionEx in the pinned
    protocol/{trojan,hysteria2}/inbound.go. Payload replies separately prove that
    the connection really reached its sink.
    """
    expected = {}
    if name == "selector-trojan":
        expected = {"a": ports["tcp"]}
    elif name == "selector-hysteria2":
        expected = {"b": ports["tcp"]}
    elif name == "urltest":
        expected = {"a": ports["tcp"], "b": ports["tcp"]}
    elif name == "detour":
        expected = {"proxy": ports["tcp"], "carrier": ports["proxy"]}
    plain = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", log)
    for tag, port in expected.items():
        pattern = (re.escape("[" + tag + "-in]") + r":[^\n]*\binbound connection to "
                   + re.escape(BOUNDARY + ":" + str(port)) + r"(?:\s|$)")
        require(re.search(pattern, plain) is not None, "graph-forwarding-evidence")
    return list(expected)


def write_private(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    path.chmod(0o600)


def core_check(binary, config, log, stage):
    with log.open("ab") as output:
        result = subprocess.run([binary, "check", "-c", str(config)], stdout=output, stderr=output, timeout=15)
    require(result.returncode == 0, stage)


def start_core(binary, config, log, stage):
    with log.open("ab") as output:
        process = subprocess.Popen([binary, "run", "-c", str(config)], stdout=output, stderr=output)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise CaseFailure(stage)
            if "sing-box started" in log.read_text(errors="replace"):
                return process
            time.sleep(0.03)
        raise CaseFailure(stage)
    except BaseException:
        dns_fixture.stop_process(process)
        raise


def create_certificate(directory):
    certificate, key = directory / "certificate.pem", directory / "key.pem"
    result = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=" + SERVER_NAME, "-addext", "subjectAltName=DNS:" + SERVER_NAME + ",DNS:cloudflare-dns.com",
        "-keyout", str(key), "-out", str(certificate)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    require(result.returncode == 0, "test-certificate-generation")
    certificate.chmod(0o600)
    key.chmod(0o600)
    return certificate, key


def run_case(binary, name, original, directory, check_only=False):
    directory.mkdir(mode=0o700)
    certificate, key = create_certificate(directory)
    certificate_text = certificate.read_text()
    processes = []
    persistent = None
    with ExitStack() as stack:
        tcp_sink = stack.enter_context(serving(TCPSink((LOOPBACK, 0))))
        udp_sink = stack.enter_context(serving(UDPSink((LOOPBACK, 0))))
        # Determine DNS transport from the real compiler, before creating the resolver.
        ports = {"tcp": tcp_sink.server_address[1], "udp": udp_sink.server_address[1]}
        port_fields = ["proxy", "proxy2", "dns", "ingress_tcp", "ingress_udp", "ingress_dns"]
        if is_hopping_case(name):
            port_fields.extend("hop" + str(index) for index in range(8))
        for field in port_fields:
            port = dns_fixture.free_dns_port()
            while port in ports.values():
                port = dns_fixture.free_dns_port()
            ports[field] = port
        _, _, _, policy = build_configs(name, original, ports, certificate_text, str(certificate), str(key))
        if policy["dns_transport"] == "https":
            resolver = stack.enter_context(serving(dns_fixture.HTTPSServer(certificate, key)))
        else:
            resolver = stack.enter_context(serving(dns_fixture.UDPServer()))
        ports["dns"] = resolver.server_address[1]
        canaries = [stack.enter_context(serving(TCPSink((BOUNDARY, ports["tcp"])))),
                    stack.enter_context(serving(UDPSink((BOUNDARY, ports["udp"])))),
                    stack.enter_context(serving(TCPSink((BOUNDARY, ports["dns"])))),
                    stack.enter_context(serving(UDPSink((BOUNDARY, ports["dns"]))))]
        source, client, server, policy = build_configs(name, original, ports, certificate_text, str(certificate), str(key))
        write_private(directory / "managed-source.json", source)
        write_private(directory / "client.json", client)
        write_private(directory / "server.json", server)
        core_check(binary, directory / "server.json", directory / "server.log", "core-check-server")
        core_check(binary, directory / "client.json", directory / "client.log", "core-check-client")
        if check_only:
            return {"case": name, "status": "CONFIG_PASS", "runtime_tested": False}
        try:
            relay = None
            if is_hopping_case(name):
                relay = stack.enter_context(MultiportRelay([ports["hop" + str(index)] for index in range(8)], ports["proxy"]))
            proxy = start_core(binary, directory / "server.json", directory / "server.log", "start-server")
            processes.append(proxy)
            client_process = start_core(binary, directory / "client.json", directory / "client.log", "start-client")
            processes.append(client_process)
            persistent = socket.create_connection((LOOPBACK, ports["ingress_tcp"]), TIMEOUT)
            reply = tcp_exchange(ports["ingress_tcp"], "tcp-forward", persistent)
            require(reply == {"peer": PROXY_EXIT, "token": "tcp-forward"}, "tcp-forward-and-proxy-source")
            udp_supported = "udp" in policy["payload_networks"]
            if udp_supported:
                reply = udp_exchange(ports["ingress_udp"], "udp-forward")
                require(reply == {"peer": PROXY_EXIT, "token": "udp-forward"}, "udp-forward-and-proxy-source")
            else:
                require_unavailable(lambda: udp_exchange(ports["ingress_udp"], "udp-refusal"), "tcp-only-udp-refusal")
                require(not udp_sink.seen, "tcp-only-udp-reached-sink")
            observed_hop_ports = []
            if relay is not None:
                # Random port choice may repeat a port. Eight choices and a
                # bounded 45-second observation window avoid assuming the first
                # scheduled hop must pick a different one.
                deadline = time.monotonic() + 45
                while len(relay.observed_ports) < 2 and time.monotonic() < deadline:
                    reply = tcp_exchange(ports["ingress_tcp"], "tcp-during-hop", persistent)
                    require(reply == {"peer": PROXY_EXIT, "token": "tcp-during-hop"}, "tcp-stream-during-hop")
                    time.sleep(0.15)
                observed_hop_ports = relay.observed_ports
                require(len(observed_hop_ports) >= 2, "actual-port-rotation-not-observed")
                require(set(observed_hop_ports).issubset(set(relay.ports)), "hop-outside-declared-ports")
                reply = tcp_exchange(ports["ingress_tcp"], "tcp-after-hop", persistent)
                require(reply == {"peer": PROXY_EXIT, "token": "tcp-after-hop"}, "tcp-stream-after-hop")
                reply = udp_exchange(ports["ingress_udp"], "udp-after-hop")
                require(reply == {"peer": PROXY_EXIT, "token": "udp-after-hop"}, "udp-after-hop")
            first = dns_fixture.query(ports["ingress_dns"], "udp", 0x1234)
            require(first == "203.0.113.1" and resolver.query_count == 1, "dns-first")
            cached = dns_fixture.query(ports["ingress_dns"], "tcp", 0x5678)
            require(cached == first and resolver.query_count == 1, "dns-shared-cache")
            time.sleep(dns_fixture.TTL + 0.2)
            refreshed = dns_fixture.query(ports["ingress_dns"], "udp", 0x9ABC)
            require(refreshed == "203.0.113.2" and resolver.query_count == 2, "dns-ttl-refetch")
            require(not resolver.errors, "dns-resolver-fixture")
            graph_forwarded = graph_evidence(name, (directory / "server.log").read_text(errors="replace"), ports)
            if name == "urltest":
                health_requests = [message for _, message in tcp_sink.seen if message.startswith((b"GET ", b"HEAD "))]
                require(len(health_requests) >= 2, "urltest-all-candidate-health-requests")
            require(canaries_quiet(canaries), "direct-canary-before-stop")
            udp_count_before_stop = len(udp_sink.seen)
            dns_fixture.stop_process(proxy)
            require_unavailable(lambda: tcp_exchange(ports["ingress_tcp"], "existing-after-stop", persistent), "existing-tcp-after-server-stop")
            require_unavailable(lambda: tcp_exchange(ports["ingress_tcp"], "new-after-stop"), "new-tcp-after-server-stop")
            require_unavailable(lambda: udp_exchange(ports["ingress_udp"], "udp-after-stop"), "udp-after-server-stop")
            require(len(udp_sink.seen) == udp_count_before_stop, "udp-reached-sink-after-stop")
            require(not any(b"after-stop" in message for _, message in tcp_sink.seen), "tcp-reached-sink-after-stop")
            # Restart only the client to remove cached DNS answers; the proxy stays dead.
            dns_fixture.stop_process(client_process)
            fresh = start_core(binary, directory / "client.json", directory / "client-after-stop.log", "restart-client-with-proxy-down")
            processes.append(fresh)
            require_unavailable(lambda: dns_fixture.query(ports["ingress_dns"], "tcp", 0xAABB), "dns-after-server-stop")
            require(resolver.query_count == 2, "resolver-reached-after-stop")
            require(canaries_quiet(canaries), "direct-canary-after-stop")
            return {"case": name, "status": "PASS", "runtime_tested": True, "scope": "loopback-only",
                    "tcp": "forwarded", "udp": "forwarded" if udp_supported else "refused",
                    "proxy_source": PROXY_EXIT, "dns": policy["dns_transport"], "cache": "shared-and-ttl-refetched",
                    "server_stop": ["existing-tcp-refused", "new-tcp-refused", "udp-refused", "uncached-dns-refused"],
                    "direct_canaries": "no-traffic", "host_firewall_tested": False,
                    "graph_forwarded": graph_forwarded,
                    "observed_hop_ports": observed_hop_ports,
                    "configured_outer_endpoints": policy["outer_endpoints"]}
        finally:
            if persistent is not None:
                persistent.close()
            for process in reversed(processes):
                if process.poll() is None:
                    dns_fixture.stop_process(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", help="Actual pinned worker executable; required except with --list")
    parser.add_argument("--config", type=Path, default=ROOT / "network.json")
    parser.add_argument("--case", action="append", choices=case_names() + list(EXPERIMENTAL_CASES),
                        help="Repeat to select cases; defaults to the verified 41-case matrix. Experimental cases require explicit selection")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--check-only", action="store_true", help="Emit CONFIG_PASS only; never count configuration checks as runtime verification")
    parser.add_argument("--artifacts", type=Path, help="New root-private directory retaining fake fixture configs/logs; otherwise temporary files are removed")
    args = parser.parse_args()
    if args.list:
        print(json.dumps({"cases": case_names(), "experimental_cases": EXPERIMENTAL_CASES,
                          "blocked": BLOCKED, "scope": "loopback-only"}, sort_keys=True))
        return 0
    if not args.engine or not shutil.which(args.engine) or not shutil.which("openssl") or not shutil.which("jq"):
        parser.error("A pinned --engine, openssl and jq are required")
    binary = shutil.which(args.engine)
    os.umask(0o077)
    dns_fixture.TIMEOUT = TIMEOUT
    version = subprocess.run([binary, "version"], text=True, capture_output=True, timeout=10)
    try:
        validate_version(version.stdout)
    except CaseFailure as error:
        print(json.dumps({"status": "FAIL", "stage": error.code}, sort_keys=True))
        return 1
    original = json.loads(args.config.read_text())
    with ExitStack() as stack:
        if args.artifacts:
            args.artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
            directory = args.artifacts
        else:
            directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="worker-protocol-matrix-")))
        failures = 0
        for name in args.case or case_names():
            try:
                result = run_case(binary, name, original, directory / name, args.check_only)
            except CaseFailure as error:
                failures += 1
                result = {"case": name, "status": "FAIL", "stage": error.code, "runtime_completed": False}
            except Exception as error:
                failures += 1
                result = {"case": name, "status": "FAIL", "stage": "fixture-" + type(error).__name__, "runtime_completed": False}
            result["experimental"] = name in EXPERIMENTAL_CASES
            print(json.dumps(result, sort_keys=True), flush=True)
        print(json.dumps({"summary": "FAIL" if failures else "CONFIG_PASS" if args.check_only else "PASS",
                          "cases": len(args.case or case_names()), "failures": failures, "blocked": BLOCKED,
                          "experimental_cases": [name for name in args.case or case_names() if name in EXPERIMENTAL_CASES],
                          "host_firewall_tested": False}, sort_keys=True), flush=True)
        return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
