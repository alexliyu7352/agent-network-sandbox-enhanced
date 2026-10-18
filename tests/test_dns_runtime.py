#!/usr/bin/env python3
"""離線 DNS 契約：實際 sing-box Hysteria2、UDP 上游及跨 TCP/UDP 的快取。
只將 TUN 換成本機 direct inbound，節點替換為本機 Hysteria2 測試伺服器。
上游綁定 127.0.0.1，客戶端要求 127.0.0.2，只有經 Hysteria2 的路由改寫可到達。
--check-only 只檢查配置；執行失敗絕不計作快取／傳輸驗證通過。
"""

import argparse
import copy
import json
from pathlib import Path
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time


TTL = 3
TIMEOUT = 5
TEST_PASSWORD = "offline-hysteria2-dns-contract"
DNS_BOUNDARY_ADDRESS = "127.0.0.2"
HY2_SERVER_NAME = "hy2.test"
QNAME = b"\x0ecache-contract\x04test\x00"
QUESTION = QNAME + b"\x00\x01\x00\x01"  # A, IN


def receive_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise EOFError("connection closed before the complete message")
        data.extend(chunk)
    return bytes(data)


def name_end(message, offset):
    while True:
        length = message[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        if length > 63:
            raise AssertionError("invalid DNS label")
        offset += length


def a_answers(message, transaction_id):
    received_id, flags, questions, answers, _, _ = struct.unpack("!6H", message[:12])
    assert received_id == transaction_id, "cached answer lost the query's DNS ID"
    assert flags & 0x800F == 0x8000, f"DNS error: flags={flags:#06x}"
    assert questions == 1 and answers == 1, "expected one successful A answer"
    offset = name_end(message, 12) + 4
    offset = name_end(message, offset)
    record_type, record_class, _, size = struct.unpack("!HHIH", message[offset:offset + 10])
    assert (record_type, record_class, size) == (1, 1, 4), "expected an IPv4 A record"
    return socket.inet_ntoa(message[offset + 10:offset + 14])


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), UDPHandler)
        self.query_count = 0
        self.errors = []
        self.lock = threading.Lock()


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            query, sock = self.request
            end = name_end(query, 12) + 4
            assert query[12:end] == QUESTION, "unexpected query reached UDP upstream"
            with self.server.lock:
                self.server.query_count += 1
                answer_number = self.server.query_count
            answer = (query[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0)
                      + QUESTION + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, TTL, 4)
                      + bytes((203, 0, 113, answer_number)))
            sock.sendto(answer, self.client_address)
        except Exception as error:
            with self.server.lock:
                self.server.errors.append(repr(error))


def fixture_without_cache():
    config = json.loads((Path(__file__).resolve().parents[1] / 'network.json').read_text())
    config['dns']['disable_cache'] = True
    return config


def local_test_config(original, dns_port, hy2_port, upstream_port, certificate):
    config = copy.deepcopy(original)
    tun_tag = next(item["tag"] for item in config["inbounds"] if item["type"] == "tun")
    config["inbounds"] = [{
        "type": "direct", "tag": tun_tag, "listen": "127.0.0.1",
        "listen_port": dns_port, "override_address": "1.1.1.1", "override_port": 53,
    }]
    assert len(config["outbounds"]) == 1, "expected one native Hysteria2 outbound"
    hy2 = config["outbounds"][0]
    assert (hy2["type"], hy2["tag"]) == ("hysteria2", "proxy"), "native proxy contract changed"
    hy2["server"] = "127.0.0.1"
    hy2["server_port"] = hy2_port
    hy2["password"] = TEST_PASSWORD
    hy2.pop("bind_interface", None)  # Kernel interface routing is outside this loopback test.
    hy2["tls"] = {
        "enabled": True, "server_name": HY2_SERVER_NAME, "certificate_path": str(certificate),
        "alpn": ["h3"],
    }
    assert len(config["dns"]["servers"]) == 1, "expected one UDP upstream"
    server = config["dns"]["servers"][0]
    assert (server["type"], server["server"], server["server_port"], server["detour"]) == (
        "udp", "1.1.1.1", 53, "proxy"), "production UDP DNS contract changed"
    server["server"] = DNS_BOUNDARY_ADDRESS
    server["server_port"] = upstream_port
    config["log"] = {"level": "debug", "timestamp": False}
    return config


def local_hy2_server_config(hy2_port, upstream_port, certificate, key):
    """唯有 Hysteria2 收到指定 UDP DNS 目的地時，才改寫到本機 UDP listener。"""
    return {
        "log": {"level": "debug", "timestamp": False},
        "inbounds": [{
            "type": "hysteria2", "tag": "hy2-test-in", "listen": "127.0.0.1",
            "listen_port": hy2_port,
            "users": [{"name": "offline-test", "password": TEST_PASSWORD}],
            "tls": {
                "enabled": True, "certificate_path": str(certificate),
                "key_path": str(key), "alpn": ["h3"],
            },
        }],
        "outbounds": [{"type": "direct", "tag": "local-dns"}],
        "route": {"rules": [
            {
                "inbound": ["hy2-test-in"], "network": "udp",
                "ip_cidr": [DNS_BOUNDARY_ADDRESS + "/32"], "port": [upstream_port],
                "action": "route", "outbound": "local-dns",
                "override_address": "127.0.0.1", "override_port": upstream_port,
            },
            {"action": "reject"},
        ]},
    }


def free_dns_port():
    with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        tcp.bind(("127.0.0.1", 0))
        port = tcp.getsockname()[1]
        udp.bind(("127.0.0.1", port))
        return port


def query(port, transport, transaction_id):
    message = struct.pack("!6H", transaction_id, 0x0100, 1, 0, 0, 0) + QUESTION
    if transport == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect(("127.0.0.1", port))
            sock.send(message)
            response = sock.recv(4096)
    else:
        with socket.create_connection(("127.0.0.1", port), TIMEOUT) as sock:
            sock.sendall(struct.pack("!H", len(message)) + message)
            length = struct.unpack("!H", receive_exact(sock, 2))[0]
            response = receive_exact(sock, length)
    return a_answers(response, transaction_id)


def wait_started(process, log_path, name):
    deadline = time.monotonic() + TIMEOUT
    while True:
        if process.poll() is not None:
            raise RuntimeError(f"{name} could not start; DNS cache behavior was not tested")
        if "sing-box started" in log_path.read_text():
            return
        assert time.monotonic() < deadline, f"{name} did not start within {TIMEOUT} seconds"
        time.sleep(0.02)


def stop_process(process):
    process.terminate()
    try:
        process.wait(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=TIMEOUT)


def run_contract(binary, original, check_only=False):
    with tempfile.TemporaryDirectory(prefix="worker-dns-test-") as directory:
        temporary = Path(directory)
        cert = temporary / "test-ca.pem"
        key = temporary / "test-key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=cloudflare-dns.com", "-addext",
            f"subjectAltName=DNS:cloudflare-dns.com,DNS:{HY2_SERVER_NAME}",
            "-keyout", str(key), "-out", str(cert),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=TIMEOUT)
        with UDPServer() as server:
            dns_port = free_dns_port()
            hy2_port = free_dns_port()
            while hy2_port == dns_port:
                hy2_port = free_dns_port()
            upstream_port = server.server_address[1]
            client_config_path = temporary / "client.json"
            hy2_config_path = temporary / "hy2-server.json"
            client_config_path.write_text(json.dumps(local_test_config(
                original, dns_port, hy2_port, upstream_port, cert
            )))
            hy2_config_path.write_text(json.dumps(local_hy2_server_config(hy2_port, upstream_port, cert, key)))
            for config_path in (hy2_config_path, client_config_path):
                subprocess.run([binary, "check", "-c", str(config_path)], check=True, timeout=TIMEOUT)
            if check_only:
                print("PASS: local Hysteria2 server/client configurations pass sing-box check; runtime behavior was not tested.")
                return
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            thread.start()
            client_log_path = temporary / "client.log"
            hy2_log_path = temporary / "hy2-server.log"
            with client_log_path.open("w") as client_log, hy2_log_path.open("w") as hy2_log:
                processes = []
                try:
                    hy2_process = subprocess.Popen(
                        [binary, "run", "-c", str(hy2_config_path)], stdout=hy2_log, stderr=hy2_log
                    )
                    processes.append(hy2_process)
                    wait_started(hy2_process, hy2_log_path, "local Hysteria2 server")
                    client_process = subprocess.Popen(
                        [binary, "run", "-c", str(client_config_path)], stdout=client_log, stderr=client_log
                    )
                    processes.append(client_process)
                    wait_started(client_process, client_log_path, "DNS client")
                    first = query(dns_port, "udp", 0x1234)
                    assert first == "203.0.113.1", f"wrong first DNS answer: {first}"
                    assert server.query_count == 1, f"first query made {server.query_count} upstream requests"
                    cached = query(dns_port, "tcp", 0x5678)
                    assert server.query_count == 1, (
                        "DNS cache contract failed: the second query must reuse the first answer; "
                        f"observed {server.query_count} upstream requests"
                    )
                    assert cached == "203.0.113.1", f"cached answer changed before TTL expiry: {cached}"
                    time.sleep(TTL + 0.3)
                    expired = query(dns_port, "udp", 0x9ABC)
                    assert expired == "203.0.113.2", f"DNS answer did not refresh after TTL: {expired}"
                    assert server.query_count == 2, f"expected two total upstream requests, got {server.query_count}"
                    hy2_log_text = hy2_log_path.read_text()
                    assert "inbound/hysteria2[hy2-test-in]" in hy2_log_text, "Hysteria2 inbound was not observed"
                    assert f"{DNS_BOUNDARY_ADDRESS}:{upstream_port}" in hy2_log_text, "Hysteria2 did not receive the UDP DNS datagram"
                    assert not server.errors, f"local upstream errors: {server.errors}"
                    print("PASS: UDP/TCP DNS share the cache; TTL expiry refetches; UDP DNS travels through a real local Hysteria2 connection.")
                except Exception:
                    print("Local Hysteria2 server log:\n" + hy2_log_path.read_text(), file=sys.stderr)
                    print("DNS client log:\n" + client_log_path.read_text(), file=sys.stderr)
                    if server.errors:
                        print(f"Local upstream errors: {server.errors}", file=sys.stderr)
                    raise
                finally:
                    for process in reversed(processes):
                        stop_process(process)
                    server.shutdown()
                    thread.join(timeout=TIMEOUT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", "--sing-box", dest="engine", required=True,
                        help="Path to worker (the pinned sing-box executable)")
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parents[1] / "network.json")
    parser.add_argument("--negative-control", action="store_true", help="Run the no-cache fixture; an assertion failure is expected")
    parser.add_argument("--check-only", action="store_true", help="Validate both local configurations without starting runtime services")
    args = parser.parse_args()
    binary = shutil.which(args.engine)
    if not binary:
        parser.error(f"network engine executable not found: {args.engine}")
    if not shutil.which("openssl"):
        parser.error("openssl is required to create a temporary local test certificate")
    original = fixture_without_cache() if args.negative_control else json.loads(args.config.read_text())
    if args.negative_control:
        action = "configuration validation only" if args.check_only else "the cache assertion must fail"
        print(f"NEGATIVE CONTROL: caching is deliberately disabled; {action}.", flush=True)
    run_contract(binary, original, check_only=args.check_only)


if __name__ == "__main__":
    main()
