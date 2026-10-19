"""Offline contracts for the real-worker protocol matrix fixture."""
import json
from pathlib import Path
import socket
import time
import unittest

import protocol_runtime as runtime


class ProtocolRuntimeFixtureTests(unittest.TestCase):
    def setUp(self):
        self.original = json.loads((Path(__file__).resolve().parents[1] / "network.json").read_text())
        self.original["outbounds"][0]["password"] = "PRIVATE-SOURCE-MUST-NOT-BE-COPIED"
        self.ports = {"proxy": 31001, "proxy2": 31002, "tcp": 31003, "udp": 31004,
                      "dns": 31005, "ingress_tcp": 31006, "ingress_udp": 31007,
                      "ingress_dns": 31008}
        self.ports.update({"hop" + str(index): 31100 + index for index in range(8)})

    def test_matrix_includes_protocol_transports_and_graphs(self):
        names = runtime.case_names()
        for kind in ("hysteria", "hysteria2", "tuic", "shadowsocks", "anytls", "http", "https",
                     "socks5-tcp", "socks5-uot", "naive", "naive-quic", "snell6",
                     "selector-trojan", "selector-hysteria2", "urltest", "detour"):
            self.assertIn(kind, names)
        for kind in ("trojan", "vmess", "vless"):
            for transport in ("http", "ws", "grpc", "httpupgrade", "quic"):
                self.assertIn(kind + "-" + transport, names)
        self.assertEqual(len(names), len(set(names)))

    def test_generated_fixture_restricts_egress_and_keeps_source_private(self):
        for name in runtime.case_names():
            with self.subTest(case=name):
                source, client, server, policy = runtime.build_configs(
                    name, self.original, self.ports, "TEST CERTIFICATE", "/fake/cert", "/fake/key")
                self.assertNotIn("PRIVATE-SOURCE-MUST-NOT-BE-COPIED", json.dumps([source, client, server]))
                self.assertEqual(server["route"]["rules"][-1], {"action": "reject"})
                self.assertEqual(server["outbounds"][0]["inet4_bind_address"], runtime.PROXY_EXIT)
                self.assertTrue(all(item["listen"] == "127.0.0.1" for item in client["inbounds"]))
                self.assertTrue(all(item["listen"] == "127.0.0.1" for item in server["inbounds"]))
                self.assertTrue(all(item["address"] in {"127.0.0.1", "127.0.0.2"}
                                    for item in policy["outer_endpoints"]))
                self.assertEqual(client["dns"]["servers"][0]["detour"], "proxy")
                self.assertEqual(client["dns"]["servers"][0]["server"], runtime.BOUNDARY)
                self.assertFalse(any("bind_interface" in outbound for outbound in client["outbounds"]))

    def test_tcp_only_cases_compile_https_dns(self):
        for name in ("http", "https", "socks4-tcp", "socks4a-tcp", "socks5-tcp", "naive", "naive-quic"):
            _, client, _, policy = runtime.build_configs(
                name, self.original, self.ports, "TEST CERTIFICATE", "/fake/cert", "/fake/key")
            self.assertEqual(policy["payload_networks"], ["tcp"])
            self.assertEqual(client["dns"]["servers"][0]["type"], "https")
            self.assertNotIn("insecure", client["dns"]["servers"][0]["tls"])

    def test_detour_has_only_carrier_as_physical_endpoint(self):
        _, client, _, policy = runtime.build_configs(
            "detour", self.original, self.ports, "TEST CERTIFICATE", "/fake/cert", "/fake/key")
        self.assertEqual(client["outbounds"][0]["detour"], "carrier")
        self.assertEqual([entry["port_start"] for entry in policy["outer_endpoints"]], [31002])

    def test_stop_guard_rejects_success_instead_of_treating_it_as_unavailable(self):
        with self.assertRaises(runtime.CaseFailure):
            runtime.require_unavailable(lambda: b"unexpected direct success", "negative-control")
        runtime.require_unavailable(lambda: (_ for _ in ()).throw(TimeoutError()), "expected-timeout")

    def test_canary_records_connections_without_a_complete_request(self):
        with runtime.serving(runtime.TCPSink((runtime.LOOPBACK, 0))) as sink:
            self.assertTrue(runtime.canaries_quiet([sink]))
            with socket.create_connection(sink.server_address, timeout=1) as connection:
                connection.sendall(b"partial request without newline")
                deadline = time.monotonic() + 1
                while not sink.connections and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertFalse(runtime.canaries_quiet([sink]))

    def test_version_check_is_exact(self):
        runtime.validate_version("sing-box version 1.14.2\nRevision: " + runtime.REVISION)
        for value in ("sing-box version 1.14.3", "sing-box version 1.14.20", "worker version unknown"):
            with self.assertRaises(runtime.CaseFailure):
                runtime.validate_version(value)

    def test_graph_evidence_requires_forwarding_not_listener_startup(self):
        startup = "INFO inbound/trojan[a-in]: tcp server started at 127.0.0.1:31001\n"
        a_forward = "INFO inbound/trojan[a-in]: [matrix-user] inbound connection to 127.0.0.2:31003\n"
        b_forward = "INFO inbound/hysteria2[b-in]: [matrix-user] inbound connection to 127.0.0.2:31003\n"
        with self.assertRaises(runtime.CaseFailure):
            runtime.graph_evidence("selector-trojan", startup, self.ports)
        self.assertEqual(runtime.graph_evidence("selector-trojan", startup + a_forward, self.ports), ["a"])
        with self.assertRaises(runtime.CaseFailure):
            runtime.graph_evidence("urltest", startup + a_forward, self.ports)
        self.assertEqual(runtime.graph_evidence("urltest", a_forward + b_forward, self.ports), ["a", "b"])

    def test_hopping_policy_contains_relay_ports_but_not_backend(self):
        _, client, server, policy = runtime.build_configs(
            "hysteria2-port-hopping", self.original, self.ports, "TEST CERTIFICATE", "/fake/cert", "/fake/key")
        self.assertEqual(client["outbounds"][0]["hop_interval"], "5s")
        actual = {port for entry in policy["outer_endpoints"]
                  for port in range(entry["port_start"], entry["port_end"] + 1)}
        self.assertEqual(actual, {31100 + index for index in range(8)})
        self.assertNotIn(server["inbounds"][0]["listen_port"], actual)

    def test_multiport_relay_records_real_destination_changes(self):
        with runtime.serving(runtime.UDPSink((runtime.LOOPBACK, 0))) as sink:
            with runtime.MultiportRelay([0, 0], sink.server_address[1]) as relay:
                for index, port in enumerate(relay.ports):
                    reply = runtime.udp_exchange(port, "relay-" + str(index))
                    self.assertEqual(reply, {"peer": runtime.LOOPBACK, "token": "relay-" + str(index)})
                self.assertEqual(relay.observed_ports, sorted(relay.ports))


if __name__ == "__main__":
    unittest.main()
