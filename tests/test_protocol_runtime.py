"""Offline contracts for the real-worker protocol matrix fixture."""
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
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
        self.ports["cover"] = 31200

    def test_matrix_includes_protocol_transports_and_graphs(self):
        names = runtime.case_names()
        for kind in ("hysteria", "hysteria2", "tuic", "shadowsocks", "http", "https",
                     "socks5-tcp", "socks5-uot", "naive", "naive-quic", "snell4", "snell6",
                     "hysteria-port-hopping", "hysteria2-port-hopping",
                     "ssh", "shadowtls1", "shadowtls2", "shadowtls3",
                     "selector-trojan", "selector-hysteria2", "urltest", "detour"):
            self.assertIn(kind, names)
        for kind in ("trojan", "vmess", "vless"):
            self.assertIn(kind, names)
            for transport in ("http", "ws", "grpc", "quic"):
                self.assertIn(kind + "-" + transport, names)
        self.assertEqual(len(names), len(set(names)))

    def test_generated_fixture_restricts_egress_and_keeps_source_private(self):
        for name in runtime.case_names():
            with self.subTest(case=name):
                source, client, server, policy = runtime.build_configs(
                    name, self.original, self.ports, "TEST CERTIFICATE", "/fake/cert", "/fake/key",
                    ssh_host_key="ssh-rsa TEST-EPHEMERAL-HOST-KEY")
                self.assertNotIn("PRIVATE-SOURCE-MUST-NOT-BE-COPIED", json.dumps([source, client, server]))
                if name == "ssh":
                    self.assertEqual(server["fixture"], "paramiko-3.5.1")
                    self.assertEqual(server["allowed_ports"], [self.ports["tcp"], self.ports["dns"]])
                else:
                    self.assertEqual(server["route"]["rules"][-1], {"action": "reject"})
                    self.assertEqual(server["outbounds"][0]["inet4_bind_address"], runtime.PROXY_EXIT)
                    self.assertTrue(all(item["listen"] == "127.0.0.1" for item in server["inbounds"]))
                self.assertTrue(all(item["listen"] == "127.0.0.1" for item in client["inbounds"]))
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

    def test_inventory_and_help_select_43_recipes_and_report_blocked_cases(self):
        self.assertEqual(len(runtime.case_names()), 43)
        result = subprocess.run([sys.executable, str(Path(runtime.__file__)), "--list"],
                                check=True, capture_output=True, text=True)
        inventory = json.loads(result.stdout)
        self.assertEqual(inventory["experimental_cases"], [])
        self.assertEqual(inventory["cases"], runtime.case_names())
        blocked = {kind + "-httpupgrade" for kind in ("trojan", "vmess", "vless")} | {"anytls"}
        self.assertEqual(set(inventory["blocked"]), blocked)
        self.assertFalse(blocked.intersection(inventory["cases"] + inventory["experimental_cases"]))
        for name, reason in inventory["blocked"].items():
            self.assertIn("pinned-core", reason)
            self.assertIn("native-fault-recovery" if name == "anytls" else "paired-reliability", reason)
        help_result = subprocess.run([sys.executable, str(Path(runtime.__file__)), "--help"],
                                     check=True, capture_output=True, text=True)
        self.assertIn("accepted 43-case loopback matrix", " ".join(help_result.stdout.split()))
        self.assertNotIn("Experimental cases", help_result.stdout)

    def test_httpupgrade_cannot_be_selected_or_built_as_an_opt_in_case(self):
        for kind in ("trojan", "vmess", "vless"):
            name = kind + "-httpupgrade"
            with self.subTest(case=name):
                with self.assertRaisesRegex(runtime.CaseFailure, "httpupgrade.*paired-reliability"):
                    runtime.build_configs(name, self.original, self.ports, "TEST CERTIFICATE", "/fake/cert", "/fake/key")
                result = subprocess.run([sys.executable, str(Path(runtime.__file__)), "--case", name],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertIn("invalid choice", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_anytls_cannot_be_selected_or_built_as_an_opt_in_case(self):
        with self.assertRaisesRegex(runtime.CaseFailure, "anytls.*native-fault-recovery"):
            runtime.build_configs("anytls", self.original, self.ports, "TEST CERTIFICATE", "/fake/cert", "/fake/key")
        result = subprocess.run([sys.executable, str(Path(runtime.__file__)), "--case", "anytls"],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_snell4_recipe_uses_the_real_server_version5_schema(self):
        _, client, server, policy = runtime.build_configs(
            "snell4", self.original, self.ports, "TEST CERTIFICATE", "/fake/cert", "/fake/key")
        outbound, inbound = client["outbounds"][0], server["inbounds"][0]
        self.assertEqual((outbound["type"], outbound["version"]), ("snell", 4))
        self.assertEqual((inbound["type"], inbound["version"]), ("snell", 5))
        self.assertEqual(outbound["psk"], inbound["psk"])
        self.assertEqual(outbound["obfs_mode"], "none")
        self.assertEqual(inbound["obfs_mode"], "none")
        self.assertEqual(policy["payload_networks"], ["tcp", "udp"])
        self.assertEqual({entry["protocol"] for entry in policy["outer_endpoints"]}, {"tcp"})

    def test_hysteria1_hopping_uses_its_own_auth_and_hop_fields(self):
        _, client, server, policy = runtime.build_configs(
            "hysteria-port-hopping", self.original, self.ports, "TEST CERTIFICATE", "/fake/cert", "/fake/key")
        outbound, inbound = client["outbounds"][0], server["inbounds"][0]
        self.assertEqual((outbound["type"], inbound["type"]), ("hysteria", "hysteria"))
        self.assertEqual(outbound["auth_str"], inbound["users"][0]["auth_str"])
        self.assertEqual(outbound["hop_interval"], "5s")
        self.assertNotIn("hop_interval_max", outbound)
        self.assertNotIn("server_port", outbound)
        actual = {port for entry in policy["outer_endpoints"]
                  for port in range(entry["port_start"], entry["port_end"] + 1)}
        self.assertEqual(actual, {31100 + index for index in range(8)})
        self.assertEqual({entry["protocol"] for entry in policy["outer_endpoints"]}, {"udp"})
        self.assertNotIn(inbound["listen_port"], actual)

    def test_shadowtls_uses_only_the_wrapper_endpoint_and_injects_inner_uot(self):
        for version in (1, 2, 3):
            _, client, server, policy = runtime.build_configs(
                "shadowtls" + str(version), self.original, self.ports,
                "TEST CERTIFICATE", "/fake/cert", "/fake/key")
            self.assertEqual(client["outbounds"][0]["detour"], "cover")
            self.assertTrue(client["outbounds"][0]["udp_over_tcp"])
            self.assertEqual(client["outbounds"][1]["version"], version)
            wrapper = next(item for item in server["inbounds"] if item["type"] == "shadowtls")
            self.assertEqual(wrapper["detour"], "proxy-in")
            self.assertEqual(wrapper["handshake"], {"server": runtime.LOOPBACK, "server_port": 31200})
            self.assertEqual({item["protocol"] for item in policy["outer_endpoints"]}, {"tcp"})
            self.assertEqual([item["port_start"] for item in policy["outer_endpoints"]], [31002])

    def test_cover_sends_no_post_handshake_records_into_shadowtls2_payload(self):
        # v2 stops using the TLS client after its handshake. Any cover session
        # ticket that arrives afterwards is mistaken for inner proxy payload.
        # Drive a real TLS1.3 handshake without TCP timing or a sing-box binary.
        with tempfile.TemporaryDirectory(prefix="protocol-cover-test-") as directory:
            certificate, key = runtime.create_certificate(Path(directory))
            with runtime.TLSCoverServer(0, certificate, key) as cover:
                client_context = ssl.create_default_context(cafile=str(certificate))
                client_context.minimum_version = ssl.TLSVersion.TLSv1_3
                client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
                server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
                client = client_context.wrap_bio(client_in, client_out,
                                                 server_hostname=runtime.SERVER_NAME)
                server = cover.context.wrap_bio(server_in, server_out, server_side=True)
                with self.assertRaises(ssl.SSLWantReadError):
                    client.do_handshake()
                server_in.write(client_out.read())
                with self.assertRaises(ssl.SSLWantReadError):
                    server.do_handshake()
                client_in.write(server_out.read())
                client.do_handshake()
                server_in.write(client_out.read())
                server.do_handshake()
                self.assertEqual(client.version(), "TLSv1.3")
                self.assertEqual(server_out.pending, 0,
                                 "cover records after handshake corrupt the ShadowTLS2 inner stream")

    def test_ssh_pins_ephemeral_host_key_and_uses_tcp_only_dns_policy(self):
        _, client, server, policy = runtime.build_configs(
            "ssh", self.original, self.ports, "TEST CERTIFICATE", "/fake/cert", "/fake/key",
            ssh_host_key="ssh-rsa TEST-EPHEMERAL-HOST-KEY")
        self.assertEqual(client["outbounds"][0]["host_key"], ["ssh-rsa TEST-EPHEMERAL-HOST-KEY"])
        self.assertEqual(client["outbounds"][0]["user"], runtime.USERNAME)
        self.assertEqual(client["outbounds"][0]["password"], runtime.PASSWORD)
        self.assertEqual(policy["payload_networks"], ["tcp"])
        self.assertEqual(policy["dns_transport"], "https")
        self.assertEqual(server["fixture"], "paramiko-3.5.1")
        self.assertEqual(server["allowed_ports"], [31003, 31005])


if __name__ == "__main__":
    unittest.main()
