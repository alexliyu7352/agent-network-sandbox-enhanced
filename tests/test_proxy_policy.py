"""Behavior contracts for the shared, offline jq proxy policy compiler."""
import copy
import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROGRAM = ROOT / "gateway-policy.jq"
PUBLIC = json.loads((ROOT / "network.json").read_text())
UUID = "00000000-0000-4000-8000-000000000001"


def node(kind, tag="proxy", address="192.0.2.1", port=443, **options):
    value = {"type": kind, "tag": tag, "server": address, "server_port": port}
    if kind in {"hysteria", "hysteria2", "tuic", "trojan", "anytls", "shadowtls", "naive"}:
        value["tls"] = {"enabled": True, "server_name": "proxy.example"}
    if kind in {"hysteria2", "tuic", "trojan", "anytls", "shadowtls", "naive", "ssh", "shadowsocks"}:
        value["password"] = "TEST-CREDENTIAL-DO-NOT-PRINT"
    if kind in {"tuic", "vmess", "vless"}:
        value["uuid"] = UUID
    if kind == "hysteria":
        value.update(up_mbps=100, down_mbps=100, auth_str="TEST-AUTH")
    elif kind == "shadowsocks":
        value["method"] = "chacha20-ietf-poly1305"
    elif kind == "vmess":
        value["security"] = "auto"
    elif kind == "snell":
        value.update(version=4, psk="TEST-PRE-SHARED-KEY")
    elif kind == "shadowtls":
        value["version"] = 3
    elif kind == "ssh":
        value["user"] = "example"
    elif kind == "naive":
        value["username"] = "example"
    value.update(options)
    return value


def config(*outbounds):
    value = copy.deepcopy(PUBLIC)
    value["outbounds"] = list(outbounds)
    return value


def endpoint(address="192.0.2.1", protocol="tcp", start=443, end=None):
    return {"family": 4, "address": address, "protocol": protocol,
            "port_start": start, "port_end": start if end is None else end}


class ProxyPolicyTests(unittest.TestCase):
    def run_jq(self, value, mode="policy"):
        self.assertTrue(PROGRAM.is_file(), "shared proxy compiler is not implemented")
        return subprocess.run(["jq", "-ceS", "--arg", "mode", mode, "-f", str(PROGRAM)],
                              input=json.dumps(value), text=True, capture_output=True, timeout=10)

    def parse(self, value, mode="policy"):
        result = self.run_jq(value, mode)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def rejected(self, value, reason=None):
        for mode in ("policy", "effective"):
            with self.subTest(mode=mode):
                result = self.run_jq(value, mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "", "invalid policies must emit no partial result")
                self.assertTrue(result.stderr.startswith("gateway-policy: "), result.stderr)
                self.assertEqual(len(result.stderr.splitlines()), 1)
                self.assertNotIn("TEST-CREDENTIAL-DO-NOT-PRINT", result.stderr)
                if reason:
                    self.assertIn(reason, result.stderr)

    def test_hysteria_tcp_payload_still_needs_outer_udp(self):
        result = self.parse(config(node("hysteria2", network="tcp")))
        self.assertEqual(result, {"format": 1, "proxy_tag": "proxy",
                         "outer_endpoints": [endpoint(protocol="udp")],
                         "payload_networks": ["tcp"], "dns_transport": "https"})

    def test_final_proxy_must_guarantee_tcp_for_session_readiness(self):
        self.rejected(config(node("hysteria2", network="udp")), "guarantee TCP")
        self.rejected(config({"type": "selector", "tag": "proxy", "outbounds": ["udp-only"]},
                             node("hysteria2", "udp-only", network="udp")), "guarantee TCP")

    def test_udp_only_carrier_can_transport_a_tcp_capable_quic_proxy(self):
        value = config(node("hysteria2", detour="carrier"),
                       node("shadowsocks", "carrier", "192.0.2.2", 8388, network="udp"))
        result = self.parse(value)
        self.assertEqual(result["payload_networks"], ["tcp", "udp"])
        self.assertEqual(result["outer_endpoints"], [endpoint("192.0.2.2", "udp", 8388)])

    def test_urltest_requires_tcp_health_probes_on_every_candidate(self):
        value = config(node("hysteria2", detour="carrier-test"),
                       {"type": "urltest", "tag": "carrier-test", "outbounds": ["carrier"]},
                       node("shadowsocks", "carrier", "192.0.2.2", 8388, network="udp"))
        self.rejected(value, "urltest TCP health probes")

    def test_urltest_requires_forwarding_candidates_not_raw_shadowtls_wrappers(self):
        for nested in (False, True):
            with self.subTest(nested=nested):
                value = config(node("shadowsocks", detour="cover-test", udp_over_tcp=True),
                               {"type": "urltest", "tag": "cover-test", "outbounds": ["group" if nested else "cover"]},
                               node("shadowtls", "cover", "192.0.2.2"))
                if nested:
                    value["outbounds"].append({"type": "selector", "tag": "group", "outbounds": ["cover"]})
                self.rejected(value, "ShadowTLS")
        valid = config({"type": "urltest", "tag": "proxy", "outbounds": ["leaf"]},
                       node("shadowsocks", "leaf", detour="cover", udp_over_tcp=True),
                       node("shadowtls", "cover", "192.0.2.2"))
        self.assertEqual(self.parse(valid)["outer_endpoints"], [endpoint("192.0.2.2")])

    def test_shared_selector_graph_is_evaluated_without_expanding_every_path(self):
        nodes = [{"type": "selector", "tag": "proxy", "outbounds": ["a0", "b0"]}]
        depth = 24
        for level in range(depth):
            children = ["a" + str(level + 1), "b" + str(level + 1)] if level + 1 < depth else ["leaf"]
            nodes.extend({"type": "selector", "tag": prefix + str(level), "outbounds": children}
                         for prefix in ("a", "b"))
        nodes.append(node("http", "leaf"))
        result = subprocess.run(["jq", "-ceS", "--arg", "mode", "policy", "-f", str(PROGRAM)],
                                input=json.dumps(config(*nodes)), text=True, capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["outer_endpoints"], [endpoint()])

    def test_shipped_hysteria_config_is_accepted(self):
        result = self.parse(PUBLIC)
        self.assertEqual(result["outer_endpoints"], [endpoint(protocol="udp")])
        self.assertEqual(result["payload_networks"], ["tcp", "udp"])
        self.assertEqual(result["dns_transport"], "udp")

    def test_fixed_protocol_payload_and_outer_matrix(self):
        cases = [
            (node("hysteria"), ["udp"], ["tcp", "udp"]),
            (node("hysteria2"), ["udp"], ["tcp", "udp"]),
            (node("tuic", udp_over_stream=True), ["udp"], ["tcp", "udp"]),
            (node("shadowsocks"), ["tcp", "udp"], ["tcp", "udp"]),
            (node("shadowsocks", network="tcp"), ["tcp"], ["tcp"]),
            (node("trojan"), ["tcp"], ["tcp", "udp"]),
            (node("vmess"), ["tcp"], ["tcp", "udp"]),
            (node("vless"), ["tcp"], ["tcp", "udp"]),
            (node("anytls"), ["tcp"], ["tcp", "udp"]),
            (node("snell", version=4), ["tcp"], ["tcp", "udp"]),
            (node("snell", version=6), ["tcp"], ["tcp", "udp"]),
            (node("http"), ["tcp"], ["tcp"]),
            (node("http", tls={"enabled": True}), ["tcp"], ["tcp"]),
            (node("ssh"), ["tcp"], ["tcp"]),
            (node("naive"), ["tcp"], ["tcp"]),
            (node("naive", udp_over_tcp=True), ["tcp"], ["tcp", "udp"]),
            (node("naive", quic=True), ["udp"], ["tcp"]),
            (node("socks", version="4", network="tcp"), ["tcp"], ["tcp"]),
            (node("socks", version="4a", network="tcp"), ["tcp"], ["tcp"]),
            (node("socks", version="5", network="tcp"), ["tcp"], ["tcp"]),
            (node("socks", version="5", udp_over_tcp=True), ["tcp"], ["tcp", "udp"]),
        ]
        for outbound, outer, payload in cases:
            with self.subTest(type=outbound["type"], options=tuple(outbound)):
                result = self.parse(config(outbound))
                self.assertEqual(result["outer_endpoints"], [endpoint(protocol=p) for p in outer])
                self.assertEqual(result["payload_networks"], payload)

    def test_v2ray_encapsulation_chooses_actual_transport(self):
        for kind in ("trojan", "vmess", "vless"):
            for transport in (None, "http", "ws", "grpc", "quic"):
                with self.subTest(kind=kind, transport=transport):
                    outbound = node(kind, tls={"enabled": True, "server_name": "proxy.example",
                                              "certificate": ["PUBLIC-FAKE-CERTIFICATE"], "insecure": False})
                    if transport is not None:
                        outbound["transport"] = {"type": transport}
                    value = config(outbound)
                    result = self.parse(value)
                    self.assertEqual(result["outer_endpoints"],
                                     [endpoint(protocol="udp" if transport == "quic" else "tcp")])
                    self.assertEqual(result["payload_networks"], ["tcp", "udp"])
                    effective = self.parse(value, "effective")["outbounds"][0]
                    self.assertEqual(effective.pop("bind_interface"), "eth0")
                    self.assertEqual(effective, outbound, "accepted alternatives must preserve TLS and auth")

    def test_httpupgrade_rejected_for_every_base_protocol_and_graph_position(self):
        reason = ("HTTPUpgrade is not accepted for pinned core 1.14.2 after paired reliability failures; "
                  "use native TCP (omit transport), ws, http, grpc, or quic")
        for kind in ("trojan", "vmess", "vless"):
            wrapped = node(kind, transport={"type": "httpupgrade", "path": "/private-path",
                                           "headers": {"X-Fixture-Auth": "TEST-CREDENTIAL-DO-NOT-PRINT"}})
            for position in ("direct", "selector", "urltest", "inner-detour", "carrier-detour"):
                with self.subTest(kind=kind, position=position):
                    leaf = copy.deepcopy(wrapped)
                    if position == "direct":
                        value = config(leaf)
                    elif position in {"selector", "urltest"}:
                        leaf["tag"] = "wrapped"
                        group = {"type": position, "tag": "proxy", "outbounds": ["good", "wrapped"]}
                        if position == "selector":
                            group["default"] = "good"
                        value = config(group, node("http", "good", "192.0.2.2"), leaf)
                    elif position == "inner-detour":
                        leaf["detour"] = "carrier"
                        value = config(leaf, node("hysteria2", "carrier", "192.0.2.2"))
                    else:
                        leaf["tag"] = "carrier"
                        value = config(node("http", detour="carrier"), leaf)
                    self.rejected(value, reason)

    def test_uot_and_multiplex_remove_native_shadowsocks_udp(self):
        for extra in ({"udp_over_tcp": True}, {"udp_over_tcp": {"enabled": True, "version": 1}},
                      {"multiplex": {"enabled": True, "protocol": "smux"}},
                      {"multiplex": {"enabled": True}, "udp_over_tcp": True}):
            with self.subTest(extra=extra):
                result = self.parse(config(node("shadowsocks", **extra)))
                self.assertEqual(result["outer_endpoints"], [endpoint()])
                self.assertEqual(result["payload_networks"], ["tcp", "udp"])

    def test_disabled_uot_and_mux_keep_native_udp(self):
        result = self.parse(config(node("shadowsocks", udp_over_tcp={"enabled": False},
                                             multiplex={"enabled": False})))
        self.assertEqual(result["outer_endpoints"], [endpoint(), endpoint(protocol="udp")])

    def test_port_hopping_overrides_single_port_and_merges_exact_union(self):
        for kind in ("hysteria", "hysteria2"):
            result = self.parse(config(node(kind, port=9999,
                 server_ports=["8445:8448", "443:443", "8443:8446", "443:443", "8449:8450"])))
            self.assertEqual(result["outer_endpoints"],
                             [endpoint(protocol="udp"), endpoint(protocol="udp", start=8443, end=8450)])

    def test_port_hopping_can_omit_server_port(self):
        outbound = node("hysteria2", server_ports="8443:8445")
        del outbound["server_port"]
        self.assertEqual(self.parse(config(outbound))["outer_endpoints"],
                         [endpoint(protocol="udp", start=8443, end=8445)])

    def test_selector_union_and_payload_intersection_drive_dns(self):
        selection = {"type": "selector", "tag": "proxy", "outbounds": ["h2", "web"], "default": "web"}
        value = config(selection, node("hysteria2", "h2", "192.0.2.10", server_ports=["8443:8445", "443:443"]),
                       node("http", "web", "192.0.2.20", 3128))
        result = self.parse(value)
        self.assertEqual(result["outer_endpoints"], [endpoint("192.0.2.10", "udp"),
                         endpoint("192.0.2.10", "udp", 8443, 8445), endpoint("192.0.2.20", "tcp", 3128)])
        self.assertEqual(result["payload_networks"], ["tcp"])
        self.assertEqual(result["dns_transport"], "https")

    def test_urltest_checks_all_candidates_without_direct_probe_allowance(self):
        value = config({"type": "urltest", "tag": "proxy", "outbounds": ["a", "b"],
                        "url": "https://www.example.com/", "interval": "3m"},
                       node("trojan", "a"), node("hysteria2", "b", "192.0.2.2"))
        self.assertEqual(self.parse(value)["outer_endpoints"],
                         [endpoint(), endpoint("192.0.2.2", "udp")])

    def test_detour_allows_only_real_outer_hop(self):
        value = config(node("trojan", detour="carrier"),
                       node("hysteria2", "carrier", "192.0.2.2", 8443))
        result = self.parse(value)
        self.assertEqual(result["outer_endpoints"], [endpoint("192.0.2.2", "udp", 8443)])
        self.assertEqual(result["payload_networks"], ["tcp", "udp"])
        effective = self.parse(value, "effective")
        self.assertNotIn("bind_interface", effective["outbounds"][0])
        self.assertEqual(effective["outbounds"][1]["bind_interface"], "eth0")

    def test_detour_channel_demand_avoids_unused_native_udp_permission(self):
        value = config(node("trojan", detour="carrier"),
                       node("shadowsocks", "carrier", "192.0.2.2", 8388))
        self.assertEqual(self.parse(value)["outer_endpoints"], [endpoint("192.0.2.2", "tcp", 8388)])

    def test_quic_over_uot_detour_has_outer_tcp(self):
        value = config(node("hysteria2", detour="carrier"),
                       node("socks", "carrier", "192.0.2.2", 1080, udp_over_tcp=True))
        self.assertEqual(self.parse(value)["outer_endpoints"], [endpoint("192.0.2.2", "tcp", 1080)])

    def test_urltest_detour_also_needs_tcp_for_its_health_probes(self):
        value = config(node("hysteria2", detour="test"),
                       {"type": "urltest", "tag": "test", "outbounds": ["carrier"]},
                       node("shadowsocks", "carrier", "192.0.2.2", 8388))
        self.assertEqual(self.parse(value)["outer_endpoints"],
                         [endpoint("192.0.2.2", "tcp", 8388), endpoint("192.0.2.2", "udp", 8388)])

    def test_naive_reserved_headers_cannot_override_transport(self):
        self.rejected(config(node("naive", quic=True,
                     extra_headers={"-force-quic": "false"})), "Naive")

    def test_naive_rejects_tls_options_unsupported_by_the_pinned_client(self):
        options = {"cipher_suites": ["TLS_AES_128_GCM_SHA256"], "curve_preferences": ["X25519"],
                   "client_certificate": ["TEST-CERT"], "client_key": ["TEST-KEY"],
                   "fragment": True, "record_fragment": True, "kernel_tx": True, "kernel_rx": True}
        for name, value in options.items():
            with self.subTest(option=name):
                self.rejected(config(node("naive", tls={"enabled": True, name: value})), "Naive")

    def test_quic_through_tcp_only_detour_is_rejected(self):
        self.rejected(config(node("hysteria2", detour="carrier"), node("http", "carrier")), "detour")

    def test_shadowtls_only_works_as_a_transport_wrapper(self):
        self.rejected(config(node("shadowtls")), "ShadowTLS")
        value = config(node("shadowsocks", detour="cover", udp_over_tcp=True),
                       node("shadowtls", "cover", "192.0.2.2"))
        self.assertEqual(self.parse(value)["outer_endpoints"], [endpoint("192.0.2.2")])

    def test_native_socks_udp_requires_explicit_tcp_or_uot(self):
        for options in ({}, {"network": ["tcp", "udp"]}, {"network": "udp"},
                        {"network": "tcp", "version": "6"}, {"version": "4", "udp_over_tcp": True}):
            self.rejected(config(node("socks", **options)), "SOCKS")

    def test_managed_https_dns_uses_proxy_and_verified_tls_name(self):
        result = self.parse(config(node("http")), "effective")
        self.assertEqual(result["dns"]["servers"], [{"type": "https", "tag": "upstream-dns",
              "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "detour": "proxy",
              "tls": {"enabled": True, "server_name": "cloudflare-dns.com"}}])
        self.assertFalse(result["dns"]["disable_cache"])
        self.assertEqual(result["route"], PUBLIC["route"])

    def test_effective_config_is_idempotent_and_preserves_credentials_tls_log(self):
        value = config(node("trojan", password="TEST-CREDENTIAL-DO-NOT-PRINT\n$()",
                     tls={"enabled": True, "insecure": True, "server_name": "name.example",
                          "certificate": ["TEST-CERT"], "utls": {"enabled": True, "fingerprint": "chrome"}},
                     transport={"type": "ws", "path": "/private", "headers": {"Authorization": "TEST-HEADER"}}))
        value["log"] = {"level": "warn", "timestamp": False}
        result = self.parse(value, "effective")
        self.assertEqual(result["outbounds"][0], {**value["outbounds"][0], "bind_interface": "eth0"})
        self.assertEqual(result["log"], value["log"])
        self.assertEqual(self.parse(result, "effective"), result)
        self.assertEqual(self.parse(result), self.parse(value))
        serialized = json.dumps(self.parse(value))
        for secret in ("TEST-CREDENTIAL", "TEST-HEADER", "TEST-CERT"):
            self.assertNotIn(secret, serialized)

    def test_reference_errors_and_unreachable_nodes_fail_closed(self):
        invalid = [
            config(node("trojan", detour="missing")),
            config(node("trojan"), node("hysteria2")),
            config(node("trojan", detour="proxy")),
            config(node("trojan", detour="a"), node("trojan", "a", detour="proxy")),
            config({"type": "selector", "tag": "proxy", "outbounds": ["missing"]}),
            config({"type": "selector", "tag": "proxy", "outbounds": ["a"], "default": "missing"}, node("trojan", "a")),
            config({"type": "selector", "tag": "proxy", "outbounds": []}),
            config(node("trojan"), node("trojan", "unused")),
        ]
        for value in invalid:
            self.rejected(value)

    def test_addresses_ports_tags_and_networks_are_strictly_typed(self):
        cases = [("server", v) for v in ("proxy.example", "::1", "192.0.2.01", "192.0.2.256", "192.0.2.1\n", 123)]
        cases += [("server_port", v) for v in (0, 65536, 1.5, "443", True, None)]
        cases += [("tag", v) for v in ("proxy\n", "$(id)", None, [], "")]
        cases += [("network", v) for v in ("tcp,udp", "icmp", ["tcp", "icmp"], 1, {}, "")]
        for key, value in cases:
            with self.subTest(field=key):
                self.rejected(config(node("hysteria2", **{key: value})))

    def test_hopping_rejects_unbounded_reversed_and_noncore_syntax(self):
        for ports in (["443"], [443], ["443-445"], [":443"], ["443:"], ["445:443"],
                      ["0:443"], ["443:65536"], ["443:445\n"], [True], {}, False):
            self.rejected(config(node("hysteria2", server_ports=ports)), "port")

    def test_unknown_or_dynamic_features_are_rejected_without_secret_echo(self):
        extras = [{"realm": {}}, {"routing_mark": 100}, {"netns": "outside"},
                  {"bind_interface": "other0"}, {"domain_resolver": "system"},
                  {"inet4_bind_address": "192.0.2.50"}, {"tcp_multi_path": True},
                  {"network_strategy": "fallback"}, {"fallback_network_type": ["wifi"]},
                  {"mystery": "TEST-CREDENTIAL-DO-NOT-PRINT"}]
        for extra in extras:
            self.rejected(config(node("hysteria2", **extra)))
        for transport in ({"type": "tcp"}, {"type": "kcp"}, {"type": "ws", "server": "outside.example"}):
            self.rejected(config(node("trojan", transport=transport)), "transport")
        for tls in ({"enabled": True, "ech": {"enabled": True}},
                    {"enabled": True, "spoof": "outside.example"},
                    {"enabled": True, "certificate_path": "/tmp/cert.pem"}):
            self.rejected(config(node("trojan", tls=tls)), "TLS")
        self.rejected(config(node("shadowsocks", plugin="v2ray-plugin", plugin_opts="mode=quic")), "plugin")

    def test_unmanaged_exit_channels_are_rejected(self):
        for kind in ("direct", "bridge", "block", "dns", "wireguard", "tor", "shadowsocksr", "tailcat", "unknown"):
            self.rejected(config(node(kind)))
        for key, extra in (("endpoints", [{"type": "wireguard"}]), ("services", [{"type": "api"}]),
                           ("experimental", {"clash_api": {"external_controller": "0.0.0.0:9090"}}),
                           ("ntp", {"enabled": True}), ("certificate", {"store": "mozilla"})):
            value = config(node("trojan")); value[key] = extra
            self.rejected(value)
        for field, change in (("route", {"final": "proxy", "rule_set": [{"type": "remote", "url": "https://example.com"}]}),
                              ("inbounds", [{"type": "socks", "listen": "0.0.0.0", "listen_port": 1080}]),
                              ("dns", {"servers": [{"type": "local"}]})):
            value = config(node("trojan")); value[field] = change
            self.rejected(value)

    def test_policy_output_is_deterministic_sorted_and_unique(self):
        value = config({"type": "selector", "tag": "proxy", "outbounds": ["b", "a", "c"]},
                       node("trojan", "a"), node("trojan", "b", "192.0.2.2"), node("trojan", "c"))
        self.assertEqual(self.parse(value)["outer_endpoints"], [endpoint(), endpoint("192.0.2.2")])
        first = self.run_jq(value).stdout
        value["outbounds"].reverse()
        self.assertEqual(self.run_jq(value).stdout, first)

    def test_multiple_json_documents_cannot_produce_partial_policy(self):
        for mode in ("policy", "effective"):
            result = subprocess.run(["jq", "-ceS", "--arg", "mode", mode, "-f", str(PROGRAM)],
                         input=json.dumps(PUBLIC) + "\n" + json.dumps(config(node("http"))),
                         capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertIn("one JSON", result.stderr)


if __name__ == "__main__":
    unittest.main()
