#!/usr/bin/env python3
"""R7 regression checks through the real entrypoint and offline command shims.

The kernel boundary is simulated by test_entrypoint; these tests make no claim
about live netfilter or Docker startup timing. Every new node fixture uses a
documentation address and a fake password, and no proxy is started.
"""
import unittest

import test_entrypoint as gateway


def configuration():
    config = gateway.native_config()
    config["outbounds"][0]["server"] = "192.0.2.10"
    config["outbounds"][0]["password"] = "review-only-fake-password"
    return config


class GatewayReviewTests(unittest.TestCase):
    def test_dns_direct_or_uncached_configuration_is_rejected_before_core(self):
        for field, value in (('detour', 'direct'), ('type', 'https'), ('server_port', 443)):
            config = configuration()
            config['dns']['servers'][0][field] = value
            result, events, state = self.run_gateway(args=('--check',), config=config)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(events)
        config = configuration()
        config['dns']['disable_cache'] = True
        result, events, state = self.run_gateway(args=('--check',), config=config)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(events)

    def run_gateway(self, **kwargs):
        return gateway.GatewayTests().run_gateway(**kwargs)

    def test_valid_server_ports_override_is_accepted_without_touching_runtime(self):
        for ports in (["8443:8444"], ["443:443"], "8443:8444"):
            with self.subTest(server_ports=ports):
                config = configuration()
                config["outbounds"][0]["server_ports"] = ports
                result, events, state = self.run_gateway(
                    args=("--check",), config=config, stale_runtime=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(state["check_config"], config)
                self.assertEqual([event[:2] for event in events], [["worker", "check"]])
                self.assertEqual(state["runtime_after"], state["runtime_before"])

    def test_invalid_server_ports_types_are_rejected_before_core_check(self):
        for ports in ("", {}, 0, 443, False, True, [None], [[]], ["443"]):
            with self.subTest(server_ports=ports):
                config = configuration()
                config["outbounds"][0]["server_ports"] = ports
                result, events, state = self.run_gateway(
                    args=("--check",), config=config)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("server_ports", result.stderr)
                self.assertFalse(events)
                self.assertEqual(state["runtime_after"], {})

    def test_absent_null_and_empty_server_ports_preserve_scalar_configuration(self):
        variants = [configuration()]
        for ports in (None, []):
            config = configuration()
            config["outbounds"][0]["server_ports"] = ports
            variants.append(config)
        for config in variants:
            with self.subTest(server_ports=config["outbounds"][0].get("server_ports", "absent")):
                result, events, state = self.run_gateway(
                    args=("--check",), config=config, stale_runtime=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(state["check_config"], config)
                self.assertEqual([event[:2] for event in events], [["worker", "check"]])
                self.assertEqual(state["runtime_after"], state["runtime_before"])

    def test_port_override_replaces_scalar_allowance_and_retains_forward_drop(self):
        config = configuration()
        config["outbounds"][0]["server_ports"] = ["8443:8444"]
        result, events, state = self.run_gateway(config=config, stale_runtime=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(state["marker"].startswith("{"))
        self.assertEqual(state["policies"], dict.fromkeys(gateway.CHAINS, "DROP"))
        for port, expected in ((443, "DROP"), (8442, "DROP"), (8443, "ACCEPT"),
                               (8444, "ACCEPT"), (8445, "DROP")):
            self.assertEqual(gateway.verdict(state, "OUTPUT", **{
                "-o": "eth0", "-d": "192.0.2.10", "-p": "udp", "--dport": port,
            }), expected)
            self.assertEqual(gateway.verdict(state, "FORWARD", **{
                "-i": "eth0", "-o": "eth0", "-d": "192.0.2.10", "-p": "udp", "--dport": port,
            }), "DROP")


if __name__ == "__main__":
    unittest.main()
