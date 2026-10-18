#!/usr/bin/env python3
"""Run the real shell against a simulated kernel/process boundary.

All ip, iptables, sysctl, proxy, and probe commands are intercepted. Synthetic
endpoints are used; the runner's firewall and network are never modified.
"""
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import select
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(os.environ.get("GATEWAY_SCRIPT", ROOT / "entrypoint-gateway.sh"))
ENDPOINT = "203.0.113.45"
POLICY_FILE = Path(os.environ.get("GATEWAY_POLICY_FILE", ROOT / "gateway-policy.jq"))
PROBES = {"getent", "dig", "nslookup", "host", "curl", "wget", "ping", "ping6",
          "nc", "socat", "traceroute", "tun2socks", "sing-box"}
CHAINS = ("INPUT", "OUTPUT", "FORWARD")


def native_config():
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {"servers": [{"type": "udp", "tag": "upstream-dns", "server": "1.1.1.1",
                              "server_port": 53, "detour": "proxy"}],
                "final": "upstream-dns", "strategy": "ipv4_only",
                "disable_cache": False, "disable_expire": False},
        "inbounds": [{"type": "tun", "tag": "tun-in", "interface_name": "tun0",
                      "address": ["198.18.0.1/15"], "mtu": 1500, "stack": "mixed",
                      "auto_route": False, "auto_redirect": False, "dns_mode": "disabled"}],
        "outbounds": [{
            "type": "hysteria2", "tag": "proxy", "server": ENDPOINT,
            "server_port": 443, "bind_interface": "eth0",
            "password": "test-only-not-a-real-credential",
            "disable_path_mtu_discovery": True,
            "tls": {"enabled": True, "insecure": True, "alpn": ["h3"]},
        }],
        "route": {"rules": [{"inbound": ["tun-in"], "port": 53,
                              "action": "hijack-dns"}], "final": "proxy"},
    }


def http_config():
    config = native_config()
    config["outbounds"] = [{
        "type": "http", "tag": "proxy", "server": "192.0.2.20", "server_port": 3128,
        "username": "offline-user", "password": "fake-http-password",
    }]
    return config


def mixed_config():
    config = native_config()
    hy2 = config["outbounds"][0]
    hy2.update(tag="quic-node", server="192.0.2.10", server_ports=["8443:8445", "443:443"])
    http = http_config()["outbounds"][0]
    http["tag"] = "tcp-node"
    config["outbounds"] = [
        {"type": "selector", "tag": "proxy", "outbounds": ["quic-node", "tcp-node"]},
        hy2, http,
    ]
    return config


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


SHIM = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
name, args = Path(sys.argv[0]).name, sys.argv[1:]
state_path = Path(os.environ["KERNEL_STATE"])
state = json.loads(state_path.read_text())
with open(os.environ["CALL_LOG"], "a") as stream:
    stream.write(json.dumps([name] + args) + "\n")

def invoke():
    if name == "cp":
        # Compose uses a read-only root filesystem. Never let a regression
        # write to the test host's /etc or /sbin either.
        print("cp: Read-only file system", file=sys.stderr)
        return 1
    if name == "iptables-legacy":
        words = [word for word in args if word != "-w"]
        op, chain = words[:2]
        rules = state["rules"].setdefault(chain, [])
        if op == "-P":
            if os.environ.get("FAIL_POLICY") == chain:
                return 1
            state["policies"][chain] = words[2]
        elif op == "-F":
            rules.clear()
        elif op == "-N":
            pass
        elif op == "-A":
            if os.environ.get("FAIL_APPEND") == chain:
                return 1
            rules.append(words[2:])
        elif op == "-I":
            rules.insert(int(words[2]) - 1, words[3:])
        elif op == "-D":
            try:
                rules.remove(words[2:])
            except ValueError:
                return 1
        elif op == "-C":
            if os.environ.get("VERIFY_MISSING_RULE") == chain:
                return 1
            return 0 if words[2:] in rules else 1
        elif op == "-S":
            if chain in state["policies"]:
                policy = state["policies"][chain]
                if os.environ.get("VERIFY_BAD_POLICY") == chain:
                    policy = "ACCEPT"
                print("-P " + chain + " " + policy)
            visible_rules = list(rules)
            if os.environ.get("VERIFY_REORDER_RULES") == chain:
                visible_rules.reverse()
            if os.environ.get("VERIFY_MISSING_RULE") == chain and visible_rules:
                visible_rules.pop()
            for rule in visible_rules:
                if os.environ.get("KERNEL_CANONICAL_RULES") == "1":
                    pairs = [rule[index:index + 2] for index in range(0, len(rule), 2)]
                    for pair in pairs:
                        if pair == ["--ctstate", "ESTABLISHED,RELATED"]:
                            pair[1] = "RELATED,ESTABLISHED"
                    if ["-p", "tcp"] in pairs and ["-m", "tcp"] not in pairs:
                        pairs.append(["-m", "tcp"])
                    if ["-p", "udp"] in pairs and ["-m", "udp"] not in pairs:
                        pairs.append(["-m", "udp"])
                    rule = [word for pair in reversed(pairs) for word in pair]
                print("-A " + chain + " " + " ".join(rule))
            if os.environ.get("VERIFY_EXTRA_RULE") == chain:
                print("-A " + chain + " -j ACCEPT")
        else:
            raise AssertionError("Unsupported firewall operation: " + repr(args))
    elif name == "ip":
        if "route" in args and "show" in args:
            if "default" in args:
                gateway = os.environ.get("DEFAULT_GATEWAY", "172.19.0.1")
                routes = [] if os.environ.get("NO_DEFAULT") == "1" else [
                    {"dst": "default", "gateway": gateway, "dev": "eth0", "flags": []}]
                if "-j" in args:
                    print(json.dumps(routes))
                elif routes:
                    print("default via " + gateway + " dev eth0")
            elif "exact" in args:
                prefix = args[args.index("exact") + 1]
                route = state["routes"].get(prefix)
                routes = [] if route is None else [dict(route)]
                if os.environ.get("BAD_ROUTE") == prefix and routes:
                    routes[0]["dev"] = "tun0" if routes[0]["dev"] == "eth0" else "eth0"
                if os.environ.get("MISSING_ROUTE") == prefix:
                    routes = []
                print(json.dumps(routes))
            else:
                routes = [dict(route) for route in state["routes"].values()]
                routes.extend([
                    {"dst": "default", "dev": "eth0", "gateway": "172.19.0.1", "flags": []},
                    {"dst": "172.19.0.0/16", "dev": "eth0", "scope": "link", "flags": []},
                    {"dst": "198.18.0.0/15", "dev": "tun0", "scope": "link", "flags": []},
                ])
                if os.environ.get("EXTRA_NODE_ROUTE"):
                    routes.append({"dst": "192.0.2.99", "dev": os.environ["EXTRA_NODE_ROUTE"],
                                   "gateway": "172.19.0.1", "flags": []})
                if os.environ.get("EXTRA_ETH0_ROUTE"):
                    routes.append({"dst": "192.0.2.0/24", "dev": "eth0",
                                   "gateway": "172.19.0.1", "flags": []})
                print(json.dumps(routes))
        elif "route" in args and "replace" in args:
            prefix = args[args.index("replace") + 1]
            destination = prefix[:-3] if prefix.endswith("/32") else prefix
            route = {"dst": destination, "dev": args[args.index("dev") + 1], "flags": []}
            if "via" in args:
                route["gateway"] = args[args.index("via") + 1]
            state["routes"][prefix] = route
        elif "tuntap" in args and "add" in args:
            state["tun"] = {"ifname": "tun0", "flags": [], "mtu": 1500, "addr_info": [],
                            "linkinfo": {"info_kind": "tun", "info_data": {"type": "tun", "persist": True}}}
        elif "link" in args and "show" in args:
            if not state.get("tun"):
                return 1
            link = dict(state["tun"])
            if os.environ.get("BAD_TUN") == "flags":
                link["flags"] = []
            if os.environ.get("BAD_TUN") == "mtu":
                link["mtu"] = 1280
            print(json.dumps([link]) if "-j" in args else "tun0")
        elif "link" in args and "set" in args:
            state["tun"]["flags"] = ["UP"]
            state["tun"]["mtu"] = int(args[args.index("mtu") + 1])
        elif "addr" in args and "replace" in args:
            address, prefix = args[args.index("replace") + 1].split("/")
            state["tun"]["addr_info"] = [{"family": "inet", "local": address, "prefixlen": int(prefix)}]
        elif "addr" in args and "show" in args:
            link = dict(state["tun"])
            if os.environ.get("BAD_TUN") == "address":
                link["addr_info"] = []
            print(json.dumps([link]))
        else:
            raise AssertionError("Unsupported ip operation: " + repr(args))
    elif name == "sysctl":
        if "-w" in args:
            raise AssertionError("Gateway must leave forwarding to the trusted host manager")
        value = os.environ.get("FORWARDING_STATE", "0")
        if state["routes"] and os.environ.get("FORWARDING_AFTER_ROUTES"):
            value = os.environ["FORWARDING_AFTER_ROUTES"]
        print(value)
    elif name == "worker":
        mode = args[0]
        state[mode + "_config"] = json.loads(Path(args[args.index("-c") + 1]).read_text())
        state[mode + "_policies"] = dict(state["policies"])
        marker = Path(os.environ["GATEWAY_RUNTIME_DIR"]) / "policy-ready"
        state[mode + "_marker"] = marker.read_text() if marker.exists() else None
        if mode == "check" and os.environ.get("BAD_CONFIG") == "1":
            return 1
        if mode == "check" and os.environ.get("CHANGE_SOURCE_DURING_CHECK") == "1":
            source = Path(os.environ["CONFIG_TEMPLATE"])
            source.write_text(source.read_text() + "\n")
        if mode == "check" and os.environ.get("CHANGE_EFFECTIVE_DURING_CHECK") == "1":
            effective = Path(args[args.index("-c") + 1])
            changed = json.loads(effective.read_text())
            changed["outbounds"][-1]["password"] = "changed-fake-authentication"
            effective.write_text(json.dumps(changed))
        if mode == "check" and os.environ.get("CHANGE_PARSER_DURING_CHECK") == "1":
            parser = Path(os.environ["GATEWAY_POLICY_FILE"])
            parser.write_text(parser.read_text() + "\n# altered parser identity\n")
        if mode == "run":
            return int(os.environ.get("CORE_EXIT", "0"))
    else:
        raise AssertionError("Unexpected network/proxy probe: " + name)
    return 0

try:
    status = invoke()
finally:
    state_path.write_text(json.dumps(state))
sys.exit(status)
'''


def is_network_mutation(event):
    name, *args = event
    if name == "sysctl":
        return "-w" in args
    if name == "iptables-legacy":
        return bool(set(args) & {"-A", "-I", "-D", "-F", "-N", "-X", "-P", "-R"})
    if name == "ip":
        return bool(set(args) & {"replace", "add", "del", "delete", "set", "flush"})
    return False


def verdict(firewall, chain, **packet):
    """Evaluate emitted filter rules against representative packets."""
    for rule in firewall["rules"].get(chain, []):
        matches, target = True, None
        for index in range(0, len(rule), 2):
            flag, value = rule[index:index + 2]
            if flag == "-m":
                continue
            if flag == "-j":
                target = value
            elif flag in ("-i", "-o", "-p"):
                matches &= str(packet.get(flag, "")) == value
            elif flag in ("--dport", "--sport"):
                lower, _, upper = value.partition(":")
                matches &= int(lower) <= int(packet.get(flag, 0)) <= int(upper or lower)
            elif flag == "--ctstate":
                matches &= packet.get("state", "NEW") in value.split(",")
            elif flag in ("-s", "-d"):
                matches &= ipaddress.ip_address(packet.get(flag, "192.0.2.1")) in ipaddress.ip_network(value)
            else:
                raise AssertionError(f"Unsupported packet matcher {flag}: {rule}")
        if matches:
            if target == "RETURN":
                return None
            if target in ("ACCEPT", "DROP", "REJECT"):
                return target
            nested = verdict(firewall, target, **packet)
            if nested:
                return nested
    return firewall["policies"].get(chain)


class GatewayTests(unittest.TestCase):
    def run_gateway(self, extra_env=None, args=(), config=None, template_text=None,
                    stale_runtime=False, initial_rules=None, initial_tun=None):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            bindir = base / "bin"
            bindir.mkdir()
            shim = bindir / "shim"
            shim.write_text(SHIM)
            shim.chmod(0o755)
            for name in {"ip", "iptables-legacy", "sysctl", "worker", "cp"} | PROBES:
                (bindir / name).symlink_to(shim)
            template = base / "template.json"
            template.write_text(json.dumps(native_config() if config is None else config)
                                if template_text is None else template_text)
            parser_file = base / "policy.jq"
            parser_file.write_bytes(POLICY_FILE.read_bytes())
            calls, kernel, runtime = base / "calls.jsonl", base / "kernel.json", base / "run"
            kernel.write_text(json.dumps({"policies": dict.fromkeys(CHAINS, "ACCEPT"),
                                         "rules": initial_rules or {}, "routes": {}, "tun": initial_tun}))
            if stale_runtime:
                runtime.mkdir()
                (runtime / "policy-ready").write_text("stale-ready\n")
                (runtime / "config.json").write_text("old runtime bytes\n")
            before = {p.name: p.read_bytes() for p in runtime.iterdir()} if runtime.exists() else {}
            env = dict(os.environ)
            for name in ("PROXY_HOST_IP", "PROXY_PROTOCOL", "PROXY_PORT", "LOG_LEVEL"):
                env.pop(name, None)
            env.update(PATH=f"{bindir}:{os.environ['PATH']}", CALL_LOG=str(calls),
                       KERNEL_STATE=str(kernel), CONFIG_TEMPLATE=str(template),
                       GATEWAY_RUNTIME_DIR=str(runtime), TMPDIR=str(base),
                       GATEWAY_POLICY_FILE=str(parser_file))
            env.update(extra_env or {})
            result = subprocess.run(["/bin/sh", str(SCRIPT), *args], env=env,
                                    capture_output=True, text=True, timeout=10)
            events = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
            state = json.loads(kernel.read_text())
            after = {p.name: p.read_bytes() for p in runtime.iterdir()} if runtime.exists() else {}
            marker = runtime / "policy-ready"
            state.update(runtime_before=before, runtime_after=after,
                         source_bytes=template.read_bytes(),
                         marker=marker.read_text() if marker.exists() else None,
                         marker_mode=marker.stat().st_mode & 0o777 if marker.exists() else None)
            return result, events, state

    def assert_offline_failure(self, result, events, state):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(any(e[0] == "worker" and "run" in e for e in events))
        self.assertIsNone(state["marker"])
        self.assertFalse([e for e in events if e[0] in PROBES])

    def assert_check_rejected(self, config=None, extra_env=None, template_text=None):
        result, events, state = self.run_gateway(extra_env, args=("--check",), config=config,
                                                 template_text=template_text)
        self.assert_offline_failure(result, events, state)
        self.assertFalse([e for e in events if is_network_mutation(e)])

    def assert_ready_identity(self, state):
        self.assertTrue(state["marker"].startswith("{"), "readiness must be versioned JSON")
        ready = json.loads(state["marker"])
        self.assertEqual(set(ready), {"format", "source_sha256", "effective_sha256",
                                     "policy_parser_sha256", "policy"})
        self.assertEqual(ready["format"], 2)
        self.assertEqual(ready["source_sha256"], hashlib.sha256(state["source_bytes"]).hexdigest())
        self.assertEqual(ready["effective_sha256"],
                         hashlib.sha256(state["runtime_after"]["config.json"]).hexdigest())
        self.assertEqual(ready["policy_parser_sha256"], hashlib.sha256(POLICY_FILE.read_bytes()).hexdigest())
        self.assertEqual(state["runtime_after"]["config.json"], canonical_json(state["run_config"]))
        self.assertEqual(state["marker"].encode(), canonical_json(ready))
        return ready

    def test_native_config_is_preserved_without_any_outbound_probe(self):
        result, events, state = self.run_gateway()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["run_config"], native_config())
        self.assertFalse([e for e in events if e[0] in PROBES])
        self.assertFalse(any(e[0] == "ip" and "get" in e for e in events))

    def test_engine_command_and_runtime_files_use_neutral_names(self):
        result, events, state = self.run_gateway()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        commands = [event for event in events if event[0] == "worker"]
        self.assertEqual([event[1] for event in commands], ["check", "run"])
        self.assertFalse(any(event[0] == "sing-box" for event in events))
        self.assertEqual(set(state["runtime_after"]), {"config.json", "policy-ready"})
        self.assert_ready_identity(state)

    def test_source_log_authentication_and_node_are_preserved_despite_legacy_env(self):
        original = native_config()
        original["outbounds"][0].update(server="198.51.100.17", server_port=2443)
        result, _, state = self.run_gateway({
            "LOG_LEVEL": "debug", "PROXY_HOST_IP": "192.0.2.99", "PROXY_PORT": "1081",
            "PROXY_PROTOCOL": "obsolete-protocol",
        }, config=original)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["run_config"], original)
        self.assertIn("198.51.100.17/32", state["routes"])
        self.assertNotIn("192.0.2.99/32", state["routes"])
        for port, allowed in ((2443, "ACCEPT"), (443, "DROP")):
            self.assertEqual(verdict(state, "OUTPUT", **{
                "-o": "eth0", "-d": "198.51.100.17", "-p": "udp", "--dport": port,
            }), allowed)

    def test_drop_policies_and_stale_rule_removal_precede_core_and_routes(self):
        result, events, state = self.run_gateway(initial_rules={
            "OUTPUT": [["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]],
            "FORWARD": [["-j", "ACCEPT"]], "INPUT": [["-j", "ACCEPT"]],
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        normalized = [tuple(word for word in event if word != "-w") for event in events]
        boundary = next(i for i, e in enumerate(events) if e[0] in ("worker", "ip"))
        for chain in CHAINS:
            self.assertIn(("iptables-legacy", "-P", chain, "DROP"), normalized)
            self.assertIn(("iptables-legacy", "-F", chain), normalized)
            policy = normalized.index(("iptables-legacy", "-P", chain, "DROP"))
            flush = normalized.index(("iptables-legacy", "-F", chain))
            self.assertLess(policy, flush)
            self.assertLess(flush, boundary)
        self.assertEqual(state["check_policies"], dict.fromkeys(CHAINS, "DROP"))
        self.assertEqual(verdict(state, "OUTPUT", **{"-o": "eth0", "state": "ESTABLISHED"}), "DROP")

    def test_output_allows_only_local_tun_and_exact_outer_udp_endpoint(self):
        result, _, state = self.run_gateway()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for interface in ("lo", "tun0"):
            self.assertEqual(verdict(state, "OUTPUT", **{"-o": interface}), "ACCEPT")
        for connection in ("NEW", "ESTABLISHED", "RELATED"):
            outer = {"-o": "eth0", "-d": ENDPOINT, "-p": "udp", "--dport": 443, "state": connection}
            self.assertEqual(verdict(state, "OUTPUT", **outer), "ACCEPT")
            for change in ({"-d": "192.0.2.9"}, {"-p": "tcp"}, {"--dport": 53}, {"-o": "eth1"}):
                self.assertEqual(verdict(state, "OUTPUT", **{**outer, **change}), "DROP")
            self.assertEqual(verdict(state, "OUTPUT", **{
                "-o": "eth0", "-d": "127.0.0.11", "-p": "udp", "--dport": 53, "state": connection,
            }), "DROP")

    def test_forward_node_exception_never_allows_established_or_direct_fallback(self):
        result, _, state = self.run_gateway()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(verdict(state, "FORWARD", **{"-i": "eth0", "-o": "tun0"}), "ACCEPT")
        for connection in ("ESTABLISHED", "RELATED"):
            self.assertEqual(verdict(state, "FORWARD", **{"-i": "tun0", "-o": "eth0", "state": connection}), "ACCEPT")
        self.assertEqual(verdict(state, "FORWARD", **{"-i": "tun0", "-o": "eth0"}), "DROP")
        for connection in ("NEW", "ESTABLISHED", "RELATED"):
            for target in (ENDPOINT, "192.0.2.9"):
                self.assertEqual(verdict(state, "FORWARD", **{
                    "-i": "eth0", "-o": "eth0", "-d": target, "-p": "udp", "--dport": 443, "state": connection,
                }), "DROP")
        self.assertEqual(verdict(state, "FORWARD", **{"-i": "eth1", "-o": "tun0"}), "DROP")

    def test_input_admits_outer_replies_related_icmp_and_local_tun_only(self):
        result, _, state = self.run_gateway()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for interface in ("lo", "tun0"):
            self.assertEqual(verdict(state, "INPUT", **{"-i": interface}), "ACCEPT")
        outer = {"-i": "eth0", "-s": ENDPOINT, "-p": "udp", "--sport": 443, "state": "ESTABLISHED"}
        self.assertEqual(verdict(state, "INPUT", **outer), "ACCEPT")
        for change in ({"state": "NEW"}, {"-s": "192.0.2.9"}, {"--sport": 53}, {"-p": "tcp"}):
            self.assertEqual(verdict(state, "INPUT", **{**outer, **change}), "DROP")
        self.assertEqual(verdict(state, "INPUT", **{"-i": "eth0", "-p": "icmp", "state": "RELATED"}), "ACCEPT")
        self.assertEqual(verdict(state, "INPUT", **{"-i": "eth0", "-p": "icmp", "state": "NEW"}), "DROP")
        for connection in ("NEW", "ESTABLISHED"):
            self.assertEqual(verdict(state, "INPUT", **{"-i": "eth0", "-p": "tcp", "--dport": 22, "state": connection}), "DROP")

    def test_endpoint_route_uses_original_gateway_before_tun_routes(self):
        result, events, state = self.run_gateway({"DEFAULT_GATEWAY": "172.28.0.1"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["routes"][ENDPOINT + "/32"]["gateway"], "172.28.0.1")
        self.assertEqual(state["routes"][ENDPOINT + "/32"]["dev"], "eth0")
        endpoint = next(i for i, e in enumerate(events) if e[0] == "ip" and "replace" in e and ENDPOINT + "/32" in e)
        launch = next(i for i, e in enumerate(events) if e[0] == "worker" and "run" in e)
        for prefix in ("0.0.0.0/1", "128.0.0.0/1"):
            route = next(i for i, e in enumerate(events) if e[0] == "ip" and "replace" in e and prefix in e)
            self.assertLess(endpoint, route)
            self.assertLess(route, launch)
            self.assertEqual(state["routes"][prefix]["dev"], "tun0")

    def test_gateway_never_enables_forwarding_and_rechecks_before_readiness(self):
        result, events, _ = self.run_gateway()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(any(e[0] == "sysctl" and "-w" in e for e in events))
        self.assert_offline_failure(*self.run_gateway({"FORWARDING_AFTER_ROUTES": "1"}))

    def test_initial_forwarding_or_missing_default_aborts_with_deny_policies(self):
        for environment in ({"FORWARDING_STATE": "1"}, {"NO_DEFAULT": "1"}):
            with self.subTest(environment=environment):
                result, events, state = self.run_gateway(environment, stale_runtime=True)
                self.assert_offline_failure(result, events, state)
                self.assertEqual(state["policies"], dict.fromkeys(CHAINS, "DROP"))
                self.assertFalse(state["routes"])

    def test_readiness_requires_verified_policies_rules_and_no_extra_allowances(self):
        for failure in ("VERIFY_BAD_POLICY", "VERIFY_MISSING_RULE", "VERIFY_EXTRA_RULE",
                        "VERIFY_REORDER_RULES"):
            for chain in CHAINS:
                with self.subTest(failure=failure, chain=chain):
                    self.assert_offline_failure(*self.run_gateway({failure: chain}, stale_runtime=True))

    def test_readiness_requires_node_and_both_tun_routes_to_match(self):
        for prefix in (ENDPOINT + "/32", "0.0.0.0/1", "128.0.0.0/1"):
            for failure in ("BAD_ROUTE", "MISSING_ROUTE"):
                with self.subTest(prefix=prefix, failure=failure):
                    self.assert_offline_failure(*self.run_gateway({failure: prefix}))

    def test_readiness_requires_tun_address_mtu_and_administrative_up_state(self):
        for fault in ("flags", "mtu", "address"):
            with self.subTest(fault=fault):
                self.assert_offline_failure(*self.run_gateway({"BAD_TUN": fault}))

    def test_existing_wrong_tun_kind_or_mode_never_gets_traffic_allowances(self):
        for kind, mode in (("veth", None), ("tun", "tap")):
            with self.subTest(kind=kind, mode=mode):
                result, events, state = self.run_gateway(initial_tun={
                    "ifname": "tun0", "flags": ["UP"], "mtu": 1500,
                    "addr_info": [{"family": "inet", "local": "198.18.0.1", "prefixlen": 15}],
                    "linkinfo": {"info_kind": kind, "info_data": {"type": mode, "persist": True}},
                })
                self.assert_offline_failure(result, events, state)
                self.assertFalse(state["routes"])
                self.assertEqual(verdict(state, "OUTPUT", **{"-o": "tun0"}), "DROP")
                self.assertEqual(verdict(state, "FORWARD", **{"-i": "eth0", "-o": "tun0"}), "DROP")

    def test_policy_error_still_closes_every_independently_writable_chain(self):
        for failed in CHAINS:
            with self.subTest(failed=failed):
                result, events, state = self.run_gateway({"FAIL_POLICY": failed},
                    initial_rules={chain: [["-j", "ACCEPT"]] for chain in CHAINS})
                self.assert_offline_failure(result, events, state)
                self.assertFalse(state["routes"])
                for chain in CHAINS:
                    if chain != failed:
                        self.assertEqual(verdict(state, chain), "DROP")

    def test_policy_marker_is_private_and_published_only_after_local_checks(self):
        result, events, state = self.run_gateway(stale_runtime=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIsNone(state["check_marker"])
        self.assertEqual(state["run_marker"], state["marker"])
        ready = self.assert_ready_identity(state)
        self.assertEqual(ready["policy"], {
            "format": 1, "proxy_tag": "proxy", "outer_endpoints": [{"family": 4,
                "address": ENDPOINT, "protocol": "udp", "port_start": 443, "port_end": 443}],
            "payload_networks": ["tcp", "udp"], "dns_transport": "udp",
        })
        self.assertEqual(state["marker_mode"], 0o600)
        self.assertFalse([name for name in state["runtime_after"] if name.startswith(".policy-ready")])
        self.assertFalse([e for e in events if e[0] in PROBES])

    def test_rule_installation_error_stops_without_marker_or_route_changes(self):
        for environment in ({"FAIL_POLICY": "OUTPUT"}, {"FAIL_APPEND": "OUTPUT"}):
            with self.subTest(environment=environment):
                result, events, state = self.run_gateway(environment, stale_runtime=True)
                self.assert_offline_failure(result, events, state)
                self.assertFalse(state["routes"])

    def test_core_failure_keeps_policy_and_never_starts_fallback(self):
        result, events, state = self.run_gateway({"CORE_EXIT": "17"})
        self.assertEqual(result.returncode, 17, result.stdout + result.stderr)
        self.assertEqual(sum(e[0] == "worker" and "run" in e for e in events), 1)
        self.assertFalse([e for e in events if e[0] in PROBES])
        self.assertEqual(verdict(state, "OUTPUT", **{"-o": "eth0", "state": "ESTABLISHED"}), "DROP")
        self.assertEqual(verdict(state, "FORWARD", **{"-i": "eth0", "-o": "eth0", "state": "ESTABLISHED"}), "DROP")

    def test_invalid_startup_leaves_drop_policies_and_no_stale_marker(self):
        for environment, template in (({"BAD_CONFIG": "1"}, None), ({}, "{ invalid json")):
            with self.subTest(environment=environment, template=template):
                result, events, state = self.run_gateway(environment, template_text=template, stale_runtime=True)
                self.assert_offline_failure(result, events, state)
                self.assertEqual(state["policies"], dict.fromkeys(CHAINS, "DROP"))
                self.assertFalse(state["routes"])

    def test_check_changes_neither_network_nor_existing_runtime_state(self):
        result, events, state = self.run_gateway(args=("--check",), stale_runtime=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["check_config"], native_config())
        self.assertFalse([e for e in events if is_network_mutation(e)])
        self.assertEqual(state["runtime_after"], state["runtime_before"])
        self.assertFalse([e for e in events if e[0] in PROBES | {"ip", "iptables-legacy", "sysctl"}])
        self.assertFalse(any(e[0] == "worker" and "run" in e for e in events))

    def test_check_does_not_create_persistent_runtime_directory(self):
        result, events, state = self.run_gateway(args=("--check",))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["runtime_after"], {})
        self.assertFalse([e for e in events if is_network_mutation(e)])

    def test_invalid_endpoint_and_port_are_rejected_in_check_mode(self):
        for server in ("node.example.com", "", "2001:db8::1", "256.1.2.3", "1.2.3", "01.2.3.4",
                       "1.2.3.4/32", "1.2.3.4 trailing", "1.2.3.4\n", None, 1234):
            with self.subTest(server=server):
                config = native_config()
                config["outbounds"][0]["server"] = server
                self.assert_check_rejected(config=config)
        for port in (0, -1, 65536, 443.5, "443", None, True):
            with self.subTest(port=port):
                config = native_config()
                config["outbounds"][0]["server_port"] = port
                self.assert_check_rejected(config=config)

    def test_port_boundaries_are_accepted(self):
        for port in (1, 65535):
            with self.subTest(port=port):
                config = native_config()
                config["outbounds"][0]["server_port"] = port
                result, _, state = self.run_gateway(args=("--check",), config=config)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(state["check_config"]["outbounds"][0]["server_port"], port)

    def test_wrong_or_ambiguous_proxy_shape_is_rejected(self):
        variants = []
        for field, value in (("type", "socks"), ("tag", "other"), ("bind_interface", "tun0"), ("detour", "other")):
            config = native_config()
            config["outbounds"][0][field] = value
            variants.append(config)
        for field in ("type", "tag", "server", "server_port"):
            config = native_config()
            del config["outbounds"][0][field]
            variants.append(config)
        for extra in (copy.deepcopy(native_config()["outbounds"][0]), {"type": "direct", "tag": "direct"}):
            config = native_config()
            config["outbounds"].append(extra)
            variants.append(config)
        for value in ([], {}, None):
            config = native_config()
            config["outbounds"] = value
            variants.append(config)
        config = native_config()
        del config["outbounds"]
        variants.append(config)
        for index, config in enumerate(variants):
            with self.subTest(variant=index):
                self.assert_check_rejected(config=config)

    def test_tcp_only_proxy_gets_https_dns_and_only_tcp_outer_permissions(self):
        config = http_config()
        result, events, state = self.run_gateway(config=config)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        effective = state["run_config"]
        expected_outbound = {**config["outbounds"][0], "bind_interface": "eth0"}
        self.assertEqual(effective["outbounds"], [expected_outbound])
        self.assertEqual(effective["log"], config["log"])
        self.assertEqual(effective["dns"]["servers"], [{
            "type": "https", "tag": "upstream-dns", "server": "1.1.1.1", "server_port": 443,
            "path": "/dns-query", "detour": "proxy",
            "tls": {"enabled": True, "server_name": "cloudflare-dns.com"},
        }])
        self.assertEqual(state["source_bytes"], json.dumps(config).encode())
        self.assertIn("does not support UDP", result.stdout)
        for transport, expected in (("tcp", "ACCEPT"), ("udp", "DROP")):
            self.assertEqual(verdict(state, "OUTPUT", **{
                "-o": "eth0", "-d": "192.0.2.20", "-p": transport, "--dport": 3128,
            }), expected)
        ready = self.assert_ready_identity(state)
        self.assertEqual(ready["policy"]["payload_networks"], ["tcp"])
        self.assertEqual(ready["policy"]["dns_transport"], "https")
        self.assertNotIn("fake-http-password", state["marker"] + result.stdout + result.stderr)
        self.assertFalse([event for event in events if event[0] in PROBES])

    def test_selector_installs_exact_mixed_transports_port_ranges_and_node_routes(self):
        result, _, state = self.run_gateway(config=mixed_config())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(set(state["routes"]), {
            "192.0.2.10/32", "192.0.2.20/32", "0.0.0.0/1", "128.0.0.0/1",
        })
        endpoints = [("192.0.2.10", "udp", 443), ("192.0.2.10", "udp", 8443),
                     ("192.0.2.10", "udp", 8444), ("192.0.2.10", "udp", 8445),
                     ("192.0.2.20", "tcp", 3128)]
        for address, protocol, port in endpoints:
            self.assertEqual(verdict(state, "OUTPUT", **{
                "-o": "eth0", "-d": address, "-p": protocol, "--dport": port,
            }), "ACCEPT")
            self.assertEqual(verdict(state, "INPUT", **{
                "-i": "eth0", "-s": address, "-p": protocol, "--sport": port,
                "state": "ESTABLISHED",
            }), "ACCEPT")
            for connection in ("NEW", "ESTABLISHED", "RELATED"):
                self.assertEqual(verdict(state, "FORWARD", **{
                    "-i": "eth0", "-o": "eth0", "-d": address, "-p": protocol,
                    "--dport": port, "state": connection,
                }), "DROP")
        for address, protocol, port in (("192.0.2.10", "udp", 8442),
                                        ("192.0.2.10", "udp", 8446),
                                        ("192.0.2.10", "tcp", 8443),
                                        ("192.0.2.20", "udp", 3128),
                                        ("192.0.2.99", "tcp", 3128)):
            self.assertEqual(verdict(state, "OUTPUT", **{
                "-o": "eth0", "-d": address, "-p": protocol, "--dport": port,
            }), "DROP")
        ready = self.assert_ready_identity(state)
        self.assertEqual(ready["policy"]["outer_endpoints"], [
            {"family": 4, "address": "192.0.2.10", "protocol": "udp", "port_start": 443, "port_end": 443},
            {"family": 4, "address": "192.0.2.10", "protocol": "udp", "port_start": 8443, "port_end": 8445},
            {"family": 4, "address": "192.0.2.20", "protocol": "tcp", "port_start": 3128, "port_end": 3128},
        ])

    def test_kernel_option_order_and_implicit_transport_module_are_accepted(self):
        result, _, _ = self.run_gateway({"KERNEL_CANONICAL_RULES": "1"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_readiness_rejects_extra_node_host_routes_and_extra_eth0_gateway_routes(self):
        for environment in ({"EXTRA_NODE_ROUTE": "eth0"}, {"EXTRA_NODE_ROUTE": "tun0"},
                            {"EXTRA_ETH0_ROUTE": "1"}):
            with self.subTest(environment=environment):
                self.assert_offline_failure(*self.run_gateway(environment, stale_runtime=True))

    def test_readiness_rejects_source_effective_authentication_or_parser_drift(self):
        for key in ("CHANGE_SOURCE_DURING_CHECK", "CHANGE_EFFECTIVE_DURING_CHECK",
                    "CHANGE_PARSER_DURING_CHECK"):
            with self.subTest(key=key):
                self.assert_offline_failure(*self.run_gateway({key: "1"}, stale_runtime=True))

    def test_nonpersistent_existing_tun_never_receives_traffic_allowances(self):
        result, events, state = self.run_gateway(initial_tun={
            "ifname": "tun0", "flags": ["UP"], "mtu": 1500, "addr_info": [],
            "linkinfo": {"info_kind": "tun", "info_data": {"type": "tun", "persist": False}},
        })
        self.assert_offline_failure(result, events, state)
        self.assertFalse(state["routes"])

    def test_malformed_configuration_never_exposes_source_text_in_errors(self):
        result, events, state = self.run_gateway(
            template_text='{"password":"SENSITIVE_FAKE_CANARY", "broken": SENSITIVE_FAKE_CANARY}',
            stale_runtime=True)
        self.assert_offline_failure(result, events, state)
        self.assertNotIn("SENSITIVE_FAKE_CANARY", result.stdout + result.stderr)

    def test_multiple_configuration_documents_are_rejected_before_core_check(self):
        source = json.dumps(native_config()) + "\n" + json.dumps(native_config()) + "\n"
        result, events, state = self.run_gateway(args=("--check",), template_text=source,
                                                  stale_runtime=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(events, "the compiler must reject multiple documents before invoking the core")
        self.assertEqual(state["runtime_before"], state["runtime_after"])


class EngineNameTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("DEV_NETWORK_TEST_ENGINE"),
                         "set DEV_NETWORK_TEST_ENGINE to the pinned sing-box binary")
    def test_real_renamed_binary_has_neutral_comm_cmdline_and_executable(self):
        """Hold `check` on stdin: inspect the actual ELF without any sockets.

        This checks Linux process presentation, not a Docker build or a live
        gateway. The installed image renames this same underlying executable.
        """
        source = Path(os.environ["DEV_NETWORK_TEST_ENGINE"])
        self.assertTrue(source.is_file(), "DEV_NETWORK_TEST_ENGINE must name an executable file")
        with tempfile.TemporaryDirectory(prefix="worker-name-test-") as directory:
            staged = Path(directory) / "sing-box"
            shutil.copy2(str(source), str(staged))
            worker = staged.with_name("worker")
            staged.rename(worker)
            self.assertFalse(staged.exists())
            # The worker reports its /proc identity before exec, because a CI
            # runner may mount /proc from an ancestor PID namespace. Popen.pid
            # would then index an unrelated process in that mounted filesystem.
            identity_read, identity_write = os.pipe()
            report_and_exec = (
                "import os,sys; fd=int(sys.argv[1]); "
                "os.write(fd, os.readlink('/proc/self').encode()); os.close(fd); "
                "os.execv(sys.argv[2], sys.argv[2:])")
            try:
                process = subprocess.Popen(
                    [sys.executable, "-I", "-c", report_and_exec, str(identity_write),
                     str(worker), "check", "-c", "/dev/stdin"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    pass_fds=(identity_write,))
            finally:
                os.close(identity_write)
            try:
                self.assertTrue(select.select([identity_read], [], [], 5)[0],
                                "worker did not report its /proc identity")
                child_identity = os.read(identity_read, 64).decode("ascii")
                self.assertTrue(child_identity.isdecimal(), "invalid child /proc identity")
                proc = Path("/proc") / child_identity
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    self.assertIsNone(process.poll(), "engine exited before process inspection")
                    # execve publishes comm and argv separately. Both must be
                    # ready before inspecting their final values.
                    if ((proc / "comm").read_text().strip() == "worker" and
                        (proc / "cmdline").read_bytes().split(b"\0")[:-1] ==
                            [os.fsencode(worker), b"check", b"-c", b"/dev/stdin"]):
                        break
                    time.sleep(0.01)
                self.assertEqual((proc / "comm").read_text().strip(), "worker")
                self.assertEqual((proc / "cmdline").read_bytes().split(b"\0")[:-1],
                                 [os.fsencode(worker), b"check", b"-c", b"/dev/stdin"])
                self.assertEqual(os.readlink(str(proc / "exe")), str(worker))
                stdout, stderr = process.communicate(b"{}\n", timeout=5)
                self.assertEqual(process.returncode, 0, (stdout + stderr).decode(errors="replace"))
            finally:
                os.close(identity_read)
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
