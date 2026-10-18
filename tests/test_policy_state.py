"""Exercise host state/admission using real JSON and only privileged boundaries doubled."""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = {"format": 1, "proxy_tag": "proxy", "outer_endpoints": [
    {"family": 4, "address": "203.0.113.8", "protocol": "udp", "port_start": 443, "port_end": 443}],
    "payload_networks": ["tcp", "udp"], "dns_transport": "udp"}
CGROUP = {"format": 1, "mode": "v2", "mount": "/sys/fs/cgroup", "mount_identity": "1:2",
          "manager_hierarchy": "0", "path": "devsession.slice", "identity": "1:3", "boot_id": "a" * 36}


def call(body, runtime, *args):
    setup = '''set -euo pipefail
source "$1/lib/host.sh"
ROOT=$1; RUNTIME=$2; PROXY_POLICY_JSON=$3; CGROUP_TEST_STATE=$4; shift 4
BRIDGE=br-test; GATEWAY_IP=172.30.90.2
NODE_IP=203.0.113.8; NODE_PORT=443; CGROOT=$RUNTIME/group
GATEWAY_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
GATEWAY_NETWORK_ID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
GATEWAY_NS_ID=4:99
SOURCE_SHA256=1111111111111111111111111111111111111111111111111111111111111111
EFFECTIVE_SHA256=2222222222222222222222222222222222222222222222222222222222222222
POLICY_PARSER_SHA256=3333333333333333333333333333333333333333333333333333333333333333
cgroup_state_json() { printf '%s\\n' "$CGROUP_TEST_STATE"; }
cgroup_load_state() { CGROUP_TEST_STATE=$1; }
cgroup_verify() { :; }
trusted_path() { [[ -f $1 && ! -L $1 ]]; }
mkdir -p "$RUNTIME/requests"
'''
    return subprocess.run(["bash", "-c", setup + body, "state-test", str(ROOT), str(runtime),
                           json.dumps(POLICY), json.dumps(CGROUP), *args], capture_output=True, text=True)


class PolicyStateTests(unittest.TestCase):
    def test_binding_contains_versioned_nonsecret_configuration_and_group_identity(self):
        with tempfile.TemporaryDirectory() as td:
            p = call('binding_write; cat "$RUNTIME/binding"', td)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue(p.stdout.startswith('{'), p.stdout)
            state = json.loads(p.stdout)
            self.assertEqual(state, {"format": 2, "cgroup": CGROUP,
                "gateway": {"bridge": "br-test", "address": "172.30.90.2", "container_id": "a" * 64,
                            "network_id": "b" * 64, "namespace_identity": "4:99"},
                "proxy_policy": POLICY, "source_sha256": "1" * 64,
                "effective_sha256": "2" * 64, "policy_parser_sha256": "3" * 64})

    def test_binding_verification_rejects_each_config_or_namespace_change(self):
        changes = ['SOURCE_SHA256=' + '4' * 64, 'EFFECTIVE_SHA256=' + '4' * 64,
                   'POLICY_PARSER_SHA256=' + '4' * 64, 'GATEWAY_NS_ID=4:100',
                   'GATEWAY_ID=' + 'c' * 64, 'BRIDGE=br-other',
                   'CGROUP_TEST_STATE=$(jq -c \' .identity="1:9" \' <<<"$CGROUP_TEST_STATE")',
                   'PROXY_POLICY_JSON=$(jq -c \' .outer_endpoints[0].port_end=444 \' <<<"$PROXY_POLICY_JSON")']
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as td:
                p = call('binding_write; binding_verify; ' + change + '; '
                         'if binding_verify; then echo INCORRECTLY_ACCEPTED; exit 9; fi', td)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_old_and_malformed_binding_never_loads_a_cgroup(self):
        old = 'br-old\n172.30.90.2\n203.0.113.8\n443\n'
        for data in [old, '{}', '{"format":1}', '{"format":2,"cgroup":{}}']:
            with self.subTest(data=data), tempfile.TemporaryDirectory() as td:
                Path(td, 'binding').write_text(data)
                p = call('type binding_load >/dev/null || exit 7; '
                         'cgroup_load_state() { echo GROUP_LOADED; }; '
                         'if binding_load; then echo ACCEPTED; exit 9; fi', td)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertNotIn('GROUP_LOADED', p.stdout)

    def test_binding_rejects_additional_json_documents_before_loading(self):
        with tempfile.TemporaryDirectory() as td:
            p = call('binding_write; state=$(cat "$RUNTIME/binding"); '
                     'printf "%s\\n" "$state" >>"$RUNTIME/binding"; '
                     'cgroup_load_state() { echo GROUP_LOADED; }; '
                     'if binding_load; then echo ACCEPTED; exit 9; fi', td)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertNotIn('GROUP_LOADED', p.stdout)

    def test_bound_group_failure_cannot_trigger_redetection_or_firewall_repair(self):
        with tempfile.TemporaryDirectory() as td:
            p = call('binding_write; read_proxy_policy() { :; }; read_node() { :; }; '
                     'gateway_open() { :; }; cgroup_verify() { return 19; }; '
                     'systemctl() { :; }; sysctl() { return 19; }; '
                     'cgroup_detect() { echo REDETECTED; }; policy_install() { echo REPAIRED; }; '
                     'if prepare_policy init; then echo ACCEPTED; exit 9; fi', td)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertNotIn('REDETECTED', p.stdout)
            self.assertNotIn('REPAIRED', p.stdout)

    def test_group_or_binding_failure_prevents_forwarding_admission(self):
        for boundary in ['cgroup_verify', 'binding_verify']:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as td:
                p = call('binding_verify() { :; }; gateway_verify() { :; }; policy_verify() { :; }; '
                         'route_verify() { :; }; gw() { echo FORWARDING_ENABLED; }; '
                         + boundary + '() { return 19; }; '
                         'if admit_gateway; then exit 9; fi', td)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertNotIn('FORWARDING_ENABLED', p.stdout)


if __name__ == '__main__':
    unittest.main()
