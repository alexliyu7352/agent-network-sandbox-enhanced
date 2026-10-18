"""Execute the real Bash policy generator; model its emitted iptables rules.

No host network changes. These tests are not Linux packet integration tests.
"""
import ipaddress
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TAG = 0x6D730001


def emit(family, table, mode='v1', endpoints=None):
    script = ROOT / 'lib/network.sh'
    if not script.exists():
        raise AssertionError('shared network policy has not been implemented')
    policy = {'format': 1, 'proxy_tag': 'proxy', 'outer_endpoints': endpoints or [
        {'family': 4, 'address': '203.0.113.8', 'protocol': 'udp', 'port_start': 443, 'port_end': 443}],
        'payload_networks': ['tcp', 'udp'], 'dns_transport': 'udp'}
    p = subprocess.run(['bash', '-c', 'source "$1"; BRIDGE=br-test; '
                        'GATEWAY_IP=172.30.90.2; NODE_IP=203.0.113.8; '
                        'NODE_PORT=443; CGROUP_MODE=$4; PROXY_POLICY_JSON=$5; '
                        'cgroup_match() { case $CGROUP_MODE in '
                        'v1) echo "-m cgroup --cgroup 0x6d730001";; '
                        'v2) echo "-m cgroup --path devsession.slice";; *) return 1;; esac; }; '
                        'policy_emit "$2" "$3"',
                        'test', str(script), str(family), table, mode, json.dumps(policy)],
                       text=True, capture_output=True, check=True)
    return p.stdout


class Rules:
    def __init__(self, text):
        self.chains = {}
        for row in text.splitlines():
            if row.startswith('-A '):
                _, chain, *args = shlex.split(row)
                self.chains.setdefault(chain, []).append(args)

    def visit(self, chain, p):
        for args in self.chains.get(chain, []):
            fields, modules = {}, []
            it = iter(args)
            for key in it:
                val = next(it)
                if key == '-m': modules.append(val)
                else: fields[key] = val
            if '--cgroup' in fields and p['classid'] != int(fields['--cgroup'], 0): continue
            if '--path' in fields:
                origin = p.get('socket_cgroup', '').strip('/')
                parent = fields['--path'].strip('/')
                if origin != parent and not origin.startswith(parent + '/'): continue
            if '--mark' in fields:
                value, *mask = fields['--mark'].split('/')
                field = 'connmark' if 'connmark' in modules else 'mark'
                if p[field] & int(mask[0] if mask else '0xffffffff', 0) != int(value, 0): continue
            if '-o' in fields and p['out'] != fields['-o']: continue
            if '-i' in fields and p.get('in') != fields['-i']: continue
            if '-d' in fields and ipaddress.ip_address(p['dst']) not in ipaddress.ip_network(fields['-d'], strict=False): continue
            if '-s' in fields and ipaddress.ip_address(p['src']) not in ipaddress.ip_network(fields['-s'], strict=False): continue
            if '-p' in fields and p['proto'] != fields['-p']: continue
            if '--dport' in fields:
                interval = list(map(int, fields['--dport'].split(':')))
                if not interval[0] <= p['port'] <= interval[-1]: continue
            target = fields['-j']
            if target in ('DROP', 'RETURN', 'ACCEPT'): return target
            if target in ('MARK', 'CONNMARK'):
                value, mask = fields['--set-xmark'].split('/')
                field = 'mark' if target == 'MARK' else 'connmark'
                p[field] = (p[field] & ~int(mask, 0)) ^ int(value, 0)
            elif target == 'DNAT':
                p['dst'], port = fields['--to-destination'].split(':')
                p['port'] = int(port)
                return 'DNAT'
            elif target == 'MASQUERADE': return target
            else:
                result = self.visit(target, p)
                if result != 'RETURN': return result
        return 'RETURN'


def packet(**kw):
    p = dict(classid=TAG, mark=0, connmark=0, out='br-test',
             src='192.0.2.5', dst='8.8.8.8', proto='tcp', port=443)
    p.update(kw)
    return p


class SharedPolicyTests(unittest.TestCase):
    def test_v2_subtree_matches_socket_origin_and_retains_marked_old_flows(self):
        rules = Rules(emit(4, 'mangle', mode='v2'))
        self.assertEqual(rules.visit('D8POST', packet(classid=0, out='eth0',
            socket_cgroup='/devsession.slice/dev-session-one.service', process_cgroup='/other.slice')), 'DROP')
        self.assertEqual(rules.visit('D8POST', packet(classid=0, out='eth0',
            socket_cgroup='/other.slice', process_cgroup='/devsession.slice/dev-session-one.service')), 'RETURN')
        self.assertEqual(rules.visit('D8POST', packet(classid=0, out='eth0',
            socket_cgroup='/devsession.slice-other/service')), 'RETURN')
        self.assertEqual(rules.visit('D8POST', packet(classid=0, out='eth0',
            socket_cgroup='/removed-parent/old-service', connmark=TAG)), 'DROP')

    def test_v2_dns_and_ipv6_use_the_same_socket_subtree(self):
        for proto in ('tcp', 'udp'):
            p = packet(classid=0, proto=proto, dst='127.0.0.53', port=53, out='lo',
                       socket_cgroup='/devsession.slice/dev-session-one.service')
            Rules(emit(4, 'mangle', mode='v2')).visit('D8OUT', p)
            self.assertEqual(Rules(emit(4, 'nat', mode='v2')).visit('D8DNS', p), 'DNAT')
        for hook in ('D8OUT6', 'D8POST6'):
            for dst in ('::1', '2606:4700:4700::1111'):
                self.assertEqual(Rules(emit(6, 'mangle', mode='v2')).visit(hook,
                    packet(classid=0, out='eth0', dst=dst,
                           socket_cgroup='/devsession.slice/dev-session-one.service')), 'DROP')

    def test_multi_endpoint_guard_opens_only_explicit_outer_transport_ranges(self):
        endpoints = [
            {'family': 4, 'address': '203.0.113.8', 'protocol': 'udp', 'port_start': 8443, 'port_end': 8445},
            {'family': 4, 'address': '192.0.2.10', 'protocol': 'tcp', 'port_start': 443, 'port_end': 443}]
        rules = Rules(emit(4, 'mangle', endpoints=endpoints))
        for ip, proto, port, expected in [
            ('203.0.113.8', 'udp', 8443, 'RETURN'), ('203.0.113.8', 'udp', 8445, 'RETURN'),
            ('203.0.113.8', 'udp', 8442, 'DROP'), ('203.0.113.8', 'tcp', 8443, 'DROP'),
            ('192.0.2.10', 'tcp', 443, 'RETURN'), ('192.0.2.10', 'udp', 443, 'DROP'),
            ('8.8.8.8', 'tcp', 443, 'DROP')]:
            p = packet(classid=0, src='172.30.90.2', dst=ip, proto=proto, port=port)
            p['in'] = 'br-test'
            self.assertEqual(rules.visit('D8GW', p), expected, (ip, proto, port))

    def test_every_managed_selector_denies_physical_egress(self):
        r = Rules(emit(4, 'mangle'))
        for field in ('classid', 'mark', 'connmark'):
            p = packet(classid=0, out='eth0'); p[field] = TAG
            self.assertEqual(r.visit('D8POST', p), 'DROP', field)

    def test_ipv4_loopback_development_and_designated_bridge_work(self):
        r = Rules(emit(4, 'mangle'))
        for dst, out in [('127.0.0.1', 'lo'), ('127.23.4.5', 'lo'), ('8.8.8.8', 'br-test')]:
            for proto in ('tcp', 'udp'):
                p = packet(dst=dst, out=out, proto=proto)
                self.assertEqual(r.visit('D8OUT', p), 'RETURN')
                self.assertEqual(r.visit('D8POST', p), 'RETURN')

    def test_host_nonloopback_address_on_lo_is_denied(self):
        r = Rules(emit(4, 'mangle'))
        self.assertEqual(r.visit('D8POST', packet(dst='203.0.113.4', out='lo')), 'DROP')

    def test_private_lan_multicast_are_rejected(self):
        r = Rules(emit(4, 'mangle'))
        for dst in ('10.1.2.3', '172.16.1.1', '192.168.1.1', '169.254.1.1',
                    '100.64.1.1', '224.0.0.1', '255.255.255.255', '0.0.0.1'):
            self.assertEqual(r.visit('D8OUT', packet(dst=dst)), 'DROP', dst)

    def test_all_ipv6_including_loopback_is_denied(self):
        r = Rules(emit(6, 'mangle'))
        for hook in ('D8OUT6', 'D8POST6'):
            for dst in ('::1', '2606:4700:4700::1111'):
                for field in ('classid', 'mark', 'connmark'):
                    p = packet(classid=0, dst=dst, out='lo'); p[field] = TAG
                    self.assertEqual(r.visit(hook, p), 'DROP')

    def test_unmanaged_host_traffic_is_not_blocked(self):
        for family in (4, 6):
            r = Rules(emit(family, 'mangle'))
            for hook in (('D8OUT', 'D8POST') if family == 4 else ('D8OUT6', 'D8POST6')):
                self.assertEqual(r.visit(hook, packet(classid=0, out='eth0')), 'RETURN')

    def test_dns_is_intercepted_after_classification_regardless_of_address(self):
        m, n = Rules(emit(4, 'mangle')), Rules(emit(4, 'nat'))
        for proto in ('tcp', 'udp'):
            for dst in ('127.0.0.53', '8.8.8.8', '10.0.0.53'):
                p = packet(dst=dst, out='lo' if dst.startswith('127.') else 'br-test', proto=proto, port=53)
                m.visit('D8OUT', p)
                self.assertEqual(n.visit('D8DNS', p), 'DNAT')
                self.assertEqual((p['dst'], p['port']), ('1.1.1.1', 53))

    def test_forward_guard_only_allows_native_gateway_outer_endpoint(self):
        r = Rules(emit(4, 'mangle'))
        p = packet(classid=0, src='172.30.90.2', dst='203.0.113.8', proto='udp', port=443)
        p['in'] = 'br-test'
        self.assertEqual(r.visit('D8GW', p), 'RETURN')
        for change in ({'src': '192.0.2.5'}, {'dst': '8.8.8.8'}, {'port': 53}, {'proto': 'tcp'}):
            self.assertEqual(r.visit('D8GW', dict(p, **change)), 'DROP')

    def test_repeated_sessions_have_no_per_session_rules_or_id_growth(self):
        first = emit(4, 'mangle')
        self.assertLess(len(first.splitlines()), 90)
        self.assertEqual(first, emit(4, 'mangle'))
        # An old socket has exactly the same restriction, with no identity recycled.
        r = Rules(first)
        self.assertEqual(r.visit('D8POST', packet(out='eth0', connmark=TAG)), 'DROP')

    def test_repair_does_not_remove_live_hooks_outside_atomic_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            binpath = Path(tmp) / 'fw'
            binpath.write_text('#!/bin/bash\nif [[ $* == *" -S "* ]]; then\n'
                               'h=${!#}; echo "-P $h ACCEPT"; exit 0; fi\n'
                               'echo "non-atomic firewall write: $*" >&2; exit 73\n')
            binpath.chmod(0o700)
            restore = Path(str(binpath) + '-restore')
            restore.write_text('#!/bin/bash\ncat >>"$TRANSACTIONS"\n')
            restore.chmod(0o700)
            p = subprocess.run(['bash', '-c', 'source "$1"; '
                'firewall_tool() { echo "$2"; }; '
                # $2 inside a function is not the script positional parameter.
                'firewall_tool() { echo "$FW_TEST"; }; '
                'cgroup_match() { echo "-m cgroup --cgroup 0x6d730001"; }; '
                'BRIDGE=br-test; GATEWAY_IP=172.30.90.2; policy_install',
                'test', str(ROOT / 'lib/network.sh')], text=True, capture_output=True,
                env={'PATH': '/usr/bin:/bin', 'FW_TEST': str(binpath), 'TRANSACTIONS': tmp+'/transactions',
                     'PROXY_POLICY_JSON': json.dumps({'format': 1, 'outer_endpoints': [
                         {'family': 4, 'address': '203.0.113.8', 'protocol': 'udp', 'port_start': 443, 'port_end': 443}]})})
            self.assertEqual(p.returncode, 0, p.stderr)
            transactions = (Path(tmp)/'transactions').read_text()
            self.assertIn('-I OUTPUT 1 -j D8OUT', transactions)
            self.assertNotIn('-F OUTPUT', transactions)

    def test_invalid_endpoint_cannot_install_a_partial_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            restore = Path(tmp) / 'fw-restore'
            restore.write_text('#!/bin/bash\ncat >>"$TRANSACTIONS"\n')
            restore.chmod(0o700)
            p = subprocess.run(['bash', '-c', 'set -euo pipefail; source "$1"; '
                'cgroup_match() { echo "-m cgroup --cgroup 0x6d730001"; }; '
                'firewall_tool() { echo "$FW_TEST"; }; '
                'BRIDGE=br-test; GATEWAY_IP=172.30.90.2; '
                'if policy_install; then exit 9; fi', 'test', str(ROOT / 'lib/network.sh')],
                text=True, capture_output=True, env={'PATH': '/usr/bin:/bin',
                'FW_TEST': str(Path(tmp) / 'fw'), 'TRANSACTIONS': tmp + '/transactions',
                'PROXY_POLICY_JSON': '{"format":1,"outer_endpoints":[{"protocol":"all"}]}'})
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertFalse((Path(tmp) / 'transactions').exists())
            self.assertNotIn('No such file', p.stderr, 'Validation must precede firewall access')


if __name__ == '__main__': unittest.main()
