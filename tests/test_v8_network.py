"""Execute the real Bash policy generator; model its emitted iptables rules.

No host network changes. These tests are not Linux packet integration tests.
"""
import ipaddress
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TAG = 0x6D730001


def emit(family, table):
    script = ROOT / 'lib/network.sh'
    if not script.exists():
        raise AssertionError('shared network policy has not been implemented')
    p = subprocess.run(['bash', '-c', 'source "$1"; BRIDGE=br-test; '
                        'GATEWAY_IP=172.30.90.2; NODE_IP=203.0.113.8; '
                        'NODE_PORT=443; policy_emit "$2" "$3"',
                        'test', str(script), str(family), table],
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
            if '--mark' in fields:
                value, *mask = fields['--mark'].split('/')
                field = 'connmark' if 'connmark' in modules else 'mark'
                if p[field] & int(mask[0] if mask else '0xffffffff', 0) != int(value, 0): continue
            if '-o' in fields and p['out'] != fields['-o']: continue
            if '-i' in fields and p.get('in') != fields['-i']: continue
            if '-d' in fields and ipaddress.ip_address(p['dst']) not in ipaddress.ip_network(fields['-d'], strict=False): continue
            if '-s' in fields and ipaddress.ip_address(p['src']) not in ipaddress.ip_network(fields['-s'], strict=False): continue
            if '-p' in fields and p['proto'] != fields['-p']: continue
            if '--dport' in fields and p['port'] != int(fields['--dport']): continue
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
                'BRIDGE=br-test; GATEWAY_IP=172.30.90.2; NODE_IP=203.0.113.8; NODE_PORT=443; policy_install',
                'test', str(ROOT / 'lib/network.sh')], text=True, capture_output=True,
                env={'PATH': '/usr/bin:/bin', 'FW_TEST': str(binpath), 'TRANSACTIONS': tmp+'/transactions'})
            self.assertEqual(p.returncode, 0, p.stderr)
            transactions = (Path(tmp)/'transactions').read_text()
            self.assertIn('-I OUTPUT 1 -j D8OUT', transactions)
            self.assertNotIn('-F OUTPUT', transactions)


if __name__ == '__main__': unittest.main()
