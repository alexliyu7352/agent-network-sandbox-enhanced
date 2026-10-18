import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
LIB=ROOT/'lib/network.sh'


def call(body,*args):
    return subprocess.run(['bash','-c','set -euo pipefail; source "$1"; shift; '+body,
                           'fixture',str(LIB),*map(str,args)],capture_output=True,text=True)


class PlatformTests(unittest.TestCase):
    def test_readback_checks_rule_order_and_kernel_serialization(self):
        p=call('type rules_equal >/dev/null 2>&1 || exit 7; '
               'a="-A D8OUT -m cgroup --cgroup 0x6d730001 -j MARK --set-xmark 0x6d730001/0xffffffff"; '
               'b="-A D8OUT -m cgroup --cgroup 1836253185 -j MARK --set-xmark 0x6d730001/0xffffffff"; '
               'rules_equal "$a" "$b"; '
               'a+=$\'\\n-A D8OUT -j DROP\'; '
               'b=$\'-A D8OUT -j DROP\\n\'"$b"; '
               'if rules_equal "$a" "$b"; then exit 8; fi')
        self.assertEqual(p.returncode,0,p.stderr)
    def test_route_fallback_is_unreachable_before_default_or_rule(self):
        p=call('type route_install >/dev/null 2>&1 || { echo missing-route-installer; exit 7; }; '
               'ip() { printf "%s\\n" "$*"; }; BRIDGE=br-test; GATEWAY_IP=172.30.90.2; route_install')
        self.assertEqual(p.returncode,0,p.stdout+p.stderr)
        lines=p.stdout.splitlines()
        self.assertIn('unreachable default',lines[0])
        self.assertIn('rule add',lines[-1])
        self.assertTrue(all('flush' not in line for line in lines))

    def test_readback_rejects_extra_or_missing_route(self):
        expected=[{'dst':'default','type':'unreachable','metric':32760},
                  {'dst':'172.30.90.2','dev':'br-test','scope':'link'},
                  {'dst':'default','gateway':'172.30.90.2','dev':'br-test'}]
        for data,ok in [(expected,True),(expected[1:],False),
                        (expected+[{'dst':'8.8.8.8','dev':'eth0'}],False)]:
            p=call('type routes_match >/dev/null 2>&1 || { echo missing-route-check; exit 7; }; '
                   'BRIDGE=br-test; GATEWAY_IP=172.30.90.2; routes_match "$1"',json.dumps(data))
            self.assertEqual(p.returncode==0,ok,p.stdout+p.stderr)

    def test_node_validation_rejects_dns_names_or_extra_outbounds(self):
        base={'outbounds':[{'type':'hysteria2','tag':'proxy','server':'203.0.113.8','server_port':443,'bind_interface':'eth0'}],
              'dns':{'servers':[{'type':'udp','tag':'upstream-dns','server':'1.1.1.1','server_port':53,'detour':'proxy'}],
                     'final':'upstream-dns','disable_cache':False,'disable_expire':False}}
        with tempfile.TemporaryDirectory() as td:
            for changed,ok in [(base,True),
               (dict(base,outbounds=[dict(base['outbounds'][0],server='node.example')]),False),
               (dict(base,outbounds=base['outbounds']+[{'type':'direct'}]),False)]:
                path=Path(td)/'network.json';path.write_text(json.dumps(changed))
                p=call('type read_node >/dev/null 2>&1 || { echo missing-node-validation; exit 7; }; read_node "$1"',path)
                self.assertEqual(p.returncode==0,ok,p.stdout+p.stderr)

    def test_owned_hook_must_be_first_even_if_expected_rules_exist(self):
        # Check behavior via the real verifier. The boundary reports every
        # individual expected rule present, but inserts an earlier ACCEPT.
        p=call('firewall_tool() { echo fw; }; fw() { '
               'if [[ $* == *" -C "* ]]; then return 0; fi; '
               'c=${!#}; if [[ $c == OUTPUT ]]; then printf "%s\\n" "-P OUTPUT ACCEPT" "-A OUTPUT -j ACCEPT" "-A OUTPUT -j D8OUT6"; '
               'else policy_emit 6 mangle | awk -v c="$c" \'$2==c\'; fi; }; '
               'BRIDGE=br-test; GATEWAY_IP=172.30.90.2; NODE_IP=203.0.113.8; NODE_PORT=443; policy_verify')
        self.assertNotEqual(p.returncode,0)


if __name__=='__main__':unittest.main()
