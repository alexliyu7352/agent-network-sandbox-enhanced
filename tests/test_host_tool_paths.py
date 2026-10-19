"""工具路徑回歸：在 namespace 執行邊界模擬未合併 /usr 的宿主。"""
import os
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

# 只替代 namespace／工具邊界；保留真正的 gw、gateway_verify、admit_gateway。
# 舊版 /usr/sbin/sysctl、/usr/sbin/ip 必須失敗，不能被測試機的連結掩蓋。
BOUNDARY = r'''
timeout() { shift 2; "$@"; }
nsenter() {
    [[ $1 == --net=/proc/$$/fd/9 && $2 == -- ]] || return 90
    shift 2
    case $1 in
        /usr/sbin/sysctl|/usr/sbin/ip)
            echo "nsenter: failed to execute $1: No such file or directory" >&2; return 127 ;;
        /usr/sbin/iptables-legacy) shift; iptables-legacy "$@" ;;
        /*) return 91 ;;
        *) "$@" ;;
    esac
}
docker() {
    case "$*" in
        'exec worker cat /run/worker/policy-ready') printf '%s\n' "$READY_TEXT" ;;
        'exec worker sha256sum /etc/worker/network.json /run/worker/config.json /usr/local/lib/worker/gateway-policy.jq')
            printf '%s  /etc/worker/network.json\n' "$SOURCE_SHA256"
            printf '%s  /run/worker/config.json\n' "${READBACK_EFFECTIVE_SHA256:-$EFFECTIVE_SHA256}"
            printf '%s  /usr/local/lib/worker/gateway-policy.jq\n' "$POLICY_PARSER_SHA256" ;;
        'inspect -f {{.Id}} {{.State.Pid}} {{.State.Running}} worker')
            printf '%s 1234 true\n' "$GATEWAY_ID" ;;
        *) return 96 ;;
    esac
}
iptables-legacy() {
    if [[ $3 == -S ]]; then
        echo "-P $4 DROP"
        case $4 in
        OUTPUT)
            echo '-A OUTPUT -o lo -j ACCEPT'
            echo '-A OUTPUT -o tun0 -j ACCEPT'
            echo '-A OUTPUT -d 203.0.113.8/32 -o eth0 -p udp -m udp --dport 443 -j ACCEPT' ;;
        FORWARD)
            echo '-A FORWARD -i eth0 -o tun0 -j ACCEPT'
            echo '-A FORWARD -i tun0 -o eth0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' ;;
        INPUT)
            echo '-A INPUT -i lo -j ACCEPT'
            echo '-A INPUT -i tun0 -j ACCEPT'
            echo '-A INPUT -s 203.0.113.8/32 -i eth0 -p udp -m udp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT'
            echo '-A INPUT -i eth0 -p icmp -m conntrack --ctstate RELATED -j ACCEPT' ;;
        *) return 92;; esac
        if [[ ${EXTRA_RULE:-} == "$4" ]]; then echo "-A $4 -j ACCEPT"; fi
    elif [[ $3 != -C ]]; then return 93; fi
}
ip() {
    case "$*" in
        '-d -j link show dev tun0') echo '[{"mtu":1500,"flags":["UP"],"linkinfo":{"info_kind":"tun","info_data":{"type":"tun","persist":true}}}]' ;;
        '-j -4 addr show dev tun0') echo '[{"addr_info":[{"local":"198.18.0.1","prefixlen":15}]}]' ;;
        '-j -4 route show default dev eth0') echo '[{"gateway":"172.19.0.1"}]' ;;
        *' exact 0.0.0.0/1') echo '[{"dst":"0.0.0.0/1","dev":"tun0"}]' ;;
        *' exact 128.0.0.0/1') echo '[{"dst":"128.0.0.0/1","dev":"tun0"}]' ;;
        *' exact 203.0.113.8/32') echo '[{"dst":"203.0.113.8","gateway":"172.19.0.1","dev":"eth0"}]' ;;
        '-j -4 route show table main') echo '[{"dst":"default","gateway":"172.19.0.1","dev":"eth0"},{"dst":"172.19.0.0/16","dev":"eth0","scope":"link"},{"dst":"198.18.0.0/15","dev":"tun0","scope":"link"},{"dst":"0.0.0.0/1","dev":"tun0"},{"dst":"128.0.0.0/1","dev":"tun0"},{"dst":"203.0.113.8","gateway":"172.19.0.1","dev":"eth0"}]' ;;
        *) return 94 ;;
    esac
}
GWFD=9; GATEWAY=worker; NODE_IP=203.0.113.8; NODE_PORT=443
GATEWAY_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
GATEWAY_PID=1234
SOURCE_SHA256=1111111111111111111111111111111111111111111111111111111111111111
EFFECTIVE_SHA256=2222222222222222222222222222222222222222222222222222222222222222
POLICY_PARSER_SHA256=3333333333333333333333333333333333333333333333333333333333333333
cgroup_verify() { :; }
binding_verify() { :; }
'''


class HostToolPathsTests(unittest.TestCase):
    def run_boundary(self, body, sysctl_status=0):
        with tempfile.TemporaryDirectory() as td:
            sysctl = Path(td)/'sysctl'
            sysctl.write_text('#!/bin/sh\n'
                             'printf "%s\\n" "$*" >>"$TOOL_LOG"\n'
                             'case "$*" in -n*) echo 1;; esac\n'
                             'exit "$SYSCTL_STATUS"\n')
            sysctl.chmod(0o700)
            policy = {'format':1,'proxy_tag':'proxy','outer_endpoints':[
                {'family':4,'address':'203.0.113.8','protocol':'udp','port_start':443,'port_end':443}],
                'payload_networks':['tcp','udp'],'dns_transport':'udp'}
            ready = {'format':2,'source_sha256':'1'*64,'effective_sha256':'2'*64,
                     'policy_parser_sha256':'3'*64,'policy':policy}
            p = subprocess.run(['/bin/bash','-p','-c',
                'set -euo pipefail; source "$1/lib/host.sh"; source "$1/lib/network.sh"; '
                +BOUNDARY+'\n'+body,'test',str(ROOT)],capture_output=True,text=True,
                env=dict(os.environ,PATH=td+':/usr/bin:/bin',TOOL_LOG=td+'/calls',
                         SYSCTL_STATUS=str(sysctl_status),PROXY_POLICY_JSON=json.dumps(policy),
                         READY_TEXT=json.dumps(ready)))
            log = Path(td)/'calls'
            return p, log.read_text().splitlines() if log.exists() else []

    def test_gateway_verification_uses_host_search_path_on_split_usr(self):
        p, calls = self.run_boundary('gateway_verify')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(calls,['-n net.ipv6.conf.'+x+'.disable_ipv6' for x in ('all','default','lo')])

    def test_forwarding_enable_and_readback_find_sysctl_on_split_usr(self):
        p, calls = self.run_boundary('gateway_verify() { :; }; policy_verify() { :; }; '
                                    'route_verify() { :; }; admit_gateway')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(calls,['-q -w net.ipv4.ip_forward=1','-n net.ipv4.ip_forward'])

    def test_failed_forwarding_write_still_rejects_admission(self):
        p, calls = self.run_boundary('gateway_verify() { :; }; policy_verify() { :; }; '
                                    'route_verify() { :; }; admit_gateway; echo RELEASED',sysctl_status=17)
        self.assertEqual(p.returncode,17,p.stderr)
        self.assertEqual(calls,['-q -w net.ipv4.ip_forward=1'])
        self.assertNotIn('RELEASED',p.stdout)

    def test_legacy_ready_is_rejected(self):
        p, calls = self.run_boundary('READY_TEXT=worker-policy-v8; gateway_verify')
        self.assertNotEqual(p.returncode, 0)

    def test_changed_effective_config_is_rejected_despite_matching_ready(self):
        p, calls = self.run_boundary('READBACK_EFFECTIVE_SHA256=' + '9'*64 + '; gateway_verify')
        self.assertNotEqual(p.returncode, 0)

    def test_extra_container_rule_is_rejected(self):
        p, calls = self.run_boundary('EXTRA_RULE=OUTPUT; gateway_verify')
        self.assertNotEqual(p.returncode, 0)


if __name__ == '__main__':
    unittest.main()
