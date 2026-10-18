"""工具路徑回歸：在 namespace 執行邊界模擬未合併 /usr 的宿主。"""
import os
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
docker() { echo worker-policy-v8; }
iptables-legacy() {
    if [[ $3 == -S ]]; then
        case $4 in OUTPUT) n=3;; FORWARD) n=2;; INPUT) n=4;; *) return 92;; esac
        echo "-P $4 DROP"
        for ((i=0;i<n;i++)); do echo "-A $4 -j ACCEPT"; done
    elif [[ $3 != -C ]]; then return 93; fi
}
ip() {
    case "$*" in
        '-d -j link show dev tun0') echo '[{"mtu":1500,"flags":["UP"],"linkinfo":{"info_kind":"tun","info_data":{"type":"tun"}}}]' ;;
        '-j -4 addr show dev tun0') echo '[{"addr_info":[{"local":"198.18.0.1","prefixlen":15}]}]' ;;
        '-j -4 route show default dev eth0') echo '[{"gateway":"172.19.0.1"}]' ;;
        *' exact 0.0.0.0/1') echo '[{"dst":"0.0.0.0/1","dev":"tun0"}]' ;;
        *' exact 128.0.0.0/1') echo '[{"dst":"128.0.0.0/1","dev":"tun0"}]' ;;
        *' exact 203.0.113.8/32') echo '[{"dst":"203.0.113.8","gateway":"172.19.0.1","dev":"eth0"}]' ;;
        *) return 94 ;;
    esac
}
GWFD=9; GATEWAY=worker; NODE_IP=203.0.113.8; NODE_PORT=443
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
            p = subprocess.run(['/bin/bash','-p','-c',
                'set -euo pipefail; source "$1/lib/host.sh"; source "$1/lib/network.sh"; '
                +BOUNDARY+'\n'+body,'test',str(ROOT)],capture_output=True,text=True,
                env=dict(os.environ,PATH=td+':/usr/bin:/bin',TOOL_LOG=td+'/calls',
                         SYSCTL_STATUS=str(sysctl_status)))
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


if __name__ == '__main__':
    unittest.main()
