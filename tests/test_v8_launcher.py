import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
LIB=ROOT/'lib/host.sh'

def call(body,*args):
    return subprocess.run(['bash','-c','set -euo pipefail; source "$1"; shift; '+body,
        'fixture',str(LIB),*map(str,args)],capture_output=True,text=True)

class LauncherTests(unittest.TestCase):
    def test_privileged_entry_clears_environment_before_loading_main(self):
        # Replace only the final /bin/bash boundary with /usr/bin/env. This
        # exercises the actual entrypoint and checks what the clean loader gets.
        with tempfile.TemporaryDirectory() as td:
            launcher=(ROOT/'dev-session').read_text()
            before,separator,after=launcher.partition('/bin/bash -p -c')
            self.assertTrue(separator,'missing clean-environment loader')
            path=Path(td)/'entry';path.write_text(before+'/usr/bin/env\n')
            env=dict(os.environ,DBUS_SYSTEM_BUS_ADDRESS='unixexec:path=/untrusted',
                     DOCKER_HOST='tcp://untrusted:1234',SYSTEMD_PAGER='/untrusted',
                     BASH_ENV='/untrusted',TERM='xterm-256color')
            p=subprocess.run(['/bin/bash','-p',str(path)],env=env,capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertNotIn('untrusted',p.stdout)
            self.assertIn('TERM=xterm-256color',p.stdout)

    def test_failed_request_removal_never_prevents_unit_stop(self):
        launcher=(ROOT/'lib/main.sh').read_text() if (ROOT/'lib/main.sh').exists() else (ROOT/'dev-session').read_text()
        finish=launcher.split('finish() {',1)[1].split('\n}\n',1)[0]
        p=subprocess.run(['bash','-c','set -euo pipefail; exec 3>&1; unit=dev-session-test.service; '
            'client=""; RUNTIME=/unused; sid=test; rm() { return 1; }; '
            'reclaim_stopped_group() { :; }; '
            'timeout() { echo "BOUNDED:$1:$2" >&3; return 1; }; '
            'systemctl() { echo STOP >&3; }; finish() {'+finish+'\n}; finish'],capture_output=True,text=True)
        self.assertIn('STOP',p.stdout,p.stderr)
        self.assertIn('BOUNDED:--signal=KILL:2s',p.stdout)

    def test_finish_reclaims_group_after_systemd_finishes_stopping(self):
        finish=(ROOT/'lib/main.sh').read_text().split('finish() {',1)[1].split('\n}\n',1)[0]
        p=subprocess.run(['bash','-c','set -euo pipefail; exec 3>&1; unit=dev-session-test.service; '
            'client=""; RUNTIME=/unused; sid=test; stopped=no; timeout() { :; }; '
            'systemctl() { stopped=yes; echo STOP_COMPLETE >&3; }; '
            'reclaim_stopped_group() { [[ $stopped == yes ]] || return 1; echo RECLAIMED >&3; }; '
            'finish() {'+finish+'\n}; finish'],capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(p.stdout.splitlines(),['STOP_COMPLETE','RECLAIMED'])
    def test_request_serialization_preserves_literal_dollars_and_spaces(self):
        with tempfile.TemporaryDirectory() as td:
            value='${HOME} $(touch never) a b; " c\nnext'
            p=call('RUNTIME="$1"; mkdir "$RUNTIME/requests"; '
                   'write_request "$2" "$3" ""; read_request "$2"; '
                   'printf "%s\\0" "${REQUEST[@]}"',td,'a'*32,value)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual(p.stdout,value+'\0\0')
            self.assertFalse((Path(td)/'requests'/('a'*32)).exists())

    def test_untrusted_or_symlink_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            file=Path(td)/'file';file.write_text('x');file.chmod(0o666)
            p=call('trusted_path "$1"',file)
            self.assertNotEqual(p.returncode,0)
            link=Path(td)/'link';link.symlink_to(file)
            self.assertNotEqual(call('trusted_path "$1"',link).returncode,0)

    def test_admission_stops_on_each_failed_precondition(self):
        for failing in ('cgroup_verify','binding_verify','gateway_verify','policy_verify','route_verify'):
            p=call('cgroup_verify() { echo cgroup; }; binding_verify() { echo binding; }; '
                   'gateway_verify() { echo gateway; }; '
                   'policy_verify() { echo firewall; }; route_verify() { echo route; }; '
                   'gw() { echo enabled; }; '
                   'eval "$1() { echo failed; return 17; }"; '
                   'admit_gateway; echo RELEASED',failing)
            self.assertNotEqual(p.returncode,0,p.stderr)
            self.assertNotIn('enabled',p.stdout)
            self.assertNotIn('RELEASED',p.stdout)

    def test_internal_operations_reject_unbound_cgroups_before_bootstrap_or_cleanup(self):
        internal=(ROOT/'lib/main.sh').read_text().split('case ${1:-} in',1)[1].split('\nesac',1)[0]
        for operation in ('--internal-child', '--internal-clean'):
            for failing in ('binding_load', 'cgroup_verify'):
                p=call('valid_session_id() { :; }; binding_load() { :; }; cgroup_verify() { :; }; '
                       'trusted_path() { :; }; read_request() { :; }; '
                       'bootstrap_workload() { echo BOOTSTRAP_RAN; }; '
                       'cleanup_group() { echo CLEANUP_RAN; }; '
                       'eval "$3() { return 19; }"; set -- "$1" "$2"; RUNTIME=/unused; '
                       'case ${1:-} in'+internal+'\nesac',operation,'a'*32,failing)
                self.assertEqual(p.returncode,125,p.stdout+p.stderr)
                self.assertNotIn('BOOTSTRAP_RAN',p.stdout)
                self.assertNotIn('CLEANUP_RAN',p.stdout)

if __name__=='__main__':unittest.main()
