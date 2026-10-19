"""Behavioral fixtures for Bash session functions; no system manager changes."""
import json
import os
import pty
import stat
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / 'lib/session.sh'


def run(body, *args, env=None):
    if not LIB.exists():
        raise AssertionError('native session management has not been implemented')
    # These tests isolate the established v1 session lifecycle. The cgroup
    # adapter's state/readback validation has its own complete mount fixtures.
    return subprocess.run(['bash', '-c', 'set -euo pipefail; source "${1%/*}/cgroup.sh"; '
                           'source "$1"; CGROUP_MODE=v1; cgroup_verify() { :; }; shift; '+body,
                           'test', str(LIB), *map(str,args)], text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, env=dict(os.environ, **(env or {})))


def credential_status(bounding='000001ffffffffff', **changes):
    fields = {
        'Uid': '1000\t1000\t1000\t1000',
        'CapInh': '0000000000000000',
        'CapPrm': '0000000000000000',
        'CapEff': '0000000000000000',
        'CapBnd': bounding,
        'CapAmb': '0000000000000000',
        'NoNewPrivs': '1',
        'Seccomp': '2',
    }
    fields.update(changes)
    return ''.join(f'{name}:\t{value}\n' for name, value in fields.items()
                   if value is not None)


class SessionTests(unittest.TestCase):
    def test_restricted_credentials_accept_unchanged_inherited_bounding_set(self):
        for bounding in ('0000000000000000', '000001ffffffffff'):
            with self.subTest(bounding=bounding):
                p = run('credentials_match "$1" 1000 "$2"',
                        credential_status(bounding), bounding)
                self.assertEqual(p.returncode, 0, p.stderr)

    def test_credentials_reject_each_usable_capability_set(self):
        for field in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'):
            with self.subTest(field=field):
                p = run('credentials_match "$1" 1000 "$2"',
                        credential_status(**{field: '0000000000000001'}),
                        '000001ffffffffff')
                self.assertNotEqual(p.returncode, 0)

    def test_credentials_require_valid_unchanged_bounding_field(self):
        cases = (
            ('missing', None, '000001ffffffffff'),
            ('nonhex', '000000000000000g', '0000000000000000'),
            ('short', '000000000000000', '0000000000000000'),
            ('long', '00000000000000000', '0000000000000000'),
            ('changed', '0000000000000000', '000001ffffffffff'),
            # Hex masks must compare as strings; decimal-looking masks can
            # otherwise become equal after awk floating-point conversion.
            ('numeric_precision', '9999999999999998', '9999999999999999'),
        )
        for name, actual, expected in cases:
            with self.subTest(case=name):
                p = run('credentials_match "$1" 1000 "$2"',
                        credential_status(actual), expected)
                self.assertNotEqual(p.returncode, 0)

    def test_credentials_require_valid_expected_bounding_mask(self):
        for expected in (None, '', '000000000000000', '00000000000000000',
                         '000000000000000g', '000001FFFFFFFFFF'):
            with self.subTest(expected=expected):
                body = 'credentials_match "$1" 1000'
                args = [credential_status('0000000000000000')]
                if expected is not None:
                    body += ' "$2"'
                    args.append(expected)
                p = run(body, *args)
                self.assertNotEqual(p.returncode, 0)

    def test_credentials_require_target_uid_in_all_four_columns(self):
        for column in range(4):
            with self.subTest(column=column):
                uids = ['1000'] * 4
                uids[column] = '0'
                p = run('credentials_match "$1" 1000 "$2"',
                        credential_status(Uid='\t'.join(uids)),
                        '000001ffffffffff')
                self.assertNotEqual(p.returncode, 0)
        p = run('credentials_match "$1" 0 "$2"',
                credential_status(Uid='0\t0\t0\t0'), '000001ffffffffff')
        self.assertNotEqual(p.returncode, 0)

    def test_credentials_require_no_new_privileges_and_seccomp_filter(self):
        for field, value in (('NoNewPrivs', '0'), ('Seccomp', '0'), ('Seccomp', '1')):
            with self.subTest(field=field, value=value):
                p = run('credentials_match "$1" 1000 "$2"',
                        credential_status(**{field: value}), '000001ffffffffff')
                self.assertNotEqual(p.returncode, 0)

    def test_user_checks_inspects_current_bash_process_status(self):
        # Observe the actual status supplied to the validator. This process
        # need not have workload credentials, so only the validator is replaced.
        # Builtin reads use the PID visible through this /proc mount, even if
        # it belongs to an ancestor PID namespace.
        p = run('read -r caller rest </proc/self/stat; '
                'printf "ExpectedPid:\\t%s\\n" "$caller"; '
                'credentials_match() { printf "%s\\n" "$1"; }; '
                'user_checks 1000 "$1" || :', '000001ffffffffff')
        self.assertEqual(p.returncode, 0, p.stderr)
        fields = dict(line.split(':', 1) for line in p.stdout.splitlines()
                      if ':' in line)
        self.assertIn('Pid', fields, p.stdout)
        self.assertIn('Name', fields, p.stdout)
        self.assertEqual(fields['Pid'].strip(), fields['ExpectedPid'].strip())
        self.assertEqual(fields['Name'].strip(), 'bash')

    def test_private_tty_changes_only_new_slave_and_rejects_outer_slave(self):
        outer_master,outer_slave=pty.openpty()
        master,slave=pty.openpty()
        try:
            before=os.fstat(outer_slave)
            identity=f'{before.st_dev}:{before.st_ino}:{os.major(before.st_rdev):x}:{os.minor(before.st_rdev):x}'
            command=['bash','-c','set -euo pipefail; source "$1"; private_tty "$2" "$3" "$4"',
                     'fixture',str(LIB),identity,str(os.getuid()),str(os.getgid())]
            p=subprocess.run(command,stdin=slave,stdout=slave,stderr=slave,timeout=5)
            self.assertEqual(p.returncode,0)
            self.assertEqual(stat.S_IMODE(os.fstat(slave).st_mode),0o600)
            self.assertEqual(os.fstat(outer_slave).st_mode,before.st_mode)
            p=subprocess.run(command,stdin=outer_slave,stdout=outer_slave,stderr=outer_slave,timeout=5)
            self.assertNotEqual(p.returncode,0)
        finally:
            for fd in (master,slave,outer_master,outer_slave):os.close(fd)
    def test_bootstrap_attaches_before_dropping_privileges_and_passes_argv(self):
        with tempfile.TemporaryDirectory() as td:
            p=run('type bootstrap_workload >/dev/null 2>&1 || { echo missing; exit 7; }; '
                  'CGROOT="$1"; mkdir "$CGROOT/$2"; touch "$CGROOT/$2/net_cls.classid" "$CGROOT/$2/cgroup.procs"; '
                  'attach_group() { echo attached; }; '
                  'REQUEST=(developer 1000 1000 /home/developer / pipe none xterm https://example.test /usr/bin/printf \'$HOME\'); '
                  'bootstrap_workload "$2"; printf "%s\\0" "${DROP_ARGS[@]}"',td,'a'*32)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertTrue(p.stdout.startswith('attached\n'))
            args=p.stdout[len('attached\n'):].split('\0')[:-1]
            self.assertIn('--clear-groups',args)
            self.assertIn('--no-new-privs',args)
            self.assertFalse(any(x == '--bounding-set' or x.startswith('--bounding-set=')
                                 for x in args))
            # Numeric indices also cover capabilities newer than Focal's
            # build-time headers; setpriv 2.34 rejects the "all" alias there.
            last_cap=int(Path('/proc/sys/kernel/cap_last_cap').read_text())
            for option in ('--inh-caps=', '--ambient-caps='):
                value=next(x[len(option):] for x in args if x.startswith(option))
                self.assertEqual(set(value.split(',')),
                                 {f'-cap_{i}' for i in range(last_cap+1)})
            inherited = next(line.split()[1] for line in
                             Path('/proc/self/status').read_text().splitlines()
                             if line.startswith('CapBnd:'))
            self.assertEqual(args[args.index('dev-session-user') + 1:],
                             ['1000', inherited, 'https://example.test', '/',
                              '/usr/bin/printf', '$HOME'])

    def test_bootstrap_environment_finds_read_only_sbin_tool(self):
        if not any(os.access(p, os.X_OK) for p in ('/usr/sbin/sysctl', '/sbin/sysctl')):
            self.skipTest('sysctl is not installed in a system sbin directory')
        p = run('attach_group() { :; }; '
                'REQUEST=(developer 1000 1000 /home/developer / pipe none xterm https://example.test /bin/true); '
                'bootstrap_workload "$1"; printf "%s\\0" "${DROP_ARGS[@]}"', 'a'*32)
        self.assertEqual(p.returncode, 0, p.stderr)
        args = p.stdout.split('\0')[:-1]
        start = args.index('/usr/bin/env')
        end = args.index('/bin/bash', start)
        # Exercise the actual sanitized environment without starting a service
        # or changing credentials, networking, or the sysctl value.
        result = subprocess.run(args[start:end] + ['/bin/sh', '-c', 'sysctl -n kernel.ostype'],
                                text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), Path('/proc/sys/kernel/ostype').read_text().strip())

    def test_session_identifiers_cannot_name_foreign_units_or_paths(self):
        for bad in ('', '../other', 'abc.service', 'a'*31, 'a'*33, 'A'*32, 'a'*32+'\n'):
            self.assertNotEqual(run('valid_session_id "$1"', bad).returncode, 0, repr(bad))
        self.assertEqual(run('valid_session_id "$1"', 'b'*32).returncode, 0)

    def test_cleanup_only_removes_empty_exact_session_group(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); owned=root/('a'*32); other=root/('b'*32)
            owned.mkdir(); other.mkdir()
            (owned/'cgroup.procs').write_text('')
            (other/'cgroup.procs').write_text('123\n')
            # Real regular directories cannot emulate virtual cgroup files;
            # only rmdir is replaced and records its exact target.
            p = run('CGROOT="$1"; rmdir() { printf "removed:%s\\n" "$*"; }; cleanup_group "$2"', root, 'a'*32)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.strip(), 'removed:-- '+str(owned))
            (owned/'cgroup.procs').write_text('99\n')
            p = run('CGROOT="$1"; rmdir() { echo BAD; }; cleanup_group "$2"', root, 'a'*32)
            self.assertNotEqual(p.returncode, 0)
            self.assertNotIn('BAD', p.stdout)
            p = run('CGROOT="$1"; cleanup_group "$2"', root, 'c'*32)
            self.assertEqual(p.returncode, 0)

    def test_cleanup_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/('a'*32)).symlink_to(root)
            p = run('CGROOT="$1"; cleanup_group "$2"', root, 'a'*32)
            self.assertNotEqual(p.returncode, 0)

    def test_cleanup_tolerates_concurrent_removal_but_not_other_failures(self):
        for boundary,removed in [('cat',True),('rmdir',True),('rmdir',False)]:
            with self.subTest(boundary=boundary,removed=removed), tempfile.TemporaryDirectory() as td:
                path=Path(td)/('a'*32);path.mkdir();(path/'cgroup.procs').write_text('')
                replacement='command rm -rf -- "$CGROOT/$sid"; ' if removed else ''
                p=run('CGROOT="$1"; sid="$2"; '+boundary+'() { '+replacement+'return 1; }; cleanup_group "$sid"',td,'a'*32)
                self.assertEqual(p.returncode==0,removed,p.stderr)

    def test_stopped_group_retries_only_busy_state_with_a_finite_bound(self):
        for outcomes,success in [('2 2 0',True),('1',False),('2',False)]:
            p=run('calls=0; sleeps=0; outcomes=($1); '
                  'cleanup_group() { calls=$((calls+1)); i=$((calls-1)); '
                  '(( i < ${#outcomes[@]} )) || i=$((${#outcomes[@]}-1)); return "${outcomes[i]}"; }; '
                  'sleep() { sleeps=$((sleeps+1)); }; '
                  'status=0; reclaim_stopped_group "$2" || status=$?; '
                  'printf "%s %s %s\\n" "$status" "$calls" "$sleeps"',outcomes,'a'*32)
            self.assertEqual(p.returncode,0,p.stderr)
            status,calls,sleeps=map(int,p.stdout.split())
            self.assertEqual(status==0,success,p.stderr)
            self.assertLessEqual(calls,100)
            if outcomes=='1':self.assertEqual(sleeps,0)
            if success:self.assertEqual(calls,3)

    def test_unit_uses_native_lifecycle_and_does_not_restart_workload(self):
        p = run('ROOT=/opt/dev-session; unit_arguments "$1" pty; printf "%s\\0" "${UNIT_ARGS[@]}"', 'a'*32)
        self.assertEqual(p.returncode, 0, p.stderr)
        args = p.stdout.split('\0')[:-1]
        for value in ('--pty', '--wait', '--collect', '--service-type=exec',
                      '--property=KillMode=control-group', '--property=Restart=no',
                      '--property=NoNewPrivileges=yes', '--property=TimeoutStopSec=10s'):
            self.assertIn(value,args)
        self.assertIn('--property=ExecStopPost=/opt/dev-session/dev-session --internal-clean '+ 'a'*32,args)
        self.assertIn('--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK',args)
        self.assertFalse(any('--user' == x for x in args))

    def test_failed_probe_never_executes_user_command(self):
        p = run('probe_network() { return 42; }; enter_workload https://example.test / /bin/echo SHOULD_NOT_RUN')
        self.assertNotEqual(p.returncode,0)
        self.assertNotIn('SHOULD_NOT_RUN',p.stdout)

    def test_successful_probe_preserves_argv_literally(self):
        value = 'spaces; $(touch never-created) " literal'
        p = run('probe_network() { :; }; enter_workload https://example.test / /usr/bin/printf "%s" "$1"',value)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(p.stdout,value)

    def test_probe_is_bounded_and_has_no_proxy_or_curlrc_fallback(self):
        p = run('timeout() { printf "%s\\0" "$@"; }; probe_network https://example.test/path')
        self.assertEqual(p.returncode,0,p.stderr)
        args=p.stdout.split('\0')[:-1]
        self.assertEqual(args[0:3],['--signal=KILL','20s','/usr/bin/curl'])
        self.assertIn('-q',args);self.assertIn('--noproxy',args);self.assertIn('*',args)
        self.assertNotIn('-k',args)


if __name__=='__main__': unittest.main()
