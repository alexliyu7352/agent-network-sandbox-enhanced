#!/usr/bin/env python3
"""Exercise the public session launcher without installing or invoking sudo.

The sudo recorder resets active environment and umask before executing a
manager recorder. All assertions observe process argv, cwd, or umask. These
are boundary simulations, not sudo authentication or host integration tests.

Use a real nonroot process when one is available. In single-UID executors,
force only the exact EUID guard in a private copy to take the caller branch.
Root passthrough executes the original guard and real launcher shebang.
"""
import functools
import json
import os
from pathlib import Path
import pwd
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'session-launcher'
ROOT_GUARD = 'if (( EUID == 0 )); then'
LOCALE_NAMES = ('LANG', 'LANGUAGE', 'LC_ALL', 'LC_CTYPE', 'LC_NUMERIC',
                'LC_TIME', 'LC_COLLATE', 'LC_MONETARY', 'LC_MESSAGES',
                'LC_PAPER', 'LC_NAME', 'LC_ADDRESS', 'LC_TELEPHONE',
                'LC_MEASUREMENT', 'LC_IDENTIFICATION', 'TZ')
DESKTOP_NAMES = ('DISPLAY', 'XAUTHORITY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR',
                 'DBUS_SESSION_BUS_ADDRESS', 'XDG_SESSION_TYPE',
                 'XDG_CURRENT_DESKTOP')
CONTEXT_NAMES = LOCALE_NAMES + DESKTOP_NAMES

ENCODER = '''#!/usr/bin/python3
import json, os, sys
def emit(fields):
    sys.stdout.buffer.write(b''.join(os.fsencode(field) + b'\\0' for field in fields))
    sys.stdout.buffer.flush()
'''


def _drop_identity(identity):
    os.setgroups([])
    os.setgid(identity[1])
    os.setuid(identity[0])


def _id_is_mapped(kind, value):
    path = Path('/proc/self/' + kind + '_map')
    if not path.exists():
        return True
    return any(start <= value < start + count
               for start, ignored, count in
               (map(int, line.split()) for line in path.read_text().splitlines()))


@functools.lru_cache(maxsize=1)
def _nonroot_execution():
    if os.geteuid() != 0:
        return None, False
    accounts = sorted(pwd.getpwall(), key=lambda item: (item.pw_uid < 1000, item.pw_uid))
    for account in accounts:
        identity = (account.pw_uid, account.pw_gid)
        if (identity[0] == 0 or not _id_is_mapped('uid', identity[0])
                or not _id_is_mapped('gid', identity[1])):
            continue
        try:
            probe = subprocess.run(
                ['/bin/bash', '-p', '-c', '(( EUID != 0 ))'],
                env={'PATH': '/usr/bin:/bin'}, cwd='/',
                preexec_fn=lambda: _drop_identity(identity),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0:
            return identity, False
    return None, True


class LauncherFixture:
    def __init__(self, test, root=False, manager_status=0):
        test.assertTrue(TEMPLATE.is_file(),
                        'Plain session needs a launcher before sudo changes caller context')
        temporary = tempfile.TemporaryDirectory(prefix='session-launcher-')
        test.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.base.chmod(0o755)
        self.home = self.base / 'home'
        self.home.mkdir(mode=0o755)
        self.home.chmod(0o755)
        self.cwd = self.base / 'work'
        self.cwd.mkdir(mode=0o755)
        self.cwd.chmod(0o755)
        self.effects = self.base / 'effects'
        self.effects.mkdir()
        self.effects.chmod(0o777)
        self.manager = self.base / 'manager-recorder'
        self.sudo = self.base / 'sudo-recorder'
        self.launcher = self.base / 'session'
        self.identity, simulate = (None, False) if root else _nonroot_execution()
        self.mode = 'simulated EUID branch' if simulate else 'actual process identity'

        manager = ENCODER + '''
mask = os.umask(0)
os.umask(mask)
try:
    cwd = os.getcwd()
except OSError:
    cwd = ''
emit(['manager', cwd, format(mask, '04o'),
      json.dumps({name: os.environ.get(name) for name in CONTEXT_NAMES}),
      str(len(sys.argv) - 1)] + sys.argv[1:])
sys.exit(MANAGER_STATUS)
'''
        manager = manager.replace('CONTEXT_NAMES', repr(CONTEXT_NAMES))
        manager = manager.replace('MANAGER_STATUS', str(manager_status))
        self.executable(self.manager, manager)
        # Record actual launcher output, then model sudo's environmental
        # changes. Never execute any destination except our private recorder.
        sudo = ENCODER + '''
args = sys.argv[1:]
emit(['sudo', str(len(args))] + args)
if len(args) < 2 or args[:2] != ['--', EXPECTED_MANAGER]:
    sys.exit(96)
os.umask(0o077)
os.execve(EXPECTED_MANAGER, args[1:], {
    'PATH': '/usr/bin:/bin', 'HOME': '/synthetic-sudo-home',
    'LANG': 'C', 'LC_ALL': 'C', 'PYTHONCOERCECLOCALE': '0'})
'''
        self.executable(self.sudo, sudo.replace('EXPECTED_MANAGER', repr(str(self.manager))))
        source = TEMPLATE.read_text()
        # These exact fixture substitutions are the only source edits. Fail
        # setup if the boundary moves, rather than silently invoking host sudo.
        for token in ('@SESSION_MANAGER@', '/usr/bin/sudo'):
            if source.count(token) != 1:
                raise AssertionError('Launcher fixture needs one boundary token: ' + token)
        source = source.replace('@SESSION_MANAGER@', str(self.manager))
        source = source.replace('/usr/bin/sudo', shlex.quote(str(self.sudo)))
        if simulate:
            if source.count(ROOT_GUARD) != 1:
                raise AssertionError('Cannot safely simulate the launcher EUID boundary')
            source = source.replace(ROOT_GUARD, 'if false; then')
        self.executable(self.launcher, source)

    @staticmethod
    def executable(path, source):
        path.write_text(source)
        path.chmod(0o755)

    def run(self, argv=(), values=None, mask=0o027, cwd=None, extra_env=None,
            remove_cwd=False):
        cwd = self.cwd if cwd is None else Path(cwd)
        if remove_cwd:
            # subprocess enters this fixture-owned directory before preexec.
            # Remove it in the child to reproduce a genuinely detached cwd.
            cwd = self.base / 'removed-working-directory'
            cwd.mkdir(mode=0o755)
            cwd.chmod(0o755)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.home), 'PWD': str(cwd),
               'PYTHONCOERCECLOCALE': '0'}
        env.update(values or {})
        env.update(extra_env or {})

        def prepare_child():
            os.umask(mask)
            if remove_cwd:
                os.rmdir(str(cwd))
            if self.identity is not None:
                _drop_identity(self.identity)

        # Execute the file itself so the production shebang is exercised.
        # preexec_fn keeps this fixture compatible with Python 3.8, which
        # does not have subprocess's umask/user/group keyword arguments.
        return subprocess.run([str(self.launcher), *argv], cwd=str(cwd), env=env,
                              preexec_fn=prepare_child, capture_output=True, timeout=10)


class SessionLauncherTests(unittest.TestCase):
    def test_public_launcher_template_is_available(self):
        self.assertTrue(TEMPLATE.is_file(),
                        'Plain session needs a launcher before sudo changes caller context')

    def observe(self, fixture, expected_status=0, **kwargs):
        result = fixture.run(**kwargs)
        self.assertEqual(result.returncode, expected_status,
                         fixture.mode + ': ' + os.fsdecode(result.stderr))
        self.assertTrue(result.stdout.endswith(b'\0'), repr(result.stdout))
        fields = [os.fsdecode(field) for field in result.stdout.split(b'\0')[:-1]]
        sudo_args = None
        if fields[0] == 'sudo':
            count = int(fields[1])
            sudo_args, fields = fields[2:2 + count], fields[2 + count:]
        self.assertGreaterEqual(len(fields), 5, fields)
        self.assertEqual(fields[0], 'manager')
        self.assertEqual(int(fields[4]), len(fields[5:]))
        return {'sudo': sudo_args, 'cwd': fields[1], 'mask': int(fields[2], 8),
                'environment': json.loads(fields[3]), 'argv': fields[5:]}

    def caller_context(self, fixture, observed):
        args = observed['argv']
        self.assertEqual(observed['sudo'], ['--', str(fixture.manager), *args])
        self.assertGreaterEqual(len(args), 5)
        self.assertEqual(args[0], '--caller-context')
        self.assertRegex(args[1], r'^0?[0-7]{3}$')
        self.assertRegex(args[3], r'^[0-9]+$')
        count = int(args[3])
        self.assertGreaterEqual(len(args), 5 + count)
        entries = args[4:4 + count]
        self.assertEqual(args[4 + count], '--')
        values = dict(entry.split('=', 1) for entry in entries)
        self.assertEqual(len(values), count, 'Context has duplicate variable names')
        return int(args[1], 8), args[2], values, args[5 + count:]

    def test_nonroot_boundary_captures_umask_before_sudo_changes_it(self):
        fixture = LauncherFixture(self)
        for mask in (0o000, 0o002, 0o027, 0o077):
            with self.subTest(mask=oct(mask), mode=fixture.mode):
                observed = self.observe(fixture, mask=mask)
                captured, cwd, values, argv = self.caller_context(fixture, observed)
                self.assertEqual(captured, mask)
                self.assertEqual(observed['mask'], 0o077)
                self.assertEqual(argv, [])

    def test_nonroot_boundary_distinguishes_unset_and_empty_context(self):
        fixture = LauncherFixture(self)
        for expected in ({}, dict.fromkeys(CONTEXT_NAMES, '')):
            with self.subTest(values=expected, mode=fixture.mode):
                observed = self.observe(fixture, values=expected)
                captured, cwd, values, argv = self.caller_context(fixture, observed)
                self.assertEqual(values, expected)
                self.assertEqual(observed['environment']['LC_ALL'], 'C')

    def test_nonroot_boundary_preserves_literal_environment_and_argv(self):
        fixture = LauncherFixture(self)
        marker = fixture.effects / 'must-not-exist'
        literal = '$(/usr/bin/touch ' + shlex.quote(str(marker)) + '); "$HOME" `id`\nnext = value'
        values = dict.fromkeys(LOCALE_NAMES, 'C')
        values.update(LANGUAGE='en_US:zh_TW', LC_ALL='', TZ='UTC-09')
        values.update({name: literal for name in DESKTOP_NAMES})
        argv = ['--user', 'example user', '--', '/usr/bin/printf', '%s',
                literal, '', '-n', 'a=b=c', '*', '\t']
        observed = self.observe(fixture, values=values, argv=argv)
        captured, cwd, context, original = self.caller_context(fixture, observed)
        self.assertEqual(context, values)
        self.assertEqual(original, argv)
        self.assertIsNone(observed['environment']['DISPLAY'])
        self.assertFalse(marker.exists(), 'Literal caller data was evaluated as shell code')

    def test_nonroot_boundary_forwards_only_the_finite_context_allowlist(self):
        fixture = LauncherFixture(self)
        unrelated = {name: 'synthetic-' + name for name in (
            'LC_UNLISTED_CATEGORY', 'DBUS_SYSTEM_BUS_ADDRESS', 'DOCKER_HOST',
            'SYSTEMD_PAGER', 'GCONV_PATH', 'LOCPATH', 'SSH_AUTH_SOCK',
            'ENV', 'SUDO_UID', 'SUDO_GID', 'SUDO_USER', 'USER', 'LOGNAME',
            'SESSION_MANAGER', 'manager')}
        expected = {'LANG': 'C', 'DISPLAY': ':42.7'}
        observed = self.observe(fixture, values=expected, extra_env=unrelated)
        captured, cwd, values, argv = self.caller_context(fixture, observed)
        self.assertEqual(values, expected)

    def test_nonroot_boundary_keeps_physical_cwd_including_trailing_newline(self):
        fixture = LauncherFixture(self)
        physical = fixture.base / 'actual working directory\nsecond line\n'
        physical.mkdir(mode=0o755)
        physical.chmod(0o755)
        logical = fixture.base / 'logical work link'
        logical.symlink_to(physical, target_is_directory=True)
        observed = self.observe(fixture, cwd=logical)
        captured, cwd, values, argv = self.caller_context(fixture, observed)
        self.assertEqual(cwd, str(physical), 'Caller cwd was changed or truncated')
        self.assertEqual(observed['cwd'], str(physical), 'Launcher changed cwd before sudo')

    def test_nonroot_boundary_forwards_help_admin_and_cwd_override_from_removed_cwd(self):
        fixture = LauncherFixture(self)
        values = {'LANG': 'C', 'DISPLAY': ''}
        cases = [['--help'], ['status'],
                 ['--cwd', str(fixture.home), '--', '/bin/printf', 'literal $HOME', '']]
        for argv in cases:
            with self.subTest(argv=argv, mode=fixture.mode):
                observed = self.observe(fixture, argv=argv, values=values, remove_cwd=True)
                captured, cwd, context, original = self.caller_context(fixture, observed)
                self.assertEqual(cwd, '', 'Missing physical cwd needs an empty sentinel')
                self.assertEqual(observed['cwd'], '', 'Fixture cwd was not actually removed')
                self.assertEqual(context, values)
                self.assertEqual(original, argv)

    def test_nonroot_boundary_ignores_ambient_shell_hooks_and_path_helpers(self):
        fixture = LauncherFixture(self)
        marker = fixture.effects / 'ambient-code-ran'
        startup = fixture.base / 'bash-startup'
        startup.write_text('/usr/bin/touch ' + shlex.quote(str(marker)) + '\n')
        startup.chmod(0o644)
        poison = fixture.base / 'path'
        poison.mkdir(mode=0o755)
        poison.chmod(0o755)
        for name in ('sudo', 'umask', 'pwd'):
            fixture.executable(poison / name,
                               '#!/bin/sh\n/usr/bin/touch ' + shlex.quote(str(marker))
                               + '\nexit 97\n')
        observed = self.observe(fixture, mask=0o027, extra_env={
            'PATH': str(poison) + ':/usr/bin:/bin', 'BASH_ENV': str(startup),
            'BASH_FUNC_umask%%': '() { builtin printf 0000; }',
            'BASH_FUNC_pwd%%': '() { builtin printf /wrong-directory; }'})
        captured, cwd, values, argv = self.caller_context(fixture, observed)
        self.assertEqual(captured, 0o027)
        self.assertEqual(cwd, str(fixture.cwd))
        self.assertFalse(marker.exists(), 'Launcher executed an ambient shell hook or helper')

    @unittest.skipUnless(os.geteuid() == 0, 'root passthrough needs an actual root process')
    def test_root_passes_original_args_directly_to_manager_without_sudo(self):
        fixture = LauncherFixture(self, root=True)
        for argv in ([], ['--user', 'fixture', '--', '/bin/printf', '$HOME; literal', '', '\n']):
            with self.subTest(argv=argv):
                observed = self.observe(fixture, argv=argv, mask=0o002)
                self.assertIsNone(observed['sudo'], 'Root invocation recursed through sudo')
                self.assertEqual(observed['argv'], argv)
                self.assertEqual(observed['mask'], 0o002)
                self.assertEqual(observed['cwd'], str(fixture.cwd))

    def test_manager_exit_status_reaches_the_caller(self):
        fixture = LauncherFixture(self, manager_status=23)
        observed = self.observe(fixture, expected_status=23)
        self.caller_context(fixture, observed)


if __name__ == '__main__':
    unittest.main()
