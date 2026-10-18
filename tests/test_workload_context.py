"""Behavioral workload-context fixtures; no UID, network or service changes.

The session fixture executes the real bootstrap environment and generated
helper. Only cgroup attachment, credential checking, and the network probe are
replaced, because this executor cannot provide the target host boundaries.
"""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PYTHON = ['/usr/bin/env', 'PYTHONCOERCECLOCALE=0', 'PYTHONUTF8=0',
          '/usr/bin/python3']
LOCALE_NAMES = ('LANG', 'LANGUAGE', 'LC_ALL', 'LC_CTYPE', 'LC_NUMERIC',
                'LC_TIME', 'LC_COLLATE', 'LC_MONETARY', 'LC_MESSAGES',
                'LC_PAPER', 'LC_NAME', 'LC_ADDRESS', 'LC_TELEPHONE',
                'LC_MEASUREMENT', 'LC_IDENTIFICATION', 'TZ')
DESKTOP_NAMES = ('DISPLAY', 'XAUTHORITY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR',
                 'DBUS_SESSION_BUS_ADDRESS', 'XDG_SESSION_TYPE',
                 'XDG_CURRENT_DESKTOP')
CONTEXT_NAMES = LOCALE_NAMES + DESKTOP_NAMES
UNSAFE_NAMES = ('DBUS_SYSTEM_BUS_ADDRESS', 'DOCKER_HOST', 'SYSTEMD_PAGER',
                'BASH_ENV', 'ENV', 'LOCPATH', 'GCONV_PATH', 'SSH_AUTH_SOCK')


def environment_probe(names=CONTEXT_NAMES):
    code = ('import json,os; print(json.dumps('
            '{name:os.environ.get(name) for name in ' + repr(tuple(names)) + '}))')
    return PYTHON + ['-c', code]


def workload(payload, *, context=(), mask='0022', target='65534', caller='65534',
             cwd='/', fail_probe=False, trace=False):
    script = r'''
set -euo pipefail
root=$1 target=$2 caller=$3 mask=$4 count=$5 cwd=$6 fail_probe=$7 trace=$8
shift 8
context=("${@:1:count}"); shift "$count"
workload=("$@")
source "$root/lib/session.sh"
if [[ -f $root/lib/context.sh ]]; then source "$root/lib/context.sh"; fi
umask 077
# Before the enhancement, exercise the actual original workload unchanged.
# This makes missing restoration fail on observed behavior, not source errors.
if declare -F wrap_workload_context >/dev/null; then
    wrap_workload_context "$target" "$caller" "$mask" "${context[@]}"
fi
attach_group() { :; }
user_checks() { :; }
probe_network() { :; }
if [[ $trace == yes ]]; then
    printf 'CONTEXT_ROOT %s %s %s %s %s\n' "${LC_ALL-unset}" "${LANG-unset}" \
        "${DISPLAY-unset}" "${DBUS_SESSION_BUS_ADDRESS-unset}" "$(umask)"
    user_checks() {
        printf 'CONTEXT_CHECK %s %s %s %s %s\n' "${LC_ALL-unset}" "${LANG-unset}" \
            "${DISPLAY-unset}" "${DBUS_SESSION_BUS_ADDRESS-unset}" "$(umask)"
    }
    probe_network() {
        printf 'CONTEXT_PROBE %s %s %s %s %s\n' "${LC_ALL-unset}" "${LANG-unset}" \
            "${DISPLAY-unset}" "${DBUS_SESSION_BUS_ADDRESS-unset}" "$(umask)"
    }
fi
if [[ $fail_probe == yes ]]; then
    if [[ $trace == yes ]]; then
        probe_network() {
            printf 'CONTEXT_PROBE %s %s %s %s %s\n' "${LC_ALL-unset}" "${LANG-unset}" \
                "${DISPLAY-unset}" "${DBUS_SESSION_BUS_ADDRESS-unset}" "$(umask)"
            return 42
        }
    else
        probe_network() { return 42; }
    fi
fi
REQUEST=(fixture "$target" 65534 "$cwd" "$cwd" pipe none xterm
         https://example.test "${workload[@]}")
bootstrap_workload aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# Execute the actual clean environment and Bash helper, omitting only setpriv.
for ((start=0; start<${#DROP_ARGS[@]}; start++)); do
    [[ ${DROP_ARGS[start]} != /usr/bin/env ]] || break
done
(( start < ${#DROP_ARGS[@]} ))
exec "${DROP_ARGS[@]:start}"
'''
    return subprocess.run(
        ['/bin/bash', '-p', '-c', script, 'context-fixture', str(ROOT),
         target, caller, mask, str(len(context)), str(cwd),
         'yes' if fail_probe else 'no', 'yes' if trace else 'no', *context, *payload],
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
             'HOME': '/root', 'TERM': 'xterm'},
        capture_output=True, text=True, timeout=10)


def context_function(body, *args):
    script = ('set -euo pipefail; root=$1; shift; '
              'if [[ -f $root/lib/context.sh ]]; then source "$root/lib/context.sh"; fi; '
              + body)
    return subprocess.run(['/bin/bash', '-p', '-c', script, 'context-function',
                           str(ROOT), *args], capture_output=True, text=True,
                          env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, timeout=10)


def launch_snapshot(context, *, cli=('--', '/bin/true'), mask='0027'):
    """Run the real snapshot/env-i/argv boundary with a harmless clean loader."""
    launcher = (ROOT / 'dev-session').read_text()
    prefix, marker, rest = launcher.partition("/bin/bash -p -c '")
    if not marker:
        raise AssertionError('The launcher clean-loader boundary was not found')
    ignored, marker, suffix = rest.rpartition("\n' dev-session ")
    if not marker:
        raise AssertionError('The launcher clean-loader argument boundary was not found')
    inspected = CONTEXT_NAMES + UNSAFE_NAMES + ('PATH', 'HOME', 'TERM', 'SUDO_UID')
    probe = ('import json,os,sys; print(json.dumps({'
             '"argv":sys.argv[1:],"environment":'
             '{name:os.environ.get(name) for name in ' + repr(inspected) + '}}))')
    # Keep all arguments generated by the real entrypoint. Only the trusted
    # loader body is replaced, so no installation or host policy is inspected.
    recorder = 'shift; exec /usr/bin/python3 -c ' + shlex.quote(probe) + ' "$@"'
    instrumented = prefix + '/bin/bash -p -c ' + shlex.quote(recorder) + ' dev-session ' + suffix
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/synthetic-caller-home',
           'TERM': 'xterm-256color', 'SUDO_UID': '65534'}
    env.update({name: '/synthetic-untrusted/' + name for name in UNSAFE_NAMES})
    env.update(context)
    with tempfile.TemporaryDirectory(prefix='context-launcher-') as td:
        entry = Path(td) / 'entry'
        entry.write_text(instrumented)
        p = subprocess.run(
            ['/bin/bash', '-p', '-c', 'umask "$1"; shift; exec /bin/bash -p "$@"',
             'snapshot-fixture', mask, str(entry), *cli],
            env=env, capture_output=True, text=True, timeout=10)
    return p


class WorkloadContextTests(unittest.TestCase):
    def test_c_locale_is_restored_as_actual_non_utf8_codeset(self):
        expected = subprocess.run(
            ['/usr/bin/locale', 'charmap'],
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C'},
            capture_output=True, text=True, check=True).stdout
        p = workload(['/usr/bin/locale', 'charmap'], context=['LANG=C'])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, expected,
                         'The workload still uses the bootstrap locale')

    def test_caller_umask_controls_real_file_and_directory_creation(self):
        probe = ("import json,pathlib,stat; "
                 "pathlib.Path('file').touch(); pathlib.Path('directory').mkdir(); "
                 "print(json.dumps([stat.S_IMODE(pathlib.Path(p).stat().st_mode) "
                 "for p in ('file','directory')]))")
        cases = [('0000', 0o666, 0o777), ('0002', 0o664, 0o775),
                 ('0022', 0o644, 0o755), ('027', 0o640, 0o750),
                 ('0077', 0o600, 0o700)]
        for mask, file_mode, directory_mode in cases:
            with self.subTest(mask=mask), tempfile.TemporaryDirectory(prefix='context-modes-') as td:
                p = workload(PYTHON + ['-c', probe], mask=mask, cwd=td)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(json.loads(p.stdout), [file_mode, directory_mode],
                                 'The workload did not restore the requested creation mask')

    def test_locale_category_and_lc_all_precedence_match_native_locale(self):
        for values in ({'LANG': 'C', 'LC_CTYPE': 'C.UTF-8'},
                       {'LANG': 'C.UTF-8', 'LC_CTYPE': 'C.UTF-8', 'LC_ALL': 'C'}):
            with self.subTest(values=values):
                expected = subprocess.run(
                    ['/usr/bin/locale', 'charmap'],
                    env=dict({'PATH': '/usr/bin:/bin'}, **values),
                    capture_output=True, text=True, check=True).stdout
                p = workload(['/usr/bin/locale', 'charmap'],
                             context=[name + '=' + value for name, value in values.items()])
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout, expected)

    def test_timezone_changes_actual_date_offset(self):
        expected = subprocess.run(['/usr/bin/date', '+%z'],
                                  env={'PATH': '/usr/bin:/bin', 'TZ': 'UTC-09'},
                                  capture_output=True, text=True, check=True).stdout
        p = workload(['/usr/bin/date', '+%z'], context=['TZ=UTC-09'])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, expected)

    def test_unset_context_stays_unset_including_bootstrap_lang(self):
        p = workload(environment_probe())
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), dict.fromkeys(CONTEXT_NAMES))

    def test_empty_context_values_remain_present_and_empty(self):
        p = workload(environment_probe(), context=[name + '=' for name in CONTEXT_NAMES])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), dict.fromkeys(CONTEXT_NAMES, ''))

    def test_same_account_receives_all_desktop_context_as_literal_data(self):
        values = {
            'DISPLAY': 'localhost:42.7',
            'XAUTHORITY': '/synthetic path/authority = file',
            'WAYLAND_DISPLAY': '/synthetic path/wayland socket',
            'XDG_RUNTIME_DIR': '/synthetic runtime directory',
            'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/synthetic path/bus,guid=fixture',
            'XDG_SESSION_TYPE': 'wayland',
            'XDG_CURRENT_DESKTOP': 'GNOME:Unity',
        }
        p = workload(environment_probe(DESKTOP_NAMES),
                     context=[name + '=' + value for name, value in values.items()])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), values)

    def test_other_or_unknown_caller_does_not_transfer_desktop_context(self):
        values = {'LANG': 'C', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC-09'}
        values.update({name: 'synthetic-' + name for name in DESKTOP_NAMES})
        for caller in ('65533', '', '0'):
            with self.subTest(caller=caller):
                p = workload(environment_probe(), caller=caller,
                             context=[name + '=' + value for name, value in values.items()])
                self.assertEqual(p.returncode, 0, p.stderr)
                expected = dict.fromkeys(CONTEXT_NAMES)
                expected.update({name: value for name, value in values.items()
                                 if name in LOCALE_NAMES})
                self.assertEqual(json.loads(p.stdout), expected)

    def test_environment_and_payload_metacharacters_are_never_evaluated(self):
        with tempfile.TemporaryDirectory(prefix='context-literals-') as td:
            marker = Path(td) / 'must-not-exist'
            literal = '$(touch ' + shlex.quote(str(marker)) + '); " $HOME `id`\nnext = value'
            argv = [literal, '', '-n', 'a=b=c']
            code = ('import json,os,sys; print(json.dumps({'
                    '"argv":sys.argv[1:],"authority":os.environ.get("XAUTHORITY"),'
                    '"bus":os.environ.get("DBUS_SESSION_BUS_ADDRESS")}))')
            p = workload(PYTHON + ['-c', code, *argv], cwd=td,
                         context=['LANG=C.UTF-8', 'XAUTHORITY=' + literal,
                                  'DBUS_SESSION_BUS_ADDRESS=' + literal])
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(p.stdout),
                             {'argv': argv, 'authority': literal, 'bus': literal})
            self.assertFalse(marker.exists(), 'Context data was executed as shell code')

    def test_restore_clears_contaminated_context_without_erasing_user_identity(self):
        assignments = ' '.join(name + '=' + shlex.quote('stale-' + name)
                               for name in DESKTOP_NAMES)
        body = ('export LANG=C LC_ALL=C LC_TIME=C TZ=UTC-09 HOME=/synthetic-home USER=fixture '
                + assignments + '; '
                'if declare -F restore_workload_context >/dev/null; then '
                'restore_workload_context "$@"; else shift 2; exec "$@"; fi')
        p = context_function(body, '0022', '0',
                             *environment_probe(CONTEXT_NAMES + ('HOME', 'USER')))
        self.assertEqual(p.returncode, 0, p.stderr)
        expected = dict.fromkeys(CONTEXT_NAMES)
        expected.update(HOME='/synthetic-home', USER='fixture')
        self.assertEqual(json.loads(p.stdout), expected)

    def test_context_is_restored_only_after_clean_admission_and_probe(self):
        p = workload(environment_probe(('LANG', 'LC_ALL', 'DISPLAY', 'DBUS_SESSION_BUS_ADDRESS')),
                     context=['LANG=C', 'LC_ALL=C', 'DISPLAY=:4242',
                              'DBUS_SESSION_BUS_ADDRESS=unix:path=/synthetic/bus'],
                     mask='0022', trace=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = p.stdout.splitlines()
        self.assertEqual(lines[:3], [
            'CONTEXT_ROOT C unset unset unset 0077',
            'CONTEXT_CHECK unset C.UTF-8 unset unset 0077',
            'CONTEXT_PROBE unset C.UTF-8 unset unset 0077',
        ])
        self.assertEqual(len(lines), 4, p.stdout)
        self.assertEqual(json.loads(lines[3]), {
            'LANG': 'C', 'LC_ALL': 'C', 'DISPLAY': ':4242',
            'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/synthetic/bus',
        })

    def test_failed_probe_never_starts_wrapped_payload(self):
        with tempfile.TemporaryDirectory(prefix='context-probe-') as td:
            marker = Path(td) / 'payload-started'
            p = workload(['/usr/bin/touch', str(marker)], cwd=td,
                         context=['LANG=C', 'DISPLAY=:4242'], mask='0000',
                         fail_probe=True, trace=True)
            self.assertEqual(p.returncode, 125, p.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(p.stdout.splitlines(), [
                'CONTEXT_ROOT C unset unset unset 0077',
                'CONTEXT_CHECK unset C.UTF-8 unset unset 0077',
                'CONTEXT_PROBE unset C.UTF-8 unset unset 0077',
            ])
            self.assertIn('network probe failed', p.stderr)

    def test_request_file_remains_private_under_permissive_caller_mask(self):
        with tempfile.TemporaryDirectory(prefix='context-request-') as td:
            requests = Path(td) / 'requests'
            requests.mkdir()
            body = ('source "$root/lib/host.sh"; RUNTIME=$1; umask 0000; '
                    'write_request aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa literal; '
                    'stat -c %a "$RUNTIME/requests/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"')
            p = context_function(body, td)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.strip(), '600')


class ContextPrefixTests(unittest.TestCase):
    def test_context_kind_accepts_exact_allowlist_and_rejects_other_names(self):
        body = ('declare -F context_kind >/dev/null || exit 1; '
                'context_kind "$1"')
        for expected, names in [('locale', LOCALE_NAMES), ('desktop', DESKTOP_NAMES)]:
            for name in names:
                with self.subTest(name=name):
                    p = context_function(body, name)
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertEqual(p.stdout.strip(), expected)
        for name in UNSAFE_NAMES + ('PATH', 'HOME', 'USER', 'LOGNAME', 'LC_UNKNOWN',
                                    'DISPLAY=x', 'LANG\nHOME', ''):
            with self.subTest(rejected=name):
                self.assertNotEqual(context_function(body, name).returncode, 0)

    def parse_prefix(self, *args):
        return context_function(
            'if ! declare -F read_context >/dev/null; then printf "UNPARSED\\0"; exit 0; fi; '
            'read_context "$@"; printf "%s\\0" "$CONTEXT_UMASK" "$CONTEXT_SHIFT" '
            '"${CONTEXT_ENV[@]}"; shift "$CONTEXT_SHIFT"; '
            'if (( $# )); then printf "%s\\0" "$@"; fi', *args)

    def test_prefix_consumption_preserves_empty_values_and_literal_cli(self):
        entries = ['LANG=C', 'DISPLAY=', 'XAUTHORITY=/synthetic = path\nnext']
        cli = ['--', '/usr/bin/printf', '%s', '$(not executed); a b', '']
        p = self.parse_prefix('027', str(len(entries)), *entries, *cli)
        self.assertEqual(p.returncode, 0, p.stderr)
        fields = p.stdout.split('\0')[:-1]
        self.assertGreaterEqual(len(fields), 2, 'The context prefix was not consumed')
        self.assertEqual(int(fields[0], 8), 0o027)
        self.assertEqual(fields[1:], ['5', *entries, *cli])

    def test_empty_prefix_leaves_cli_options_for_the_real_parser(self):
        cli = ['--umask', '0027', '--user', 'nobody', '--', '/bin/true']
        p = self.parse_prefix('0022', '0', *cli)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.split('\0')[:-1], ['0022', '2', *cli])

    def test_malformed_prefix_is_rejected_before_remaining_arguments(self):
        cases = [('', '0'), ('0088', '0'), ('1000', '0'), ('00222', '0'),
                 ('0022', '-1'), ('0022', 'word'), ('0022', '1\n'),
                 ('0022', '99999999999999999999999'), ('0022', '2', 'LANG=C'),
                 ('0022', '1', 'LANG'), ('0022', '1', '=value'),
                 ('0022', '1', 'BASH_ENV=/synthetic'),
                 ('0022', '1', 'LC_UNKNOWN=C'), ('0022', '1', 'LANG\nHOME=x')]
        for args in cases:
            with self.subTest(args=args):
                p = context_function(
                    'declare -F read_context >/dev/null || exit 1; '
                    'read_context "$@"; echo ARGUMENTS_ACCEPTED', *args)
                self.assertNotEqual(p.returncode, 0)
                self.assertNotIn('ARGUMENTS_ACCEPTED', p.stdout)


@unittest.skipUnless(os.geteuid() == 0, 'the real entrypoint requires root')
class ContextSnapshotTests(unittest.TestCase):
    parse_prefix = ContextPrefixTests.parse_prefix

    def snapshot(self):
        values = dict.fromkeys(LOCALE_NAMES, 'C')
        values.update(LANGUAGE='en_US:zh_TW', LC_ALL='', TZ='UTC-09')
        values.update({name: 'synthetic ' + name + '=literal\nsecond line'
                       for name in DESKTOP_NAMES})
        cli = ['--umask', '0022', '--', '/usr/bin/printf', '%s', '$HOME; literal', '']
        p = launch_snapshot(values, cli=cli)
        self.assertEqual(p.returncode, 0, p.stderr)
        return values, cli, json.loads(p.stdout)

    def test_snapshot_is_literal_prefix_consumable_before_main_cli(self):
        values, cli, result = self.snapshot()
        args = result['argv']
        self.assertGreaterEqual(len(args), 2)
        self.assertRegex(args[0], r'^[0-7]{3,4}$', 'Incoming umask was not snapshotted')
        self.assertEqual(int(args[0], 8), 0o027)
        self.assertRegex(args[1], r'^[0-9]+$')
        count = int(args[1])
        self.assertEqual(count, len(values))
        observed = dict(entry.split('=', 1) for entry in args[2:2 + count])
        self.assertEqual(observed, values)
        self.assertEqual(args[2 + count:], cli)
        parsed = self.parse_prefix(*args)
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        fields = parsed.stdout.split('\0')[:-1]
        self.assertEqual(fields[1], str(2 + count))
        self.assertEqual(fields[2:2 + count], args[2:2 + count])
        self.assertEqual(fields[2 + count:], cli)

    def test_root_loader_receives_only_fixed_active_environment(self):
        ignored_values, ignored_cli, result = self.snapshot()
        env = result['environment']
        self.assertEqual(env['LC_ALL'], 'C')
        self.assertEqual(env['PATH'], '/usr/sbin:/usr/bin:/sbin:/bin')
        self.assertEqual(env['HOME'], '/root')
        self.assertEqual(env['TERM'], 'xterm-256color')
        self.assertEqual(env['SUDO_UID'], '65534')
        for name in CONTEXT_NAMES + UNSAFE_NAMES:
            if name != 'LC_ALL':
                self.assertIsNone(env[name], name + ' reached the privileged loader')

    def test_snapshot_distinguishes_unset_from_explicitly_empty(self):
        for context, expected in [({}, {}), ({'DISPLAY': '', 'LANG': ''},
                                             {'DISPLAY': '', 'LANG': ''})]:
            with self.subTest(context=context):
                p = launch_snapshot(context)
                self.assertEqual(p.returncode, 0, p.stderr)
                args = json.loads(p.stdout)['argv']
                self.assertGreaterEqual(len(args), 2)
                self.assertRegex(args[1], r'^[0-9]+$', 'Context count was not transmitted')
                count = int(args[1])
                self.assertEqual(dict(entry.split('=', 1) for entry in args[2:2 + count]),
                                 expected)


if __name__ == '__main__':
    unittest.main()
