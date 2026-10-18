"""CLI parsing and cwd behavior, without systemd/network mutations."""
import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def parse(*args, caller="65534", cwd=None):
    return subprocess.run([
        "/bin/bash", "-p", "-c",
        'set -euo pipefail; source "$1/lib/host.sh"; '
        'source "$1/lib/cli.sh"; shift; parse_cli "$@"; '
        '[[ $command != run ]] || resolve_account; '
        'printf "%s\\0" "$command" "$user" "$workdir" "${workload[@]}"',
        "test", str(ROOT), *args,
    ], cwd=cwd, env=dict(os.environ, SUDO_UID=caller), capture_output=True, text=True)


class CliTests(unittest.TestCase):
    def test_default_user_and_cwd_come_from_sudo_caller_and_actual_directory(self):
        with tempfile.TemporaryDirectory() as td:
            p = parse(cwd=td)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.split("\0")[:3], ["run", pwd.getpwuid(65534).pw_name, td])

    def test_explicit_account_and_legacy_form_preserve_literal_arguments(self):
        account = pwd.getpwuid(65534).pw_name
        literal = 'a b; $(touch never) "$HOME"'
        for args in [("-u", account, "--", "/bin/echo", literal),
                     ("--user", account, "run", "--cwd", "/", "--", "/bin/echo", literal),
                     ("run", "-u", account, "--cwd", "/", "--", "/bin/echo", literal)]:
            p = parse(*args, caller="", cwd="/")
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.split("\0")[:-1], ["run", account, "/", "/bin/echo", literal])

    def test_explicit_account_does_not_silently_switch_to_its_home(self):
        with tempfile.TemporaryDirectory() as td:
            p = parse("-u", pwd.getpwuid(65534).pw_name, cwd=td)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.split("\0")[2], td)

    def test_root_without_target_user_is_rejected(self):
        for caller in ("", "0", "garbage", "65534\n0"):
            p = parse(caller=caller)
            self.assertEqual(p.returncode, 125, p.stderr)
            self.assertIn("--user", p.stderr)

    def test_root_target_missing_values_and_conflicting_commands_are_rejected(self):
        for args in [("-u", "root"), ("-u",), ("--cwd",),
                     ("--cwd", "relative"), ("status", "extra"),
                     ("-u", "nobody", "init"), ("--typo",), ("close", "../bad")]:
            p = parse(*args)
            self.assertEqual(p.returncode, 125, (args, p.stderr))

    def test_administrative_commands_do_not_require_sudo_caller(self):
        for cmd in ("help", "--help", "init", "check", "status"):
            p = parse(cmd, caller="")
            self.assertEqual(p.returncode, 0, p.stderr)

    def test_explicit_umask_preserves_octal_value_and_command_arguments(self):
        literal = 'a b; $(touch never) "$HOME"'
        for mask in ("0002", "0022", "0027", "0077", "077", "0000", "0777"):
            with self.subTest(mask=mask):
                p = subprocess.run([
                    "/bin/bash", "-p", "-c",
                    'set -euo pipefail; source "$1/lib/host.sh"; '
                    'source "$1/lib/cli.sh"; shift; parse_cli "$@"; '
                    'printf "%s\\0" "$workload_umask" "${workload[@]}"',
                    "test", str(ROOT), "--umask", mask, "--", "/bin/echo", literal,
                ], capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout.split("\0")[:-1], [mask, "/bin/echo", literal])

    def test_invalid_duplicate_and_administrative_umask_options_are_rejected(self):
        bad_options = [("--umask",), ("--umask", "--"), ("--umask", "888"),
                       ("--umask", "1000"), ("--umask", "-1"), ("--umask", "u=rwx"),
                       ("--umask", "0022\n"), ("--umask", "0022;true"),
                       ("--umask", "0022", "--umask", "0077"),
                       ("--umask", "0022", "init"), ("status", "--umask", "0022")]
        for args in bad_options:
            with self.subTest(args=args):
                p = parse(*args)
                self.assertEqual(p.returncode, 125, p.stderr)

    def test_inaccessible_workdir_fails_before_probe_or_workload(self):
        with tempfile.TemporaryDirectory() as td:
            p = subprocess.run(["/bin/bash", "-p", "-c",
                'source "$1/lib/session.sh"; '
                'probe_network() { echo PROBE; }; '
                'enter_workload https://example.test "$2/missing" /bin/echo WORKLOAD',
                "test", str(ROOT), td], capture_output=True, text=True)
            self.assertEqual(p.returncode, 125, p.stderr)
            self.assertNotIn("PROBE", p.stdout)
            self.assertNotIn("WORKLOAD", p.stdout)
            self.assertIn("working directory", p.stderr)

    @unittest.skipUnless(os.geteuid() == 0, "requires root to switch UID")
    def test_other_account_cannot_enter_private_project_or_run_probe(self):
        for mapping in ("uid_map", "gid_map"):
            ranges = [list(map(int, line.split())) for line in Path('/proc/self', mapping).read_text().splitlines()]
            if not any(start <= 65534 < start + count for start, outside, count in ranges):
                self.skipTest("executor does not map the ordinary test account: " + mapping)
        with tempfile.TemporaryDirectory() as td:
            Path(td).chmod(0o700)
            p = subprocess.run(["/bin/bash", "-p", "-c",
                'source "$1/lib/session.sh"; helper=$(declare -f enter_workload); '
                '/usr/bin/setpriv --reuid 65534 --regid 65534 --clear-groups '
                '/bin/bash -p -c "$helper"\'; probe_network() { echo PROBE; }; '
                'enter_workload https://example.test "$1" /bin/echo WORKLOAD\' test "$2"',
                "test", str(ROOT), td], capture_output=True, text=True)
            self.assertEqual(p.returncode, 125, p.stderr)
            self.assertNotIn("PROBE", p.stdout)
            self.assertNotIn("WORKLOAD", p.stdout)
            self.assertIn("working directory", p.stderr)


if __name__ == "__main__":
    unittest.main()
