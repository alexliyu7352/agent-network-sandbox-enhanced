"""Real installer in an isolated root-owned directory; no Docker/systemd setup."""
import json
import os
import pty
import pwd
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.geteuid() == 0, "requires root for ownership checks")
class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="session-install-test-", dir="/root")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "checkout"
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        self.root.chmod(0o755)

    def install(self, *args):
        return subprocess.run(["/bin/bash", "-p", str(self.root / "install-dev-session.sh"),
                               "--no-link", *args], capture_output=True, text=True)

    def test_installation_hardens_the_same_tree_and_is_repeatable(self):
        original = (self.root / "network.json").read_bytes()
        for _ in range(2):
            p = self.install()
            self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual((self.root / "network.json").read_bytes(), original)
        self.assertEqual(sorted(p.name for p in self.base.iterdir()), ["checkout"])
        for p in [self.root, *self.root.rglob("*")]:
            self.assertEqual(p.stat().st_uid, 0)
            self.assertEqual(stat.S_IMODE(p.stat().st_mode) & 0o077, 0, str(p))
        p = subprocess.run([str(self.root / "dev-session"), "--help"],
                           capture_output=True, text=True, cwd="/")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("session", p.stdout)

    def test_check_does_not_change_permissions(self):
        before = {p: p.stat().st_mode for p in [self.root, *self.root.rglob("*")]}
        p = self.install("--check")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(before, {p: p.stat().st_mode for p in before})

    def public_install(self, *args):
        """Redirect only the fixed public destination inside this fixture."""
        public = self.base / 'bin'
        public.mkdir(exist_ok=True)
        public.chmod(0o755)
        script = self.root / 'install-dev-session.sh'
        script.write_text(script.read_text().replace(
            'shortcut=/usr/local/bin/session', 'shortcut=' + str(public / 'session')))
        return subprocess.run(['/bin/bash', '-p', str(script), *args],
                              capture_output=True, text=True), public / 'session'

    def test_public_launcher_replaces_own_shortcut_and_updates_in_place(self):
        public = self.base / 'bin'
        public.mkdir()
        shortcut = public / 'session'
        shortcut.symlink_to(self.root / 'dev-session')
        for _ in range(2):
            p, shortcut = self.public_install()
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertFalse(shortcut.is_symlink(), 'Plain session needs a readable pre-sudo launcher')
            self.assertEqual(stat.S_IMODE(shortcut.stat().st_mode), 0o755)
            self.assertEqual(shortcut.stat().st_uid, 0)
            self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
            p = subprocess.run([str(shortcut), '--help'], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
        template = self.root / 'session-launcher'
        template.write_text(template.read_text() + '\n# Fixture for a later launcher revision.\n')
        p, shortcut = self.public_install()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('later launcher revision', shortcut.read_text())
        self.assertEqual([p.name for p in public.iterdir()], ['session'])

    def test_public_install_check_is_read_only_and_foreign_entry_is_preserved(self):
        p, shortcut = self.public_install('--check')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(shortcut.exists())
        foreign = '#!/bin/sh\nprintf unrelated\\n\n'
        shortcut.write_text(foreign)
        shortcut.chmod(0o755)
        p, shortcut = self.public_install()
        self.assertEqual(p.returncode, 125, p.stderr)
        self.assertEqual(shortcut.read_text(), foreign)

    def test_pre_sudo_context_reaches_cli_without_changing_manager_environment(self):
        self.assertEqual(self.install().returncode, 0)
        with (self.root / 'lib/host.sh').open('a') as stream:
            stream.write(r'''
host_preflight() {
    printf '%s\0' "$user" "$uid" "$workdir" "$CONTEXT_UMASK" "$(umask)" \
        "${LC_ALL-unset}" "${DISPLAY-unset}" "${#CONTEXT_ENV[@]}" \
        "${CONTEXT_ENV[@]}" "${workload[@]}"
    exit 0
}
''')
        cwd = str(self.base / 'project with spaces\nand a newline')
        selected = ['LANG=C', 'LC_ALL=', 'TZ=UTC-03', 'DISPLAY=:73',
                    'XAUTHORITY=/a path/$(touch never-created)',
                    'DBUS_SESSION_BUS_ADDRESS=unix:path=/original/bus']
        literal = 'a b; $(touch never-created) "$HOME"'
        prefix = ['--caller-context', '0002', cwd, str(len(selected)), *selected, '--']
        for extra, expected_cwd in (([], cwd), (['--cwd', '/'], '/')):
            p = subprocess.run([str(self.root / 'dev-session'), *prefix, *extra,
                                '--', '/bin/echo', literal], cwd='/',
                               env=dict(os.environ, SUDO_UID='65534', LANG='C.UTF-8',
                                        LC_ALL='C', DISPLAY='post-sudo-value'),
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.split('\0')[:-1],
                             [pwd.getpwuid(65534).pw_name, '65534', expected_cwd,
                              '0002', '0077', 'C', 'unset', str(len(selected)),
                              *selected, '/bin/echo', literal])

    def test_malformed_pre_sudo_context_is_rejected_before_host_actions(self):
        self.assertEqual(self.install().returncode, 0)
        with (self.root / 'lib/host.sh').open('a') as stream:
            stream.write('\nhost_preflight() { echo HOST_ACTION_RAN; exit 0; }\n')
        cases = [[], ['0002'], ['0002', '/', 'many', '--'],
                 ['0002', '/', '65', '--'], ['0002', 'relative', '0', '--'],
                 ['888', '/', '0', '--'], ['0002', '/', '1', 'LD_PRELOAD=bad', '--'],
                 ['0002', '/', '1', 'SUDO_UID=0', '--'],
                 ['0002', '/', '1', 'LANG=C'], ['0002', '/', '0', 'LANG=C', '--']]
        for context in cases:
            with self.subTest(context=context):
                p = subprocess.run([str(self.root / 'dev-session'), '--caller-context',
                                    *context, '--', '/bin/true'],
                                   env=dict(os.environ, SUDO_UID='65534'),
                                   capture_output=True, text=True)
                self.assertEqual(p.returncode, 125, p.stderr)
                self.assertNotIn('HOST_ACTION_RAN', p.stdout)

    def test_unresolved_caller_directory_allows_explicit_cwd_and_help(self):
        self.assertEqual(self.install().returncode, 0)
        with (self.root / 'lib/host.sh').open('a') as stream:
            stream.write('\nhost_preflight() { printf "WORKDIR:%s" "$workdir"; exit 0; }\n')
        prefix = [str(self.root / 'dev-session'), '--caller-context', '0002', '', '0', '--']
        environment = dict(os.environ, SUDO_UID='65534')
        for args in (['--cwd', '/', '--', '/bin/true'], ['--help']):
            p = subprocess.run([*prefix, *args], env=environment,
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            if args[0] == '--cwd':
                self.assertEqual(p.stdout, 'WORKDIR:/')
        p = subprocess.run(prefix, env=environment, capture_output=True, text=True)
        self.assertEqual(p.returncode, 125, p.stderr)
        self.assertIn('working directory', p.stderr)
        self.assertNotIn('WORKDIR:', p.stdout)

    def test_session_check_discards_caller_bus_and_systemd_environment(self):
        line = next(line.strip() for line in (ROOT / 'install-dev-session.sh').read_text().replace('\\\n', '').splitlines()
                    if line.strip().startswith('units=$('))
        prefix, boundary, suffix = line.partition("systemctl list-units --all --plain --no-legend 'dev-session-*.service'")
        self.assertTrue(boundary)
        # Inspect the real environment at the external systemctl boundary,
        # substituting only env as the final executable (no host bus access).
        script = prefix + '/usr/bin/env' + suffix + '\nprintf "%s" "$units"'
        p = subprocess.run(['/bin/bash', '-p', '-c', script], capture_output=True, text=True,
                           env=dict(os.environ, DBUS_SYSTEM_BUS_ADDRESS='untrusted-bus',
                                    SYSTEMD_BUS_ADDRESS='untrusted-systemd',
                                    SYSTEMD_PAGER='untrusted-pager'))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse('untrusted' in p.stdout, 'Caller bus settings reached the session check')

    def test_writable_or_symlinked_source_is_rejected_without_touching_target(self):
        for kind in ("writable", "symlink", "hardlink"):
            file = self.root / "policy.json"
            data = file.read_bytes()
            outside = self.base / "outside"
            outside.write_bytes(data)
            if kind == "writable":
                file.chmod(0o666)
            else:
                file.unlink()
                if kind == "symlink": file.symlink_to(outside)
                else: os.link(outside, file)
            p = self.install()
            self.assertEqual(p.returncode, 125, (kind, p.stderr))
            self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o644)
            file.unlink(); file.write_bytes(data); file.chmod(0o644); outside.unlink()

    def test_launcher_rejects_writable_root_before_loading_helpers(self):
        p = self.install()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.root.chmod(0o777)
        (self.root / "lib/main.sh").write_text("echo UNSAFE_HELPER_RAN\n")
        p = subprocess.run([str(self.root / "dev-session"), "--help"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 125)
        self.assertNotIn("UNSAFE_HELPER_RAN", p.stdout)

    def test_context_helper_must_exist_and_be_trusted_before_it_is_loaded(self):
        context = self.root / "lib/context.sh"
        original = context.read_bytes()
        context.unlink()
        p = self.install("--check")
        self.assertEqual(p.returncode, 125, p.stderr)
        context.write_bytes(original)
        self.assertEqual(self.install().returncode, 0)
        context.write_text("echo UNTRUSTED_CONTEXT_RAN\n")
        context.chmod(0o666)
        p = subprocess.run([str(self.root / "dev-session"), "--help"],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 125, p.stderr)
        self.assertNotIn("UNTRUSTED_CONTEXT_RAN", p.stdout)

    def test_entry_context_reaches_serialized_workload_in_pipe_and_pty_modes(self):
        self.assertEqual(self.install().returncode, 0)
        runtime = self.base / 'runtime'
        record = self.base / 'request.json'
        network = self.root / 'lib/network.sh'
        network.write_text(network.read_text().replace(
            'readonly RUNTIME=/run/dev-session-v8', 'readonly RUNTIME=' + str(runtime)))
        # Stop immediately after the real request write/read. Replace only
        # host policy setup and service submission; no host units or network
        # state are touched, and the real entry/main/parser/context run.
        harness = r'''
host_preflight() { :; }
prepare_policy() { exec {GWFD}</dev/null; }
unit_arguments() {
    local request_mode
    request_mode=$(stat -c %a "$RUNTIME/requests/$1")
    read_request "$1"
    /usr/bin/python3 -c 'import json,os,sys; json.dump({"request_mode":sys.argv[2],
        "manager_mask":sys.argv[3],"manager_env":{k:os.environ.get(k) for k in
        ("LC_ALL","DISPLAY","DBUS_SESSION_BUS_ADDRESS")},"request":sys.argv[4:]},
        open(sys.argv[1],"w"))' __RECORD__ "$request_mode" "$(umask)" "${REQUEST[@]}"
    exit 0
}
'''
        harness = harness.replace('__RECORD__', str(record))
        with (self.root / 'lib/context.sh').open('a') as stream:
            stream.write(harness)
        context = dict(os.environ, SUDO_UID='65534', LANG='C', LC_ALL='',
                       DISPLAY=':37', XAUTHORITY='/synthetic/authority',
                       DBUS_SESSION_BUS_ADDRESS='unix:path=/synthetic/session-bus')
        literal = 'a b; $(touch never-created) "$HOME"'
        for interactive in (False, True):
            with self.subTest(interactive=interactive):
                args = [str(self.root / 'dev-session'), '--umask', '0002']
                if not interactive:
                    args += ['--', '/bin/echo', '', literal]
                if interactive:
                    master, slave = pty.openpty()
                    try:
                        p = subprocess.run(args, env=context, cwd=self.base,
                                           stdin=slave, stdout=slave, stderr=slave, timeout=10)
                        os.set_blocking(master, False)
                        try:
                            detail = os.read(master, 65536).decode(errors='replace')
                        except BlockingIOError:
                            detail = ''
                    finally:
                        os.close(slave)
                        os.close(master)
                else:
                    p = subprocess.run(args, env=context, cwd=self.base,
                                       capture_output=True, text=True, timeout=10)
                    detail = p.stderr
                self.assertEqual(p.returncode, 0, detail)
                data = json.loads(record.read_text())
                self.assertEqual(data['request_mode'], '600')
                self.assertEqual(data['manager_mask'], '0077')
                self.assertEqual(data['manager_env'],
                                 {'LC_ALL': 'C', 'DISPLAY': None, 'DBUS_SESSION_BUS_ADDRESS': None})
                request = data['request']
                self.assertEqual(request[5], 'pty' if interactive else 'pipe')
                payload = request[9:]
                self.assertEqual(payload[:3], ['/bin/bash', '-p', '-c'])
                self.assertEqual(payload[5], '0002')
                count = int(payload[6])
                restored = payload[7:7 + count]
                for item in ('LANG=C', 'LC_ALL=', 'DISPLAY=:37',
                             'XAUTHORITY=/synthetic/authority',
                             'DBUS_SESSION_BUS_ADDRESS=unix:path=/synthetic/session-bus'):
                    self.assertIn(item, restored)
                self.assertEqual(payload[7 + count:], ['/bin/bash', '-i'] if interactive else
                                 ['/bin/echo', '', literal])

    def test_shortcut_preserves_caller_and_cwd_but_discards_privileged_environment(self):
        p = self.install()
        self.assertEqual(p.returncode, 0, p.stderr)
        alias = self.base / "session"
        alias.symlink_to(self.root / "dev-session")
        # Stop at the first host-dependent boundary, after the real launcher
        # and main parser. No systemd, Docker or firewall operation is run.
        with (self.root / "lib/host.sh").open("a") as stream:
            stream.write('\nhost_preflight() { printf "%s\\0" "$user" "$uid" "$workdir" '
                         '"${workload[@]}" "${DBUS_SYSTEM_BUS_ADDRESS:-clean}" '
                         '"${DOCKER_HOST:-clean}"; exit 0; }\n')
        literal = '$(touch never-created); a b'
        p = subprocess.run([str(alias), "--", "/bin/echo", literal], cwd=self.base,
                           env=dict(os.environ, SUDO_UID="65534", SUDO_USER="root",
                                    DBUS_SYSTEM_BUS_ADDRESS="untrusted", DOCKER_HOST="untrusted"),
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.split("\0")[:-1],
                         [pwd.getpwuid(65534).pw_name, "65534", str(self.base),
                          "/bin/echo", literal, "clean", "clean"])


if __name__ == "__main__":
    unittest.main()
