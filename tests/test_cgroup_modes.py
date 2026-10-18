"""Cgroup adapter behavior with simulated mounts and system-manager boundaries.

No test changes the machine's cgroups, systemd units, or firewall. The packet
matching integration matrix is deliberately separate from these unit fixtures.
"""
import configparser
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SID = 'a' * 32
BOOT = '11111111-2222-3333-4444-555555555555'


def call(body, *args):
    module = ROOT / 'lib/cgroup.sh'
    if not module.exists():
        raise AssertionError('the cgroup mode adapter has not been implemented')
    return subprocess.run(
        ['bash', '-c', 'set -euo pipefail; source "$1/lib/host.sh"; '
         'source "$1/lib/cgroup.sh"; ROOT=$1; shift; '
         'CLASSID=0x6d730001; ' + body, 'fixture', str(ROOT), *map(str, args)],
        capture_output=True, text=True, timeout=15,
    )


def mounts(*entries):
    return json.dumps({'filesystems': [dict(target=p, fstype=t, fsroot=r, options=o)
                                      for p, t, r, o in entries]})


def state(path='/sys/fs/cgroup', mode='v2'):
    return dict(format=1, mode=mode, mount=path, mount_identity='17:100',
                manager_hierarchy='0' if mode == 'v2' else 'name=systemd',
                path='devsession.slice' if mode == 'v2' else 'dev-session-v8',
                identity='17:200', boot_id=BOOT)


class CgroupModesTests(unittest.TestCase):
    def test_mount_discovery_uses_controller_options_and_full_hierarchy_mounts(self):
        data = mounts(('/sys/fs/cgroup/net_cls', 'cgroup', '/', 'rw,net_cls'),
                      ('/sys/fs/cgroup/combined', 'cgroup', '/', 'rw,net_prio,net_cls'),
                      ('/sys/fs/cgroup/unified', 'cgroup2', '/', 'rw,nosuid'),
                      ('/subtree', 'cgroup', '/foreign', 'rw,net_cls'),
                      ('/read-only', 'cgroup', '/', 'ro,net_cls'),
                      ('/not-net-cls', 'cgroup', '/', 'rw,net_cls_extra'))
        for mode, expected in [('v1', ['/sys/fs/cgroup/net_cls', '/sys/fs/cgroup/combined']),
                               ('v2', ['/sys/fs/cgroup/unified'])]:
            with self.subTest(mode=mode):
                p = call('fixture_mounts=$1; findmnt() { printf "%s\\n" "$fixture_mounts"; }; '
                         'cgroup_find_mount "$2"', data, mode)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout.splitlines(), expected)

    def test_hybrid_detection_prefers_working_v1_at_its_actual_mount(self):
        data = mounts(('/sys/fs/cgroup/net_cls', 'cgroup', '/', 'rw,net_cls'),
                      ('/sys/fs/cgroup/unified', 'cgroup2', '/', 'rw'))
        p = call('fixture_mounts=$1; RUNTIME=/nonexistent-cgroup-test-runtime; '
                 'findmnt() { printf "%s\\n" "$fixture_mounts"; }; '
                 'cgroup_membership() { echo "1:name=systemd:/init.scope"; echo "0::/init.scope"; }; '
                 'cgroup_probe_v1() { [[ $1 == /sys/fs/cgroup/net_cls ]]; }; '
                 'cgroup_probe_match() { [[ $1 == v1 ]] || return 71; }; '
                 'cgroup_detect; printf "%s %s %s\\n" "$CGROUP_MODE" "$CGROUP_MOUNT" "$CGROOT"', data)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), 'v1 /sys/fs/cgroup/net_cls /sys/fs/cgroup/net_cls/dev-session-v8')

    def test_unusable_v1_permissions_or_match_fall_back_to_v2(self):
        data = mounts(('/sys/fs/cgroup/net_cls', 'cgroup', '/', 'rw,net_cls'),
                      ('/sys/fs/cgroup', 'cgroup2', '/', 'rw'))
        for failure in ('permissions', 'match'):
            p = call('fixture_mounts=$1; failure=$2; RUNTIME=/nonexistent-cgroup-test-runtime; '
                     'findmnt() { printf "%s\\n" "$fixture_mounts"; }; '
                     'cgroup_membership() { echo "0::/init.scope"; }; '
                     'cgroup_probe_v1() { [[ $failure != permissions ]]; }; '
                     'cgroup_probe_match() { [[ $1 == v2 || $failure != match ]]; }; '
                     'cgroup_detect; printf "%s %s\\n" "$CGROUP_MODE" "$CGROUP_MANAGER_HIERARCHY"',
                     data, failure)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.strip(), 'v2 0')

    def test_missing_manager_hierarchy_or_all_match_features_rejects_start(self):
        data = mounts(('/sys/fs/cgroup', 'cgroup2', '/', 'rw'))
        for proc, result in [('4:cpu:/', 0), ('0::/init.scope', 1)]:
            p = call('fixture_mounts=$1; membership=$2; result=$3; RUNTIME=/nonexistent-cgroup-test-runtime; '
                     'findmnt() { printf "%s\\n" "$fixture_mounts"; }; '
                     'cgroup_membership() { printf "%s\\n" "$membership"; }; '
                     'cgroup_probe_match() { return "$result"; }; '
                     'cgroup_detect && echo WORKLOAD_RAN', data, proc, result)
            self.assertNotEqual(p.returncode, 0)
            self.assertNotIn('WORKLOAD_RAN', p.stdout)

    def test_detection_refuses_to_replace_an_existing_binding(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / 'binding').write_text('old four line state\n')
            p = call('RUNTIME=$1; findmnt() { echo PROBE_RAN; return 1; }; '
                     'cgroup_detect && echo WORKLOAD_RAN', td)
            self.assertNotEqual(p.returncode, 0)
            self.assertNotIn('PROBE_RAN', p.stdout)
            self.assertEqual((Path(td) / 'binding').read_text(), 'old four line state\n')

    def test_v1_permission_probe_writes_classid_without_moving_a_process(self):
        for allowed in (True, False):
            with self.subTest(allowed=allowed), tempfile.TemporaryDirectory() as td:
                mount = Path(td)
                (mount / 'net_cls.classid').write_text('0\n')
                (mount / 'cgroup.procs').write_text('111\n222\n')
                p = call(r'''
fixture=$1; allowed=$2
trusted_path() { [[ -e $1 && ! -L $1 ]]; }
mkdir() {
    [[ $allowed == yes ]] || return 1
    command mkdir "$@" || return
    local target=${!#}
    : >"$target/net_cls.classid"
    printf 'sentinel\n' >"$target/cgroup.procs"
}
rmdir() {
    local target=${!#}
    [[ $(cat "$target/cgroup.procs") == sentinel ]] || return 76
    command rm -- "$target/net_cls.classid" "$target/cgroup.procs"
    command rmdir "$@"
}
cgroup_probe_v1 "$fixture"
''', td, 'yes' if allowed else 'no')
                self.assertEqual(p.returncode == 0, allowed, p.stderr)
                self.assertEqual((mount / 'cgroup.procs').read_text(), '111\n222\n')
                self.assertEqual((mount / 'net_cls.classid').read_text(), '0\n')
                self.assertEqual(list(mount.glob('.dev-session-probe-*')), [])

    def test_match_probe_commits_only_unhooked_chains_for_both_families(self):
        with tempfile.TemporaryDirectory() as td:
            for fail in ('none', 'ipv6'):
                log = Path(td) / fail
                p = call(r'''
log=$1; fail=$2
fw() {
    printf '%s\n' "$*" >>"$log"
    [[ $* != *' -I '* && $* != *' -A OUTPUT '* && $* != *' -A POSTROUTING '* ]] || return 77
    if [[ $fail == ipv6 && $1 == 6 && $* == *' -A '* ]]; then return 1; fi
}
iptables-legacy() { fw 4 "$@"; }
ip6tables-legacy() { fw 6 "$@"; }
cgroup_probe_match v2 /
''', log, fail)
                self.assertEqual(p.returncode == 0, fail == 'none', p.stderr)
                lines = log.read_text().splitlines()
                for family in ('4', '6'):
                    subset = [s for s in lines if s.startswith(family + ' ')]
                    self.assertTrue(any(' -N ' in s for s in subset), lines)
                    self.assertTrue(any(' -A ' in s and '--path /' in s for s in subset), lines)
                    self.assertTrue(any(' -X ' in s for s in subset), lines)
                    self.assertFalse(any(' -F OUTPUT' in s or ' -F POSTROUTING' in s for s in subset))

    def test_selected_match_is_explicit_and_cannot_use_shell_text(self):
        cases = [('v1', '-m cgroup --cgroup 0x6d730001'),
                 ('v2', '-m cgroup --path devsession.slice')]
        for mode, expected in cases:
            p = call('CGROUP_MODE=$1; cgroup_match', mode)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.strip(), expected)
        for mode in ('', 'v3', 'v2; echo unsafe'):
            p = call('CGROUP_MODE=$1; cgroup_match', mode)
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(p.stdout, '')

    def test_cgroup_state_roundtrip_preserves_explicit_identity(self):
        for mode in ('v1', 'v2'):
            data = state(mode=mode)
            p = call('cgroup_load_state "$1"; cgroup_state_json', json.dumps(data))
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(p.stdout), data)

    def test_invalid_state_is_rejected_without_partially_loaded_globals(self):
        good = state()
        bad = [None, ['v2'], 'old\nbinding\nstate\n443', dict(good, mode='auto'),
               dict(good, path='../system.slice'), dict(good, identity=12),
               dict(good, mount='/sys/fs/cgroup\nunsafe'), dict(good, extra='ignored'),
               dict(good, manager_hierarchy='name=systemd'), dict(good, boot_id='unknown')]
        for data in bad:
            p = call('cgroup_load_state "$1"; '
                     'if cgroup_load_state "$2"; then echo ACCEPTED; exit 2; fi; '
                     'printf "%s|%s\\n" "${CGROUP_MODE-unset}" "${CGROOT-unset}"',
                     json.dumps(good), json.dumps(data))
            self.assertEqual(p.returncode, 0, (data, p.stderr))
            self.assertEqual(p.stdout.strip(), 'unset|unset')

    def fixture(self, td, mode='v2'):
        root = Path(td)
        mount = root / 'cgroup'
        parent = mount / ('devsession.slice' if mode == 'v2' else 'dev-session-v8')
        parent.mkdir(parents=True)
        mount.chmod(0o755); parent.chmod(0o755)
        for path in (mount, parent):
            (path / 'cgroup.procs').write_text('')
            (path / ('cgroup.controllers' if mode == 'v2' else 'net_cls.classid')).write_text('')
        if mode == 'v2':
            (parent / 'cgroup.events').write_text('populated 0\nfrozen 0\n')
        data = state(str(mount), mode)
        data['mount_identity'] = f'{mount.stat().st_dev}:{mount.stat().st_ino}'
        data['identity'] = f'{parent.stat().st_dev}:{parent.stat().st_ino}'
        unit = root / 'devsession.slice'
        # This is the systemd unit-file boundary, not a new production path.
        setup = r'''
fixture=$1; data=$2
trusted_path() { [[ -e $1 && ! -L $1 ]]; }
cgroup_boot_id() { printf '%s\n' '11111111-2222-3333-4444-555555555555'; }
cgroup_unit_file() { printf '%s\n' "$fixture/devsession.slice"; }
cgroup_membership() { printf '%s\n' '0::/init.scope'; }
findmnt() { printf '%s\n' "$mount_data"; }
cgroup_load_state "$data"
systemctl() {
    case $* in
        *dev-session-*.service*)
            if [[ $* == *Delegate* ]]; then echo no;
            else printf '/devsession.slice/dev-session-%s.service\n' "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; fi ;;
        *) printf '%s\n' LoadState=loaded ActiveState=active \
            "FragmentPath=$fixture/devsession.slice" DropInPaths= \
            ControlGroup=/devsession.slice StopWhenUnneeded=no RefuseManualStop=yes ;;
    esac
}
'''
        fs = mounts((str(mount), 'cgroup2' if mode == 'v2' else 'cgroup', '/',
                     'rw' if mode == 'v2' else 'rw,net_cls'))
        setup = 'mount_data=$3; ' + setup
        if mode == 'v1':
            setup += '\ncgroup_membership() { echo "1:name=systemd:/init.scope"; };\n'
        else:
            setup += '\ncgroup_slice_text >"$fixture/devsession.slice";\n'
        return data, parent, setup, fs, unit

    def test_verification_rejects_recreated_parent_and_mount_identity(self):
        for replacement in ('parent', 'mount', 'boot'):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as td:
                data, parent, setup, fs, unit = self.fixture(td)
                suffix = {'parent': 'CGROUP_IDENTITY=17:999;',
                          'mount': 'CGROUP_MOUNT_IDENTITY=17:999;',
                          'boot': 'cgroup_boot_id() { echo 99999999-2222-3333-4444-555555555555; };'}[replacement]
                p = call(setup + 'cgroup_verify; ' + suffix +
                         'if cgroup_verify; then echo WORKLOAD_RAN; exit 2; fi',
                         td, json.dumps(data), fs)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertNotIn('WORKLOAD_RAN', p.stdout)

    def test_verify_rejects_same_named_slice_from_another_installation(self):
        with tempfile.TemporaryDirectory() as td:
            data, parent, setup, fs, unit = self.fixture(td)
            p = call(setup + 'cgroup_verify; printf "foreign\\n" >"$fixture/devsession.slice"; '
                     'if cgroup_verify; then echo WORKLOAD_RAN; exit 2; fi',
                     td, json.dumps(data), fs)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(unit.read_text(), 'foreign\n')

    def test_prepare_does_not_recreate_a_bound_parent(self):
        with tempfile.TemporaryDirectory() as td:
            data, parent, setup, fs, unit = self.fixture(td)
            p = call(setup + 'CGROUP_IDENTITY=17:999; '
                     'mkdir() { echo MUTATION_RAN; return 1; }; '
                     'if cgroup_prepare; then exit 2; fi', td, json.dumps(data), fs)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertNotIn('MUTATION_RAN', p.stdout)

    def test_prepare_v2_creates_owned_persistent_slice_before_rules(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); mount = root / 'cgroup'; mount.mkdir()
            (mount / 'cgroup.controllers').write_text('')
            (mount / 'cgroup.procs').write_text('')
            p = call(r'''
fixture=$1; CGROUP_MODE=v2; CGROUP_MOUNT=$1/cgroup
CGROUP_PATH=devsession.slice; CGROOT=$CGROUP_MOUNT/$CGROUP_PATH
CGROUP_MANAGER_HIERARCHY=0
trusted_path() { [[ -e $1 && ! -L $1 ]]; }
cgroup_unit_file() { printf '%s\n' "$fixture/devsession.slice"; }
cgroup_boot_id() { echo 11111111-2222-3333-4444-555555555555; }
cgroup_membership() { echo '0::/init.scope'; }
mount_data=$2
findmnt() { printf '%s\n' "$mount_data"; }
systemctl() {
    printf '%s\n' "$*" >>"$fixture/systemctl.log"
    if [[ $1 == daemon-reload ]]; then return 0; fi
    if [[ $1 == start ]]; then
        [[ -f $fixture/devsession.slice ]] || return 70
        command mkdir "$CGROOT"
        : >"$CGROOT/cgroup.procs"; : >"$CGROOT/cgroup.controllers"
        printf 'populated 0\nfrozen 0\n' >"$CGROOT/cgroup.events"
        return 0
    fi
    if [[ -d $CGROOT ]]; then
        printf '%s\n' LoadState=loaded ActiveState=active \
            "FragmentPath=$fixture/devsession.slice" DropInPaths= \
            ControlGroup=/devsession.slice StopWhenUnneeded=no RefuseManualStop=yes
    elif [[ $* == *StopWhenUnneeded* ]]; then
        printf '%s\n' LoadState=loaded ActiveState=inactive \
            "FragmentPath=$fixture/devsession.slice" DropInPaths= \
            ControlGroup= StopWhenUnneeded=no RefuseManualStop=yes
    else
        printf '%s\n' LoadState=loaded ActiveState=inactive FragmentPath= DropInPaths= ControlGroup= Transient=no
    fi
}
cgroup_prepare
cgroup_state_json
''', td, mounts((str(mount), 'cgroup2', '/', 'rw')))
            self.assertEqual(p.returncode, 0, p.stderr)
            saved = json.loads(p.stdout)
            self.assertEqual(saved['mode'], 'v2')
            self.assertEqual(saved['path'], 'devsession.slice')
            config = configparser.ConfigParser()
            config.read(root / 'devsession.slice')
            self.assertEqual(config['Unit']['StopWhenUnneeded'], 'no')
            self.assertEqual(config['Unit']['RefuseManualStop'], 'yes')
            log = (root / 'systemctl.log').read_text().splitlines()
            self.assertLess(log.index('daemon-reload'), log.index('start devsession.slice'))
            before = (mount / 'devsession.slice').stat().st_ino
            self.assertEqual(saved['identity'], f'{mount.stat().st_dev}:{before}')

    def test_reload_cannot_activate_a_foreign_higher_precedence_slice(self):
        with tempfile.TemporaryDirectory() as td:
            mount = Path(td) / 'cgroup'; mount.mkdir()
            p = call(r'''
fixture=$1; CGROUP_MODE=v2; CGROUP_MOUNT=$1/cgroup; CGROUP_PATH=devsession.slice
CGROOT=$CGROUP_MOUNT/$CGROUP_PATH; CGROUP_MANAGER_HIERARCHY=0; reloaded=no
trusted_path() { [[ -e $1 && ! -L $1 ]]; }
cgroup_unit_file() { printf '%s\n' "$fixture/devsession.slice"; }
systemctl() {
    if [[ $1 == daemon-reload ]]; then reloaded=yes; return 0; fi
    if [[ $1 == start ]]; then echo FOREIGN_SLICE_STARTED; return 79; fi
    if [[ $reloaded == yes ]]; then
        printf '%s\n' LoadState=loaded ActiveState=inactive \
            FragmentPath=/etc/systemd/system/devsession.slice DropInPaths= \
            ControlGroup= StopWhenUnneeded=no RefuseManualStop=yes
    else
        printf '%s\n' LoadState=loaded ActiveState=inactive FragmentPath= DropInPaths= ControlGroup= Transient=no
    fi
}
cgroup_prepare
''', td)
            self.assertNotEqual(p.returncode, 0)
            self.assertNotIn('FOREIGN_SLICE_STARTED', p.stdout)

    def test_foreign_slice_unit_is_rejected_without_overwriting_it(self):
        with tempfile.TemporaryDirectory() as td:
            unit = Path(td) / 'devsession.slice'
            unit.write_text('[Unit]\nDescription=Foreign service group\n')
            p = call('CGROUP_MODE=v2; CGROUP_MOUNT=$1; CGROUP_PATH=devsession.slice; '
                     'CGROOT=$1/cgroup/devsession.slice; fixture=$1; '
                     'cgroup_unit_file() { printf "%s\\n" "$fixture/devsession.slice"; }; '
                     'systemctl() { echo MUTATION_RAN; return 1; }; '
                     'cgroup_prepare && echo WORKLOAD_RAN', td)
            self.assertNotEqual(p.returncode, 0)
            self.assertNotIn('MUTATION_RAN', p.stdout)
            self.assertEqual(unit.read_text(), '[Unit]\nDescription=Foreign service group\n')

    def test_v2_bootstrap_requires_birth_in_exact_systemd_service(self):
        for belongs in (True, False):
            with self.subTest(belongs=belongs), tempfile.TemporaryDirectory() as td:
                data, parent, setup, fs, unit = self.fixture(td)
                service = parent / ('dev-session-' + SID + '.service')
                service.mkdir(); (service / 'cgroup.procs').write_text('123\n')
                location = '/devsession.slice/dev-session-' + SID + '.service' if belongs else '/system.slice/foreign.service'
                p = call(setup + r'''
location=$4
cgroup_membership() {
    if [[ $1 == self ]]; then printf '0::%s\n' "$location"; else echo '0::/init.scope'; fi
}
mkdir() { echo MUTATION_RAN; return 72; }
chmod() { echo MUTATION_RAN; return 72; }
cgroup_attach aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa && echo WORKLOAD_READY
''', td, json.dumps(data), fs, location)
                self.assertEqual(p.returncode == 0, belongs, p.stderr)
                self.assertEqual('WORKLOAD_READY' in p.stdout, belongs)
                self.assertNotIn('MUTATION_RAN', p.stdout)
                self.assertEqual((service / 'cgroup.procs').read_text(), '123\n')

    def test_v1_attach_uses_discovered_mount_and_only_its_own_pid(self):
        with tempfile.TemporaryDirectory() as td:
            data, parent, setup, fs, unit = self.fixture(td, mode='v1')
            p = call(setup + r'''
systemctl() {
    if [[ $* == *Delegate* ]]; then echo no;
    else echo /system.slice/dev-session-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.service; fi
}
cgroup_membership() {
    if [[ $1 == 1 ]]; then echo '1:name=systemd:/init.scope'; return; fi
    echo '1:name=systemd:/system.slice/dev-session-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.service'
    if [[ -s $CGROOT/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cgroup.procs ]]; then
        echo '2:net_cls,net_prio:/dev-session-v8/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    else echo '2:net_cls,net_prio:/'; fi
}
mkdir() {
    command mkdir "$@" || return
    local target=${!#}
    : >"$target/net_cls.classid"; : >"$target/cgroup.procs"
}
read -r expected rest </proc/self/stat
cgroup_attach aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
printf 'expected=%s\n' "$expected"
''', td, json.dumps(data), fs)
            self.assertEqual(p.returncode, 0, p.stderr)
            child = parent / SID
            self.assertEqual((child / 'cgroup.procs').read_text().strip(), p.stdout.strip().split('=')[1])
            self.assertEqual((child / 'net_cls.classid').read_text(), '1836253185\n')
            self.assertEqual(child.stat().st_mode & 0o777, 0o700)

    def test_v2_cleanup_never_deletes_parent_or_service_cgroups(self):
        for population, expected in [(0, 0), (1, 2)]:
            with self.subTest(population=population), tempfile.TemporaryDirectory() as td:
                data, parent, setup, fs, unit = self.fixture(td)
                service = parent / ('dev-session-' + SID + '.service')
                service.mkdir(); (service / 'cgroup.procs').write_text('123\n' if population else '')
                (service / 'cgroup.events').write_text(f'populated {population}\nfrozen 0\n')
                p = call(setup + 'rmdir() { echo REMOVAL_RAN; return 72; }; '
                         'cgroup_cleanup aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         td, json.dumps(data), fs)
                self.assertEqual(p.returncode, expected, p.stderr)
                self.assertEqual(p.stdout, '')
                self.assertTrue(parent.is_dir())
                self.assertTrue(service.is_dir())

    def test_v2_admission_rejects_foreign_slice_children(self):
        for name in ('unrelated.service', '.hidden-foreign-group'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                data, parent, setup, fs, unit = self.fixture(td)
                (parent / name).mkdir()
                p = call(setup + 'cgroup_verify && echo WORKLOAD_RAN',
                         td, json.dumps(data), fs)
                self.assertNotEqual(p.returncode, 0)
                self.assertNotIn('WORKLOAD_RAN', p.stdout)

    def test_v2_unit_arguments_use_systemd_slice_without_delegation(self):
        p = call('source "$ROOT/lib/session.sh"; CGROUP_MODE=v2; '
                 'unit_arguments "$1" pipe; printf "%s\\0" "${UNIT_ARGS[@]}"', SID)
        self.assertEqual(p.returncode, 0, p.stderr)
        args = p.stdout.split('\0')[:-1]
        self.assertIn('--slice=devsession.slice', args)
        self.assertIn('--property=Delegate=no', args)
        self.assertIn('--service-type=exec', args)
        self.assertIn('--property=KillMode=control-group', args)


if __name__ == '__main__':
    unittest.main()
