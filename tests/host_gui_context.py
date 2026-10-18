#!/usr/bin/env python3
"""Ordinary-user Xvfb acceptance for the real workload-context helpers.

This fixture does not run dev-session, admission probes, setpriv, systemd or
cgroup/firewall setup. It starts its own cookie-protected local X server and
executes wrap_workload_context/restore_workload_context as its existing UID.
Python 3.8 is supported. No package installation or privilege change is done.
"""
import argparse
import ctypes
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import secrets
import select
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time


SCOPE = ('ordinary-user context helper and local X11 authorization/window only; '
         'no root launcher, admission probe, NNP, systemd, cgroup, network-policy, '
         'Wayland or desktop-session acceptance')
ENV_NAMES = ('LANG', 'LANGUAGE', 'LC_ALL', 'LC_TIME', 'TZ', 'DISPLAY',
             'XAUTHORITY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR',
             'DBUS_SESSION_BUS_ADDRESS', 'XDG_SESSION_TYPE',
             'XDG_CURRENT_DESKTOP')
WRAPPER = r'''
set -euo pipefail
source "$1"
target=$2 count=$3
shift 3
context=("${@:1:count}")
shift "$count"
workload=("$@")
wrap_workload_context "$target" "$target" 0027 "${context[@]}"
exec "${workload[@]}"
'''


class WindowAttributes(ctypes.Structure):
    _fields_ = [(name, kind) for name, kind in (
        ('x', ctypes.c_int), ('y', ctypes.c_int),
        ('width', ctypes.c_int), ('height', ctypes.c_int),
        ('border_width', ctypes.c_int), ('depth', ctypes.c_int),
        ('visual', ctypes.c_void_p), ('root', ctypes.c_ulong),
        ('window_class', ctypes.c_int), ('bit_gravity', ctypes.c_int),
        ('win_gravity', ctypes.c_int), ('backing_store', ctypes.c_int),
        ('backing_planes', ctypes.c_ulong), ('backing_pixel', ctypes.c_ulong),
        ('save_under', ctypes.c_int), ('colormap', ctypes.c_ulong),
        ('map_installed', ctypes.c_int), ('map_state', ctypes.c_int),
        ('all_event_masks', ctypes.c_long), ('your_event_mask', ctypes.c_long),
        ('do_not_propagate_mask', ctypes.c_long),
        ('override_redirect', ctypes.c_int), ('screen', ctypes.c_void_p))]


def x11_client():
    """Runs only as the wrapper's final payload, in a disposable working dir."""
    lib = ctypes.CDLL(ctypes.util.find_library('X11') or 'libX11.so.6')
    pointer, window = ctypes.c_void_p, ctypes.c_ulong
    signatures = {
        'XOpenDisplay': ([ctypes.c_char_p], pointer),
        'XDefaultRootWindow': ([pointer], window),
        'XCreateSimpleWindow': ([pointer, window, ctypes.c_int, ctypes.c_int,
                                ctypes.c_uint, ctypes.c_uint, ctypes.c_uint,
                                ctypes.c_ulong, ctypes.c_ulong], window),
        'XMapWindow': ([pointer, window], ctypes.c_int),
        'XSync': ([pointer, ctypes.c_int], ctypes.c_int),
        'XGetWindowAttributes': ([pointer, window, ctypes.POINTER(WindowAttributes)],
                                ctypes.c_int),
        'XDestroyWindow': ([pointer, window], ctypes.c_int),
        'XCloseDisplay': ([pointer], ctypes.c_int),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(lib, name)
        function.argtypes, function.restype = arguments, result
    info = {'uid': os.getuid(), 'euid': os.geteuid(),
            'environment': {name: os.environ.get(name) for name in ENV_NAMES}}
    display = lib.XOpenDisplay(None)
    info['opened'] = bool(display)
    if not display:
        print(json.dumps(info, sort_keys=True), flush=True)
        return 0
    xid = 0
    try:
        xid = lib.XCreateSimpleWindow(display, lib.XDefaultRootWindow(display),
                                     0, 0, 240, 160, 0, 0, 0x223344)
        if not xid:
            raise RuntimeError('XCreateSimpleWindow returned no window')
        lib.XMapWindow(display, xid)
        lib.XSync(display, 0)
        attributes = WindowAttributes()
        if not lib.XGetWindowAttributes(display, xid, ctypes.byref(attributes)):
            raise RuntimeError('XGetWindowAttributes failed')
        info['window'] = {'width': attributes.width, 'height': attributes.height,
                          'map_state': attributes.map_state}
        lib.XDestroyWindow(display, xid)
        xid = 0
        lib.XSync(display, 0)
        info['destroy_synced'] = True
        mask = os.umask(0o777)
        os.umask(mask)
        Path('created-file').touch()
        Path('created-directory').mkdir()
        info['umask'] = format(mask, '04o')
        info['created_modes'] = {
            name: format(stat.S_IMODE(Path(name).stat().st_mode), '04o')
            for name in ('created-file', 'created-directory')}
    finally:
        if xid:
            lib.XDestroyWindow(display, xid)
            lib.XSync(display, 0)
        lib.XCloseDisplay(display)
    print(json.dumps(info, sort_keys=True), flush=True)
    return 0


def write_authority(path, number, cookie):
    # Xauthority's binary format: FamilyWild followed by four length/value
    # fields. Cookie bytes never enter argv, stdout or evidence.
    fields = (b'', number.encode('ascii'), b'MIT-MAGIC-COOKIE-1', cookie)
    data = struct.pack('!H', 65535)
    data += b''.join(struct.pack('!H', len(value)) + value for value in fields)
    path.write_bytes(data)
    path.chmod(0o600)


def read_display(process, descriptor, timeout=8):
    deadline, data = time.monotonic() + timeout, b''
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('Xvfb exited before publishing a display')
        remaining = max(0.0, deadline - time.monotonic())
        ready, _, _ = select.select([descriptor], [], [], min(0.1, remaining))
        if ready:
            chunk = os.read(descriptor, 64)
            if not chunk:
                raise RuntimeError('Xvfb display descriptor closed without a display')
            data += chunk
            if b'\n' in data:
                number = data.split(b'\n', 1)[0].decode('ascii')
                if not number.isdigit() or len(number) > 5:
                    raise RuntimeError('Invalid Xvfb display number')
                return number
            if len(data) > 32:
                raise RuntimeError('Oversized Xvfb display response')
    raise RuntimeError('Xvfb readiness timed out')


def tcp_sockets(pid):
    inodes = set()
    for path in Path('/proc', str(pid), 'fd').iterdir():
        try:
            target = os.readlink(str(path))
        except FileNotFoundError:
            continue
        if target.startswith('socket:['):
            inodes.add(target[8:-1])
    matches = []
    for name in ('tcp', 'tcp6'):
        path = Path('/proc/net', name)
        if path.exists():
            for line in path.read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 9 and fields[9] in inodes:
                    matches.append(name)
    return matches


def run_payload(context_file, context, cwd):
    base = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'HOME': pwd.getpwuid(os.getuid()).pw_dir, 'LANG': 'C.UTF-8',
            'LC_ALL': 'C.UTF-8', 'TZ': 'stale-fixture-zone',
            'WAYLAND_DISPLAY': 'stale-fixture-display',
            'XDG_RUNTIME_DIR': '/nonexistent-session-gui-fixture',
            'DBUS_SESSION_BUS_ADDRESS': 'stale-fixture-address'}
    argv = ['/bin/bash', '-p', '-c', WRAPPER, 'x11-context-fixture',
            str(context_file), str(os.getuid()), str(len(context))]
    argv += context + ['/usr/bin/env', 'PYTHONCOERCECLOCALE=0', 'PYTHONUTF8=0',
                       sys.executable, str(Path(__file__).resolve()), '--client']
    result = subprocess.run(argv, cwd=str(cwd), env=base, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=10)
    info = json.loads(result.stdout) if result.returncode == 0 else None
    return {'returncode': result.returncode, 'result': info,
            'stderr': result.stderr[-1500:]}


def run_fixture(args):
    result = {'status': 'not_run', 'scope': SCOPE, 'checks': {}, 'errors': [],
              'metadata': {'uid': os.getuid(), 'euid': os.geteuid(),
                           'python': platform.python_version(),
                           'kernel': platform.release()}}
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        result['errors'].append('Run as an ordinary user without a privilege change')
        return result
    context_file = Path(args.context).resolve()
    xvfb = shutil.which(args.xvfb)
    if not context_file.is_file() or not xvfb or not ctypes.util.find_library('X11'):
        result['errors'].append('Readable context helper, executable Xvfb and libX11 are required')
        return result
    result['metadata']['context_sha256'] = hashlib.sha256(context_file.read_bytes()).hexdigest()
    result['metadata']['xvfb_sha256'] = hashlib.sha256(Path(xvfb).read_bytes()).hexdigest()
    process, ready, temporary_path = None, False, None
    try:
        with tempfile.TemporaryDirectory(prefix='session-x11-context-', dir=args.temporary_parent) as temporary:
            temporary_path = Path(temporary)
            server_auth, good_auth, wrong_auth = [temporary_path / name for name in
                                                ('server.auth', 'good.auth', 'wrong.auth')]
            cookie, wrong = secrets.token_bytes(16), secrets.token_bytes(16)
            while wrong == cookie:
                wrong = secrets.token_bytes(16)
            write_authority(server_auth, '', cookie)
            server_env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                          'HOME': pwd.getpwuid(os.getuid()).pw_dir,
                          'TMPDIR': temporary}
            if args.xvfb_library_dir:
                server_env['LD_LIBRARY_PATH'] = ':'.join(args.xvfb_library_dir)
            log_path = temporary_path / 'xvfb.log'
            read_fd, write_fd = os.pipe()
            try:
                with log_path.open('wb') as log:
                    command = [xvfb, '-displayfd', str(write_fd), '-screen', '0',
                               '640x480x24', '-auth', str(server_auth),
                               '-nolisten', 'tcp', '-noreset']
                    if args.xkbdir:
                        command += ['-xkbdir', args.xkbdir]
                    process = subprocess.Popen(command, env=server_env, pass_fds=(write_fd,),
                                               stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                os.close(write_fd)
                write_fd = None
                number = read_display(process, read_fd)
                ready = True
                result['status'] = 'failed'
                result['metadata']['display'] = ':' + number
                status = Path('/proc', str(process.pid), 'status').read_text()
                server_uids = next(line.split()[1:] for line in status.splitlines()
                                   if line.startswith('Uid:'))
                result['checks']['ordinary_user_server'] = all(int(x) == os.getuid() for x in server_uids)
                result['checks']['tcp_disabled'] = not tcp_sockets(process.pid)
                write_authority(good_auth, number, cookie)
                write_authority(wrong_auth, number, wrong)
                for name, auth in (('correct_cookie', good_auth), ('wrong_cookie', wrong_auth)):
                    cwd = temporary_path / name
                    cwd.mkdir()
                    context = ['LANG=C', 'LANGUAGE=', 'LC_TIME=C', 'TZ=UTC0',
                               'DISPLAY=:' + number, 'XAUTHORITY=' + str(auth),
                               'XDG_SESSION_TYPE=x11', 'XDG_CURRENT_DESKTOP=fixture']
                    case = run_payload(context_file, context, cwd)
                    result[name] = case
                    info = case['result']
                    if not info or case['returncode'] != 0:
                        raise RuntimeError(name + ' payload failed')
                    expected = dict.fromkeys(ENV_NAMES)
                    expected.update(item.split('=', 1) for item in context)
                    result['checks'][name + '_environment'] = info['environment'] == expected
                    result['checks'][name + '_uid'] = info['uid'] == info['euid'] == os.getuid()
                    if name == 'correct_cookie':
                        result['checks']['authorized_window'] = (
                            info['opened'] and info.get('destroy_synced') is True and
                            info.get('window') == {'width': 240, 'height': 160, 'map_state': 2})
                        result['checks']['workload_umask'] = info.get('umask') == '0027'
                        result['checks']['created_modes'] = info.get('created_modes') == {
                            'created-file': '0640', 'created-directory': '0750'}
                    else:
                        result['checks']['wrong_cookie_rejected'] = info['opened'] is False
            finally:
                os.close(read_fd)
                if write_fd is not None:
                    os.close(write_fd)
                if process is not None:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=3)
                    result['checks']['own_server_stopped'] = process.poll() is not None
                result['xvfb_log'] = log_path.read_text(errors='replace')[-3000:] if log_path.exists() else ''
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        result['errors'].append(type(error).__name__ + ': ' + str(error))
    if temporary_path is not None:
        result['checks']['private_fixture_removed'] = not temporary_path.exists()
    if ready and not result['errors'] and all(result['checks'].values()):
        result['status'] = 'passed'
    return result


def main():
    if sys.argv[1:] == ['--client']:
        return x11_client()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', default=str(Path(__file__).resolve().parents[1] / 'lib/context.sh'))
    parser.add_argument('--xvfb', default='Xvfb')
    parser.add_argument('--xvfb-library-dir', action='append', default=[],
                        help='Private library directory used only by this Xvfb process')
    parser.add_argument('--xkbdir', help='Optional existing XKB data directory')
    parser.add_argument('--temporary-parent', help='Existing directory for the private temporary fixture')
    parser.add_argument('--output', required=True, help='JSON evidence file')
    args = parser.parse_args()
    os.umask(0o077)
    result = run_fixture(args)
    output = Path(args.output)
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'passed' else 2 if result['status'] == 'not_run' else 1


if __name__ == '__main__':
    sys.exit(main())
