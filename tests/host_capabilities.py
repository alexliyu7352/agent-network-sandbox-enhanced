#!/usr/bin/env python3
"""Root-only capability acceptance on an installed, working VPS fixture."""
import argparse, errno, json, os, platform, pwd, re, shutil, stat, subprocess, tempfile
from pathlib import Path

INSTALL_ROOT = Path(__file__).resolve().parents[1]
DEV = str(INSTALL_ROOT / 'dev-session')
PAYLOAD = r'''
import json, socket, subprocess, sys
def status(text):
    wanted = ('Uid', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp')
    return {k: v.strip() for k, v in (s.split(':', 1) for s in text.splitlines() if ':' in s) if k in wanted}
def command(argv):
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, timeout=8)
        return {'returncode': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
    except OSError as e:
        return {'returncode': None, 'errno': e.errno}
    except subprocess.TimeoutExpired:
        return {'returncode': None, 'error': 'timeout'}
own = status(open('/proc/self/status').read())
child = command([sys.argv[1], '/proc/self/status'])
child['status'] = status(child.pop('stdout', ''))
try:
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP):
        raw_errno = 0
except OSError as e:
    raw_errno = e.errno
print('CAPABILITIES ' + json.dumps({'status': own, 'capprobe': child, 'raw_errno': raw_errno,
      'ping': command(['/bin/ping', '-V']), 'sysctl': command(['sysctl', '-n', 'kernel.ostype'])}, sort_keys=True))
'''


def command(argv, timeout=12):
    return subprocess.run([str(x) for x in argv], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                          timeout=timeout, env=dict(os.environ, LC_ALL='C'))


def metadata(path):
    s = path.stat()
    return {'uid': s.st_uid, 'gid': s.st_gid, 'mode': oct(stat.S_IMODE(s.st_mode)), 'size': s.st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user', required=True)
    parser.add_argument('--output', required=True, help='root-private evidence directory')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('must run as root')
    os.umask(0o077)
    output, temporary, probe, stderr, launched, timed_out = Path(args.output), None, None, '', False, False
    output_ready = False
    names = ('fixture', 'zero_bounding_exec_eperm', 'launcher', 'credentials', 'capprobe_exec',
             'capprobe_credentials', 'raw_socket_eperm', 'ping_version', 'sysctl_linux', 'session_cleanup', 'fixture_cleanup')
    result = {'passed': False, 'checks': dict.fromkeys(names, False), 'metadata': {}, 'errors': []}
    checks = result['checks']
    try:
        output.mkdir(mode=0o700, parents=True, exist_ok=True)
        if output.is_symlink() or output.stat().st_uid != 0 or output.stat().st_mode & 0o077:
            raise RuntimeError('output must be a root-private directory')
        output_ready = True
        account = pwd.getpwnam(args.user)
        if account.pw_uid == 0:
            raise RuntimeError('target user must be nonroot')
        last = int(Path('/proc/sys/kernel/cap_last_cap').read_text())
        if not 0 <= last <= 63:
            raise RuntimeError('unsupported kernel capability range')
        source = Path('/bin/cat').resolve()
        with source.open('rb') as f:
            if f.read(4) != b'\x7fELF':
                raise RuntimeError('/bin/cat must be a real ELF executable')
        temporary = Path(tempfile.mkdtemp(prefix='dev-session-capabilities-'))
        os.chown(str(temporary), 0, account.pw_gid)
        temporary.chmod(0o710)  # 目標帳戶只能穿越；不能列出或修改測試檔案。
        probe = temporary / 'capprobe'
        shutil.copyfile(str(source), str(probe))
        os.chown(str(probe), 0, account.pw_gid)
        probe.chmod(0o550)
        if command(['setcap', 'cap_net_raw=ep', probe]).returncode:
            raise RuntimeError('cannot set fixture file capability')
        caps = command(['getcap', probe]).stdout.strip()[len(str(probe)):].strip().lstrip('=').strip()
        checks['fixture'] = caps in ('cap_net_raw=ep', 'cap_net_raw+ep')
        if not checks['fixture']:
            raise RuntimeError('fixture file capability was not verified')
        result['metadata'] = {'kernel': platform.release(), 'python': platform.python_version(),
            'setpriv': command(['setpriv', '--version']).stdout.strip(), 'cat': metadata(source),
            'capprobe': metadata(probe), 'capprobe_caps': caps, 'ping': metadata(Path('/bin/ping')),
            'ping_caps': command(['getcap', '/bin/ping']).stdout.strip(), 'target_uid': account.pw_uid}
        drops = ','.join('-cap_{}'.format(i) for i in range(last + 1))
        # setpriv 若降權失敗便不執行檔案；只接受執行該檔案時的 EPERM。
        negative = command(['setpriv', '--reuid', account.pw_uid, '--regid', account.pw_gid, '--clear-groups',
            '--bounding-set=' + drops, '--inh-caps=' + drops, '--ambient-caps=' + drops, '--no-new-privs', probe, '/proc/self/status'])
        checks['zero_bounding_exec_eperm'] = (negative.returncode != 0 and 'failed to execute' in negative.stderr
            and str(probe) in negative.stderr and 'Operation not permitted' in negative.stderr and 'Uid:' not in negative.stdout)
        result['negative_control'] = {'returncode': negative.returncode, 'stderr': negative.stderr.strip()}
        launched = True
        try:
            p = command([DEV, '--user', args.user, 'run', '--cwd', '/', '--', '/usr/bin/python3', '-c', PAYLOAD, probe], 90)
            stderr = p.stderr
        except subprocess.TimeoutExpired as e:
            timed_out, stderr = True, e.stderr or ''
            if isinstance(stderr, bytes): stderr = stderr.decode('utf-8', 'replace')
            raise RuntimeError('launcher timed out')
        checks['launcher'] = p.returncode == 0
        rows = [line[13:] for line in p.stdout.splitlines() if line.startswith('CAPABILITIES ')]
        if len(rows) != 1: raise RuntimeError('launcher did not return exactly one payload result')
        info = result['payload'] = json.loads(rows[0])
        bounding = info['status'].get('CapBnd', '')
        def restricted(s):
            return (s.get('Uid', '').split() == [str(account.pw_uid)] * 4 and s.get('CapBnd') == bounding
                and all(s.get(k) == '0000000000000000' for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'))
                and s.get('NoNewPrivs') == '1' and s.get('Seccomp') == '2')
        checks['credentials'] = bool(re.fullmatch('[0-9a-f]{16}', bounding) and int(bounding, 16) & (1 << 13) and restricted(info['status']))
        checks['capprobe_exec'] = info['capprobe']['returncode'] == 0
        checks['capprobe_credentials'] = restricted(info['capprobe']['status'])
        checks['raw_socket_eperm'] = info['raw_errno'] == errno.EPERM  # 只建立 socket；從不送出封包。
        checks['ping_version'] = info['ping']['returncode'] == 0
        checks['sysctl_linux'] = info['sysctl']['returncode'] == 0 and info['sysctl'].get('stdout', '').strip() == 'Linux'
    except Exception as e:
        result['errors'].append(type(e).__name__ + ': ' + str(e))
    finally:
        try:
            sids = set(re.findall(r'^Session ([0-9a-f]{32});', stderr, re.M))
            if len(sids) == 1:
                sid = sids.pop(); result['session_id'] = sid
                paths = [Path('/sys/fs/cgroup/net_cls,net_prio/dev-session-v8') / sid, Path('/run/dev-session-v8/requests') / sid]
                show = ['systemctl', 'show', '--property=LoadState', '--value', 'dev-session-' + sid + '.service']
                state = command(show).stdout.strip()
                if timed_out or any(p.exists() for p in paths) or state != 'not-found':
                    command([DEV, 'close', sid], 30)
                    state = command(show).stdout.strip()
                checks['session_cleanup'] = not any(p.exists() for p in paths) and state == 'not-found'
            else: checks['session_cleanup'] = not launched
        except Exception as e: result['errors'].append('session cleanup: ' + str(e))
        try:
            try:
                if probe is not None and probe.exists(): command(['setcap', '-r', probe])
            finally:
                if temporary is not None: shutil.rmtree(str(temporary))
            checks['fixture_cleanup'] = temporary is None or not temporary.exists()
        except Exception as e: result['errors'].append('fixture cleanup: ' + str(e))
    result['passed'] = all(checks.values()) and not result['errors']
    evidence = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if output_ready:
        try: (output / 'results.json').write_text(evidence)
        except OSError as e:
            result['passed'] = False; result['errors'].append('evidence write: ' + str(e))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
