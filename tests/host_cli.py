#!/usr/bin/env python3
"""Real sudo/PTY acceptance for the short CLI on a disposable test host.

Requires an initialized gateway, a sudo-capable caller, and a separate ordinary
target account. Creates only temporary projects; accounts are managed outside
this runner. Run sequentially with the network/lifecycle fault suites.
"""
import argparse
import json
import os
from pathlib import Path
import pty
import pwd
import re
import select
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from host_acceptance import Binding, INSTALL_ROOT, RUNTIME


INFO = """import json,os,pathlib
s=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
print('CLI_RESULT '+json.dumps({'uid':os.getuid(),'groups':os.getgroups(),
 'cwd':os.getcwd(),'home':os.environ['HOME'],'user':os.environ['USER'],
 'cgroup':pathlib.Path('/proc/self/cgroup').read_text(),
 'caps':{k:s[k].strip() for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')},
 'nnp':s['NoNewPrivs'].strip(),'seccomp':s['Seccomp'].strip()}),flush=True)
"""


class Acceptance:
    def __init__(self, args):
        self.caller = pwd.getpwnam(args.caller)
        self.target = pwd.getpwnam(args.target)
        assert self.caller.pw_uid and self.target.pw_uid
        assert self.caller.pw_uid != self.target.pw_uid
        self.output = Path(args.output)
        self.output.mkdir(parents=True, mode=0o700, exist_ok=True)
        assert not self.output.is_symlink() and self.output.stat().st_uid==0 and self.output.stat().st_mode&0o077==0,'output must be root private'
        self.records, self.sids, self.projects = [], set(), []
        self.launcher=str(Path(args.launcher))
        assert os.path.isabs(args.launcher),'launcher must be absolute'
        self.command = ['/usr/bin/sudo', '-n', self.launcher]
        self.binding=Binding.load()
        (self.output/'binding.json').write_text(json.dumps(self.binding.data,indent=2)+'\n')

    def drop_caller(self):
        os.setgroups([])
        os.setgid(self.caller.pw_gid)
        os.setuid(self.caller.pw_uid)

    def environment(self):
        return {'PATH':'/usr/local/bin:/usr/bin:/bin', 'TERM':'xterm', 'LC_ALL':'C.UTF-8',
                'HOME':self.caller.pw_dir, 'USER':self.caller.pw_name,
                'LOGNAME':self.caller.pw_name}

    def project(self, owner, mode):
        path = Path(tempfile.mkdtemp(prefix='session cli ', dir='/var/tmp'))
        self.projects.append(path)
        os.chown(path, owner.pw_uid, owner.pw_gid)
        path.chmod(mode)
        return path

    def log(self, name, text):
        (self.output/(name+'.log')).write_text(text)
        self.sids.update(re.findall(r'Session ([0-9a-f]{32});', text))

    def run(self, name, args, cwd, stdout_fd=None):
        # File-backed output cannot keep communicate() waiting after a relay
        # timeout. Register printed SIDs even when the launcher fails to finish.
        with tempfile.TemporaryFile(mode='w+t') as out, tempfile.TemporaryFile(mode='w+t') as err:
            p = subprocess.Popen(self.command + args, cwd=str(cwd), env=self.environment(),
                preexec_fn=self.drop_caller, stdin=subprocess.DEVNULL,
                stdout=out if stdout_fd is None else stdout_fd, stderr=err, text=True)
            try:
                p.wait(timeout=45)
            except subprocess.TimeoutExpired:
                out.seek(0); err.seek(0)
                self.log(name,out.read()+err.read())
                p.terminate()
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=3)
                raise
            finally:
                out.seek(0); err.seek(0)
                stdout, stderr = out.read(), err.read()
                self.log(name,stdout+stderr)
            return subprocess.CompletedProcess(p.args,p.returncode,stdout,stderr)

    def verify(self, output, account, cwd):
        match = re.search(r'CLI_RESULT (\{[^\r\n]+\})', output)
        assert match, output
        info = json.loads(match.group(1))
        assert info['uid'] == account.pw_uid, info
        assert info['groups'] == [], info
        assert info['cwd'] == str(cwd.resolve()), info
        assert info['home'] == account.pw_dir and info['user'] == account.pw_name, info
        assert all(int(info['caps'][k],16) == 0
                   for k in ('CapInh','CapPrm','CapEff','CapAmb')), info
        assert info['nnp'] == '1' and info['seccomp'] == '2', info
        sids=set(re.findall(r'Session ([0-9a-f]{32});',output))
        assert len(sids)==1,'missing unique session identity'
        self.binding.verify_membership(info['cgroup'],next(iter(sids)))
        self.binding.verify_parent()
        return info

    def record(self, name, fn):
        start = time.monotonic()
        try:
            result = {'name':name, 'passed':True, 'detail':fn()}
        except BaseException as error:
            result = {'name':name, 'passed':False, 'error':repr(error)}
            self.records.append(result)
            self.save()
            raise
        result['seconds'] = round(time.monotonic()-start, 3)
        self.records.append(result)
        self.save()
        print(json.dumps(result), flush=True)

    def save(self):
        (self.output/'results.json').write_text(json.dumps(self.records, indent=2)+'\n')

    def success(self, name, args, cwd, account, expected_cwd=None):
        p = self.run(name, args+['--','/usr/bin/python3','-c',INFO], cwd)
        assert p.returncode == 0, p.stdout+p.stderr
        return self.verify(p.stdout+p.stderr, account, expected_cwd or cwd)

    def terminal(self, cwd):
        child, fd = pty.fork()
        if child == 0:
            os.chdir(cwd)
            self.drop_caller()
            os.execve(self.command[0], self.command, self.environment())
        output = b''
        status = None
        try:
            os.write(fd, ('/usr/bin/python3 -c '+shlex.quote(INFO)+'\nexit\n').encode())
            deadline = time.monotonic()+45
            while time.monotonic() < deadline:
                if select.select([fd],[],[],0.2)[0]:
                    try:
                        data = os.read(fd, 65536)
                    except OSError:
                        data = b''
                    output += data
                found, value = os.waitpid(child, os.WNOHANG)
                if found:
                    status = value
                    break
            assert status == 0, (status, output.decode(errors='replace'))
            return self.verify(output.decode(errors='replace'), self.caller, cwd)
        finally:
            self.log('bare_sudo_session_pty', output.decode(errors='replace'))
            os.close(fd)
            if status is None:
                try:
                    os.kill(child, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                for sig in (signal.SIGTERM,signal.SIGKILL):
                    try:
                        os.kill(child,sig)
                    except ProcessLookupError:
                        pass
                    deadline=time.monotonic()+3
                    while time.monotonic()<deadline:
                        if os.waitpid(child,os.WNOHANG)[0]:
                            status=0
                            break
                        time.sleep(0.05)
                    if status is not None:
                        break
                assert status is not None,'PTY relay could not be reaped'

    def exercise(self):
        mine = self.project(self.caller, 0o700)
        shared = self.project(self.target, 0o755)
        self.record('default_caller_and_current_directory', lambda:self.success(
            'default_caller', [], mine, self.caller))
        alias = mine/'project-link'
        alias.symlink_to(shared, target_is_directory=True)
        self.record('physical_working_directory', lambda:self.success(
            'physical_cwd', [], alias, self.caller))
        self.record('dedicated_user_short_option', lambda:self.success(
            'dedicated_user', ['-u',self.target.pw_name], shared, self.target))
        self.record('explicit_cwd', lambda:self.success(
            'explicit_cwd', ['-u',self.target.pw_name,'--cwd',str(shared)],
            mine, self.target, shared))
        self.record('legacy_syntax', lambda:self.success(
            'legacy_syntax', ['--user',self.target.pw_name,'run','--cwd',str(shared)],
            mine, self.target, shared))

        def denied_cwd():
            marker = shared/'must-not-run'
            p = self.run('denied_cwd', ['-u',self.target.pw_name,'--','/usr/bin/touch',str(marker)], mine)
            assert p.returncode != 0 and not marker.exists(), p.stdout+p.stderr
            assert 'working directory' in p.stderr.lower(), p.stderr
            return {'exit':p.returncode,'payload_created':False,'message':p.stderr.strip()}
        self.record('inaccessible_cwd_stops_payload', denied_cwd)

        def private_install():
            p = self.run('private_install', ['-u',self.target.pw_name,'--','/usr/bin/python3','-c',
                "import os; assert not os.access({!r},os.R_OK); assert not os.access({!r},os.X_OK); print('PRIVATE_INSTALL_OK')".format(
                    str(INSTALL_ROOT/'network.json'),str(INSTALL_ROOT))], shared)
            assert p.returncode == 0 and 'PRIVATE_INSTALL_OK' in p.stdout, p.stdout+p.stderr
            return {'target_cannot_read_configuration':True}
        self.record('configuration_private_to_root', private_install)

        def inherited_socket():
            marker = mine/'socket-must-not-run'
            parent, child = socket.socketpair()
            try:
                p = self.run('inherited_socket',['--','/usr/bin/touch',str(marker)],mine,stdout_fd=child)
                assert p.returncode == 125 and not marker.exists(),p.stderr
                return {'exit':p.returncode,'payload_created':False}
            finally:
                parent.close()
                child.close()
        self.record('inherited_socket_stdio_rejected', inherited_socket)
        self.record('bare_sudo_session_real_pty', lambda:self.terminal(mine))

    def cleanup(self):
        errors=[]
        for sid in self.sids:
            try:
                subprocess.run([self.launcher,'close',sid], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=25)
                assert not (RUNTIME/'requests'/sid).exists(),sid
                assert not self.binding.session_path(sid).exists(),sid
                active = subprocess.run(['systemctl','show','--property=LoadState','--value','dev-session-'+sid+'.service'],
                                        capture_output=True,text=True,timeout=10)
                assert active.stdout.strip()=='not-found',sid
            except Exception as error:
                errors.append(sid+': '+repr(error))
        for project in self.projects:
            try:
                shutil.rmtree(project)
            except Exception as error:
                errors.append(str(project)+': '+repr(error))
        try:self.binding.verify_parent()
        except Exception as error:errors.append('retained binding: '+repr(error))
        assert not errors,'Cleanup incomplete: '+ '; '.join(errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--caller', default='ubuntu')
    parser.add_argument('--target', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--launcher',default='/usr/local/bin/session',help='absolute public launcher used through sudo')
    args = parser.parse_args()
    assert os.geteuid() == 0, 'root required on a disposable test host'
    os.umask(0o077)
    suite = Acceptance(args)
    try:
        suite.exercise()
    finally:
        suite.cleanup()
    print('HOST_CLI_ACCEPTANCE_PASSED', flush=True)


if __name__ == '__main__':
    main()
