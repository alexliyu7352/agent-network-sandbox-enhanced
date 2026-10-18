#!/usr/bin/env python3
"""Real systemd/PTY lifecycle tests; run only on the disposable test host."""
import argparse
import concurrent.futures
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import termios
import threading
import time
from host_acceptance import DEV, RUNTIME, Suite, Session, command, udp_target


class Terminal:
    def __init__(self,suite,name):
        self.suite,self.name,self.sid=suite,name,None
        self.buffer=b'';self.status=None
        self.log=(suite.output/(name+'.pty')).open('wb')
        self.pid,self.fd=pty.fork()
        if self.pid==0:
            os.execv(DEV,[DEV,'--user',suite.user,'run','--cwd','/'])
        suite.terminals.append(self)
        fcntl.ioctl(self.fd,termios.TIOCSWINSZ,struct.pack('HHHH',24,80,0,0))
        self.write(b"printf '\\137\\137PTY_READY\\137\\137\\n'\n")
        self.until(b'__PTY_READY__\r\n',35)

    def write(self,data):os.write(self.fd,data)

    def until(self,marker,timeout=8):
        end=time.monotonic()+timeout
        while marker not in self.buffer:
            remaining=end-time.monotonic()
            if remaining<=0:raise AssertionError(self.name+' missing '+repr(marker))
            ready,_,_=select.select([self.fd],[],[],remaining)
            if not ready:continue
            try:data=os.read(self.fd,65536)
            except OSError:raise AssertionError(self.name+' PTY closed before '+repr(marker))
            if not data:raise AssertionError(self.name+' EOF before '+repr(marker))
            self.log.write(data);self.log.flush();self.buffer+=data
            match=re.search(rb'Session ([0-9a-f]{32});',self.buffer)
            if match:self.sid=match.group(1).decode()
        index=self.buffer.index(marker)+len(marker)
        result=self.buffer[:index];self.buffer=self.buffer[index:]
        return result

    def wait(self,timeout=18):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            pid,status=os.waitpid(self.pid,os.WNOHANG)
            if pid:
                self.status=status
                if self.sid:self.suite.reclaimed(self.sid)
                return status
            time.sleep(0.05)
        raise AssertionError(self.name+' launcher did not terminate')

    def background(self):
        self.write(b"nohup /bin/bash -c 'trap \"\" HUP TERM; exec /bin/sleep 600' >/dev/null 2>&1 & printf '\\137\\137CHILD:%s\\n' \"$!\"\n")
        output=self.until(b'__CHILD:')
        output+=self.until(b'\r\n')
        match=re.search(rb'__CHILD:([0-9]+)',output)
        assert match,output
        pid=int(match.group(1));self.suite.ignores_signals([pid]);return pid

    def dispose(self):
        if self.sid:command(DEV,'close',self.sid,check=False,timeout=20)
        if self.fd is not None:
            os.close(self.fd);self.fd=None
        if self.status is None:
            try:self.wait(3)
            except (AssertionError,ChildProcessError):
                try:os.kill(self.pid,signal.SIGTERM)
                except ProcessLookupError:pass
        self.log.close()


class Lifecycle(Suite):
    def __init__(self,args):
        super().__init__(args);self.terminals=[]

    def ignores_signals(self,pids):
        end=time.monotonic()+3
        required=(1<<(signal.SIGHUP-1))|(1<<(signal.SIGTERM-1))
        while time.monotonic()<end:
            ready=True
            for pid in pids:
                try:
                    status=Path('/proc/'+str(pid)+'/status').read_text()
                    ignored=int(re.search(r'^SigIgn:\s+([0-9a-f]+)',status,re.M).group(1),16)
                    ready=ready and (ignored&required)==required
                except (FileNotFoundError,AttributeError):ready=False
            if ready:return
            time.sleep(0.02)
        raise AssertionError('descendants did not install HUP/TERM ignore handlers')

    def gone(self,pids):
        end=time.monotonic()+3
        while time.monotonic()<end:
            alive=[]
            for pid in pids:
                try:
                    status=Path('/proc/'+str(pid)+'/status').read_text()
                    if not re.search(r'^State:\s+Z',status,re.M):alive.append(pid)
                except FileNotFoundError:pass
            if not alive:return
            time.sleep(0.1)
        raise AssertionError('surviving descendants: '+repr(alive))

    def descendants(self,session):
        script="""import os,signal,time,sys
if os.fork():os._exit(0)
os.setsid()
if os.fork():os._exit(0)
signal.signal(signal.SIGHUP,signal.SIG_IGN)
signal.signal(signal.SIGTERM,signal.SIG_IGN)
open(sys.argv[1],'w').write(str(os.getpid()))
time.sleep(600)
"""
        code="""
import os,subprocess,tempfile,time
directory=tempfile.mkdtemp(prefix='d8-descendant-')
path=directory+'/pid'
p=subprocess.Popen(['/usr/bin/python3','-c',{script!r},path],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
p.wait(timeout=3)
end=time.monotonic()+3
while not os.path.exists(path) and time.monotonic()<end:time.sleep(0.02)
pid=int(open(path).read());os.unlink(path);os.rmdir(directory)
q=subprocess.Popen(['/usr/bin/nohup','/bin/bash','-c','trap "" HUP TERM; exec /bin/sleep 600'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
result=[pid,q.pid]
""".format(script=script)
        pids=session.value(code);self.ignores_signals(pids);return pids

    def run_lifecycle(self):
        other=Session(self,'survivor-B')
        def normal():
            a=Session(self,'normal-A');pids=self.descendants(a);start=time.monotonic();a.close()
            self.gone(pids);assert other.value('result=40+2')==42
            return {'seconds':round(time.monotonic()-start,3),'descendants':pids,'other_session_alive':True}
        self.record('normal_exit_kills_nohup_doublefork',normal)
        def term():
            a=Session(self,'term-A');pids=self.descendants(a);a.p.terminate();a.p.wait(timeout=18)
            self.reclaimed(a.sid);self.gone(pids);assert other.value('result=True')
            return {'exit':a.p.returncode,'other_session_alive':True}
        self.record('wrapper_TERM_cleanup',term)
        def client_kill():
            a=Session(self,'client-kill-A')
            children=Path('/proc/{0}/task/{0}/children'.format(a.p.pid)).read_text().split()
            clients=[int(pid) for pid in children if b'systemd-run\0' in Path('/proc/'+pid+'/cmdline').read_bytes()]
            assert len(clients)==1,children
            os.kill(clients[0],signal.SIGKILL);a.p.wait(timeout=18);self.reclaimed(a.sid)
            assert other.value('result=True')
            return {'exit':a.p.returncode,'other_session_alive':True}
        self.record('native_relay_SIGKILL_cleanup',client_kill)
        def explicit_close():
            a=Session(self,'explicit-close-A');pids=self.descendants(a)
            command(DEV,'close',a.sid,timeout=20)
            a.p.wait(timeout=18);self.reclaimed(a.sid);self.gone(pids)
            assert other.value('result=True')
            return {'close_exit':0,'launcher_exit':a.p.returncode,'other_session_alive':True}
        self.record('explicit_close_and_launcher_cleanup_race',explicit_close)
        def wrapper_kill():
            a=Session(self,'wrapper-kill-A')
            pids=self.descendants(a)
            capture=self.physical_capture('wrapper-kill-direct')
            a.p.kill();a.p.wait(timeout=3)
            active=command('systemctl','is-active','dev-session-'+a.sid+'.service',check=False).stdout.strip()=='active'
            if active:
                self.credentials(a);self.forced_egress(a)
            self.stop_captures()
            physical=self.verify_physical_capture(capture)
            self.assert_rules()
            command(DEV,'close',a.sid,timeout=20);self.reclaimed(a.sid);self.gone(pids)
            return dict(physical,unit_remained_after_SIGKILL=active,
                        restrictions_retained_if_alive=True,explicit_close_reclaimed=True)
        self.record('wrapper_SIGKILL_documented_limit',wrapper_kill)
        def terminal_controls():
            terminal=Terminal(self,'interactive-controls')
            terminal.write("printf '\\137\\137UNICODE:%s\\n' '中文終端'\n".encode())
            terminal.until('__UNICODE:中文終端\r\n'.encode())
            terminal.write(b"printf '\\137\\137EDIT:%s\\n' abX\x7fc\n")
            terminal.until(b'__EDIT:abc\r\n')
            terminal.write(b'sleep 30\n');time.sleep(0.2);terminal.write(b'\x03')
            terminal.write(b"printf '\\137\\137CTRL_C_OK\\n'\n");terminal.until(b'__CTRL_C_OK\r\n')
            terminal.write(b'sleep 30\n');time.sleep(0.2);terminal.write(b'\x1a');terminal.until(b'Stopped')
            terminal.write(b'fg\n');time.sleep(0.2);terminal.write(b'\x03')
            terminal.write(b"printf '\\137\\137FG_OK\\n'\n");terminal.until(b'__FG_OK\r\n')
            fcntl.ioctl(terminal.fd,termios.TIOCSWINSZ,struct.pack('HHHH',31,97,0,0));time.sleep(0.15)
            terminal.write(b"printf '\\137\\137SIZE:'; stty size\n");terminal.until(b'__SIZE:31 97\r\n')
            child=terminal.background();terminal.write(b'exit\n');terminal.wait();self.gone([child])
            return {'unicode':True,'readline_edit':True,'ctrl_c':True,'ctrl_z_fg':True,'resize':[31,97],'background_reaped':True}
        self.record('real_PTY_controls_and_exit',terminal_controls)
        def terminal_close():
            terminal=Terminal(self,'terminal-hangup');child=terminal.background()
            os.close(terminal.fd);terminal.fd=None;terminal.wait();self.gone([child])
            assert other.value('result=True')
            return {'PTY_master_closed':True,'stubborn_child_reaped':True,'other_session_alive':True}
        self.record('terminal_close_cleanup',terminal_close)
        other.close()
        def docker_restart():
            a=Session(self,'docker-restart-A');b=Session(self,'docker-restart-B')
            c=Session(self,'docker-restart-C')
            self.credentials(a);before=self.https(a,keep=True);assert before['ok']
            capture=self.physical_capture('docker-restart-direct')
            start_event=threading.Event();finished=threading.Event();started=time.monotonic()
            def connections(existing):
                start_event.wait();attempts=[]
                while not attempts or not finished.is_set():
                    at=time.monotonic()-started
                    response=self.existing_https(a) if existing else self.https(c)
                    attempts.append({'started':at,'response':response})
                    if finished.wait(0.1):break
                return attempts
            def forced():
                start_event.wait();attempts=[]
                while not attempts or not finished.is_set():
                    attempts.append({'started':time.monotonic()-started,'attempts':self.forced_egress(b)})
                    if finished.wait(0.25):break
                return attempts
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                old_work=pool.submit(connections,True);new_work=pool.submit(connections,False)
                forced_work=pool.submit(forced)
                process=subprocess.Popen(['systemctl','restart','docker'],stdin=subprocess.DEVNULL,
                                         stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                start_event.set()
                try:
                    out,err=process.communicate(timeout=45)
                    elapsed=time.monotonic()-started
                    assert process.returncode==0,(process.returncode,out,err)
                finally:finished.set()
                old_attempts=old_work.result(timeout=20);new_attempts=new_work.result(timeout=20)
                forced_attempts=forced_work.result(timeout=20)
            assert all(attempts[0]['started']<elapsed for attempts in (old_attempts,new_attempts,forced_attempts))
            recovery=self.after_namespace_fault('docker-restart')
            if not recovery['offline_maintenance_required']:assert self.https(c)['ok']
            self.credentials(a);self.assert_rules();a.close();b.close();c.close()
            self.stop_captures();physical=self.verify_physical_capture(capture)
            if not recovery['offline_maintenance_required']:
                self.gateway_ready()
                recovered=Session(self,'docker-recovered');assert self.https(recovered)['ok'];recovered.close()
            self.assert_rules()
            return dict(physical,session_survived=True,capabilities_unchanged=True,
                        recovery=recovery,all_test_sessions_closed=True,
                        restart_seconds=round(elapsed,3),existing_attempts=old_attempts,
                        new_attempts=new_attempts,forced_attempts=forced_attempts)
        def concurrent_sessions():
            sessions=[Session(self,'parallel-'+name) for name in 'ABC']
            assert len({session.sid for session in sessions})==3
            for session in sessions:self.credentials(session)
            for session in (sessions[1],sessions[0],sessions[2]):
                session.close();sessions.remove(session)
                for survivor in sessions:assert survivor.value('result=42')==42
            self.assert_rules()
            return {'simultaneously_ready':3,'close_order':'B,A,C','cross_cleanup':False}
        self.record('three_live_sessions_independent_cleanup',concurrent_sessions)
        def repetitions():
            started=time.monotonic();completed=0
            def one(index):
                p=command(DEV,'--user',self.user,'run','--cwd','/','--','/usr/bin/true',check=False,timeout=55)
                if p.returncode:
                    (self.output/('repeat-failure-'+str(index)+'.log')).write_text(p.stdout+p.stderr)
                    raise AssertionError('short session {} failed: {}'.format(index,p.returncode))
                sid=re.search(r'Session ([0-9a-f]{32});',p.stderr).group(1)
                self.reclaimed(sid)
                return index
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                for done in pool.map(one,range(self.repetitions)):
                    completed+=1
                    if completed%10==0:print('SHORT_SESSIONS_COMPLETED='+str(completed),flush=True)
            assert not [path for path in self.binding.cgroup_root.iterdir() if path.is_dir()]
            assert list((RUNTIME/'requests').iterdir())==[]
            self.assert_rules()
            return {'sessions':completed,'concurrency':3,'seconds':round(time.monotonic()-started,3),'residual_sessions':0,'constant_rule_count':len(self.baseline)}
        self.record('repeated_parallel_sessions',repetitions)
        self.record('lifecycle_policy_unchanged',self.assert_rules)
        if self.namespace_fault=='docker-restart':
            self.record('Docker_daemon_restart',docker_restart)

    def cleanup(self):
        for terminal in self.terminals:terminal.dispose()
        super().cleanup()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user',default='ubuntu')
    parser.add_argument('--output',default='/root/dev-session-acceptance-20261009/lifecycle')
    parser.add_argument('--repetitions',type=int,default=100)
    parser.add_argument('--udp-echo',type=udp_target)
    parser.add_argument('--namespace-fault',choices=('none','docker-restart'),default='none',
                        help='last scenario; namespace changes require offline rebind after sessions close')
    args=parser.parse_args();assert os.geteuid()==0
    os.umask(0o077);suite=Lifecycle(args)
    try:suite.run_lifecycle()
    finally:suite.cleanup()
    print('HOST_LIFECYCLE_ACCEPTANCE_PASSED',flush=True)


if __name__=='__main__':main()
