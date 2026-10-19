#!/usr/bin/env python3
"""Privileged acceptance runner for a disposable Ubuntu test machine only.

Requires an installed dev-session and a working upstream (the separate local
Hysteria2 fixture is supported). Writes evidence beneath --output. Test Python
is not part of the runtime launcher or gateway. No global firewall flushes.
"""
import argparse
import concurrent.futures
import errno
import fcntl
import http.client
import ipaddress
import json
import os
from pathlib import Path
import pty
import queue
import re
import select
import signal
import socket
import socketserver
import struct
import subprocess
import termios
import threading
import time
import tempfile
from types import SimpleNamespace
import uuid
import unittest
from unittest import mock

INSTALL_ROOT = Path(__file__).resolve().parents[1]
DEV = str(INSTALL_ROOT / 'dev-session')
RUNTIME = Path('/run/dev-session-v8')
WORKER = r'''
import json, os, sys
state = {}
print('WORKER_READY', flush=True)
for line in sys.stdin:
    request = json.loads(line)
    if request.get('exit'):
        break
    scope = {'state': state}
    try:
        exec(request['code'], scope)
        response = {'ok': True, 'result': scope.get('result')}
    except Exception as e:
        response = {'ok': False, 'error': type(e).__name__ + ': ' + str(e),
                    'errno': getattr(e, 'errno', None)}
    print('RESULT ' + json.dumps(response), flush=True)
'''
INFO = '''
import os, socket
before=open('/proc/self/cgroup').read()
probes=[]
for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
    sock=socket.socket(socket.AF_INET,kind);probes.append(sock)
    sock.bind(('127.0.0.1',0))
    if kind==socket.SOCK_STREAM:sock.listen(1)
state['membership_sockets']=probes
result={'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),
        'status':open('/proc/self/status').read(),
        'cgroup':open('/proc/self/cgroup').read(),
        'cgroup_before_sockets':before,'pid':os.getpid(),
        'socket_inodes':[int(os.readlink('/proc/self/fd/'+str(s.fileno()))[8:-1]) for s in probes],
        'proxy_env':[k for k in os.environ if k.lower().endswith('_proxy')]}
'''


def command(*args, check=True, timeout=40):
    p = subprocess.run(list(args), stdin=subprocess.DEVNULL, capture_output=True,
                       text=True, timeout=timeout)
    if check and p.returncode:
        raise AssertionError('command failed {}: {}'.format(args, (p.stdout+p.stderr)[-2000:]))
    return p


class Binding:
    """Independent strict reader for the installed format-2 runtime contract."""

    @classmethod
    def from_text(cls, text):
        def unique(pairs):
            result={}
            for key,value in pairs:
                if key in result:raise ValueError('duplicate JSON binding key')
                result[key]=value
            return result
        value=json.loads(text,object_pairs_hook=unique)
        def keys(obj,expected):
            assert isinstance(obj,dict) and set(obj)==set(expected.split()),'unexpected binding schema'
        def match(value,pattern):
            return isinstance(value,str) and re.fullmatch(pattern,value) is not None
        def version(obj,number):
            assert type(obj['format']) is int and obj['format']==number,'unexpected binding version'
        def ipv4(value):
            assert isinstance(value,str) and str(ipaddress.IPv4Address(value))==value,'noncanonical IPv4 address'
        keys(value,'format cgroup gateway proxy_policy source_sha256 effective_sha256 policy_parser_sha256')
        version(value,2)
        for key in ('source_sha256','effective_sha256','policy_parser_sha256'):
            assert match(value[key],r'[0-9a-f]{64}'),'invalid binding hash'
        group=value['cgroup']
        keys(group,'format mode mount mount_identity manager_hierarchy path identity boot_id');version(group,1)
        assert group['mode'] in ('v1','v2'),'unsupported cgroup mode'
        assert match(group['mount'],r'(?:/[A-Za-z0-9_.,-]+)+'),'unsafe cgroup mount'
        assert all(part not in ('.','..') for part in group['mount'].split('/')),'unsafe cgroup mount'
        for key in ('mount_identity','identity'):
            assert match(group[key],r'[0-9]+:[1-9][0-9]*'),'invalid cgroup identity'
        assert match(group['boot_id'],r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'),'invalid boot identity'
        assert ((group['mode']=='v1' and group['path']=='dev-session-v8' and group['manager_hierarchy'] in ('0','name=systemd'))
                or (group['mode']=='v2' and group['path']=='devsession.slice' and group['manager_hierarchy']=='0')),'invalid cgroup parent'
        gateway=value['gateway']
        keys(gateway,'bridge address container_id network_id namespace_identity')
        assert match(gateway['bridge'],r'[A-Za-z0-9_-]{1,15}'),'invalid bridge'
        ipv4(gateway['address'])
        for key in ('container_id','network_id'):
            assert match(gateway[key],r'[0-9a-f]{64}'),'invalid Docker identity'
        assert match(gateway['namespace_identity'],r'[0-9]+:[1-9][0-9]*'),'invalid namespace identity'
        policy=value['proxy_policy']
        keys(policy,'format proxy_tag outer_endpoints payload_networks dns_transport');version(policy,1)
        assert policy['proxy_tag']=='proxy' and policy['payload_networks'] in (['tcp'],['tcp','udp']),'invalid payload policy'
        assert policy['dns_transport']==('udp' if 'udp' in policy['payload_networks'] else 'https'),'inconsistent DNS transport'
        endpoints=policy['outer_endpoints']
        assert isinstance(endpoints,list) and endpoints,'missing outer endpoints'
        previous=None
        for endpoint in endpoints:
            keys(endpoint,'family address protocol port_start port_end')
            assert type(endpoint['family']) is int and endpoint['family']==4,'invalid endpoint family'
            ipv4(endpoint['address'])
            assert endpoint['protocol'] in ('tcp','udp'),'invalid outer protocol'
            assert all(type(endpoint[key]) is int for key in ('port_start','port_end')),'invalid outer port'
            assert 1<=endpoint['port_start']<=endpoint['port_end']<=65535,'invalid outer range'
            order=(int(ipaddress.IPv4Address(endpoint['address'])),endpoint['protocol'],endpoint['port_start'],endpoint['port_end'])
            if previous:
                assert previous<order,'noncanonical endpoint ordering'
                if previous[:2]==order[:2]:assert previous[3]+1<order[2],'unmerged endpoint ranges'
            previous=order
        result=cls();result.data=value;result.raw=text;result.cgroup=group;result.gateway=gateway;result.policy=policy
        result.cgroup_root=Path(group['mount'])/group['path']
        return result

    @classmethod
    def load(cls,path=RUNTIME/'binding'):
        path=Path(path)
        assert not path.is_symlink() and path.is_file(),'binding must be a regular file'
        metadata=path.stat()
        assert metadata.st_uid==0 and metadata.st_mode&0o077==0,'binding must be root private'
        binding=cls.from_text(path.read_text());binding.file=path;binding.verify_parent()
        return binding

    def session_path(self,sid):
        assert re.fullmatch(r'[0-9a-f]{32}',sid),'invalid session ID'
        return self.cgroup_root/(sid if self.cgroup['mode']=='v1' else 'dev-session-'+sid+'.service')

    def service_path(self,sid):
        self.session_path(sid)
        parent='/system.slice' if self.cgroup['mode']=='v1' else '/'+self.cgroup['path']
        return parent+'/dev-session-'+sid+'.service'

    def verify_parent(self):
        assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==self.cgroup['boot_id'],'boot identity changed'
        for path,key in ((Path(self.cgroup['mount']),'mount_identity'),(self.cgroup_root,'identity')):
            assert path.resolve()==path and path.is_dir(),'cgroup path changed'
            metadata=path.stat()
            assert metadata.st_uid==0 and metadata.st_mode&0o022==0,'cgroup parent is writable by nonroot'
            assert '{}:{}'.format(metadata.st_dev,metadata.st_ino)==self.cgroup[key],'cgroup identity changed'
        if hasattr(self,'file'):
            assert not self.file.is_symlink() and self.file.read_text()==self.raw,'binding changed during acceptance'

    def verify_membership(self,text,sid):
        entries=[line.split(':',2) for line in text.splitlines()]
        assert entries and all(len(entry)==3 for entry in entries),'invalid process cgroup evidence'
        service=self.service_path(sid)
        hierarchy=self.cgroup['manager_hierarchy']
        manager=([entry for entry in entries if entry[0]=='0' and entry[1]==''] if hierarchy=='0' else
                 [entry for entry in entries if 'name=systemd' in entry[1].split(',')])
        assert len(manager)==1 and manager[0][2]==service,'process outside bound systemd service'
        if self.cgroup['mode']=='v1':
            controller=[entry for entry in entries if 'net_cls' in entry[1].split(',')]
            assert len(controller)==1 and controller[0][2]=='/'+self.cgroup['path']+'/'+sid,'process outside bound net_cls group'

    @staticmethod
    def verify_socket_rows(text,inodes,service):
        assert len(inodes)==2 and len(set(inodes))==2,'missing independently created TCP/UDP socket evidence'
        for inode in inodes:
            rows=[line for line in text.splitlines() if re.search(r'(?:^|\s)ino:'+str(inode)+r'(?:\s|$)',line)]
            assert len(rows)==1,'created socket missing or ambiguous in ss evidence'
            groups=re.findall(r'(?:^|\s)cgroup:([^\s]+)',rows[0])
            assert groups and set(groups)=={service},'socket was created outside the bound service'

    @staticmethod
    def endpoint_bpf(endpoint):
        port=('dst port '+str(endpoint['port_start']) if endpoint['port_start']==endpoint['port_end'] else
              'dst portrange '+str(endpoint['port_start'])+'-'+str(endpoint['port_end']))
        return '(dst host '+endpoint['address']+' and '+endpoint['protocol']+' and '+port+')'

    def outer_bpf(self):
        return '(ip and src host '+self.gateway['address']+' and ('+' or '.join(self.endpoint_bpf(e) for e in self.policy['outer_endpoints'])+'))'


def udp_target(value):
    try:
        address,port=value.rsplit(':',1);address=str(ipaddress.IPv4Address(address));port=int(port)
        assert 1<=port<=65535 and port!=53
    except (ValueError,AssertionError):raise argparse.ArgumentTypeError('expected IPv4:non-DNS-port')
    return address,port


class Session:
    def __init__(self, suite, name):
        self.suite, self.name, self.sid = suite, name, None
        self.lines = queue.Queue()
        self.log = (suite.output/(name+'.log')).open('w')
        self.p = subprocess.Popen([DEV, '--user', suite.user, 'run', '--cwd', '/', '--',
                                   '/usr/bin/python3', '-u', '-c', WORKER],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, bufsize=1)
        suite.sessions.append(self)
        self.reader = threading.Thread(target=self.read, daemon=True); self.reader.start()
        self.until('WORKER_READY', 35)

    def read(self):
        for line in self.p.stdout:
            self.log.write(line); self.log.flush()
            match = re.search(r'Session ([0-9a-f]{32});', line)
            if match:
                self.sid = match.group(1)
            self.lines.put(line.rstrip('\n'))
        self.lines.put(None)

    def until(self, prefix, timeout=20):
        end = time.monotonic()+timeout
        while time.monotonic()<end:
            try:
                line = self.lines.get(timeout=max(0.01, end-time.monotonic()))
            except queue.Empty:
                break
            if line is None:
                raise AssertionError(self.name+' exited before '+prefix)
            if line.startswith(prefix):
                return line[len(prefix):]
        raise AssertionError(self.name+' timed out waiting for '+prefix)

    def call(self, code, timeout=20):
        self.p.stdin.write(json.dumps({'code':code})+'\n'); self.p.stdin.flush()
        return json.loads(self.until('RESULT ', timeout))

    def value(self, code, timeout=20):
        response = self.call(code, timeout)
        assert response['ok'], response
        return response['result']

    def close(self,strict=True):
        if self.p.poll() is None:
            try:
                self.p.stdin.write('{"exit":true}\n'); self.p.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
        try:
            self.p.wait(timeout=17)
        except subprocess.TimeoutExpired:
            if strict:raise AssertionError(self.name+' did not exit and reclaim naturally')
            if self.sid:
                command(DEV, 'close', self.sid, check=False, timeout=20)
            self.p.wait(timeout=5)
        if self.sid:
            self.suite.reclaimed(self.sid)


class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.received += 1
        self.request.settimeout(3)
        self.request.sendall(self.request.recv(2048))


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.received += 1
        data, sock = self.request
        sock.sendto(data, self.client_address)


class Suite:
    def __init__(self, args):
        self.output, self.user, self.repetitions = Path(args.output), args.user, args.repetitions
        self.output.mkdir(mode=0o700, parents=True, exist_ok=True)
        assert not self.output.is_symlink() and self.output.stat().st_uid==0 and self.output.stat().st_mode&0o077==0,'output must be root private'
        self.sessions, self.servers, self.captures, self.results = [], [], [], []
        self.namespace_fault=getattr(args,'namespace_fault','none')
        self.udp_echo=getattr(args,'udp_echo',None)
        self.binding=Binding.load()
        (self.output/'binding.json').write_text(json.dumps(self.binding.data,indent=2)+'\n')
        self.next_probe_port=21000
        assert int(Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split()[0])>21199
        self.uid = int(command('id','-u',self.user).stdout)
        self.gid = int(command('id','-g',self.user).stdout)
        self.host_ip = json.loads(command('ip','-j','-4','route','get','1.1.1.1').stdout)[0]['prefsrc']
        self.interface = json.loads(command('ip','-j','-4','route','get','1.1.1.1').stdout)[0]['dev']
        self.bridge=self.binding.gateway['bridge'];self.gateway=self.binding.gateway['address']
        address=json.loads(command('ip','-j','-4','addr','show','dev',self.bridge).stdout)[0]['addr_info'][0]
        self.bridge_network=str(ipaddress.ip_network(address['local']+'/'+str(address['prefixlen']),strict=False))
        local_addresses=[a['local'] for link in json.loads(command('ip','-j','-4','addr','show').stdout)
                         for a in link['addr_info'] if a['family']=='inet']
        # Bridge ingress also includes decrypted responses after reverse NAT.
        # Exclude only actual host destinations, loopback and this bridge subnet.
        excludes=['dst net '+self.bridge_network,'dst net 127.0.0.0/8']
        excludes+=['dst host '+address for address in local_addresses]
        self.external_filter='(ip and not ('+' or '.join(excludes)+')) or ip6'
        self.baseline = self.policy_snapshot()

    def record(self, name, fn):
        start=time.monotonic()
        try:
            detail=fn()
            result={'name':name,'passed':True,'seconds':round(time.monotonic()-start,3),'detail':detail}
        except Exception as error:
            result={'name':name,'passed':False,'seconds':round(time.monotonic()-start,3),'error':repr(error)}
            self.results.append(result); self.save(); print(json.dumps(result),flush=True)
            raise
        self.results.append(result); self.save(); print(json.dumps(result),flush=True)

    def save(self):
        (self.output/'results.json').write_text(json.dumps(self.results,indent=2))

    def policy_snapshot(self):
        rows=[]
        for binary,table in [('iptables-legacy','mangle'),('iptables-legacy','nat'),('ip6tables-legacy','mangle')]:
            text=command(binary,'-t',table,'-S').stdout
            rows.extend(line for line in text.splitlines() if 'D8' in line)
        rows.extend(line for line in command('ip','-4','rule','show').stdout.splitlines() if '32190' in line)
        return rows

    def reclaimed(self, sid):
        end=time.monotonic()+16
        while time.monotonic()<end:
            unit=command('systemctl','show','--property=LoadState','--value','dev-session-'+sid+'.service',check=False).stdout.strip()
            if not self.binding.session_path(sid).exists() and not (RUNTIME/'requests'/sid).exists() and unit=='not-found':
                self.binding.verify_parent()
                return
            time.sleep(0.1)
        raise AssertionError('session not reclaimed: '+sid)

    def server(self, cls, address, port, handler):
        server=cls((address,port),handler);server.received=0
        threading.Thread(target=server.serve_forever,kwargs={'poll_interval':0.05},daemon=True).start()
        self.servers.append(server)
        return server

    def capture(self, name, interface, expression, direction=None):
        path=self.output/(name+'.pcap')
        log=(self.output/(name+'-tcpdump.log')).open('w')
        args=['tcpdump','--immediate-mode','-ni',interface,'-U','-s','512','-w',str(path)]
        if direction:args+=['-Q',direction]
        p=subprocess.Popen(args+[expression],
                           stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        self.captures.append({'process':p,'log':log,'path':path,'stopped':False})
        time.sleep(0.15)
        assert p.poll() is None, 'capture failed'
        return path

    def stop_captures(self,strict=True):
        errors=[]
        for capture in self.captures:
            if capture['stopped']:continue
            p,log,path=(capture[key] for key in ('process','log','path'))
            if p.poll() is not None:
                errors.append(str(path)+': collector exited before observation ended')
            else:
                if strict and capture.get('physical'):
                    # Observe a trailing packet in the savefile before stopping;
                    # -U alone flushes userspace output, not capture buffers.
                    marker=('D8-END-'+uuid.uuid4().hex).encode()
                    self.physical_canary(marker)
                    end=time.monotonic()+3
                    while marker not in path.read_bytes() and time.monotonic()<end:
                        time.sleep(0.02)
                    if marker not in path.read_bytes():errors.append(str(path)+': trailing canary missing')
                p.send_signal(signal.SIGINT)
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill();p.wait();errors.append(str(path)+': collector would not stop')
            log.close();capture['stopped']=True
            if p.returncode!=0:errors.append(str(path)+': collector exit '+str(p.returncode))
            stats=Path(log.name).read_text()
            dropped=re.search(r'^(\d+) packets dropped by kernel$',stats,re.M)
            if not dropped or int(dropped.group(1))!=0:
                errors.append(str(path)+': missing statistics or dropped packets')
            if capture.get('physical'):
                captured=re.search(r'^(\d+) packets? captured$',stats,re.M)
                received=re.search(r'^(\d+) packets? received by filter$',stats,re.M)
                if not captured or not received or captured.group(1)!=received.group(1):
                    errors.append(str(path)+': physical capture did not process every received packet')
        if strict:assert not errors,errors

    def physical_capture(self,name):
        destinations=['(dst host 9.9.9.9 and dst port 44443)']
        if self.udp_echo:destinations.append('(dst host '+self.udp_echo[0]+' and dst port '+str(self.udp_echo[1])+')')
        path=self.capture(name,self.interface,
                          'src portrange 21000-21199 and ('+' or '.join(destinations)+')')
        self.captures[-1]['physical']=True
        # Positive control proves the exact capture can see a direct host flow.
        # Workload attempts use 21001..21199; this root-only canary uses 21000.
        self.physical_canary(b'D8-CAPTURE-POSITIVE-CONTROL')
        return path

    def physical_canary(self,payload):
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.bind(('0.0.0.0',21000))
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,self.interface.encode()+b'\0')
            sock.sendto(payload,('9.9.9.9',44443))

    def verify_physical_capture(self,path):
        canary=command('tcpdump','-nn','-r',str(path),'src port 21000').stdout.splitlines()
        direct=command('tcpdump','-nn','-r',str(path),'src portrange 21001-21199').stdout.splitlines()
        assert len(canary)>=2,'physical capture did not observe both positive controls'
        assert not direct,direct
        return {'positive_control_packets':len(canary),'direct_workload_packets':len(direct)}

    def credentials(self, session):
        info=session.value(INFO)
        # getgroups() lists supplementary groups; the primary gid is separate.
        assert (info['uid'],info['gid'],info['groups'])==(self.uid,self.gid,[]), info
        status=dict(line.split(':',1) for line in info['status'].splitlines() if ':' in line)
        uids=list(map(int,status['Uid'].split()))
        assert self.uid!=0 and uids==[self.uid]*4,uids
        for key in ('CapInh','CapPrm','CapEff','CapAmb'):
            assert int(status[key].strip(),16)==0,(key,status[key])
        assert status['NoNewPrivs'].strip()=='1' and status['Seccomp'].strip()=='2'
        self.binding.verify_membership(info['cgroup_before_sockets'],session.sid)
        self.binding.verify_membership(info['cgroup'],session.sid)
        socket_evidence=None
        try:
            if self.binding.cgroup['mode']=='v2':
                rows=command('ss','-H','-t','-u','-a','-n','-p','-e','--cgroup').stdout
                (self.output/(session.name+'-socket-cgroups.log')).write_text(rows)
                service=self.binding.service_path(session.sid)
                self.binding.verify_socket_rows(rows,info['socket_inodes'],service)
                socket_evidence={'inodes':info['socket_inodes'],'cgroup':service,'created_inside_service':True}
            else:
                classid=int((self.binding.session_path(session.sid)/'net_cls.classid').read_text().strip(),0)
                assert classid==0x6d730001,'incorrect session net_cls classid'
        finally:
            session.value("[s.close() for s in state.pop('membership_sockets',[])];result=True")
        self.binding.verify_parent()
        assert info['proxy_env']==[]
        return {'uid':info['uid'],'uids':uids,'groups':info['groups'],
                'privilege_caps_zero':True,'cap_bnd':status['CapBnd'].strip(),
                'no_new_privs':1,'seccomp':2,'cgroup_mode':self.binding.cgroup['mode'],
                'cgroup_mount':self.binding.cgroup['mount'],'socket_creation':socket_evidence}

    def echo(self, session, address, port, udp=False):
        code="""
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if {udp} else socket.SOCK_STREAM) as sock:
    sock.settimeout(2); sock.connect(({address!r},{port}))
    sock.sendall(b'd8-loopback-proof'); result=sock.recv(200).decode()
""".format(udp=udp,address=address,port=port)
        assert session.value(code)=='d8-loopback-proof'

    def dns(self, session, address, tcp, name):
        code=r"""
import socket,struct
name={name!r}
question=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\x00\x00\x01\x00\x01'
message=struct.pack('!6H',0x4d38,0x0100,1,0,0,0)+question
with socket.socket(socket.AF_INET,socket.SOCK_STREAM if {tcp} else socket.SOCK_DGRAM) as sock:
    sock.settimeout(4);sock.connect(({address!r},53))
    if {tcp}:
        sock.sendall(struct.pack('!H',len(message))+message)
        header=sock.recv(2);length=struct.unpack('!H',header)[0];reply=b''
        while len(reply)<length: reply+=sock.recv(length-len(reply))
    else:
        sock.send(message);reply=sock.recv(4096)
    tid,flags,qd,an,_,_=struct.unpack('!6H',reply[:12])
    assert tid==0x4d38 and flags&0x8000 and flags&15 in (0,3)
    result={{'rcode':flags&15,'answers':an}}
""".format(name=name,tcp=tcp,address=address)
        return session.value(code)

    def ordinary_udp(self,session):
        assert self.udp_echo,'full network acceptance requires a controlled --udp-echo IPv4:port'
        address,port=self.udp_echo
        assert address not in {entry['address'] for entry in self.binding.policy['outer_endpoints']},'UDP echo must be separate from outer nodes'
        self.next_probe_port+=1;source_port=self.next_probe_port;assert source_port<=21199
        token='D8-UDP-'+uuid.uuid4().hex
        self.udp_token=token.encode()
        result=session.value('''
import socket
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
    sock.settimeout(3);sock.bind(('0.0.0.0',{source_port}))
    try:
        sock.connect(({address!r},{port}));sock.send({token!r}.encode())
        data=sock.recv(2048);result={{'echo':data=={token!r}.encode(),'received':True}}
    except OSError as error:result={{'echo':False,'received':False,'errno':error.errno}}
'''.format(source_port=source_port,address=address,port=port,token=token))
        supported='udp' in self.binding.policy['payload_networks']
        assert result['echo'] if supported else not result['received'],result
        return dict(result,payload_udp=supported,source_port=source_port,target=[address,port],
                    expected='echo through proxy' if supported else 'ordinary UDP fails closed')

    def https(self, session, keep=False):
        code="""
import http.client
connection=state.get('https') if {keep} else None
if connection is None:
    connection=http.client.HTTPSConnection('1.1.1.1',timeout=3)
    if {keep}: state['https']=connection
connection.request('GET','/cdn-cgi/trace')
response=connection.getresponse();body=response.read()
result={{'status':response.status,'tls':connection.sock is not None,'body_length':len(body)}}
if {keep}:
    assert connection.sock is not None, 'server closed the connection before fault injection'
    state['kept_socket']=connection.sock
    result['socket']=[connection.sock.fileno(),connection.sock.getsockname(),connection.sock.getpeername()]
if not {keep}: connection.close()
""".format(keep=keep)
        return session.call(code,10)

    def existing_https(self,session):
        # Use the established TLS socket itself: HTTPConnection.request()
        # would silently reconnect if the previous response closed it.
        return session.call(r'''
sock=state['kept_socket']
assert sock is state['https'].sock
sock.sendall(b'GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: keep-alive\r\n\r\n')
data=sock.recv(4096)
if not data: raise ConnectionError('established TLS socket closed')
result={'response':data[:100].decode('ascii','replace')}
''',10)

    def gateway_ready(self):
        end=time.monotonic()+18
        while time.monotonic()<end:
            p=command(DEV,'check',check=False,timeout=15)
            if p.returncode==0:
                return
            time.sleep(0.2)
        raise AssertionError('gateway did not recover: '+p.stderr)

    def after_namespace_fault(self,label):
        """Inspect recovery without deleting bindings or repairing live guards."""
        deadline=time.monotonic()+25
        while True:
            inspected=command('docker','inspect','worker',check=False)
            try:
                container=json.loads(inspected.stdout)[0];pid=container['State']['Pid']
                assert pid>0 and container['State']['Running']
                metadata=Path('/proc/'+str(pid)+'/ns/net').stat()
                identity='{}:{}'.format(metadata.st_dev,metadata.st_ino)
                break
            except (ValueError,KeyError,IndexError,AssertionError,OSError):
                if time.monotonic()>=deadline:raise AssertionError('gateway did not restart for namespace identity check')
                time.sleep(0.2)
        changed=identity!=self.binding.gateway['namespace_identity'] or container['Id']!=self.binding.gateway['container_id']
        check=command(DEV,'check',check=False)
        (self.output/(label+'-check.log')).write_text(check.stdout+check.stderr)
        init_exit=None;rejection=None
        if changed:
            assert check.returncode!=0,'changed gateway namespace was admitted'
            self.assert_rules()
            init=command(DEV,'init',check=False)
            (self.output/(label+'-init.log')).write_text(init.stdout+init.stderr)
            init_exit=init.returncode
            assert init.returncode!=0,'init rebound the gateway while prior binding remained'
            self.assert_rules()
            rejection=self.rejected_start(label+'-offline-rebind')
        elif check.returncode:
            rejection=self.rejected_start(label+'-policy-drift')
        else:
            self.gateway_ready()
        self.assert_rules()
        return {'namespace_before':self.binding.gateway['namespace_identity'],'namespace_after':identity,
                'namespace_changed':changed,'check_exit':check.returncode,'init_exit':init_exit,
                'rejected_start':rejection,'binding_and_guards_retained':True,
                'offline_rebind_required':changed,'offline_maintenance_required':bool(check.returncode)}

    def gateway_namespace_fault(self,action):
        before=self.https(self.a,keep=True);assert before['ok'],before
        try:
            if action=='gateway-stop':command('docker','stop','--time','1','worker')
            else:command('docker','kill','--signal=KILL','worker')
            old=self.existing_https(self.a);new=self.https(self.a)
            assert not old['ok'] and not new['ok'],{'old':old,'new':new}
            self.rejected_start(action)
            self.echo(self.b,'127.0.0.1',self.tcp.server_address[1])
            self.forced_egress(self.a)
        finally:command('docker','start','worker')
        result=self.after_namespace_fault(action)
        result.update(existing_connection_blocked_during_fault=True,new_connection_blocked_during_fault=True,
                      other_session_loopback_alive=True)
        return result

    def rejected_start(self, label):
        marker=Path('/tmp/d8-should-not-run-'+uuid.uuid4().hex)
        p=command(DEV,'--user',self.user,'run','--cwd','/','--','/usr/bin/touch',str(marker),check=False,timeout=40)
        (self.output/(label+'-admission.log')).write_text(p.stdout+p.stderr)
        assert p.returncode!=0 and not marker.exists(),(p.returncode,p.stdout,p.stderr)
        match=re.search(r'Session ([0-9a-f]{32});',p.stderr)
        if match:self.reclaimed(match.group(1))
        return {'exit':p.returncode,'payload_executed':False}

    def fault(self, name, apply, restore, reject=True):
        before=self.https(self.a,keep=True)
        assert before['ok'] and before['result']['status']==200 and before['result']['tls'],before
        try:
            apply()
            old=self.existing_https(self.a);new=self.https(self.a)
            assert not old['ok'] and not new['ok'],{'old':old,'new':new}
            if reject:self.rejected_start(name)
            self.echo(self.b,'127.0.0.1',self.tcp.server_address[1])
            self.forced_egress(self.a)
        finally:
            restore();self.gateway_ready();self.assert_rules()
        assert self.https(self.a)['ok']
        self.a.value("state.pop('https').close();state.pop('kept_socket',None);result=True")
        return {'existing_socket':before['result']['socket'],'existing_connection_blocked':True,
                'new_connection_blocked':True,'other_session_loopback_alive':True,
                'gateway_readback_verified_after_restore':True,'binding_and_guards_retained':True}

    def gateway_command(self,*args):
        pid=command('docker','inspect','-f','{{.State.Pid}}','worker').stdout.strip()
        assert re.fullmatch(r'[1-9][0-9]*',pid),'gateway is not running'
        namespace=Path('/proc/'+pid+'/ns/net');metadata=namespace.stat()
        assert '{}:{}'.format(metadata.st_dev,metadata.st_ino)==self.binding.gateway['namespace_identity'],\
            'refusing fault injection into an unbound gateway namespace'
        return command('nsenter','--net='+str(namespace),'--',*args)

    def tun_link_fault(self):
        prefixes=('0.0.0.0/1','128.0.0.0/1')
        def read_routes():
            rows=json.loads(self.gateway_command('ip','-j','-4','route','show','table','main').stdout)
            assert isinstance(rows,list) and all(isinstance(row,dict) and isinstance(row.get('dst'),str)
                                                for row in rows),'unexpected gateway route JSON'
            return rows
        def canonical(rows):return sorted(json.dumps(row,sort_keys=True) for row in rows)
        def unrelated(rows):return canonical([row for row in rows if row['dst'] not in prefixes])
        before=read_routes();saved={}
        for prefix in prefixes:
            rows=[row for row in before if row['dst']==prefix]
            # These are the exact host iproute2 rows created by the gateway.
            # Refuse other attributes before injecting a fault we cannot undo.
            assert rows==[{'dst':prefix,'dev':'tun0','scope':'link','flags':[]}],\
                'TUN fault requires exactly reproducible preexisting half routes'
            saved[prefix]=rows[0]
        restored=[]
        def restore():
            self.gateway_command('ip','link','set','dev','tun0','up')
            current=read_routes();missing=[]
            assert unrelated(current)==unrelated(before),'unrelated gateway routes changed during TUN fault'
            # Link down removes the /1 routes on Linux; link up retains the
            # connected subnet but does not recreate these explicit routes.
            # Preflight BOTH destinations before adding any missing entry.
            for prefix in prefixes:
                rows=[row for row in current if row['dst']==prefix]
                assert not rows or rows==[saved[prefix]],'gateway half route changed during TUN fault'
                if not rows:missing.append(saved[prefix])
            for row in missing:
                self.gateway_command('ip','-4','route','add',row['dst'],'dev',row['dev'],
                                     'scope',row['scope'],'table','main')
                restored.append(row['dst'])
            assert canonical(read_routes())==canonical(before),'gateway routes were not restored exactly'
        result=self.fault('gateway-tun-down',
            lambda:self.gateway_command('ip','link','set','dev','tun0','down'),restore)
        return dict(result,missing_half_routes_restored=len(restored),gateway_route_snapshot_restored=True)

    def node_outage(self):
        addresses=sorted({endpoint['address'] for endpoint in self.binding.policy['outer_endpoints']},
                         key=ipaddress.IPv4Address)
        comment='d8-acceptance-node-outage-'+uuid.uuid4().hex
        installed=[]
        def apply():
            for address in addresses:
                rule=('-o','eth0','-d',address+'/32','-m','comment','--comment',comment,'-j','DROP')
                self.gateway_command('iptables-legacy','-w','5','-I','OUTPUT','1',*rule)
                installed.append(rule)
        def restore():
            failures=[]
            # Track successful inserts; never flush or delete another rule.
            # Continue restoring other nodes if one delete fails, then fail.
            for rule in reversed(installed):
                try:self.gateway_command('iptables-legacy','-w','5','-D','OUTPUT',*rule)
                except Exception as error:failures.append(error)
            if failures:raise AssertionError('could not restore every owned node-outage rule') from failures[0]
        result=self.fault('controlled-node-outage',apply,restore)
        return dict(result,blocked_outer_addresses=addresses,owned_drop_rules_removed=len(installed))

    def forced_egress(self, session):
        outcomes=[]
        for option in ('device','unicast'):
            for udp in (False,True):
                self.next_probe_port+=1;port=self.next_probe_port
                assert port<=21199
                code="""
import socket,struct
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if {udp} else socket.SOCK_STREAM) as sock:
    sock.settimeout(0.5);sock.bind(('0.0.0.0',{port}))
    try:
        if {option!r}=='device': sock.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,{interface!r}.encode()+b'\\0')
        else: sock.setsockopt(socket.IPPROTO_IP,50,struct.pack('!I',socket.if_nametoindex({interface!r})))
        sock.connect(('9.9.9.9',44443));sock.sendall(b'D8-NO-DIRECT-EGRESS')
        # A TUN stack may complete the local TCP handshake before the remote
        # peer connects. Packet capture, not connect(), determines direct escape.
        result={{'connected':True,'udp':{udp},'local':sock.getsockname()}}
    except OSError as error: result={{'error':str(error),'errno':error.errno}}
""".format(udp=udp,port=port,option=option,interface=self.interface)
                outcomes.append({'option':option,'udp':udp,'source_port':port,'result':session.value(code)})
        return outcomes

    def run_core(self):
        assert self.udp_echo,'--udp-echo is required for full TCP/UDP acceptance; use the separate fake upstream fixture'
        self.tcp=self.server(TCP,'0.0.0.0',0,TCPHandler)
        # Bind each UDP address so replies preserve the destination address;
        # a wildcard UDP listener would answer 127.0.0.2 from 127.0.0.1.
        udps={address:self.server(UDP,address,0,UDPHandler)
              for address in ('127.0.0.1','127.0.0.2')}
        local_dns_tcp=self.server(TCP,'127.0.0.1',53,TCPHandler)
        local_dns_udp=self.server(UDP,'127.0.0.1',53,UDPHandler)
        self.wire=self.physical_capture('physical-direct-probes')
        self.outer=self.capture('gateway-outer',self.bridge,
                                self.external_filter,direction='in')
        self.dns_pcap=self.capture('redirected-dns',self.bridge,'dst port 53')
        self.a=Session(self,'session-A');self.b=Session(self,'session-B')
        self.record('two_session_credentials',lambda:[self.credentials(self.a),self.credentials(self.b)])
        def loopback():
            for address in ('127.0.0.1','127.0.0.2'):
                self.echo(self.a,address,self.tcp.server_address[1]);self.echo(self.a,address,udps[address].server_address[1],True)
            return 'TCP/UDP on both loopback addresses'
        self.record('host_loopback',loopback)
        self.record('public_https',lambda:self.assert_https())
        def dns_checks():
            results=[]
            self.query_names=[]
            for address in ('127.0.0.1','127.0.0.53','8.8.8.8','10.0.0.53'):
                for tcp in (False,True):
                    name='d8-'+uuid.uuid4().hex+'.example.com';self.query_names.append(name)
                    results.append({'target':address,'tcp':tcp,'response':self.dns(self.a,address,tcp,name)})
            assert local_dns_tcp.received==0 and local_dns_udp.received==0
            return results
        self.record('all_dns_destinations_redirected',dns_checks)
        self.record('ordinary_udp_capability',lambda:self.ordinary_udp(self.a))
        self.record('forced_physical_interface',lambda:self.forced_egress(self.a))
        def blocked():
            evidence=[]
            def drop_counts():
                rows=[line.split() for line in command('iptables-legacy','-t','mangle','-L','D8DEST','-v','-n','-x').stdout.splitlines()]
                return {row[8]:int(row[0]) for row in rows if len(row)>=9 and row[2]=='DROP'}
            for target in (self.host_ip,'169.254.169.254','10.0.0.1'):
                before=drop_counts()
                prefix=next(net for net in before if ipaddress.ip_address(target) in ipaddress.ip_network(net))
                response=self.a.call("import socket\ns=socket.create_connection((%r,%d),0.4)\nresult=True"%(target,self.tcp.server_address[1]))
                after=drop_counts()
                assert not response['ok'] and after[prefix]>before[prefix],response
                evidence.append({'response':response,'drop_prefix':prefix,'new_dropped_packets':after[prefix]-before[prefix]})
            for target in ('::1','2606:4700:4700::1111'):
                response=self.a.call("import socket\ns=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)\ns.connect((%r,443))\nresult=True"%target)
                assert not response['ok'] and response['errno']==errno.EAFNOSUPPORT,response
                evidence.append(response)
            response=self.a.value("import subprocess\np=subprocess.run(['sudo','-n','true'],capture_output=True,text=True)\nresult={'exit':p.returncode,'error':p.stderr}")
            assert response['exit']!=0;evidence.append(response)
            return evidence
        self.record('private_ipv6_privilege_denials',blocked)
        self.record('controlled_upstream_node_outage',self.node_outage)
        self.record('gateway_TUN_link_down',self.tun_link_fault)
        self.record('host_default_route_removed',lambda:self.fault('host-route',
            lambda:command('ip','-4','route','del','default','via',self.gateway,'dev',self.bridge,'table','32190'),
            lambda:command('ip','-4','route','add','default','via',self.gateway,'dev',self.bridge,'table','32190')))
        self.record('gateway_half_route_removed',lambda:self.fault('gateway-half-route',
            lambda:self.gateway_command('ip','-4','route','del','0.0.0.0/1','dev','tun0'),
            lambda:self.gateway_command('ip','-4','route','add','0.0.0.0/1','dev','tun0')))
        def bad_probe():
            policy=INSTALL_ROOT/'policy.json';original=policy.read_bytes()
            try:
                value=json.loads(original);value['probe_url']='https://127.0.0.1:1/'
                policy.write_text(json.dumps(value))
                return self.rejected_start('failed-https-probe')
            finally:policy.write_bytes(original)
        self.record('failed_probe_no_payload',bad_probe)
        def extra_rule():
            command('iptables-legacy','-t','mangle','-A','D8POST','-j','RETURN')
            try:return self.rejected_start('extra-rule')
            finally:command('iptables-legacy','-t','mangle','-D','D8POST','-j','RETURN')
        self.record('extra_policy_rule_rejected',extra_rule)
        def bad_permissions():
            path=INSTALL_ROOT/'policy.json';mode=path.stat().st_mode&0o777
            path.chmod(0o622)
            try:return self.rejected_start('bad-permissions')
            finally:path.chmod(mode)
        self.record('writable_policy_rejected',bad_permissions)
        if self.namespace_fault!='none':
            self.record(self.namespace_fault,lambda:self.gateway_namespace_fault(self.namespace_fault))
        self.stop_captures()
        def captures():
            physical=self.verify_physical_capture(self.wire)
            outer=command('tcpdump','-nn','-r',str(self.outer)).stdout.splitlines()
            assert outer,'no outer packets observed'
            unexpected=command('tcpdump','-nn','-r',str(self.outer),'not '+self.binding.outer_bpf()).stdout.splitlines()
            assert not unexpected,unexpected[:20]
            endpoint_counts=[]
            for endpoint in self.binding.policy['outer_endpoints']:
                packets=command('tcpdump','-nn','-r',str(self.outer),self.binding.endpoint_bpf(endpoint)).stdout.splitlines()
                endpoint_counts.append(dict(endpoint,packets=len(packets)))
            content=self.outer.read_bytes()
            qnames=[b''.join(bytes([len(label)])+label.encode() for label in name.split('.'))+b'\0'
                    for name in self.query_names]
            assert all(name not in content for name in qnames)
            assert self.udp_token not in content,'ordinary UDP appeared in plaintext on outer link'
            dns=command('tcpdump','-nn','-r',str(self.dns_pcap)).stdout.splitlines()
            unexpected_dns=command('tcpdump','-nn','-r',str(self.dns_pcap),
                                   'not (ip and dst host 1.1.1.1 and (tcp or udp) and dst port 53)').stdout.splitlines()
            assert dns and not unexpected_dns,unexpected_dns[:5]
            return dict(physical,outer_packets=len(outer),outer_endpoints=endpoint_counts,
                        redirected_dns_packets=len(dns),plaintext_dns_on_outer=False,
                        dns_transport=self.binding.policy['dns_transport'],payload_networks=self.binding.policy['payload_networks'])
        self.record('packet_capture_evidence',captures)
        self.a.close();self.b.close()
        self.record('shared_rules_unchanged',lambda:self.assert_rules())

    def assert_https(self):
        result=self.https(self.a);assert result['ok'] and result['result']['status']==200,result
        return result

    def assert_rules(self):
        assert self.policy_snapshot()==self.baseline
        self.binding.verify_parent()
        return {'owned_rule_lines':len(self.baseline),'binding_retained':True,'cgroup_parent_identity':self.binding.cgroup['identity']}

    def cleanup(self):
        self.stop_captures(strict=False)
        for session in self.sessions:
            if session.sid:command(DEV,'close',session.sid,check=False,timeout=20)
            try:session.close(strict=False)
            except Exception:pass
        for server in self.servers:server.shutdown();server.server_close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user',default='ubuntu')
    parser.add_argument('--output',default='/root/dev-session-acceptance-20261009/core')
    parser.add_argument('--repetitions',type=int,default=100)
    parser.add_argument('--udp-echo',type=udp_target,required=True,help='controlled non-DNS echo target, reachable only through the upstream fixture')
    parser.add_argument('--namespace-fault',choices=('none','gateway-stop','gateway-kill'),default='none',
                        help='last scenario; changed namespace leaves guards and binding in place for offline rebind')
    args=parser.parse_args()
    assert os.geteuid()==0,'requires root on a disposable test host'
    os.umask(0o077)
    suite=Suite(args)
    try:suite.run_core()
    finally:suite.cleanup()
    print('HOST_CORE_ACCEPTANCE_PASSED',flush=True)


class BindingTests(unittest.TestCase):
    """Pure regression tests: no root, network, cgroup or firewall changes."""

    @staticmethod
    def document(mode='v2'):
        return {'format':2, 'source_sha256':'a'*64, 'effective_sha256':'b'*64,
                'policy_parser_sha256':'c'*64,
                'cgroup':{'format':1, 'mode':mode, 'mount':'/sys/fs/cgroup' if mode=='v2' else '/sys/fs/cgroup/net_cls',
                          'mount_identity':'25:1', 'manager_hierarchy':'0',
                          'path':'devsession.slice' if mode=='v2' else 'dev-session-v8',
                          'identity':'25:123', 'boot_id':'11111111-2222-3333-4444-555555555555'},
                'gateway':{'bridge':'br-fixture', 'address':'172.19.0.2', 'container_id':'d'*64,
                           'network_id':'e'*64, 'namespace_identity':'4:555'},
                'proxy_policy':{'format':1, 'proxy_tag':'proxy', 'dns_transport':'udp',
                                'payload_networks':['tcp','udp'], 'outer_endpoints':[
                                    {'family':4,'address':'192.0.2.8','protocol':'tcp','port_start':443,'port_end':443},
                                    {'family':4,'address':'198.51.100.9','protocol':'udp','port_start':8443,'port_end':8445}]}}

    def test_version_two_dynamic_paths_and_membership(self):
        sid='1'*32
        for mode in ('v1','v2'):
            with self.subTest(mode=mode):
                binding=Binding.from_text(json.dumps(self.document(mode)))
                leaf=sid if mode=='v1' else 'dev-session-'+sid+'.service'
                self.assertEqual(binding.session_path(sid),binding.cgroup_root/leaf)
                text=('7:net_prio,net_cls:/dev-session-v8/'+sid+'\n0::/system.slice/dev-session-'+sid+'.service\n'
                      if mode=='v1' else '0::/devsession.slice/dev-session-'+sid+'.service\n')
                binding.verify_membership(text,sid)
                with self.assertRaises(AssertionError):
                    binding.verify_membership(text.replace(sid,'2'*32),sid)
                with self.assertRaises(AssertionError):
                    binding.verify_membership(text.replace('.service','.service/child'),sid)

    def test_binding_rejects_legacy_duplicate_keys_and_noncanonical_policy(self):
        value=self.document()
        bad=[ 'br-test\n172.19.0.2\n192.0.2.8\n443\n',
              json.dumps(value)+'\n'+json.dumps(value),
              json.dumps(value).replace('"format": 2','"format": 2, "format": 2',1)]
        for section,key,replacement in [(None,'format',True),('cgroup','mount','/sys/fs/cgroup/../tmp'),
                 ('cgroup','identity','25:0'),('gateway','container_id','bad'),
                 ('proxy_policy','payload_networks',['udp']),('proxy_policy','dns_transport','https')]:
            altered=json.loads(json.dumps(value));target=altered[section] if section else altered
            target[key]=replacement;bad.append(json.dumps(altered))
        altered=json.loads(json.dumps(value));altered['proxy_policy']['outer_endpoints'].reverse();bad.append(json.dumps(altered))
        altered=json.loads(json.dumps(value));altered['proxy_policy']['outer_endpoints'][0]['extra']=1;bad.append(json.dumps(altered))
        for document in bad:
            with self.subTest(document=document[:80]), self.assertRaises((ValueError,AssertionError)):
                Binding.from_text(document)

    def test_outer_capture_filter_preserves_all_protocols_and_ranges(self):
        binding=Binding.from_text(json.dumps(self.document()))
        self.assertEqual(binding.outer_bpf(),
            '(ip and src host 172.19.0.2 and ((dst host 192.0.2.8 and tcp and dst port 443) or '
            '(dst host 198.51.100.9 and udp and dst portrange 8443-8445)))')

    def test_socket_evidence_requires_each_created_inode_in_exact_service(self):
        path='/devsession.slice/dev-session-'+'1'*32+'.service'
        rows='tcp LISTEN 0 1 127.0.0.1:1234 0.0.0.0:* ino:101 cgroup:'+path+'\n'
        rows+='udp UNCONN 0 0 127.0.0.1:1235 0.0.0.0:* ino:102 cgroup:'+path+'\n'
        Binding.verify_socket_rows(rows,[101,102],path)
        # iproute2 may print the same field from both -e and --cgroup.
        Binding.verify_socket_rows(rows.replace('cgroup:'+path,'cgroup:'+path+' cgroup:'+path),[101,102],path)
        for bad in (rows.replace('ino:102','ino:103'),rows.replace(path,path+'/child'),
                    rows.replace('cgroup:'+path,'cgroup:/system.slice/unrelated.service'),rows+rows,
                    rows.replace('cgroup:'+path,'cgroup:'+path+' cgroup:/system.slice/unrelated.service')):
            with self.subTest(rows=bad), self.assertRaises(AssertionError):
                Binding.verify_socket_rows(bad,[101,102],path)

    def test_namespace_change_demands_check_and_init_refusal(self):
        for check_exit,init_exit,accepted in ((1,1,True),(0,1,False),(1,0,False)):
            with self.subTest(check=check_exit,init=init_exit),tempfile.TemporaryDirectory() as directory:
                suite=object.__new__(Suite);suite.output=Path(directory)
                suite.binding=Binding.from_text(json.dumps(self.document()))
                suite.assert_rules=mock.Mock(return_value={'binding_retained':True})
                suite.rejected_start=mock.Mock(return_value={'payload_executed':False})
                suite.gateway_ready=mock.Mock(side_effect=AssertionError('changed namespace must not be admitted'))
                calls=[]
                def fake_command(*args,**kwargs):
                    calls.append(args)
                    if args==('docker','inspect','worker'):
                        return subprocess.CompletedProcess(args,0,json.dumps([{'Id':'d'*64,'State':{'Pid':123,'Running':True}}]),'')
                    assert args in ((DEV,'check'),(DEV,'init')),'unexpected external operation'
                    return subprocess.CompletedProcess(args,check_exit if args[-1]=='check' else init_exit,'','refused')
                original_stat=Path.stat
                def fake_stat(path,*args,**kwargs):
                    if str(path)=='/proc/123/ns/net':return SimpleNamespace(st_dev=4,st_ino=999)
                    return original_stat(path,*args,**kwargs)
                with mock.patch(__name__+'.command',side_effect=fake_command),mock.patch.object(Path,'stat',fake_stat):
                    if accepted:
                        result=suite.after_namespace_fault('test-namespace')
                        self.assertTrue(result['offline_rebind_required'])
                        self.assertTrue(result['binding_and_guards_retained'])
                        self.assertIn((DEV,'init'),calls)
                        suite.rejected_start.assert_called_once()
                        self.assertGreaterEqual(suite.assert_rules.call_count,3)
                    else:
                        with self.assertRaises(AssertionError):suite.after_namespace_fault('test-namespace')
                suite.gateway_ready.assert_not_called()

    def test_tcp_only_udp_rejection_may_happen_during_send(self):
        suite=object.__new__(Suite);suite.udp_echo=('192.0.2.254',40123);suite.next_probe_port=21000
        document=self.document();document['proxy_policy'].update(payload_networks=['tcp'],dns_transport='https')
        suite.binding=Binding.from_text(json.dumps(document))
        sock=mock.MagicMock();sock.__enter__.return_value=sock
        sock.send.side_effect=OSError(errno.ENETUNREACH,'test UDP rejection')
        fake_socket=SimpleNamespace(AF_INET=2,SOCK_DGRAM=2,socket=mock.Mock(return_value=sock))
        def evaluate(code):
            scope={}
            with mock.patch.dict('sys.modules',{'socket':fake_socket}):exec(code,scope)
            return scope['result']
        result=suite.ordinary_udp(SimpleNamespace(value=evaluate))
        self.assertFalse(result['received'])
        self.assertFalse(result['payload_udp'])
        self.assertEqual(result['errno'],errno.ENETUNREACH)
        suite.binding=Binding.from_text(json.dumps(self.document()))
        with self.assertRaises(AssertionError):suite.ordinary_udp(SimpleNamespace(value=evaluate))


class FaultTests(unittest.TestCase):
    """Exercise restoration through fake command boundaries, never a firewall."""

    def suite(self):
        suite=object.__new__(Suite)
        document=BindingTests.document()
        # The first IP has two transport entries but needs exactly one DROP.
        document['proxy_policy']['outer_endpoints'].insert(1,
            {'family':4,'address':'192.0.2.8','protocol':'udp','port_start':443,'port_end':443})
        suite.binding=Binding.from_text(json.dumps(document))
        suite.a=SimpleNamespace(value=mock.Mock(return_value=True));suite.b=object()
        suite.tcp=SimpleNamespace(server_address=('127.0.0.1',23456))
        healthy={'ok':True,'result':{'status':200,'tls':True,'socket':['fake-kept-socket']}}
        suite.https=mock.Mock(side_effect=[healthy,{'ok':False},healthy])
        suite.existing_https=mock.Mock(return_value={'ok':False})
        suite.rejected_start=mock.Mock();suite.echo=mock.Mock();suite.forced_egress=mock.Mock()
        suite.gateway_ready=mock.Mock();suite.assert_rules=mock.Mock()
        suite.gateway_command=mock.Mock(return_value=subprocess.CompletedProcess([],0,'',''))
        return suite

    def test_node_outage_blocks_every_unique_ip_and_deletes_only_exact_owned_rules(self):
        suite=self.suite();result=suite.node_outage()
        calls=[call.args for call in suite.gateway_command.call_args_list]
        inserted=[args for args in calls if '-I' in args];deleted=[args for args in calls if '-D' in args]
        self.assertEqual([args[args.index('-d')+1] for args in inserted],['192.0.2.8/32','198.51.100.9/32'])
        self.assertEqual([args[6:] for args in inserted],[args[5:] for args in reversed(deleted)])
        for args in inserted:
            self.assertEqual(args[:6],('iptables-legacy','-w','5','-I','OUTPUT','1'))
            self.assertEqual(args[-2:],('-j','DROP'))
            self.assertIn('--comment',args)
        self.assertEqual(result['blocked_outer_addresses'],['192.0.2.8','198.51.100.9'])
        suite.gateway_ready.assert_called_once();suite.assert_rules.assert_called_once()
        suite.forced_egress.assert_called_once_with(suite.a)

    def test_partial_node_outage_insertion_is_rolled_back_on_exception(self):
        suite=self.suite();calls=[]
        def boundary(*args):
            calls.append(args)
            if '-I' in args and '198.51.100.9/32' in args:raise RuntimeError('insertion failed')
        suite.gateway_command.side_effect=boundary
        with self.assertRaisesRegex(RuntimeError,'insertion failed'):suite.node_outage()
        deleted=[args for args in calls if '-D' in args]
        self.assertEqual(len(deleted),1);self.assertIn('192.0.2.8/32',deleted[0])
        suite.gateway_ready.assert_called_once();suite.assert_rules.assert_called_once()

    def test_cleanup_attempts_every_inserted_node_when_one_delete_fails(self):
        suite=self.suite();calls=[]
        def boundary(*args):
            calls.append(args)
            if '-D' in args and '198.51.100.9/32' in args:raise RuntimeError('deletion failed')
        suite.gateway_command.side_effect=boundary
        with self.assertRaises(AssertionError):suite.node_outage()
        self.assertEqual([args[args.index('-d')+1] for args in calls if '-D' in args],
                         ['198.51.100.9/32','192.0.2.8/32'])
        suite.gateway_ready.assert_not_called()

    def tun_boundary(self,suite,after_up=None,retain_first=False,discard_add=False):
        halves=[{'dst':prefix,'dev':'tun0','scope':'link','flags':[]}
                for prefix in ('0.0.0.0/1','128.0.0.0/1')]
        before=[{'dst':'default','gateway':'172.19.0.1','dev':'eth0','flags':[]},
                {'dst':'172.19.0.0/16','dev':'eth0','protocol':'kernel','scope':'link','prefsrc':'172.19.0.2','flags':[]},
                {'dst':'192.0.2.8','gateway':'172.19.0.1','dev':'eth0','flags':[]},
                {'dst':'198.18.0.0/15','dev':'tun0','protocol':'kernel','scope':'link','prefsrc':'198.18.0.1','flags':[]}]+halves
        state={'routes':json.loads(json.dumps(before)),'up':True}
        def boundary(*args):
            if args==('ip','-j','-4','route','show','table','main'):
                return subprocess.CompletedProcess(args,0,json.dumps(state['routes']),'')
            if args==('ip','link','set','dev','tun0','down'):
                state['up']=False
                state['routes']=[row for row in state['routes'] if row['dst'] not in ('0.0.0.0/1','128.0.0.0/1')]
            elif args==('ip','link','set','dev','tun0','up'):
                state['up']=True
                if retain_first:state['routes'].append(dict(halves[0]))
                if after_up:after_up(state['routes'])
            elif args[:4]==('ip','-4','route','add'):
                self.assertTrue(state['up'])
                self.assertIn(args[4],('0.0.0.0/1','128.0.0.0/1'))
                self.assertFalse(any(row['dst']==args[4] for row in state['routes']))
                self.assertEqual(dict(zip(args[5::2],args[6::2])),{'dev':'tun0','scope':'link','table':'main'})
                if not discard_add:state['routes'].append(next(dict(row) for row in halves if row['dst']==args[4]))
            else:raise AssertionError('unexpected route fault command')
            return subprocess.CompletedProcess(args,0,'','')
        suite.gateway_command.side_effect=boundary
        def ready():
            self.assertTrue(state['up'])
            self.assertCountEqual(state['routes'],before)
        suite.gateway_ready.side_effect=ready
        return state,before

    def test_tun_restores_lost_half_routes_even_if_fault_observation_raises(self):
        for fail in (False,True):
            for retain_first in (False,True):
                with self.subTest(fail=fail,retain_first=retain_first):
                    suite=self.suite();state,before=self.tun_boundary(suite,retain_first=retain_first)
                    if fail:suite.existing_https.side_effect=RuntimeError('observation failed')
                    if fail:
                        with self.assertRaisesRegex(RuntimeError,'observation failed'):suite.tun_link_fault()
                    else:suite.tun_link_fault()
                    self.assertCountEqual(state['routes'],before)
                    calls=[call.args for call in suite.gateway_command.call_args_list]
                    self.assertEqual(calls[0],('ip','-j','-4','route','show','table','main'))
                    self.assertEqual([args[4] for args in calls if args[:4]==('ip','-4','route','add')],
                                     ['128.0.0.0/1'] if retain_first else ['0.0.0.0/1','128.0.0.0/1'])
                    suite.gateway_ready.assert_called_once();suite.assert_rules.assert_called_once()

    def test_tun_refuses_changed_or_duplicate_halves_before_adding_any_routes(self):
        alterations=[
            [{'dst':'128.0.0.0/1','dev':'eth0','scope':'link','flags':[]}],
            [{'dst':'128.0.0.0/1','dev':'tun0','scope':'link','metric':9,'flags':[]}],
            [{'dst':'128.0.0.0/1','dev':'tun0','scope':'link','flags':[]}]*2,
            [{'dst':'203.0.113.0/24','dev':'eth0','scope':'link','flags':[]}]]
        for rows in alterations:
            with self.subTest(rows=rows):
                suite=self.suite();state,before=self.tun_boundary(suite,after_up=lambda routes:routes.extend(rows))
                with self.assertRaises(AssertionError):suite.tun_link_fault()
                self.assertTrue(state['up'])
                calls=[call.args for call in suite.gateway_command.call_args_list]
                self.assertFalse(any(args[:4]==('ip','-4','route','add') for args in calls))
                for row in rows:self.assertIn(row,state['routes'])
                suite.gateway_ready.assert_not_called();suite.assert_rules.assert_not_called()

    def test_tun_requires_reproducible_preexisting_routes_before_injection(self):
        for alteration in ('missing','duplicate','metric'):
            with self.subTest(alteration=alteration):
                suite=self.suite();state,before=self.tun_boundary(suite)
                if alteration=='missing':state['routes'].pop()
                elif alteration=='duplicate':state['routes'].append(dict(state['routes'][-1]))
                else:state['routes'][-1]['metric']=9
                original=json.loads(json.dumps(state['routes']))
                with self.assertRaises(AssertionError):suite.tun_link_fault()
                self.assertEqual(state['routes'],original)
                self.assertTrue(state['up'])
                self.assertTrue(all(call.args==('ip','-j','-4','route','show','table','main')
                                    for call in suite.gateway_command.call_args_list))
                suite.https.assert_not_called();suite.gateway_ready.assert_not_called()

    def test_tun_route_restoration_requires_exact_readback(self):
        suite=self.suite();state,before=self.tun_boundary(suite,discard_add=True)
        with self.assertRaises(AssertionError):suite.tun_link_fault()
        calls=[call.args for call in suite.gateway_command.call_args_list]
        self.assertEqual(len([args for args in calls if args[:4]==('ip','-4','route','add')]),2)
        self.assertNotEqual(state['routes'],before)
        suite.gateway_ready.assert_not_called();suite.assert_rules.assert_not_called()

    def test_gateway_command_mutates_only_the_bound_namespace(self):
        for inode in (555,999):
            with self.subTest(inode=inode):
                suite=self.suite();calls=[]
                def boundary(*args,**kwargs):
                    calls.append(args)
                    return subprocess.CompletedProcess(args,0,'123\n' if args[0]=='docker' else '','')
                original_stat=Path.stat
                def namespace_stat(path,*args,**kwargs):
                    if str(path)=='/proc/123/ns/net':return SimpleNamespace(st_dev=4,st_ino=inode)
                    return original_stat(path,*args,**kwargs)
                with mock.patch(__name__+'.command',side_effect=boundary),mock.patch.object(Path,'stat',namespace_stat):
                    if inode==555:
                        Suite.gateway_command(suite,'ip','link','set','dev','tun0','down')
                        self.assertEqual(calls[-1],('nsenter','--net=/proc/123/ns/net','--',
                                                   'ip','link','set','dev','tun0','down'))
                    else:
                        with self.assertRaises(AssertionError):Suite.gateway_command(suite,'ip','link','set','dev','tun0','down')
                        self.assertEqual(len(calls),1)


if __name__=='__main__':main()
