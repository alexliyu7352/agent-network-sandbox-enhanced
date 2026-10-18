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
import uuid

INSTALL_ROOT = Path(__file__).resolve().parents[1]
DEV = str(INSTALL_ROOT / 'dev-session')
CGROOT = Path('/sys/fs/cgroup/net_cls,net_prio/dev-session-v8')
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
import os
result={'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),
        'status':open('/proc/self/status').read(),
        'cgroup':open('/proc/self/cgroup').read(),
        'proxy_env':[k for k in os.environ if k.lower().endswith('_proxy')]}
'''


def command(*args, check=True, timeout=40):
    p = subprocess.run(list(args), stdin=subprocess.DEVNULL, capture_output=True,
                       text=True, timeout=timeout)
    if check and p.returncode:
        raise AssertionError('command failed {}: {}'.format(args, (p.stdout+p.stderr)[-2000:]))
    return p


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
        self.sessions, self.servers, self.captures, self.results = [], [], [], []
        self.next_probe_port=21000
        assert int(Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split()[0])>21199
        self.uid = int(command('id','-u',self.user).stdout)
        self.gid = int(command('id','-g',self.user).stdout)
        self.host_ip = json.loads(command('ip','-j','-4','route','get','1.1.1.1').stdout)[0]['prefsrc']
        self.interface = json.loads(command('ip','-j','-4','route','get','1.1.1.1').stdout)[0]['dev']
        self.bridge, self.gateway, self.node, self.node_port = (RUNTIME/'binding').read_text().splitlines()
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
            if not (CGROOT/sid).exists() and not (RUNTIME/'requests'/sid).exists() and unit=='not-found':
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
        path=self.capture(name,self.interface,
                          'src portrange 21000-21199 and dst host 9.9.9.9 and dst port 44443')
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
        assert ':net_cls,net_prio:/dev-session-v8/'+session.sid in info['cgroup']
        assert ':name=systemd:/system.slice/dev-session-'+session.sid+'.service' in info['cgroup']
        assert info['proxy_env']==[]
        return {'uid':info['uid'],'uids':uids,'groups':info['groups'],
                'privilege_caps_zero':True,'cap_bnd':status['CapBnd'].strip(),
                'no_new_privs':1,'seccomp':2}

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
            restore();self.gateway_ready()
        assert self.https(self.a)['ok']
        self.a.value("state.pop('https').close();state.pop('kept_socket',None);result=True")
        return {'existing_socket':before['result']['socket'],'existing_connection_blocked':True,
                'new_connection_blocked':True,'other_session_loopback_alive':True}

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
        self.record('gateway_stop',lambda:self.fault('gateway-stop',
            lambda:command('docker','stop','--time','1','worker'),
            lambda:command('docker','start','worker')))
        self.record('gateway_core_kill',lambda:self.fault('gateway-kill',
            lambda:command('docker','kill','--signal=KILL','worker'),
            lambda:command('docker','start','worker')))
        self.record('host_default_route_removed',lambda:self.fault('host-route',
            lambda:command('ip','-4','route','del','default','via',self.gateway,'dev',self.bridge,'table','32190'),
            lambda:command('ip','-4','route','add','default','via',self.gateway,'dev',self.bridge,'table','32190')))
        def ns_command(*args):
            pid=command('docker','inspect','-f','{{.State.Pid}}','worker').stdout.strip()
            return command('nsenter','--net=/proc/'+pid+'/ns/net','--',*args)
        self.record('gateway_half_route_removed',lambda:self.fault('gateway-half-route',
            lambda:ns_command('ip','-4','route','del','0.0.0.0/1','dev','tun0'),
            lambda:ns_command('ip','-4','route','add','0.0.0.0/1','dev','tun0')))
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
        self.stop_captures()
        def captures():
            physical=self.verify_physical_capture(self.wire)
            outer=command('tcpdump','-nn','-r',str(self.outer)).stdout.splitlines()
            assert len(outer)>0 and all(' > '+self.node+'.'+self.node_port+': UDP' in x for x in outer),outer[:5]
            content=self.outer.read_bytes()
            qnames=[b''.join(bytes([len(label)])+label.encode() for label in name.split('.'))+b'\0'
                    for name in self.query_names]
            assert all(name not in content for name in qnames)
            dns=command('tcpdump','-nn','-r',str(self.dns_pcap)).stdout.splitlines()
            assert len(dns)>0 and all(' > 1.1.1.1.53:' in x for x in dns),dns[:5]
            return dict(physical,outer_udp_packets=len(outer),redirected_dns_packets=len(dns),plaintext_dns_on_outer=False)
        self.record('packet_capture_evidence',captures)
        self.a.close();self.b.close()
        self.record('shared_rules_unchanged',lambda:self.assert_rules())

    def assert_https(self):
        result=self.https(self.a);assert result['ok'] and result['result']['status']==200,result
        return result

    def assert_rules(self):
        assert self.policy_snapshot()==self.baseline
        return {'owned_rule_lines':len(self.baseline)}

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
    args=parser.parse_args()
    assert os.geteuid()==0,'requires root on a disposable test host'
    os.umask(0o077)
    suite=Suite(args)
    try:suite.run_core()
    finally:suite.cleanup()
    print('HOST_CORE_ACCEPTANCE_PASSED',flush=True)


if __name__=='__main__':main()
