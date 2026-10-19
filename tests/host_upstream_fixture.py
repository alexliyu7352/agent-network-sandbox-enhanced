#!/usr/bin/env python3
"""Explicit fake upstream fixture for a disposable root-owned acceptance host.

Legacy setup accepts only documentation IPv4 endpoints and fixed HTTP/Hysteria2
test authentication from an explicit read-only --config. Protocol-case render
creates a fresh fake source from the paired runtime recipes. Setup and verify
then independently recompile it and check every immutable artifact identity.
Cleanup removes only the fixture's exact routes, rules, services and namespace.
"""
import argparse
import copy
from contextlib import ExitStack
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import pwd
import re
import select
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import unittest

INSTALL_ROOT = Path(__file__).resolve().parents[1]
NS = 'd8-test-upstream'
HOST = 'd8testh'
PEER = 'd8testn'
ADDRESS = '198.19.254.2'
UNIT = 'd8-test-upstream.service'
ECHO_UNIT = 'd8-test-upstream-echo.service'
FAKE_PASSWORD = 'd8-fixture-only-password'
FAKE_USERNAME = 'd8-fixture'
DOCUMENTATION_NETS = tuple(ipaddress.ip_network(value) for value in
                          ('192.0.2.0/24','198.51.100.0/24','203.0.113.0/24'))
HOP_PORTS = list(range(4400,4404))+list(range(4410,4414))
# Isolated helper interpreters receive only this script's trusted sibling path.
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0,str(Path(__file__).resolve().parent))
ECHO_CODE = """import socket,sys
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
    sock.bind((sys.argv[1],int(sys.argv[2])))
    while True:
        data,peer=sock.recvfrom(2048)
        sock.sendto(data,peer)
"""
CONTINUITY_CHECKS=('single_tls_socket','no_reconnect','window_port_rotation','workload_identity',
                   'workload_cgroup','session_reclaimed','binding_retained','namespace_retained','recipe_unchanged')
CONTINUITY_CONNECT=r'''
import http.client,os,ssl
class SingleConnection(http.client.HTTPSConnection):
    def connect(self):
        self.fixture_connect_calls=getattr(self,'fixture_connect_calls',0)+1
        if self.fixture_connect_calls!=1:raise RuntimeError('hopping-reconnect-denied')
        super().connect()
connection=SingleConnection('1.1.1.1',port=443,timeout=8,context=ssl.create_default_context())
connection.auto_open=0
connection.connect()
original=connection.sock
state['hop']={'connection':connection,'socket':original,'fd':original.fileno(),
              'inode':os.fstat(original.fileno()).st_ino,'peer':original.getpeername(),'exchanges':0}
result=True
'''
CONTINUITY_EXCHANGE=r'''
import ipaddress,os
hop=state['hop'];connection=hop['connection'];original=hop['socket']
def unchanged():
    if not (connection.sock is original and original.fileno()==hop['fd'] and
            os.fstat(original.fileno()).st_ino==hop['inode'] and
            original.getpeername()==hop['peer'] and connection.fixture_connect_calls==1):
        raise RuntimeError('hopping-socket-changed')
unchanged()
connection.request('GET','/cdn-cgi/trace',headers={'Connection':'keep-alive'})
unchanged()
response=connection.getresponse()
if response.status!=200 or response.will_close or 'close' in response.getheader('Connection','').lower().split(','):
    raise RuntimeError('hopping-http-closed-or-failed')
body=response.read(65537)
if len(body)>65536:raise RuntimeError('hopping-response-too-large')
rows=[row[3:] for row in body.decode('ascii').splitlines() if row.startswith('ip=')]
if len(rows)!=1 or str(ipaddress.IPv4Address(rows[0]))!=rows[0]:raise RuntimeError('hopping-trace-invalid')
unchanged()
hop['exchanges']+=1
result={'same_socket':True,'connect_calls':connection.fixture_connect_calls,'exchanges':hop['exchanges']}
'''


def command_category(value):
    if not isinstance(value,(str,os.PathLike)):return None
    name=Path(value).name
    allowed={'ip','systemctl','systemd-run','iptables-legacy','ip6tables-legacy','findmnt',
             'jq','openssl','worker','sing-box','python','python3','curl','dev-session'}
    return name if name in allowed else 'external'


class FixtureCommandError(RuntimeError):
    def __init__(self,command,returncode):
        super().__init__('fixture: command-failed')
        self.command=command_category(command)
        self.returncode=returncode if type(returncode) is int else None


def failure_evidence(error):
    """Describe the failing repository call without any subprocess payload."""
    names={'AssertionError','RuntimeError','FixtureCommandError','TimeoutExpired','OSError',
           'FileNotFoundError','FileExistsError','PermissionError','ValueError','TypeError',
           'KeyError','AttributeError','UnicodeError','UnicodeDecodeError','CaseFailure'}
    name=type(error).__name__
    location={'function':'unknown','line':0};trace=error.__traceback__
    while trace is not None:
        code=trace.tb_frame.f_code
        if (code.co_filename==str(Path(__file__).resolve()) and code.co_name not in ('run','ensure','main')
                and re.fullmatch(r'[a-z_]{1,64}',code.co_name)):
            location={'function':code.co_name,'line':trace.tb_lineno}
        trace=trace.tb_next
    command=None;returncode=None
    timeout=isinstance(error,subprocess.TimeoutExpired)
    if isinstance(error,FixtureCommandError):command,returncode=error.command,error.returncode
    elif timeout:
        argv=error.cmd
        command=command_category(argv[0] if isinstance(argv,(tuple,list)) and argv else argv)
    return {'format':1,'exception':name if name in names else 'Exception','location':location,
            'command':command,'returncode':returncode,'timeout':timeout}


def run(*args, check=True, timeout=40):
    result=subprocess.run(list(map(str,args)),stdin=subprocess.DEVNULL,capture_output=True,
                          text=True,timeout=timeout)
    if check and result.returncode:
        # Preserve only an allowlisted executable category and integer status.
        # Arguments, private paths and captured output never enter diagnostics.
        raise FixtureCommandError(args[0],result.returncode)
    return result


def fixture_ipv4(value):
    address=ipaddress.IPv4Address(value)
    assert str(address)==value and any(address in network for network in DOCUMENTATION_NETS),'fixture requires documentation IPv4 addresses'
    assert all(address not in (network.network_address,network.broadcast_address) for network in DOCUMENTATION_NETS),'fixture requires usable documentation host addresses'
    return str(address)


def fixture_plan(config):
    assert isinstance(config,dict) and isinstance(config.get('outbounds'),list) and config['outbounds'],'fixture requires outbounds'
    nodes=set();endpoints=[];inbounds=[];listeners=set()
    for leaf in config['outbounds']:
        assert isinstance(leaf,dict),'invalid fixture outbound'
        kind=leaf.get('type')
        if kind in ('selector','urltest'):continue
        assert kind in ('hysteria2','http'),'fixture supports only Hysteria2 and plain HTTP leaves'
        common={'type','tag','server','server_port','password','tls','bind_interface'}
        allowed=common|({'up_mbps','down_mbps','network'} if kind=='hysteria2' else {'username'})
        assert set(leaf)<=allowed,'unsupported fixture leaf option (port hopping and detours require a separate upstream fixture)'
        assert leaf.get('password')==FAKE_PASSWORD,'fixture requires fixed fake authentication'
        address=fixture_ipv4(leaf.get('server'))
        port=leaf.get('server_port')
        assert type(port) is int and 1<=port<=65535,'fixture requires a scalar integer port'
        inbound={'type':kind,'tag':'fixture-'+str(len(inbounds)),'listen':address,'listen_port':port}
        if kind=='hysteria2':
            tls=leaf.get('tls',{})
            assert isinstance(tls,dict) and tls.get('enabled') is True and tls.get('insecure') is True,'Hysteria2 fixture requires explicit insecure test TLS'
            assert set(tls)<={'enabled','insecure','server_name','alpn'},'unsupported fixture TLS option'
            assert tls.get('alpn',['h3'])==['h3'],'Hysteria2 fixture requires h3 ALPN'
            inbound['users']=[{'name':'fixture','password':FAKE_PASSWORD}]
            inbound['tls']={'enabled':True,'alpn':['h3']}
            protocol='udp'
        else:
            assert leaf.get('username')==FAKE_USERNAME,'HTTP fixture requires fixed fake username'
            assert leaf.get('tls',{}) in ({},{'enabled':False}),'HTTP fixture currently supports plain transport only'
            inbound['users']=[{'username':FAKE_USERNAME,'password':FAKE_PASSWORD}]
            protocol='tcp'
        listener=(address,protocol,port)
        assert listener not in listeners,'duplicate fixture listener'
        listeners.add(listener);nodes.add(address);inbounds.append(inbound)
        endpoints.append({'family':4,'address':address,'protocol':protocol,'port_start':port,'port_end':port})
    assert inbounds,'fixture has no supported listeners'
    return {'nodes':sorted(nodes,key=ipaddress.IPv4Address),'inbounds':inbounds,
            'endpoints':sorted(endpoints,key=lambda entry:(ipaddress.IPv4Address(entry['address']),entry['protocol'],entry['port_start']))}


def ensure(condition,code):
    if not condition:raise RuntimeError('fixture: '+code)


def protocol_module():
    import protocol_runtime
    return protocol_runtime


def protocol_case_names():
    module=protocol_module()
    return list(dict.fromkeys(module.case_names()+list(module.EXPERIMENTAL_CASES)))


def managed_fixture_base():
    """Literal test source: no user or production configuration is read."""
    return {'log':{'level':'info','timestamp':False},
            'dns':{'servers':[{'type':'udp','tag':'upstream-dns','server':'1.1.1.1',
                              'server_port':53,'detour':'proxy'}],
                   'final':'upstream-dns','strategy':'ipv4_only','disable_cache':False,
                   'disable_expire':False,'cache_capacity':4096},
            'inbounds':[{'type':'tun','tag':'tun-in','interface_name':'tun0',
                         'address':['198.18.0.1/15'],'mtu':1500,'stack':'mixed',
                         'auto_route':False,'auto_redirect':False,'dns_mode':'disabled'}],
            'outbounds':[],
            'route':{'rules':[{'inbound':['tun-in'],'port':53,'action':'hijack-dns'}],'final':'proxy'}}


def native_recipe(name,directory,certificate,ssh_host_key=None):
    """Reuse tested protocol/auth recipes, keeping the real managed boundary."""
    module=protocol_module();ensure(name in protocol_case_names(),'unknown-protocol-case')
    ports={'proxy':443,'proxy2':8443,'tcp':443,'udp':40123,'dns':53,
           'ingress_tcp':48080,'ingress_udp':48081,'ingress_dns':48053,'cover':9443}
    ports.update({'hop'+str(index):port for index,port in enumerate(HOP_PORTS)})
    cert=directory/'fixture-cert.pem';key=directory/'fixture-key.pem'
    source,_,server,_=module.build_configs(name,managed_fixture_base(),ports,certificate,
                                         str(cert),str(key),ssh_host_key)
    source=copy.deepcopy(source);server=copy.deepcopy(server)
    addresses={};helpers={}
    for outbound in source['outbounds']:
        tag=outbound['tag']
        if outbound['type'] in ('selector','urltest'):
            if outbound['type']=='urltest':outbound['url']='https://1.1.1.1/cdn-cgi/trace'
            continue
        if 'detour' in outbound:address='198.51.100.1'
        elif tag in ('b','carrier','cover'):address='192.0.2.2'
        else:address='192.0.2.1'
        outbound['server']=address;addresses[tag+'-in']=address
    if name=='ssh':
        server={'fixture':'paramiko-3.5.1','listen':'192.0.2.1','listen_port':ports['proxy'],
                'host_key_path':str(directory/'ssh-host-key.pem')}
        helpers['ssh']=True
    else:
        for inbound in server['inbounds']:
            inbound['listen']=addresses[inbound['tag']]
        server['outbounds']=[{'type':'direct','tag':'fixture-direct','inet4_bind_address':ADDRESS}]
        server['route']={'final':'fixture-direct'}
    if module.is_hopping_case(name):
        server['inbounds'][0]['listen']='127.0.0.1'
        helpers['hopping']={'listen':'192.0.2.1','ports':HOP_PORTS[:],
                            'backend':'127.0.0.1','backend_port':ports['proxy']}
    if name in ('shadowtls1','shadowtls2','shadowtls3'):
        # Cover is local to the upstream namespace. Its trust is inline in the
        # managed client; the host-only private key never enters the container.
        helpers['cover']={'port':ports['cover'],'certificate':str(cert),'key':str(key)}
    policy=module.compile_config(source,'policy');effective=module.compile_config(source,'effective')
    nodes=sorted({entry['address'] for entry in policy['outer_endpoints']},key=ipaddress.IPv4Address)
    for address in nodes:fixture_ipv4(address)
    namespace_addresses=sorted(set(nodes)|set(addresses.values()),key=ipaddress.IPv4Address)
    expected=[]
    if name=='selector-trojan':expected=['a-in']
    elif name=='selector-hysteria2':expected=['b-in']
    elif name=='urltest':expected=['a-in','b-in']
    elif name=='detour':expected=['proxy-in','carrier-in']
    elif name in ('shadowtls1','shadowtls2','shadowtls3'):expected=['proxy-in','cover-in']
    return {'case':name,'source':source,'effective':effective,'server':server,'policy':policy,
            'nodes':nodes,'namespace_addresses':namespace_addresses,
            'endpoints':policy['outer_endpoints'],'helpers':helpers,'expected_tags':expected}


def runtime_evidence(plan,metrics,log):
    ensure(isinstance(metrics,dict) and set(metrics)=={'format','protocol_case','ready','observed_hop_ports','tls_cover_handshakes'} and
           type(metrics.get('format')) is int and metrics['format']==1 and
           metrics.get('protocol_case')==plan['case'] and metrics.get('ready') is True,'runtime-metrics-invalid')
    ports=metrics.get('observed_hop_ports');handshakes=metrics.get('tls_cover_handshakes')
    ensure(isinstance(ports,list) and all(type(port) is int for port in ports),'runtime-ports-invalid')
    ensure(type(handshakes) is int and handshakes>=0,'runtime-cover-invalid')
    if 'hopping' in plan['helpers']:
        ensure(len(ports)==len(set(ports)) and len(ports)>=2 and
               set(ports)<=set(plan['helpers']['hopping']['ports']),'actual-port-hopping-not-observed')
    else:ensure(not ports,'unexpected-hopping-metrics')
    if 'cover' in plan['helpers']:ensure(handshakes>0,'cover-handshake-not-observed')
    else:ensure(handshakes==0,'unexpected-cover-metrics')
    plain=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',log)
    for tag in plan['expected_tags']:
        pattern=(r'inbound/[^\s\[]+\['+re.escape(tag)+r'\]:[^\n]*\binbound connection to ')
        ensure(re.search(pattern,plain) is not None,'authenticated-graph-forwarding-not-observed')
    return {'observed_hop_ports':sorted(ports),'tls_cover_handshakes':handshakes,
            'forwarded_tags':plan['expected_tags'][:]}


def ssh_destination(value):
    ensure(isinstance(value,(tuple,list)) and len(value)==2,'ssh-destination-denied')
    address,port=value
    ensure(isinstance(address,str) and type(port) is int and port==443,'ssh-destination-denied')
    try:parsed=ipaddress.IPv4Address(address)
    except (ValueError,TypeError):raise RuntimeError('fixture: ssh-destination-denied') from None
    ensure(str(parsed)==address and parsed.is_global,'ssh-destination-denied')
    return address,port


def private_file(path):
    path=Path(path)
    ensure(path.is_absolute() and path.resolve()==path and path.is_file(),'private-file-required')
    ensure(path.stat().st_uid==0 and path.stat().st_mode&0o077==0,'private-file-required')
    ensure(path.parent.stat().st_uid==0 and path.parent.stat().st_mode&0o077==0,'private-parent-required')
    return path


def trusted_executable(value):
    path=Path(value)
    ensure(path.is_absolute() and path.is_file() and os.access(path,os.X_OK),'executable-required')
    ensure(path.stat().st_uid==0 and path.stat().st_mode&0o022==0,'untrusted-executable')
    # Root-owned venv interpreters may be symlinks to a trusted system Python.
    for parent in (path.parent,path.resolve().parent):
        ensure(parent.stat().st_uid==0 and parent.stat().st_mode&0o022==0,'untrusted-executable-parent')
    return path


def file_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def recipe_components():
    names=('host_upstream_fixture.py','host_acceptance.py','protocol_runtime.py','test_dns_runtime.py','protocol_ssh_fixture.py')
    return {name:file_digest(Path(__file__).resolve().with_name(name)) for name in names}


def write_new(path,content):
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW
    with os.fdopen(os.open(str(path),flags,0o600),'wb') as stream:
        stream.write(content)


def json_bytes(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()


def read_private_json(path):
    def pairs(rows):
        value={}
        for key,item in rows:
            ensure(key not in value,'duplicate-json-field')
            value[key]=item
        return value
    try:return json.loads(private_file(path).read_text(),object_pairs_hook=pairs)
    except (ValueError,UnicodeError):raise RuntimeError('fixture: invalid-private-json') from None


def ssh_key(python,path,create=False):
    code=('import sys;sys.path.insert(0,sys.argv[1]);import protocol_ssh_fixture as f;'
          + ('print(f.create_host_key(sys.argv[2]))' if create else
             'k=f.paramiko_module().RSAKey.from_private_key_file(sys.argv[2]);print(k.get_name()+" "+k.get_base64())'))
    result=run(python,'-I','-c',code,Path(__file__).resolve().parent,path)
    value=result.stdout.strip()
    ensure(re.fullmatch(r'ssh-rsa [A-Za-z0-9+/=]+',value) is not None,'ssh-host-key-invalid')
    return value


def render(args,output):
    source=Path(args.config)
    # This check precedes openssl, imports with optional dependencies or writes.
    ensure(source.is_absolute() and not os.path.lexists(source),'new-source-required')
    ensure(source.parent.resolve()==source.parent and source.parent.is_dir() and
           source.parent.stat().st_uid==0 and source.parent.stat().st_mode&0o077==0,'private-source-parent-required')
    ensure(not any(output.iterdir()),'empty-render-output-required')
    engine=trusted_executable(args.engine);python=trusted_executable(args.python or sys.executable)
    protocol_module().validate_version(run(engine,'version').stdout)
    cert=output/'fixture-cert.pem';key=output/'fixture-key.pem'
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
        '-subj','/CN=protocol.test','-addext','subjectAltName=DNS:protocol.test',
        '-keyout',key,'-out',cert)
    cert.chmod(0o600);key.chmod(0o600)
    public_key=ssh_key(python,output/'ssh-host-key.pem',True) if args.protocol_case=='ssh' else None
    plan=native_recipe(args.protocol_case,output,cert.read_text(),public_key)
    server_path=output/'fixture-server.json';effective_path=output/'fixture-effective.json'
    write_new(server_path,json_bytes(plan['server']));write_new(effective_path,json_bytes(plan['effective']))
    if args.protocol_case!='ssh':run(engine,'check','-c',server_path)
    run(engine,'check','-c',effective_path)
    artifacts=['fixture-cert.pem','fixture-key.pem','fixture-server.json','fixture-effective.json']
    if args.protocol_case=='ssh':artifacts.append('ssh-host-key.pem')
    descriptor={'format':1,'protocol_case':args.protocol_case,'source':str(source),
                'source_sha256':hashlib.sha256(json_bytes(plan['source'])).hexdigest(),
                'engine':str(engine),'engine_sha256':file_digest(engine),'python':str(python),
                'python_sha256':file_digest(python),'parser_sha256':file_digest(INSTALL_ROOT/'gateway-policy.jq'),
                'components':recipe_components(),'artifacts':{name:file_digest(output/name) for name in artifacts},
                'policy':plan['policy']}
    # Publish the new source only after both configurations have been checked.
    write_new(source,json_bytes(plan['source']))
    write_new(output/'protocol-recipe.json',json_bytes(descriptor))
    print('UPSTREAM_FIXTURE_RENDERED',flush=True)


def load_recipe(args,output):
    descriptor=read_private_json(output/'protocol-recipe.json')
    ensure(set(descriptor)=={'format','protocol_case','source','source_sha256','engine','engine_sha256',
                            'python','python_sha256','parser_sha256','components','artifacts','policy'} and
           type(descriptor['format']) is int and descriptor['format']==1 and
           descriptor['protocol_case']==args.protocol_case,'recipe-descriptor-invalid')
    source=private_file(args.config);engine=trusted_executable(args.engine)
    python=trusted_executable(args.python or sys.executable)
    ensure(descriptor['source']==str(source) and descriptor['engine']==str(engine) and
           descriptor['python']==str(python),'recipe-path-mismatch')
    ensure(file_digest(source)==descriptor['source_sha256'] and file_digest(engine)==descriptor['engine_sha256'] and
           file_digest(python)==descriptor['python_sha256'] and
           file_digest(INSTALL_ROOT/'gateway-policy.jq')==descriptor['parser_sha256'] and
           recipe_components()==descriptor['components'],'recipe-identity-mismatch')
    expected={'fixture-cert.pem','fixture-key.pem','fixture-server.json','fixture-effective.json'}
    if args.protocol_case=='ssh':expected.add('ssh-host-key.pem')
    ensure(isinstance(descriptor['artifacts'],dict) and set(descriptor['artifacts'])==expected,'recipe-artifact-set-invalid')
    for name,digest in descriptor['artifacts'].items():
        ensure(file_digest(private_file(output/name))==digest,'recipe-artifact-mismatch')
    public_key=ssh_key(python,output/'ssh-host-key.pem') if args.protocol_case=='ssh' else None
    plan=native_recipe(args.protocol_case,output,(output/'fixture-cert.pem').read_text(),public_key)
    ensure(source.read_bytes()==json_bytes(plan['source']) and plan['policy']==descriptor['policy'] and
           (output/'fixture-server.json').read_bytes()==json_bytes(plan['server']) and
           (output/'fixture-effective.json').read_bytes()==json_bytes(plan['effective']),'recipe-content-mismatch')
    return plan,descriptor


class NativeMultiportRelay:
    """Record received frontend ports, preserving one UDP backend peer."""
    def __init__(self,listen,ports,backend,backend_port):
        self.frontends=[];self.backend=None;self.thread=None
        self.stop=threading.Event();self.lock=threading.Lock();self.seen=set();self.counts={str(port):0 for port in ports}
        try:
            for port in ports:
                sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.frontends.append(sock)
                sock.bind((listen,port))
            self.backend=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            self.backend.bind(('127.0.0.1',0));self.backend.connect((backend,backend_port))
            self.ports=[sock.getsockname()[1] for sock in self.frontends]
            self.thread=threading.Thread(target=self._serve,daemon=True);self.thread.start()
        except BaseException:
            self.close();raise

    @property
    def observed_ports(self):
        with self.lock:return sorted(self.seen)

    @property
    def received_by_port(self):
        with self.lock:return dict(self.counts)

    def _serve(self):
        current=None
        while not self.stop.is_set():
            readable,_,_=select.select(self.frontends+[self.backend],[],[],0.05)
            for sock in readable:
                try:
                    if sock is self.backend:
                        payload=sock.recv(65535)
                        if current is not None:current[0].sendto(payload,current[1])
                    else:
                        payload,peer=sock.recvfrom(65535)
                        with self.lock:
                            port=sock.getsockname()[1];self.seen.add(port);self.counts[str(port)]+=1
                        current=(sock,peer);self.backend.send(payload)
                except OSError:
                    # A stopped backend introduces no alternative destination.
                    continue

    def close(self):
        self.stop.set()
        if self.thread is not None:self.thread.join(timeout=2)
        for sock in self.frontends+([self.backend] if self.backend is not None else []):sock.close()

    def __enter__(self):return self
    def __exit__(self,*_):self.close()


def native_cover(config):
    cover=protocol_module().TLSCoverServer(config['port'],config['certificate'],config['key'])
    # A handshake-only fixture must not prepend TLS1.3 session tickets to the
    # ShadowTLS2 inner stream. Certificate verification remains enabled.
    cover.context.num_tickets=0
    return cover


def native_ssh_interface(server):
    paramiko=server.paramiko;module=protocol_module()
    class Interface(paramiko.ServerInterface):
        def __init__(self):self.destinations={}
        def get_allowed_auths(self,username):return 'password'
        def check_auth_password(self,username,password):
            return paramiko.AUTH_SUCCESSFUL if (username,password)==(module.USERNAME,module.PASSWORD) else paramiko.AUTH_FAILED
        def check_channel_request(self,kind,chanid):return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        def check_channel_direct_tcpip_request(self,chanid,origin,destination):
            try:target=ssh_destination(destination)
            except RuntimeError:return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            self.destinations[chanid]=target
            return paramiko.OPEN_SUCCEEDED
    return Interface()


def native_ssh_forward(channel,destination):
    try:
        target_address=ssh_destination(destination)
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as target:
            target.settimeout(3);target.bind((ADDRESS,0));target.connect(target_address)
            while not channel.closed:
                readable,_,_=select.select([channel,target],[],[],0.2)
                for endpoint in readable:
                    data=endpoint.recv(65536)
                    if not data:return
                    (target if endpoint is channel else channel).sendall(data)
    except (OSError,EOFError,RuntimeError):pass
    finally:channel.close()


class NativeSSHHandler(socketserver.BaseRequestHandler):
    def handle(self):
        paramiko=self.server.paramiko;transport=paramiko.Transport(self.request)
        transport.add_server_key(self.server.key);interface=native_ssh_interface(self.server)
        with self.server.lock:self.server.transports.add(transport)
        try:
            transport.start_server(server=interface)
            while transport.is_active():
                channel=transport.accept(timeout=0.2)
                if channel is None:continue
                destination=interface.destinations.pop(channel.get_id(),None)
                if destination is None:channel.close();continue
                threading.Thread(target=native_ssh_forward,args=(channel,destination),daemon=True).start()
        except (OSError,EOFError,paramiko.SSHException):pass
        finally:
            transport.close()
            with self.server.lock:self.server.transports.discard(transport)


class NativeSSHServer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
    def __init__(self,config):
        import protocol_ssh_fixture
        self.paramiko=protocol_ssh_fixture.paramiko_module()
        self.key=self.paramiko.RSAKey.from_private_key_file(config['host_key_path'])
        self.transports=set();self.lock=threading.Lock()
        super().__init__((fixture_ipv4(config['listen']),config['listen_port']),NativeSSHHandler)
    def server_close(self):
        with self.lock:transports=list(self.transports)
        for transport in transports:transport.close()
        super().server_close()


def namespace_identity(path):
    metadata=Path(path).stat()
    return '{}:{}'.format(metadata.st_dev,metadata.st_ino)


def owned_namespace(require_self=False):
    result=run('systemctl','show','--property=ActiveState,MainPID,ControlGroup','--',UNIT)
    values=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
    pid=values.get('MainPID','')
    ensure(values.get('ActiveState')=='active' and re.fullmatch(r'[1-9][0-9]*',pid) is not None and
           values.get('ControlGroup')=='/system.slice/'+UNIT,'fixture-unit-not-owned')
    named=Path('/run/netns')/NS
    ensure(not named.is_symlink() and named.stat().st_uid==0 and
           namespace_identity(named)==namespace_identity('/proc/'+pid+'/ns/net') and
           namespace_identity(named)!=namespace_identity('/proc/1/ns/net'),'fixture-namespace-not-owned')
    if require_self:ensure(int(pid)==os.getpid(),'fixture-supervisor-not-main-pid')
    return namespace_identity(named)


def start_native_core(engine,config,log):
    with log.open('ab') as stream:
        process=subprocess.Popen([str(engine),'run','-c',str(config)],stdin=subprocess.DEVNULL,
                                 stdout=stream,stderr=stream)
    try:
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            ensure(process.poll() is None,'native-core-start-failed')
            if 'sing-box started' in log.read_text(errors='replace'):return process
            time.sleep(0.05)
        raise RuntimeError('fixture: native-core-start-timeout')
    except BaseException:
        protocol_module().dns_fixture.stop_process(process);raise


def serve_recipe(args,output):
    plan,_=load_recipe(args,output);owned_namespace(require_self=True)
    stop=threading.Event()
    for signum in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(signum,lambda *_:stop.set())
    metrics={'format':1,'protocol_case':plan['case'],'ready':False,
             'observed_hop_ports':[],'tls_cover_handshakes':0}
    state_path=output/'runtime-state.json';process=None;relay=None;sequence=0
    try:
        with ExitStack() as stack:
            relay=None;cover=None
            if 'hopping' in plan['helpers']:
                helper=plan['helpers']['hopping']
                relay=stack.enter_context(NativeMultiportRelay(helper['listen'],helper['ports'],helper['backend'],helper['backend_port']))
            if 'cover' in plan['helpers']:
                cover=stack.enter_context(protocol_module().serving(native_cover(plan['helpers']['cover'])))
            if plan['case']=='ssh':
                stack.enter_context(protocol_module().serving(NativeSSHServer(plan['server'])))
            else:
                process=start_native_core(args.engine,output/'fixture-server.json',output/'fixture-server.log')
                stack.callback(protocol_module().dns_fixture.stop_process,process)
            metrics['ready']=True
            while not stop.is_set():
                if process is not None:ensure(process.poll() is None,'native-core-exited')
                metrics['observed_hop_ports']=relay.observed_ports if relay else []
                metrics['tls_cover_handshakes']=cover.handshakes if cover else 0
                save_state(state_path,metrics)
                if relay:
                    sequence+=1
                    save_state(output/'hopping-observations.json',
                        {'format':1,'protocol_case':plan['case'],'ready':True,'sequence':sequence,
                         'received_by_port':relay.received_by_port})
                stop.wait(0.2)
    finally:
        metrics['ready']=False;save_state(state_path,metrics)
        if relay:
            save_state(output/'hopping-observations.json',
                {'format':1,'protocol_case':plan['case'],'ready':False,'sequence':sequence,
                 'received_by_port':relay.received_by_port})


def validate_observation(plan,value):
    ensure(isinstance(value,dict) and set(value)=={'format','protocol_case','ready','sequence','received_by_port'} and
           type(value['format']) is int and value['format']==1 and value['protocol_case']==plan['case'] and
           value['ready'] is True and type(value['sequence']) is int and value['sequence']>0,'hopping-observation-invalid')
    counts=value['received_by_port'];ports={str(port) for port in plan['helpers']['hopping']['ports']}
    ensure(isinstance(counts,dict) and set(counts)==ports and
           all(type(count) is int and count>=0 for count in counts.values()),'hopping-counters-invalid')
    return value


def fresh_hopping_observation(plan,output):
    path=output/'hopping-observations.json'
    initial=validate_observation(plan,read_private_json(path));deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        value=validate_observation(plan,read_private_json(path))
        ensure(value['sequence']>=initial['sequence'],'hopping-observations-reset')
        if value['sequence']>initial['sequence']:return value
        time.sleep(0.03)
    raise RuntimeError('fixture: hopping-observation-stale')


def hopping_delta(plan,before,after):
    validate_observation(plan,before);validate_observation(plan,after)
    ensure(after['sequence']>before['sequence'],'hopping-observations-reset')
    deltas={port:after['received_by_port'][port]-count for port,count in before['received_by_port'].items()}
    ensure(all(value>=0 for value in deltas.values()),'hopping-counters-reset')
    changed={port:value for port,value in deltas.items() if value>0}
    ensure(len(changed)>=2,'continuous-port-hopping-not-observed')
    return changed


def hopping_window(plan,session,observe,clock=time.monotonic,sleep=time.sleep):
    ensure(session.value(CONTINUITY_CONNECT) is True,'hopping-connect-failed')
    def exchange():
        result=session.value(CONTINUITY_EXCHANGE)
        ensure(isinstance(result,dict) and result.get('same_socket') is True and
               type(result.get('connect_calls')) is int and result['connect_calls']==1 and
               type(result.get('exchanges')) is int,'hopping-exchange-invalid')
        return result['exchanges']
    ensure(exchange()==1,'hopping-first-exchange-invalid')
    # A fresh sample excludes the handshake and traffic preceding this stream.
    before=observe();started=clock()
    for index in range(10):
        sleep(2)
        ensure(exchange()==index+2,'hopping-exchange-sequence-invalid')
    after=observe();seconds=clock()-started
    # The same application socket must also work after the ending sample.
    exchanges=exchange();ensure(exchanges==12 and 20<=seconds<=180,'hopping-window-invalid')
    deltas=hopping_delta(plan,before,after)
    return {'window_seconds':seconds,'exchanges':exchanges,'connections':1,
            'observed_hop_ports':sorted(map(int,deltas)),'port_packet_deltas':deltas}


def bound_policy_digest():
    from host_acceptance import RUNTIME
    return file_digest(private_file(RUNTIME/'binding'))


def validate_hopping_proof(plan,descriptor,output,identity):
    value=read_private_json(output/'hopping-continuity.json')
    ensure(isinstance(value,dict) and set(value)=={'format','protocol_case','passed','checks','evidence','identity'} and
           type(value['format']) is int and value['format']==1 and value['protocol_case']==plan['case'] and
           value['passed'] is True,'hopping-proof-invalid')
    checks=value['checks'];evidence=value['evidence']
    ensure(isinstance(checks,dict) and set(checks)==set(CONTINUITY_CHECKS) and
           all(flag is True for flag in checks.values()),'hopping-proof-checks-invalid')
    ensure(isinstance(evidence,dict) and set(evidence)=={'window_seconds','exchanges','connections','observed_hop_ports','port_packet_deltas'},
           'hopping-proof-evidence-invalid')
    seconds=evidence['window_seconds'];deltas=evidence['port_packet_deltas'];ports=evidence['observed_hop_ports']
    ensure(type(seconds) in (int,float) and math.isfinite(seconds) and 20<=seconds<=180 and
           type(evidence['exchanges']) is int and evidence['exchanges']==12 and
           type(evidence['connections']) is int and evidence['connections']==1,'hopping-proof-continuity-invalid')
    allowed={str(port) for port in plan['helpers']['hopping']['ports']}
    ensure(isinstance(deltas,dict) and len(deltas)>=2 and set(deltas)<=allowed and
           all(type(count) is int and count>0 for count in deltas.values()) and
           isinstance(ports,list) and all(type(port) is int for port in ports) and
           ports==sorted(map(int,deltas)),'hopping-proof-rotation-invalid')
    ensure(value['identity']=={'source_sha256':descriptor['source_sha256'],
                'recipe_sha256':file_digest(output/'protocol-recipe.json'),
                'binding_sha256':bound_policy_digest(),'namespace_identity':identity},'hopping-proof-identity-changed')
    return evidence


def prove_hopping(args,output):
    from host_acceptance import Binding,DEV,RUNTIME,Session,Suite
    plan,descriptor=load_recipe(args,output)
    ensure('hopping' in plan['helpers'],'hopping-case-required')
    result_path=output/'hopping-continuity.json'
    ensure(not os.path.lexists(result_path),'new-hopping-proof-required')
    binding=Binding.load();identity=owned_namespace()
    account=pwd.getpwnam(args.user);ensure(account.pw_uid!=0,'hopping-workload-account-invalid')
    state=read_private_json(output/'upstream-fixture-state.json')
    ensure(state.get('namespace_identity')==identity and state.get('protocol_case')==plan['case'] and
           state.get('source_sha256')==descriptor['source_sha256']==binding.data['source_sha256'] and
           binding.policy==plan['policy'] and state.get('units')=={UNIT:True,ECHO_UNIT:True},'hopping-fixture-binding-invalid')
    ensure(not any((RUNTIME/'requests').iterdir()),'hopping-requires-idle-session-host')
    ensure(not run('systemctl','list-units','--all','--plain','--no-legend','dev-session-*.service').stdout.strip(),
           'hopping-requires-idle-session-host')
    run(DEV,'check');binding_hash=bound_policy_digest()
    holder=SimpleNamespace(binding=binding,user=args.user,output=output,sessions=[],uid=account.pw_uid,gid=account.pw_gid)
    holder.reclaimed=lambda sid:Suite.reclaimed(holder,sid)
    try:
        session=Session(holder,'hopping-continuity')
        Suite.credentials(holder,session)
        evidence=hopping_window(plan,session,lambda:fresh_hopping_observation(plan,output))
    finally:
        for session in holder.sessions:
            session.close(strict=False)
            session.reader.join(timeout=2);session.log.close()
    run(DEV,'check');binding.verify_parent()
    ensure(bound_policy_digest()==binding_hash and owned_namespace()==identity,'hopping-runtime-identity-changed')
    load_recipe(args,output)
    result={'format':1,'protocol_case':plan['case'],'passed':True,
            'checks':{name:True for name in CONTINUITY_CHECKS},'evidence':evidence,
            'identity':{'source_sha256':descriptor['source_sha256'],
                'recipe_sha256':file_digest(output/'protocol-recipe.json'),
                'binding_sha256':binding_hash,'namespace_identity':identity}}
    write_new(result_path,json_bytes(result))
    print('UPSTREAM_FIXTURE_HOPPING_PROVEN',flush=True)


def verify_recipe(args,output):
    result_path=output/'fixture-verification.json'
    ensure(not os.path.lexists(result_path),'new-verification-result-required')
    plan,descriptor=load_recipe(args,output)
    state=read_private_json(output/'upstream-fixture-state.json')
    ensure(type(state.get('format')) is int and state['format']==2 and
           state.get('source_sha256')==descriptor['source_sha256'] and state.get('nodes')==plan['nodes'] and
           state.get('protocol_case')==plan['case'] and state.get('units')=={UNIT:True,ECHO_UNIT:True},'fixture-state-invalid')
    identity=owned_namespace()
    ensure(state.get('namespace_identity')==identity,'fixture-namespace-changed')
    ensure(run('systemctl','is-active',ECHO_UNIT,check=False).stdout.strip()=='active','echo-service-not-active')
    metrics=read_private_json(output/'runtime-state.json')
    log='' if plan['case']=='ssh' else private_file(output/'fixture-server.log').read_text(errors='replace')
    evidence=runtime_evidence(plan,metrics,log)
    if 'hopping' in plan['helpers']:
        evidence['healthy_continuity']=validate_hopping_proof(plan,descriptor,output,identity)
    # Repeat the identity read after consuming evidence, before publishing PASS.
    load_recipe(args,output);ensure(owned_namespace()==identity,'fixture-namespace-changed')
    result={'format':1,'protocol_case':plan['case'],'passed':True,
            'checks':{'source_unchanged':True,'recipe_unchanged':True,'namespace_owned':True,
                      'services_active':True,'helper_evidence':True},'evidence':evidence}
    write_new(result_path,json_bytes(result))
    print('UPSTREAM_FIXTURE_VERIFIED',flush=True)


def firewall_rules(interface):
    return [
        ['filter','FORWARD','-i',HOST,'-o',interface,'-s',ADDRESS+'/32',
         '-m','comment','--comment','d8-host-acceptance','-j','ACCEPT'],
        ['filter','FORWARD','-i',interface,'-o',HOST,'-d',ADDRESS+'/32',
         '-m','conntrack','--ctstate','ESTABLISHED,RELATED',
         '-m','comment','--comment','d8-host-acceptance','-j','ACCEPT'],
        ['nat','POSTROUTING','-s',ADDRESS+'/32','-o',interface,
         '-m','comment','--comment','d8-host-acceptance','-j','MASQUERADE'],
    ]


def manager_mount():
    entries=[line.split(':',2) for line in Path('/proc/1/cgroup').read_text().splitlines()]
    v1=any('name=systemd' in entry[1].split(',') for entry in entries)
    def flatten(rows):
        for row in rows:
            yield row
            yield from flatten(row.get('children',[]))
    inventory=json.loads(run('findmnt','--json','--types','cgroup,cgroup2','--output','TARGET,FSTYPE,OPTIONS,FSROOT').stdout)
    candidates=[row for row in flatten(inventory['filesystems']) if row.get('fsroot')=='/' and
                ((v1 and row['fstype']=='cgroup' and 'name=systemd' in row['options'].split(',')) or
                 (not v1 and row['fstype']=='cgroup2'))]
    assert len(candidates)==1,'cannot establish actual systemd cgroup mount'
    mount=Path(candidates[0]['target']);metadata=mount.stat()
    assert mount.resolve()==mount and metadata.st_uid==0,'untrusted systemd cgroup mount'
    return {'path':str(mount),'identity':'{}:{}'.format(metadata.st_dev,metadata.st_ino)}


def save_state(path,state):
    temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps(state,sort_keys=True)+'\n');temporary.chmod(0o600)
    temporary.replace(path)


def output_directory(value):
    path=Path(value)
    assert path.is_absolute(),'output must be absolute'
    path.mkdir(mode=0o700,parents=True,exist_ok=True)
    assert not path.is_symlink() and path.resolve()==path,'output cannot contain symlinks'
    assert path.stat().st_uid==0 and path.stat().st_mode&0o077==0,'output must be root private'
    return path


def cleanup(output):
    state_path=output/'upstream-fixture-state.json'
    if not state_path.exists():return
    assert not state_path.is_symlink() and state_path.stat().st_uid==0 and state_path.stat().st_mode&0o077==0,'untrusted fixture state'
    state=json.loads(state_path.read_text())
    assert state.get('format')==2,'legacy fixture state requires manual inspection'
    assert set(state['units'])<={UNIT,ECHO_UNIT},'invalid fixture service state'
    assert re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',state['interface']),'invalid fixture interface'
    for node in state['nodes']:fixture_ipv4(node)
    mount=manager_mount()
    assert mount==state['manager_mount'],'systemd cgroup mount changed; fixture state retained'
    if 'protocol_case' in state and Path('/run/netns',NS).exists():
        ensure(state.get('namespace_identity')==namespace_identity(Path('/run/netns',NS)),
               'fixture-namespace-changed-state-retained')
    groups={}
    for unit,owned in state['units'].items():
        if not owned:continue
        group=run('systemctl','show','--property=ControlGroup','--value',unit,check=False).stdout.strip()
        if group:
            assert group=='/system.slice/'+unit,'fixture service moved outside expected systemd parent'
            groups[unit]=Path(mount['path'])/group.lstrip('/')
        run('systemctl','stop',unit,check=False)
    for node in state['nodes']:
        run('ip','-4','route','del',node+'/32','via',ADDRESS,'dev',HOST,check=False)
    for table,chain,*rule in firewall_rules(state['interface']):
        run('iptables-legacy','-w','5','-t',table,'-D',chain,*rule,check=False)
    run('ip','link','del',HOST,check=False)
    run('ip','netns','del',NS,check=False)
    errors=[]
    for unit,owned in state['units'].items():
        if not owned:continue
        properties=run('systemctl','show','--property=LoadState,ActiveState,MainPID,ControlPID',unit,check=False).stdout
        values=dict(line.split('=',1) for line in properties.splitlines() if '=' in line)
        if values.get('LoadState')!='not-found':
            if values.get('ActiveState') not in ('inactive','failed') or values.get('MainPID')!='0' or values.get('ControlPID')!='0':
                errors.append('fixture service not verifiably stopped: '+unit)
        group=groups.get(unit)
        if group and group.exists() and any(path.read_text().strip() for path in group.rglob('cgroup.procs')):
            errors.append('fixture service cgroup still has processes: '+unit)
    for node in state['nodes']:
        if json.loads(run('ip','-j','-4','route','show','exact',node+'/32').stdout):errors.append('fixture node route remains')
    for table,chain,*rule in firewall_rules(state['interface']):
        if 'd8-host-acceptance' in run('iptables-legacy','-w','5','-t',table,'-S',chain).stdout:
            errors.append('fixture firewall rule remains: '+table+'/'+chain)
    if any(link['ifname']==HOST for link in json.loads(run('ip','-j','link','show').stdout)):errors.append('fixture veth remains')
    if NS in run('ip','netns','list').stdout.split():errors.append('fixture namespace remains')
    if errors:
        state['cleanup_errors']=errors;save_state(state_path,state)
        raise RuntimeError('Cleanup incomplete; state retained: '+'; '.join(errors))
    state_path.unlink()
    print('UPSTREAM_FIXTURE_REMOVED',flush=True)


def setup(args,output):
    state_path=output/'upstream-fixture-state.json'
    assert not state_path.exists(),'fixture state exists; cleanup explicitly first'
    source=Path(args.config);engine=Path(args.engine)
    assert source.is_absolute() and source.is_file(),'explicit absolute fake --config required'
    assert engine.is_absolute() and engine.is_file() and os.access(engine,os.X_OK),'absolute executable --engine required'
    native=getattr(args,'protocol_case',None) is not None
    if native:
        # All artifact and component checks precede privileged command calls.
        plan,descriptor=load_recipe(args,output);policy=plan['policy']
        ensure(not any(os.path.lexists(output/name) for name in
                       ('fixture-info.json','runtime-state.json','fixture-server.log','fixture-verification.json',
                        'hopping-observations.json','hopping-continuity.json')),
               'native-runtime-artifacts-exist')
    else:
        ensure(not getattr(args,'python',None),'python-requires-protocol-case')
        plan=fixture_plan(json.loads(source.read_bytes()))
        version=run(engine,'version').stdout.splitlines()
        assert version and re.fullmatch(r'(?:sing-box|worker) version 1\.14\.2',version[0]),'fixture requires pinned core 1.14.2'
        parser=INSTALL_ROOT/'gateway-policy.jq'
        compiled=run('jq','-ceS','--arg','mode','policy','-f',parser,source,check=False)
        assert compiled.returncode==0,'fake source rejected by shared policy compiler'
        policy=json.loads(compiled.stdout)
        assert policy['outer_endpoints']==plan['endpoints'],'fixture listeners do not exactly match compiled outer policy'
    content=source.read_bytes()
    echo_address=fixture_ipv4(args.udp_echo_address);echo_port=args.udp_echo_port
    assert type(echo_port) is int and 1<=echo_port<=65535 and echo_port!=53,'invalid UDP echo port'
    addresses=plan['namespace_addresses'] if native else plan['nodes']
    assert echo_address not in addresses,'UDP echo must be separate from protocol listeners'
    assert run('ip','link','show',HOST,check=False).returncode!=0,'fixture link occupied'
    assert NS not in run('ip','netns','list').stdout.split(),'fixture namespace occupied'
    for unit in (UNIT,ECHO_UNIT):
        assert run('systemctl','show','--property=LoadState','--value',unit,check=False).stdout.strip()=='not-found','fixture unit name occupied'
    for node in plan['nodes']:
        assert not json.loads(run('ip','-j','-4','route','show','exact',node+'/32').stdout),'fixture node route already exists'
    interface=json.loads(run('ip','-j','-4','route','get','1.1.1.1').stdout)[0]['dev']
    mount=manager_mount()
    state={'format':2,'nodes':plan['nodes'],'interface':interface,'units':{UNIT:False,ECHO_UNIT:False},
           'manager_mount':mount,'source_sha256':hashlib.sha256(content).hexdigest()}
    # Validate the server config before changing namespaces or routes.
    config=output/'fixture-server.json'
    if native:
        state.update(protocol_case=plan['case'],namespace_identity=None)
        if plan['case']!='ssh':run(engine,'check','-c',config)
        run(engine,'check','-c',output/'fixture-effective.json')
        load_recipe(args,output)
    else:
        cert=output/'fixture-cert.pem';key=output/'fixture-key.pem'
        if any(inbound['type']=='hysteria2' for inbound in plan['inbounds']):
            run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=d8-fixture.test',
                '-keyout',key,'-out',cert)
            for inbound in plan['inbounds']:
                if inbound['type']=='hysteria2':inbound['tls'].update(certificate_path=str(cert),key_path=str(key))
        server={'log':{'level':'info','timestamp':True},'inbounds':plan['inbounds'],
                'outbounds':[{'type':'direct','tag':'fixture-direct'}],'route':{'final':'fixture-direct'}}
        config.write_text(json.dumps(server)+'\n');config.chmod(0o600)
        run(engine,'check','-c',config)
    save_state(state_path,state)
    try:
        run('ip','netns','add',NS)
        if native:
            state['namespace_identity']=namespace_identity(Path('/run/netns',NS));save_state(state_path,state)
        run('ip','link','add',HOST,'type','veth','peer','name',PEER)
        run('ip','link','set',PEER,'netns',NS)
        run('ip','addr','add','198.19.254.1/30','dev',HOST);run('ip','link','set',HOST,'up')
        run('ip','-n',NS,'addr','add',ADDRESS+'/30','dev',PEER);run('ip','-n',NS,'link','set',PEER,'up')
        run('ip','-n',NS,'link','set','lo','up')
        for address in addresses+[echo_address]:run('ip','-n',NS,'addr','add',address+'/32','dev','lo')
        run('ip','-n',NS,'route','add','default','via','198.19.254.1')
        for node in plan['nodes']:run('ip','-4','route','add',node+'/32','via',ADDRESS,'dev',HOST)
        for table,chain,*rule in firewall_rules(interface):run('iptables-legacy','-w','5','-t',table,'-A',chain,*rule)
        commands={UNIT:[str(engine),'run','-c',str(config)],
                  ECHO_UNIT:['/usr/bin/python3','-u','-c',ECHO_CODE,echo_address,str(echo_port)]}
        if native:
            commands[UNIT]=[descriptor['python'],'-I',str(Path(__file__).resolve()),'serve',
                            '--protocol-case',plan['case'],'--config',str(source),'--engine',str(engine),
                            '--output',str(output),'--python',descriptor['python']]
        for unit,argv in commands.items():
            run('systemd-run','--quiet','--collect','--unit='+unit,'--property=KillMode=control-group',
                '--property=UMask=0077','/usr/bin/ip','netns','exec',NS,*argv)
            state['units'][unit]=True;save_state(state_path,state)
        deadline=time.monotonic()+(20 if native else 8)
        while True:
            active=all(run('systemctl','is-active',unit,check=False).stdout.strip()=='active' for unit in (UNIT,ECHO_UNIT))
            if active and native:
                metrics_path=output/'runtime-state.json'
                metrics=read_private_json(metrics_path) if metrics_path.exists() else {}
                active=type(metrics.get('format')) is int and metrics['format']==1 and \
                       metrics.get('protocol_case')==plan['case'] and metrics.get('ready') is True
            if active:break
            if time.monotonic()>=deadline:raise RuntimeError('fixture services did not become active')
            time.sleep(0.1)
        probe="import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.connect((sys.argv[1],int(sys.argv[2]))); s.send(b'fixture-echo-ready'); assert s.recv(100)==b'fixture-echo-ready'"
        run('/usr/bin/ip','netns','exec',NS,'/usr/bin/python3','-c',probe,echo_address,echo_port)
        assert source.read_bytes()==content,'source changed during fixture setup'
        if native:
            load_recipe(args,output)
            ensure(owned_namespace()==state['namespace_identity'],'fixture-namespace-changed')
        info={'format':1,'endpoints':plan['endpoints'],'payload_networks':policy['payload_networks'],
              'dns_transport':policy['dns_transport'],'udp_echo':{'address':echo_address,'port':echo_port},
              'source_sha256':state['source_sha256'],'source_unchanged':True,'echo_verified_inside_upstream':True}
        if native:info['protocol_case']=plan['case']
        write_new(output/'fixture-info.json',json_bytes(info))
        print('UPSTREAM_FIXTURE_STARTED',flush=True)
    except BaseException:
        cleanup(output)
        raise


class FixtureTests(unittest.TestCase):
    def source(self,kind):
        leaf={'type':kind,'tag':'proxy','server':'192.0.2.10','server_port':8443,
              'password':'d8-fixture-only-password'}
        if kind=='hysteria2':leaf['tls']={'enabled':True,'insecure':True,'server_name':'d8-fixture.test'}
        else:leaf['username']='d8-fixture'
        return {'outbounds':[leaf]}

    def test_fake_hysteria_and_http_plans_preserve_source(self):
        for kind,protocol in [('hysteria2','udp'),('http','tcp')]:
            with self.subTest(kind=kind):
                source=self.source(kind);original=json.dumps(source,sort_keys=True)
                plan=fixture_plan(source)
                self.assertEqual(plan['nodes'],['192.0.2.10'])
                self.assertEqual(plan['endpoints'][0]['protocol'],protocol)
                self.assertEqual(plan['inbounds'][0]['users'][0]['password'],'d8-fixture-only-password')
                self.assertEqual(json.dumps(source,sort_keys=True),original)

    def test_reject_real_auth_nonfixture_addresses_and_unsupported_transport(self):
        for key,value in [('password','must-never-use-this-production-value'),('server','1.1.1.1'),
                          ('server_port',True),('server_ports',['8443:8445']),('detour','carrier')]:
            source=self.source('hysteria2');source['outbounds'][0][key]=value
            with self.subTest(key=key),self.assertRaises((AssertionError,ValueError)) as failure:
                fixture_plan(source)
            self.assertNotIn('must-never-use-this-production-value',str(failure.exception))
        for source in (self.source('http'),self.source('hysteria2')):
            source['outbounds'][0]['tls']={'enabled':True,'insecure':False}
            with self.assertRaises((AssertionError,ValueError)):fixture_plan(source)

    def test_multiple_distinct_fake_nodes(self):
        source=self.source('hysteria2');http=self.source('http')['outbounds'][0]
        http['server']='198.51.100.2';http['tag']='http';source['outbounds'].append(http)
        plan=fixture_plan(source)
        self.assertEqual(plan['nodes'],['192.0.2.10','198.51.100.2'])
        self.assertEqual([e['protocol'] for e in plan['endpoints']],['udp','tcp'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    actions=parser.add_subparsers(dest='action',required=True)
    for name in ('render','setup','verify','serve','prove-hopping'):
        action=actions.add_parser(name)
        action.add_argument('--config',required=True);action.add_argument('--engine',required=True)
        action.add_argument('--output',required=True)
        action.add_argument('--protocol-case',choices=protocol_case_names(),required=name!='setup')
        action.add_argument('--python',help='trusted interpreter for protocol helpers (including isolated SSH dependencies)')
        if name=='setup':
            action.add_argument('--udp-echo-address',default='192.0.2.254')
            action.add_argument('--udp-echo-port',type=int,default=40123)
        if name=='prove-hopping':action.add_argument('--user',required=True)
    stop=actions.add_parser('cleanup');stop.add_argument('--output',required=True)
    args=parser.parse_args()
    if os.geteuid()!=0:parser.error('root required on a disposable test host')
    if args.action=='setup' and args.python and not args.protocol_case:
        parser.error('--python requires --protocol-case')
    os.umask(0o077);output=output_directory(args.output)
    if args.action=='cleanup':cleanup(output)
    else:{'render':render,'setup':setup,'verify':verify_recipe,'serve':serve_recipe,'prove-hopping':prove_hopping}[args.action](args,output)


if __name__=='__main__':
    try:main()
    except Exception as error:
        # Worker logs and malformed JSON may contain private source material.
        print('UPSTREAM_FIXTURE_DIAGNOSTIC '+json.dumps(failure_evidence(error),sort_keys=True),
              file=sys.stderr,flush=True)
        reason=str(error) if isinstance(error,RuntimeError) and re.fullmatch(r'fixture: [a-z][a-z0-9-]{0,79}',str(error)) else 'fixture: command-failed'
        print('UPSTREAM_FIXTURE_FAILED '+reason,file=sys.stderr,flush=True)
        raise SystemExit(1) from None
