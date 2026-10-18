#!/usr/bin/env python3
"""Explicit fake upstream fixture for a disposable root-owned acceptance host.

Accepts only documentation IPv4 endpoints and fixed test authentication from an
explicit --config. The source is read only. Hysteria2 and plain HTTP are supported;
other production protocol support is exercised by the shared compiler tests.
Cleanup removes only the fixture's exact routes, rules, services and namespace.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
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
ECHO_CODE = """import socket,sys
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
    sock.bind((sys.argv[1],int(sys.argv[2])))
    while True:
        data,peer=sock.recvfrom(2048)
        sock.sendto(data,peer)
"""


def run(*args, check=True, timeout=40):
    result=subprocess.run(list(map(str,args)),stdin=subprocess.DEVNULL,capture_output=True,
                          text=True,timeout=timeout)
    if check and result.returncode:
        # Arguments may name configuration files, but no diagnostic is allowed
        # to echo their contents. All fixture credentials are fixed fake values.
        raise RuntimeError('fixture command failed: '+str(args[0])+' (exit '+str(result.returncode)+')')
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
    content=source.read_bytes()
    plan=fixture_plan(json.loads(content))
    echo_address=fixture_ipv4(args.udp_echo_address);echo_port=args.udp_echo_port
    assert type(echo_port) is int and 1<=echo_port<=65535 and echo_port!=53,'invalid UDP echo port'
    assert echo_address not in plan['nodes'],'UDP echo must be separate from outer endpoints'
    version=run(engine,'version').stdout.splitlines()
    assert version and re.fullmatch(r'(?:sing-box|worker) version 1\.14\.2',version[0]),'fixture requires pinned core 1.14.2'
    parser=INSTALL_ROOT/'gateway-policy.jq'
    compiled=run('jq','-ceS','--arg','mode','policy','-f',parser,source,check=False)
    assert compiled.returncode==0,'fake source rejected by shared policy compiler'
    policy=json.loads(compiled.stdout)
    assert policy['outer_endpoints']==plan['endpoints'],'fixture listeners do not exactly match compiled outer policy'
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
    cert=output/'fixture-cert.pem';key=output/'fixture-key.pem'
    if any(inbound['type']=='hysteria2' for inbound in plan['inbounds']):
        run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=d8-fixture.test',
            '-keyout',key,'-out',cert)
        for inbound in plan['inbounds']:
            if inbound['type']=='hysteria2':inbound['tls'].update(certificate_path=str(cert),key_path=str(key))
    server={'log':{'level':'info','timestamp':True},'inbounds':plan['inbounds'],
            'outbounds':[{'type':'direct','tag':'fixture-direct'}],'route':{'final':'fixture-direct'}}
    config=output/'fixture-server.json';config.write_text(json.dumps(server)+'\n');config.chmod(0o600)
    run(engine,'check','-c',config)
    save_state(state_path,state)
    try:
        run('ip','netns','add',NS)
        run('ip','link','add',HOST,'type','veth','peer','name',PEER)
        run('ip','link','set',PEER,'netns',NS)
        run('ip','addr','add','198.19.254.1/30','dev',HOST);run('ip','link','set',HOST,'up')
        run('ip','-n',NS,'addr','add',ADDRESS+'/30','dev',PEER);run('ip','-n',NS,'link','set',PEER,'up')
        run('ip','-n',NS,'link','set','lo','up')
        for address in plan['nodes']+[echo_address]:run('ip','-n',NS,'addr','add',address+'/32','dev','lo')
        run('ip','-n',NS,'route','add','default','via','198.19.254.1')
        for node in plan['nodes']:run('ip','-4','route','add',node+'/32','via',ADDRESS,'dev',HOST)
        for table,chain,*rule in firewall_rules(interface):run('iptables-legacy','-w','5','-t',table,'-A',chain,*rule)
        commands={UNIT:[str(engine),'run','-c',str(config)],
                  ECHO_UNIT:['/usr/bin/python3','-u','-c',ECHO_CODE,echo_address,str(echo_port)]}
        for unit,argv in commands.items():
            run('systemd-run','--quiet','--collect','--unit='+unit,'--property=KillMode=control-group',
                '--property=UMask=0077','/usr/bin/ip','netns','exec',NS,*argv)
            state['units'][unit]=True;save_state(state_path,state)
        deadline=time.monotonic()+8
        while True:
            active=all(run('systemctl','is-active',unit,check=False).stdout.strip()=='active' for unit in (UNIT,ECHO_UNIT))
            if active:break
            if time.monotonic()>=deadline:raise RuntimeError('fixture services did not become active')
            time.sleep(0.1)
        probe="import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.connect((sys.argv[1],int(sys.argv[2]))); s.send(b'fixture-echo-ready'); assert s.recv(100)==b'fixture-echo-ready'"
        run('/usr/bin/ip','netns','exec',NS,'/usr/bin/python3','-c',probe,echo_address,echo_port)
        assert source.read_bytes()==content,'source changed during fixture setup'
        info={'format':1,'endpoints':plan['endpoints'],'payload_networks':policy['payload_networks'],
              'dns_transport':policy['dns_transport'],'udp_echo':{'address':echo_address,'port':echo_port},
              'source_sha256':state['source_sha256'],'source_unchanged':True,'echo_verified_inside_upstream':True}
        (output/'fixture-info.json').write_text(json.dumps(info,indent=2)+'\n')
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
    start=actions.add_parser('setup');start.add_argument('--config',required=True)
    start.add_argument('--engine',required=True);start.add_argument('--output',required=True)
    start.add_argument('--udp-echo-address',default='192.0.2.254');start.add_argument('--udp-echo-port',type=int,default=40123)
    stop=actions.add_parser('cleanup');stop.add_argument('--output',required=True)
    args=parser.parse_args()
    if os.geteuid()!=0:parser.error('root required on a disposable test host')
    os.umask(0o077);output=output_directory(args.output)
    if args.action=='setup':setup(args,output)
    else:cleanup(output)


if __name__=='__main__':main()
