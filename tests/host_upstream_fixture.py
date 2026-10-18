#!/usr/bin/env python3
"""Root-only, temporary Hysteria2 upstream for a disposable host test.

Uses the production node IP/password only inside a separate network namespace.
One exact host /32 route temporarily directs that node to the fixture. External
traffic from the fixture has its own veth and NAT rule. No production JSON is
modified. Run cleanup before returning the test host to its normal upstream.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

BASE = Path('/root/dev-session-acceptance-20261009')
INSTALL_ROOT = Path(__file__).resolve().parents[1]
NS = 'd8-test-upstream'
HOST = 'd8testh'
PEER = 'd8testn'
ADDRESS = '198.19.254.2'
UNIT = 'd8-test-upstream.service'
STATE = BASE / 'upstream-fixture-state.json'


def run(*args, check=True):
    return subprocess.run(list(args), check=check, text=True, capture_output=True)


def firewall_rules(interface):
    return [
        ['filter', 'FORWARD', '-i', HOST, '-o', interface, '-s', ADDRESS+'/32',
         '-m', 'comment', '--comment', 'd8-host-acceptance', '-j', 'ACCEPT'],
        ['filter', 'FORWARD', '-i', interface, '-o', HOST, '-d', ADDRESS+'/32',
         '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED',
         '-m', 'comment', '--comment', 'd8-host-acceptance', '-j', 'ACCEPT'],
        ['nat', 'POSTROUTING', '-s', ADDRESS+'/32', '-o', interface,
         '-m', 'comment', '--comment', 'd8-host-acceptance', '-j', 'MASQUERADE'],
    ]


def cleanup():
    if not STATE.exists():
        return
    state = json.loads(STATE.read_text())
    unit_group=run('systemctl','show','--property=ControlGroup','--value',UNIT,check=False).stdout.strip()
    if state.get('owns_unit',False):run('systemctl', 'stop', UNIT, check=False)
    run('ip', '-4', 'route', 'del', state['node']+'/32', 'via', ADDRESS,
        'dev', HOST, check=False)
    for table, chain, *rule in firewall_rules(state['interface']):
        run('iptables-legacy', '-w', '5', '-t', table, '-D', chain, *rule, check=False)
    run('ip', 'link', 'del', HOST, check=False)
    run('ip', 'netns', 'del', NS, check=False)
    errors=[]
    if state.get('owns_unit',False):
        properties=run('systemctl','show','--property=ActiveState,MainPID,ControlPID',UNIT).stdout
        values=dict(line.split('=',1) for line in properties.splitlines() if '=' in line)
        active=values.get('ActiveState','')
        if active not in ('inactive','failed'):errors.append('fixture service not verifiably stopped: '+active)
        if values.get('MainPID')!='0' or values.get('ControlPID')!='0':
            errors.append('fixture service still has a main/control process')
        if unit_group:
            assert unit_group=='/system.slice/'+UNIT,unit_group
            group=Path('/sys/fs/cgroup/systemd'+unit_group)
            if group.exists() and any(path.read_text().strip() for path in group.rglob('cgroup.procs')):
                errors.append('fixture service cgroup still has processes')
    if json.loads(run('ip','-j','-4','route','show','exact',state['node']+'/32').stdout):
        errors.append('fixture node route remains')
    for table,chain,*rule in firewall_rules(state['interface']):
        rules=run('iptables-legacy','-w','5','-t',table,'-S',chain).stdout
        if 'd8-host-acceptance' in rules:
            errors.append('fixture firewall rule remains: '+table+'/'+chain)
    if any(link['ifname']==HOST for link in json.loads(run('ip','-j','link','show').stdout)):
        errors.append('fixture veth remains')
    if NS in run('ip','netns','list').stdout.split():
        errors.append('fixture namespace remains')
    if errors:
        state['cleanup_errors']=errors
        STATE.write_text(json.dumps(state))
        raise RuntimeError('Cleanup incomplete; state retained: '+ '; '.join(errors))
    STATE.unlink()
    print('UPSTREAM_FIXTURE_REMOVED', flush=True)


def setup():
    if STATE.exists():
        raise RuntimeError('Fixture state already exists; cleanup explicitly first')
    config = json.loads((INSTALL_ROOT/'network.json').read_text())
    node = config['outbounds'][0]
    assert node['tls']['insecure'] is True, 'Fixture requires existing insecure TLS policy'
    assert run('ip', 'link', 'show', HOST, check=False).returncode != 0
    assert NS not in run('ip', 'netns', 'list').stdout.split()
    assert run('systemctl','show','--property=LoadState','--value',UNIT,
               check=False).stdout.strip()=='not-found', 'fixture unit name is occupied'
    assert not json.loads(run('ip', '-j', '-4', 'route', 'show', 'exact',
                             node['server']+'/32').stdout)
    interface = json.loads(run('ip', '-j', '-4', 'route', 'get', '1.1.1.1').stdout)[0]['dev']
    state={'node':node['server'],'interface':interface,'owns_unit':False}
    STATE.write_text(json.dumps(state))
    STATE.chmod(0o600)
    try:
        run('ip', 'netns', 'add', NS)
        run('ip', 'link', 'add', HOST, 'type', 'veth', 'peer', 'name', PEER)
        run('ip', 'link', 'set', PEER, 'netns', NS)
        run('ip', 'addr', 'add', '198.19.254.1/30', 'dev', HOST)
        run('ip', 'link', 'set', HOST, 'up')
        run('ip', '-n', NS, 'addr', 'add', ADDRESS+'/30', 'dev', PEER)
        run('ip', '-n', NS, 'link', 'set', PEER, 'up')
        run('ip', '-n', NS, 'link', 'set', 'lo', 'up')
        run('ip', '-n', NS, 'addr', 'add', node['server']+'/32', 'dev', 'lo')
        run('ip', '-n', NS, 'route', 'add', 'default', 'via', '198.19.254.1')
        run('ip', '-4', 'route', 'add', node['server']+'/32', 'via', ADDRESS, 'dev', HOST)
        for table, chain, *rule in firewall_rules(interface):
            run('iptables-legacy', '-w', '5', '-t', table, '-A', chain, *rule)
        cert = BASE/'fixture-cert.pem'
        key = BASE/'fixture-key.pem'
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=d8-fixture.test', '-keyout', str(key), '-out', str(cert))
        server = {
            'log': {'level': 'info', 'timestamp': True},
            'inbounds': [{'type': 'hysteria2', 'tag': 'fixture-hy2',
                          'listen': node['server'], 'listen_port': node['server_port'],
                          'users': [{'name': 'fixture', 'password': node['password']}],
                          'tls': {'enabled': True, 'certificate_path': str(cert),
                                  'key_path': str(key), 'alpn': ['h3']}}],
            'outbounds': [{'type': 'direct', 'tag': 'fixture-direct'}],
            'route': {'final': 'fixture-direct'},
        }
        path = BASE/'fixture-server.json'
        path.write_text(json.dumps(server)); path.chmod(0o600)
        run('systemd-run', '--quiet', '--collect', '--unit='+UNIT,
            '--property=KillMode=control-group', '--property=UMask=0077',
            '/usr/bin/ip', 'netns', 'exec', NS, str(BASE/'worker'),
            'run', '-c', str(path))
        state['owns_unit']=True;STATE.write_text(json.dumps(state))
        print('UPSTREAM_FIXTURE_STARTED', flush=True)
    except BaseException:
        cleanup()
        raise


if __name__ == '__main__':
    if os.geteuid() != 0:
        raise SystemExit('root required on a disposable test host')
    os.umask(0o077)
    if sys.argv[1:] == ['setup']:
        setup()
    elif sys.argv[1:] == ['cleanup']:
        cleanup()
    else:
        raise SystemExit('usage: host_upstream_fixture.py setup|cleanup')
