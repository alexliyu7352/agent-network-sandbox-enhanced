#!/usr/bin/env python3
"""Compare a real workload's exit with the explicitly owned local fixture.

The expected observation is made inside the separate fake-upstream namespace.
Actual addresses and trace bodies stay in private subprocess pipes and memory;
stdout and evidence contain only validation flags, IP family and equality.
This proves egress equality for the controlled same-host fixture. It does not
measure the anonymity or location of a remote production proxy.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
from types import SimpleNamespace

from host_acceptance import Binding, DEV, Suite
from host_upstream_fixture import NS, UNIT, ECHO_UNIT


TRACE_URL='https://1.1.1.1/cdn-cgi/trace'
ERROR_CODES={
    'input_not_private','output_not_private','fixture_state_invalid','fixture_source_mismatch',
    'fixture_endpoints_mismatch','namespace_not_allowed','namespace_unit_unavailable',
    'namespace_owner_mismatch','expected_probe_failed','expected_probe_timeout','trace_not_ipv4',
    'workload_failed','workload_timeout','workload_output_invalid','workload_identity_mismatch',
    'workload_cgroup_mismatch','session_identity_missing','session_cleanup_failed',
    'postcheck_failed','binding_invalid','account_invalid','evidence_write_failed','internal_error',
}
PAYLOAD=r'''
import http.client,json,os,pathlib
connection=http.client.HTTPSConnection('1.1.1.1',timeout=12)
try:
    connection.request('GET','/cdn-cgi/trace')
    response=connection.getresponse();body=response.read(65537)
    if len(body)>65536:raise RuntimeError('trace response too large')
    print('EXIT_PROOF '+json.dumps({'status':response.status,'trace':body.decode('ascii'),
        'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),
        'cgroup':pathlib.Path('/proc/self/cgroup').read_text()}),flush=True)
finally:
    connection.close()
'''


class ProofError(RuntimeError):
    def __init__(self,code):
        self.code=code if code in ERROR_CODES else 'internal_error'
        super().__init__(self.code)


def require(condition,code):
    if not condition:raise ProofError(code)


def run_private(argv,timeout=45):
    return subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=timeout,
                          env=dict(os.environ,PATH='/usr/sbin:/usr/bin:/sbin:/bin',LC_ALL='C'))


def parse_trace_ipv4(body):
    require(isinstance(body,str) and len(body)<=65536,'trace_not_ipv4')
    rows=[line[3:] for line in body.splitlines() if line.startswith('ip=')]
    require(len(rows)==1,'trace_not_ipv4')
    try:address=ipaddress.IPv4Address(rows[0])
    except (ValueError,TypeError):raise ProofError('trace_not_ipv4') from None
    require(str(address)==rows[0],'trace_not_ipv4')
    return str(address)


def read_private_json(path):
    require(path.is_absolute() and path.resolve()==path and path.is_file(),'input_not_private')
    for candidate in (path.parent,path):
        metadata=candidate.stat()
        require(metadata.st_uid==0 and metadata.st_mode&0o077==0,'input_not_private')
    try:
        content=path.read_text()
        require(len(content)<=1024*1024,'fixture_state_invalid')
        return json.loads(content)
    except (ValueError,UnicodeError):raise ProofError('fixture_state_invalid') from None


def validate_fixture_documents(binding,state,info,namespace):
    require(namespace==NS,'namespace_not_allowed')
    require(isinstance(state,dict) and type(state.get('format')) is int and state['format']==2 and
            isinstance(info,dict) and type(info.get('format')) is int and info['format']==1,'fixture_state_invalid')
    units=state.get('units')
    require(isinstance(units,dict) and set(units)=={UNIT,ECHO_UNIT} and
            all(value is True for value in units.values()),'fixture_state_invalid')
    require(state.get('source_sha256')==info.get('source_sha256')==binding.data['source_sha256'] and
            info.get('source_unchanged') is True,'fixture_source_mismatch')
    require(info.get('endpoints')==binding.policy['outer_endpoints'] and
            info.get('payload_networks')==binding.policy['payload_networks'] and
            info.get('dns_transport')==binding.policy['dns_transport'],'fixture_endpoints_mismatch')
    nodes=sorted({endpoint['address'] for endpoint in binding.policy['outer_endpoints']},key=ipaddress.IPv4Address)
    require(state.get('nodes')==nodes,'fixture_endpoints_mismatch')


def verify_namespace_owner(namespace,runner=run_private):
    require(namespace==NS,'namespace_not_allowed')
    result=runner(['systemctl','show','--property=ActiveState,MainPID,ControlGroup','--',UNIT],timeout=10)
    require(result.returncode==0,'namespace_unit_unavailable')
    values=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
    pid=values.get('MainPID','')
    require(values.get('ActiveState')=='active' and re.fullmatch(r'[1-9][0-9]*',pid) is not None and
            values.get('ControlGroup')=='/system.slice/'+UNIT,'namespace_unit_unavailable')
    named=Path('/run/netns')/namespace
    require(not named.is_symlink(),'namespace_owner_mismatch')
    metadata=named.stat();process=Path('/proc/'+pid+'/ns/net').stat();current=Path('/proc/self/ns/net').stat()
    identity=lambda value:(value.st_dev,value.st_ino)
    require(metadata.st_uid==0 and identity(metadata)==identity(process) and
            identity(metadata)!=identity(current),'namespace_owner_mismatch')


def session_ids(stderr):
    if isinstance(stderr,bytes):stderr=stderr.decode('utf-8','replace')
    return set(re.findall(r'^Session ([0-9a-f]{32});',stderr or '',re.M))


def reclaim_session(binding,sid,runner=run_private):
    holder=SimpleNamespace(binding=binding)
    try:
        Suite.reclaimed(holder,sid)
        return
    except Exception:
        # A killed relay can leave its service alive. Close only the printed
        # exact SID, then demand the same cgroup/request/unit reclamation proof.
        closed=runner([DEV,'close',sid],timeout=30)
        require(closed.returncode==0,'session_cleanup_failed')
    try:Suite.reclaimed(holder,sid)
    except Exception:raise ProofError('session_cleanup_failed') from None


def perform_proof(binding,account,namespace,runner=run_private,reclaim=None):
    require(namespace==NS,'namespace_not_allowed')
    require(account.pw_uid!=0,'account_invalid')
    curl=['ip','netns','exec',namespace,'/usr/bin/curl','-q','--noproxy','*','--proto','=https',
          '--fail','--silent','--show-error','--connect-timeout','5','--max-time','15',TRACE_URL]
    try:expected_result=runner(curl,timeout=20)
    except subprocess.TimeoutExpired:raise ProofError('expected_probe_timeout') from None
    require(expected_result.returncode==0,'expected_probe_failed')
    expected=parse_trace_ipv4(expected_result.stdout)
    stderr='';reclaim=reclaim or (lambda sid:reclaim_session(binding,sid,runner))
    try:
        try:
            workload=runner([DEV,'--user',account.pw_name,'run','--cwd','/','--','/usr/bin/python3','-c',PAYLOAD],timeout=50)
            stderr=workload.stderr
        except subprocess.TimeoutExpired as error:
            stderr=error.stderr or ''
            raise ProofError('workload_timeout') from None
        require(workload.returncode==0,'workload_failed')
        sids=session_ids(stderr)
        require(len(sids)==1,'session_identity_missing')
        rows=[row[len('EXIT_PROOF '):] for row in workload.stdout.splitlines() if row.startswith('EXIT_PROOF ')]
        require(len(rows)==1,'workload_output_invalid')
        try:info=json.loads(rows[0])
        except (ValueError,TypeError):raise ProofError('workload_output_invalid') from None
        require(isinstance(info,dict) and info.get('status')==200,'workload_output_invalid')
        require((info.get('uid'),info.get('gid'),info.get('groups'))==
                (account.pw_uid,account.pw_gid,[]),'workload_identity_mismatch')
        try:binding.verify_membership(info.get('cgroup',''),next(iter(sids)))
        except (AssertionError,ValueError,TypeError,AttributeError):raise ProofError('workload_cgroup_mismatch') from None
        actual=parse_trace_ipv4(info.get('trace'))
        matches=expected==actual
    finally:
        sids=session_ids(stderr)
        if len(sids)==1:
            try:reclaim(next(iter(sids)))
            except Exception:raise ProofError('session_cleanup_failed') from None
    checked=runner([DEV,'check'],timeout=40)
    require(checked.returncode==0,'postcheck_failed')
    try:binding.verify_parent()
    except Exception:raise ProofError('binding_invalid') from None
    return {'format':1,'passed':matches,'exit_ip':{'valid_ipv4':True,'family':4,'matches':matches},
            'checks':{'workload_identity':True,'workload_cgroup':True,'session_reclaimed':True,
                      'postcheck':True,'binding_retained':True},
            'scope':'Egress equality with the controlled same-host fixture; remote anonymity is not measured.'}


def failure_report(error):
    code=error.code if isinstance(error,ProofError) else 'internal_error'
    return {'format':1,'passed':False,'error_code':code}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user',required=True)
    parser.add_argument('--fixture-output',required=True,help='root-private directory from host_upstream_fixture setup')
    parser.add_argument('--upstream-namespace',required=True,choices=(NS,))
    parser.add_argument('--output',required=True,help='root-private directory for address-free results.json')
    args=parser.parse_args(argv)
    if os.geteuid()!=0:parser.error('root required on the disposable fixture host')
    os.umask(0o077);output=Path(args.output);output_ready=False
    try:
        require(output.is_absolute(),'output_not_private')
        output.mkdir(mode=0o700,parents=True,exist_ok=True)
        metadata=output.stat()
        require(output.resolve()==output and metadata.st_uid==0 and metadata.st_mode&0o077==0,'output_not_private')
        output_ready=True
        try:binding=Binding.load()
        except Exception:raise ProofError('binding_invalid') from None
        account=pwd.getpwnam(args.user);require(account.pw_uid!=0,'account_invalid')
        directory=Path(args.fixture_output)
        state=read_private_json(directory/'upstream-fixture-state.json')
        info=read_private_json(directory/'fixture-info.json')
        validate_fixture_documents(binding,state,info,args.upstream_namespace)
        verify_namespace_owner(args.upstream_namespace)
        result=perform_proof(binding,account,args.upstream_namespace)
        result['checks'].update(fixture_bound_to_source=True,owned_upstream_namespace=True)
    except Exception as error:
        result=failure_report(error)
    if output_ready:
        try:
            temporary=output/'results.tmp'
            temporary.write_text(json.dumps(result,indent=2)+'\n');temporary.chmod(0o600)
            temporary.replace(output/'results.json')
        except OSError:result=failure_report(ProofError('evidence_write_failed'))
    print(json.dumps(result,sort_keys=True),flush=True)
    return 0 if result['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
