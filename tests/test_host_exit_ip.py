"""Offline regression tests; no real namespaces, sessions or network sockets."""
import copy
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

import host_exit_ip as proof
import host_acceptance
from host_acceptance import Binding


class ExitProofTests(unittest.TestCase):
    sid='1'*32
    address='198.51.100.44'

    def binding(self):
        binding=Binding.from_text(json.dumps(host_acceptance.BindingTests.document()))
        binding.verify_parent=mock.Mock()
        return binding

    def payload(self):
        return {'uid':1001,'gid':1001,'groups':[], 'status':200,
                'trace':'fl=fixture\nip='+self.address+'\n',
                'cgroup':'0::/devsession.slice/dev-session-'+self.sid+'.service\n'}

    def documents(self,binding):
        info={'format':1,'source_sha256':binding.data['source_sha256'],
              'endpoints':binding.policy['outer_endpoints'],'source_unchanged':True,
              'payload_networks':binding.policy['payload_networks'],'dns_transport':binding.policy['dns_transport']}
        state={'format':2,'source_sha256':info['source_sha256'],
               'nodes':['192.0.2.8','198.51.100.9'],
               'units':{'d8-test-upstream.service':True,'d8-test-upstream-echo.service':True}}
        return state,info

    def test_trace_parser_rejects_ambiguous_and_non_ipv4_values_without_echo(self):
        self.assertEqual(proof.parse_trace_ipv4('ip='+self.address+'\n'),self.address)
        for body in ('ip=2001:db8::4\n','ip='+self.address+'\nip=192.0.2.2\n',
                     'ip=private-sentinel-do-not-print\n','ip=010.0.0.1\n','no-ip-field'):
            with self.subTest(body=body),self.assertRaises(proof.ProofError) as failure:
                proof.parse_trace_ipv4(body)
            self.assertNotIn(body,repr(failure.exception))
            self.assertNotIn('private-sentinel',repr(failure.exception))

    def test_fixture_must_match_bound_source_and_all_endpoint_addresses(self):
        binding=self.binding();state,info=self.documents(binding)
        proof.validate_fixture_documents(binding,state,info,'d8-test-upstream')
        for section,key,value in [('state','source_sha256','f'*64),('state','nodes',['192.0.2.8']),
                    ('state','units',{'d8-test-upstream.service':False}),
                    ('info','endpoints',info['endpoints'][:1]),('info','source_unchanged',False)]:
            mutated_state,mutated_info=copy.deepcopy(state),copy.deepcopy(info)
            (mutated_state if section=='state' else mutated_info)[key]=value
            with self.subTest(section=section,key=key),self.assertRaises(proof.ProofError):
                proof.validate_fixture_documents(binding,mutated_state,mutated_info,'d8-test-upstream')
        with self.assertRaises(proof.ProofError):proof.validate_fixture_documents(binding,state,info,'some-real-upstream')

    def test_namespace_requires_active_owned_unit_and_matching_inode(self):
        def runner(argv,timeout):
            self.assertEqual(argv[:2],['systemctl','show'])
            return subprocess.CompletedProcess(argv,0,'ActiveState=active\nMainPID=345\nControlGroup=/system.slice/d8-test-upstream.service\n','')
        def metadata(path):
            inode=1 if str(path)=='/proc/self/ns/net' else 23
            return SimpleNamespace(st_dev=4,st_ino=inode,st_uid=0)
        with mock.patch.object(Path,'stat',metadata),mock.patch.object(Path,'is_symlink',return_value=False):
            proof.verify_namespace_owner('d8-test-upstream',runner)
        def mismatch(path):
            inode=99 if str(path)=='/proc/345/ns/net' else 23
            return SimpleNamespace(st_dev=4,st_ino=inode,st_uid=0)
        with mock.patch.object(Path,'stat',mismatch),mock.patch.object(Path,'is_symlink',return_value=False),self.assertRaises(proof.ProofError):
            proof.verify_namespace_owner('d8-test-upstream',runner)

    def test_real_workload_boundary_matches_and_never_returns_actual_ips(self):
        binding=self.binding();reclaim=mock.Mock();calls=[]
        def runner(argv,timeout):
            calls.append(argv)
            if argv[0]=='ip':return subprocess.CompletedProcess(argv,0,'ip='+self.address+'\n','')
            if 'run' in argv:
                return subprocess.CompletedProcess(argv,0,'EXIT_PROOF '+json.dumps(self.payload())+'\n','Session '+self.sid+'; close with test\n')
            self.assertEqual(argv,[proof.DEV,'check'])
            return subprocess.CompletedProcess(argv,0,'','')
        result=proof.perform_proof(binding,SimpleNamespace(pw_name='fixture-user',pw_uid=1001,pw_gid=1001),
                                   'd8-test-upstream',runner,reclaim)
        self.assertTrue(result['passed']);self.assertEqual(result['exit_ip'],{'valid_ipv4':True,'family':4,'matches':True})
        self.assertNotIn(self.address,json.dumps(result));reclaim.assert_called_once_with(self.sid)
        self.assertEqual(calls[0][:4],['ip','netns','exec','d8-test-upstream'])
        self.assertIn('--noproxy',calls[0]);self.assertIn('*',calls[0])
        self.assertEqual(calls[1][:5],[proof.DEV,'--user','fixture-user','run','--cwd'])
        binding.verify_parent.assert_called_once()

    def test_exit_mismatch_is_failure_and_keeps_both_addresses_private(self):
        binding=self.binding();payload=self.payload();payload['trace']='ip=203.0.113.12\n'
        def runner(argv,timeout):
            if argv[0]=='ip':return subprocess.CompletedProcess(argv,0,'ip='+self.address+'\n','')
            if 'run' in argv:return subprocess.CompletedProcess(argv,0,'EXIT_PROOF '+json.dumps(payload),'Session '+self.sid+';\n')
            return subprocess.CompletedProcess(argv,0,'','')
        result=proof.perform_proof(binding,SimpleNamespace(pw_name='fixture-user',pw_uid=1001,pw_gid=1001),
                                   'd8-test-upstream',runner,mock.Mock())
        self.assertFalse(result['passed']);self.assertFalse(result['exit_ip']['matches'])
        self.assertNotIn(self.address,json.dumps(result));self.assertNotIn('203.0.113.12',json.dumps(result))

    def test_workload_identity_or_cgroup_failure_cannot_pass_and_still_reclaims(self):
        for field,value,code in [('uid',0,'workload_identity_mismatch'),
                                  ('cgroup','0::/system.slice/other.service\n','workload_cgroup_mismatch')]:
            with self.subTest(field=field):
                payload=self.payload();payload[field]=value;reclaim=mock.Mock()
                def runner(argv,timeout):
                    if argv[0]=='ip':return subprocess.CompletedProcess(argv,0,'ip='+self.address+'\n','')
                    return subprocess.CompletedProcess(argv,0,'EXIT_PROOF '+json.dumps(payload),'Session '+self.sid+';\n')
                with self.assertRaises(proof.ProofError) as failure:
                    proof.perform_proof(self.binding(),SimpleNamespace(pw_name='fixture-user',pw_uid=1001,pw_gid=1001),
                                        'd8-test-upstream',runner,reclaim)
                self.assertEqual(failure.exception.code,code)
                self.assertNotIn(self.address,repr(failure.exception));reclaim.assert_called_once_with(self.sid)

    def test_timed_out_workload_still_reclaims_sid_and_sanitizes_error(self):
        reclaim=mock.Mock()
        def runner(argv,timeout):
            if argv[0]=='ip':return subprocess.CompletedProcess(argv,0,'ip='+self.address+'\n','')
            raise subprocess.TimeoutExpired(argv,timeout,output=self.address,
                                            stderr='Session '+self.sid+';\n'+self.address)
        with self.assertRaises(proof.ProofError) as failure:
            proof.perform_proof(self.binding(),SimpleNamespace(pw_name='fixture-user',pw_uid=1001,pw_gid=1001),
                                'd8-test-upstream',runner,reclaim)
        self.assertEqual(failure.exception.code,'workload_timeout')
        self.assertNotIn(self.address,repr(failure.exception));reclaim.assert_called_once_with(self.sid)

    def test_failure_reports_never_echo_arbitrary_exception_details(self):
        for error in (RuntimeError(self.address),ValueError('private-sentinel-do-not-print')):
            report=proof.failure_report(error)
            self.assertFalse(report['passed'])
            self.assertNotIn(self.address,json.dumps(report));self.assertNotIn('private-sentinel',json.dumps(report))


if __name__=='__main__':unittest.main()
