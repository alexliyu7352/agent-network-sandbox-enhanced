"""Pure/native-helper contracts; no namespace, route or firewall mutations."""
import copy
from contextlib import redirect_stdout
import http.client
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import host_upstream_fixture as fixture
import host_acceptance as host
import protocol_runtime as runtime


class NativeRecipeTests(unittest.TestCase):
    def recipe(self, name):
        return fixture.native_recipe(name, Path('/root/fixture-test'), 'TEST CERTIFICATE',
                                     ssh_host_key='ssh-rsa AAAATESTONLY')

    def test_all_recipes_keep_real_tun_dns_and_inline_node_trust(self):
        names=list(dict.fromkeys(runtime.case_names()+list(runtime.EXPERIMENTAL_CASES)))
        self.assertEqual(len(names),47)
        for name in names:
            with self.subTest(case=name):
                plan=self.recipe(name);source=plan['source'];effective=plan['effective']
                self.assertEqual(source['inbounds'],fixture.managed_fixture_base()['inbounds'])
                self.assertEqual(source['dns'],fixture.managed_fixture_base()['dns'])
                self.assertEqual(effective['inbounds'],source['inbounds'])
                self.assertEqual(effective['dns']['servers'][0]['server'],'1.1.1.1')
                self.assertEqual(effective['dns']['servers'][0]['detour'],'proxy')
                self.assertEqual(plan['policy'],runtime.compile_config(source,'policy'))
                self.assertTrue(all(fixture.fixture_ipv4(row['address']) for row in plan['policy']['outer_endpoints']))
                source_text=json.dumps(source)
                self.assertNotIn('insecure',source_text)
                self.assertNotIn('certificate_path',source_text)
                self.assertNotIn('127.0.0.3',json.dumps(plan))
                for outbound in source['outbounds']:
                    if 'tls' in outbound:
                        self.assertEqual(outbound['tls']['certificate'],['TEST CERTIFICATE'])
                if name!='ssh':
                    self.assertEqual(plan['server']['route'],{'final':'fixture-direct'})
                    self.assertEqual(plan['server']['outbounds'],[{'type':'direct','tag':'fixture-direct',
                                                                  'inet4_bind_address':fixture.ADDRESS}])
                    self.assertNotIn('override_address',json.dumps(plan['server']))

    def test_detour_and_wrappers_expose_only_outer_nodes(self):
        for name in ('detour','shadowtls1','shadowtls2','shadowtls3'):
            with self.subTest(case=name):
                plan=self.recipe(name)
                self.assertEqual(plan['nodes'],['192.0.2.2'])
                self.assertIn('198.51.100.1',plan['namespace_addresses'])
                self.assertNotIn('198.51.100.1',plan['nodes'])
                self.assertEqual(plan['source']['outbounds'][0]['server'],'198.51.100.1')

    def test_groups_use_two_exact_protocol_endpoints_and_real_health_url(self):
        for name in ('selector-trojan','selector-hysteria2','urltest'):
            with self.subTest(case=name):
                plan=self.recipe(name)
                self.assertEqual(plan['policy']['outer_endpoints'],[
                    {'family':4,'address':'192.0.2.1','protocol':'tcp','port_start':443,'port_end':443},
                    {'family':4,'address':'192.0.2.2','protocol':'udp','port_start':8443,'port_end':8443}])
                if name=='urltest':
                    self.assertEqual(plan['source']['outbounds'][0]['url'],'https://1.1.1.1/cdn-cgi/trace')

    def test_hopping_uses_two_exact_ranges_and_private_backend(self):
        for name in ('hysteria-port-hopping','hysteria2-port-hopping'):
            with self.subTest(case=name):
                plan=self.recipe(name)
                self.assertEqual(plan['policy']['outer_endpoints'],[
                    {'family':4,'address':'192.0.2.1','protocol':'udp','port_start':4400,'port_end':4403},
                    {'family':4,'address':'192.0.2.1','protocol':'udp','port_start':4410,'port_end':4413}])
                self.assertEqual(plan['helpers']['hopping']['ports'],list(range(4400,4404))+list(range(4410,4414)))
                self.assertEqual(plan['server']['inbounds'][0]['listen'],'127.0.0.1')
                self.assertEqual(plan['server']['inbounds'][0]['listen_port'],443)

    def test_render_refuses_any_existing_source_before_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);out=root/'fixture';out.mkdir(mode=0o700)
            source=root/'network.json';source.write_text('PRIVATE-EXISTING-SOURCE');source.chmod(0o600)
            args=SimpleNamespace(protocol_case='http',engine='/unused/worker',config=str(source),python=None)
            with mock.patch.object(fixture,'run') as command:
                with self.assertRaises((AssertionError,RuntimeError)):
                    fixture.render(args,out)
            command.assert_not_called()
            self.assertEqual(source.read_text(),'PRIVATE-EXISTING-SOURCE')
            self.assertEqual(list(out.iterdir()),[])

    def test_hopping_evidence_requires_real_multiple_declared_ports(self):
        plan=self.recipe('hysteria2-port-hopping')
        baseline={'format':1,'protocol_case':plan['case'],'ready':True,
                  'observed_hop_ports':[4400,4410],'tls_cover_handshakes':0}
        self.assertEqual(fixture.runtime_evidence(plan,baseline,'')['observed_hop_ports'],[4400,4410])
        for ports in ([],[4400],[4400,4400],[4400,4404],[4400,9999]):
            bad=copy.deepcopy(baseline);bad['observed_hop_ports']=ports
            with self.subTest(ports=ports),self.assertRaises((AssertionError,RuntimeError)):
                fixture.runtime_evidence(plan,bad,'')

    def test_graph_evidence_requires_forwarding_and_cover_handshake(self):
        plan=self.recipe('urltest')
        metrics={'format':1,'protocol_case':'urltest','ready':True,
                 'observed_hop_ports':[],'tls_cover_handshakes':0}
        a='INFO inbound/trojan[a-in]: [matrix-user] inbound connection to 1.1.1.1:443\n'
        b='INFO inbound/hysteria2[b-in]: [matrix-user] inbound connection to 1.1.1.1:443\n'
        with self.assertRaises((AssertionError,RuntimeError)):
            fixture.runtime_evidence(plan,metrics,a+'INFO [b-in]: udp server started\n')
        self.assertEqual(fixture.runtime_evidence(plan,metrics,a+b)['forwarded_tags'],['a-in','b-in'])
        shadow=self.recipe('shadowtls2');metrics['protocol_case']='shadowtls2'
        logs='INFO inbound/shadowtls[cover-in]: inbound connection to 198.51.100.1:443\n'
        logs+='INFO inbound/shadowsocks[proxy-in]: inbound connection to 1.1.1.1:443\n'
        with self.assertRaises((AssertionError,RuntimeError)):
            fixture.runtime_evidence(shadow,metrics,logs)
        metrics['tls_cover_handshakes']=1
        self.assertEqual(fixture.runtime_evidence(shadow,metrics,logs)['tls_cover_handshakes'],1)

    def test_native_ssh_allows_only_public_ipv4_https_destinations(self):
        self.assertEqual(fixture.ssh_destination(('1.1.1.1',443)),('1.1.1.1',443))
        for value in (('127.0.0.1',443),('198.19.254.1',443),('192.0.2.254',40123),
                      ('169.254.169.254',443),('1.1.1.1',22),('1.1.1.1',True),
                      ('www.cloudflare.com',443),('::1',443),('1.1.1.1',53)):
            with self.subTest(value=value),self.assertRaises((AssertionError,RuntimeError,ValueError)):
                fixture.ssh_destination(value)

    def test_metrics_reject_boolean_format_and_unexpected_fields(self):
        plan=self.recipe('http')
        for changes in ({'format':True},{'unexpected':'data'},{'tls_cover_handshakes':True}):
            metrics={'format':1,'protocol_case':'http','ready':True,
                     'observed_hop_ports':[],'tls_cover_handshakes':0}
            metrics.update(changes)
            with self.subTest(changes=changes),self.assertRaises(RuntimeError):
                fixture.runtime_evidence(plan,metrics,'')


@unittest.skipUnless(os.geteuid()==0,'root-owned artifact contracts require root')
class RenderIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.output=self.root/'fixture';self.output.mkdir(mode=0o700)
        self.engine=self.root/'worker';self.engine.write_text('inert pinned test engine');self.engine.chmod(0o700)
        self.python=self.root/'python';self.python.write_text('inert trusted test interpreter');self.python.chmod(0o700)
        self.args=SimpleNamespace(protocol_case='http',engine=str(self.engine),
                                  config=str(self.root/'network.json'),python=str(self.python))
        self.commands=[]

    def boundary(self,*argv,**kwargs):
        self.commands.append(tuple(map(str,argv)))
        if len(argv)>1 and argv[1]=='version':
            return subprocess.CompletedProcess(argv,0,'sing-box version 1.14.2\nRevision: '+runtime.REVISION+'\n','')
        if argv[0]=='openssl':
            Path(argv[argv.index('-out')+1]).write_text('TEST CERTIFICATE')
            Path(argv[argv.index('-keyout')+1]).write_text('TEST PRIVATE KEY')
        else:self.assertEqual(tuple(argv[1:3]),('check','-c'))
        return subprocess.CompletedProcess(argv,0,'','')

    def render(self):
        with mock.patch.object(fixture,'run',side_effect=self.boundary),redirect_stdout(io.StringIO()):
            fixture.render(self.args,self.output)

    def test_rendered_identity_roundtrip_and_source_immutable(self):
        self.render();source=Path(self.args.config);before=source.read_bytes()
        plan,descriptor=fixture.load_recipe(self.args,self.output)
        self.assertEqual(plan['policy'],descriptor['policy'])
        self.assertEqual(source.read_bytes(),before)
        self.assertEqual(source.stat().st_mode&0o777,0o600)
        self.assertTrue(all(path.stat().st_mode&0o077==0 for path in self.output.iterdir()))
        self.assertTrue(all(row[0]=='openssl' or row[1] in ('version','check') for row in self.commands))

    def test_source_rewrite_cannot_be_hidden_by_updating_descriptor_hash(self):
        self.render();source=Path(self.args.config)
        value=json.loads(source.read_text());value['outbounds'][0]['password']='PRIVATE-AUTH-MUST-NOT-BE-ACCEPTED'
        source.write_bytes(fixture.json_bytes(value))
        path=self.output/'protocol-recipe.json';descriptor=json.loads(path.read_text())
        descriptor['source_sha256']=fixture.file_digest(source);path.write_bytes(fixture.json_bytes(descriptor))
        with self.assertRaises(RuntimeError) as error:fixture.load_recipe(self.args,self.output)
        self.assertNotIn('PRIVATE-AUTH',str(error.exception))

    def test_artifact_and_component_tampering_refused(self):
        self.render()
        with mock.patch.object(fixture,'recipe_components',return_value={'changed':'component'}):
            with self.assertRaises(RuntimeError):fixture.load_recipe(self.args,self.output)
        path=self.output/'fixture-effective.json';path.write_text('{}\n')
        with self.assertRaises(RuntimeError):fixture.load_recipe(self.args,self.output)

    def test_source_publication_race_does_not_overwrite_other_writer(self):
        def boundary(*argv,**kwargs):
            result=self.boundary(*argv,**kwargs)
            if tuple(argv[1:3])==('check','-c') and str(argv[-1]).endswith('fixture-effective.json'):
                Path(self.args.config).write_text('EXISTING-WRITER')
            return result
        with mock.patch.object(fixture,'run',side_effect=boundary):
            with self.assertRaises(FileExistsError):fixture.render(self.args,self.output)
        self.assertEqual(Path(self.args.config).read_text(),'EXISTING-WRITER')
        self.assertFalse((self.output/'protocol-recipe.json').exists())

    def test_duplicate_descriptor_fields_refused(self):
        self.render();path=self.output/'protocol-recipe.json'
        value=path.read_text().rstrip();path.write_text(value[:-1]+',"format":1}\n')
        with self.assertRaises(RuntimeError):fixture.load_recipe(self.args,self.output)

    def setup_boundary(self,*argv,**kwargs):
        row=tuple(map(str,argv));self.commands.append(row)
        if row[:4]==('ip','link','show',fixture.HOST):
            return subprocess.CompletedProcess(row,1,'','')
        if row==('ip','netns','list'):text=''
        elif row[:3]==('systemctl','show','--property=LoadState'):text='not-found\n'
        elif row[:5]==('ip','-j','-4','route','show'):text='[]'
        elif row[:5]==('ip','-j','-4','route','get'):text='[{"dev":"eth0"}]'
        elif row[:2]==('systemctl','is-active'):text='active\n'
        elif row[0]==str(self.engine) and row[1:3]==('check','-c'):text=''
        elif row[0]=='systemd-run':
            if '--unit='+fixture.UNIT in row:
                fixture.save_state(self.output/'runtime-state.json',
                    {'format':1,'protocol_case':self.args.protocol_case,'ready':True,
                     'observed_hop_ports':[],'tls_cover_handshakes':0})
            text=''
        elif row[0] in ('ip','iptables-legacy','/usr/bin/ip'):text=''
        else:raise AssertionError('unexpected command boundary: '+str(row[:3]))
        return subprocess.CompletedProcess(row,0,text,'')

    def test_native_setup_keeps_inner_routes_private_and_runs_selected_supervisor(self):
        self.args.protocol_case='detour';self.render();before=Path(self.args.config).read_bytes()
        self.args.udp_echo_address='192.0.2.254';self.args.udp_echo_port=40123
        self.commands=[]
        with mock.patch.object(fixture,'run',side_effect=self.setup_boundary),\
             mock.patch.object(fixture,'manager_mount',return_value={'path':'/test/cgroup','identity':'1:2'}),\
             mock.patch.object(fixture,'namespace_identity',return_value='17:42'),\
             mock.patch.object(fixture,'owned_namespace',return_value='17:42'),\
             mock.patch.object(fixture,'cleanup') as cleanup,redirect_stdout(io.StringIO()):
            fixture.setup(self.args,self.output)
        cleanup.assert_not_called()
        host_routes=[row for row in self.commands if row[:4]==('ip','-4','route','add')]
        self.assertEqual(host_routes,[('ip','-4','route','add','192.0.2.2/32','via',fixture.ADDRESS,'dev',fixture.HOST)])
        self.assertIn(('ip','-n',fixture.NS,'addr','add','198.51.100.1/32','dev','lo'),self.commands)
        services=[row for row in self.commands if row[0]=='systemd-run']
        self.assertEqual(len(services),2)
        main=next(row for row in services if '--unit='+fixture.UNIT in row)
        self.assertIn(str(self.python),main)
        index=main.index(str(self.python))
        self.assertEqual(main[index+1:index+4],('-I',str(Path(fixture.__file__).resolve()),'serve'))
        self.assertEqual(main[main.index('--python')+1],str(self.python))
        self.assertNotIn('init',main);self.assertNotIn('check',main)
        state=fixture.read_private_json(self.output/'upstream-fixture-state.json')
        info=fixture.read_private_json(self.output/'fixture-info.json')
        self.assertEqual(state['namespace_identity'],'17:42')
        self.assertEqual(state['protocol_case'],'detour')
        self.assertEqual(state['units'],{fixture.UNIT:True,fixture.ECHO_UNIT:True})
        self.assertEqual(info['endpoints'],fixture.load_recipe(self.args,self.output)[0]['endpoints'])
        self.assertEqual(Path(self.args.config).read_bytes(),before)

    def test_setup_rejects_changed_recipe_before_any_privileged_command(self):
        self.render();self.args.udp_echo_address='192.0.2.254';self.args.udp_echo_port=40123
        path=self.output/'fixture-server.json';path.write_text('{}\n')
        with mock.patch.object(fixture,'run') as command,mock.patch.object(fixture,'cleanup') as cleanup:
            with self.assertRaises(RuntimeError):fixture.setup(self.args,self.output)
        command.assert_not_called();cleanup.assert_not_called()
        self.assertFalse((self.output/'upstream-fixture-state.json').exists())

    def test_setup_failure_cleans_exact_fixture_and_never_rewrites_source(self):
        self.render();before=Path(self.args.config).read_bytes()
        self.args.udp_echo_address='192.0.2.254';self.args.udp_echo_port=40123
        def fail_at_link(*argv,**kwargs):
            if tuple(map(str,argv[:3]))==('ip','link','add'):raise RuntimeError('test-owned injection')
            return self.setup_boundary(*argv,**kwargs)
        with mock.patch.object(fixture,'run',side_effect=fail_at_link),\
             mock.patch.object(fixture,'manager_mount',return_value={'path':'/test/cgroup','identity':'1:2'}),\
             mock.patch.object(fixture,'namespace_identity',return_value='17:42'),\
             mock.patch.object(fixture,'cleanup') as cleanup:
            with self.assertRaisesRegex(RuntimeError,'test-owned injection'):fixture.setup(self.args,self.output)
        cleanup.assert_called_once_with(self.output)
        self.assertEqual(Path(self.args.config).read_bytes(),before)
        self.assertFalse((self.output/'fixture-info.json').exists())

    def test_verify_publishes_safe_readonly_evidence_and_refuses_replaced_namespace(self):
        self.render();plan,descriptor=fixture.load_recipe(self.args,self.output)
        fixture.save_state(self.output/'upstream-fixture-state.json',
            {'format':2,'source_sha256':descriptor['source_sha256'],'nodes':plan['nodes'],
             'protocol_case':'http','units':{fixture.UNIT:True,fixture.ECHO_UNIT:True},'namespace_identity':'17:42'})
        fixture.save_state(self.output/'runtime-state.json',
            {'format':1,'protocol_case':'http','ready':True,'observed_hop_ports':[],'tls_cover_handshakes':0})
        fixture.write_new(self.output/'fixture-server.log',b'private-fixture-log-192.0.2.1\n')
        result=self.output/'fixture-verification.json'
        with mock.patch.object(fixture,'run',return_value=subprocess.CompletedProcess([],0,'active\n','')) as command,\
             mock.patch.object(fixture,'owned_namespace',side_effect=['17:42','17:43']):
            with self.assertRaisesRegex(RuntimeError,'fixture-namespace-changed'):fixture.verify_recipe(self.args,self.output)
        self.assertFalse(result.exists())
        self.assertEqual(command.call_args.args,('systemctl','is-active',fixture.ECHO_UNIT))
        with mock.patch.object(fixture,'run',return_value=subprocess.CompletedProcess([],0,'active\n','')),\
             mock.patch.object(fixture,'owned_namespace',return_value='17:42'),redirect_stdout(io.StringIO()) as public:
            fixture.verify_recipe(self.args,self.output)
        evidence=fixture.read_private_json(result)
        self.assertEqual(evidence['format'],1);self.assertIs(evidence['passed'],True)
        self.assertEqual(evidence['protocol_case'],'http')
        self.assertEqual(len(evidence['checks']),5);self.assertTrue(all(evidence['checks'].values()))
        self.assertNotIn('192.0.2.1',result.read_text()+public.getvalue())

    def test_hopping_verify_refuses_cumulative_ports_without_healthy_socket_proof(self):
        self.args.protocol_case='hysteria2-port-hopping';self.render()
        plan,descriptor=fixture.load_recipe(self.args,self.output)
        fixture.save_state(self.output/'upstream-fixture-state.json',
            {'format':2,'source_sha256':descriptor['source_sha256'],'nodes':plan['nodes'],
             'protocol_case':plan['case'],'units':{fixture.UNIT:True,fixture.ECHO_UNIT:True},'namespace_identity':'17:42'})
        fixture.save_state(self.output/'runtime-state.json',
            {'format':1,'protocol_case':plan['case'],'ready':True,
             'observed_hop_ports':[4400,4410],'tls_cover_handshakes':0})
        fixture.write_new(self.output/'fixture-server.log',b'server started\n')
        with mock.patch.object(fixture,'run',return_value=subprocess.CompletedProcess([],0,'active\n','')),\
             mock.patch.object(fixture,'owned_namespace',return_value='17:42'):
            with self.assertRaises((RuntimeError,FileNotFoundError)):
                fixture.verify_recipe(self.args,self.output)
        self.assertFalse((self.output/'fixture-verification.json').exists())

    def test_hopping_proof_rejects_window_and_bound_identity_tampering(self):
        self.args.protocol_case='hysteria-port-hopping';self.render()
        plan,descriptor=fixture.load_recipe(self.args,self.output)
        proof={'format':1,'protocol_case':plan['case'],'passed':True,
               'checks':{name:True for name in fixture.CONTINUITY_CHECKS},
               'evidence':{'window_seconds':20.1,'exchanges':12,'connections':1,
                           'observed_hop_ports':[4400,4410],'port_packet_deltas':{'4400':2,'4410':3}},
               'identity':{'source_sha256':descriptor['source_sha256'],
                           'recipe_sha256':fixture.file_digest(self.output/'protocol-recipe.json'),
                           'binding_sha256':'b'*64,'namespace_identity':'17:42'}}
        path=self.output/'hopping-continuity.json';fixture.write_new(path,fixture.json_bytes(proof))
        with mock.patch.object(fixture,'bound_policy_digest',return_value='b'*64):
            self.assertEqual(fixture.validate_hopping_proof(plan,descriptor,self.output,'17:42'),proof['evidence'])
            for section,key,value in [('evidence','window_seconds',19.9),('evidence','connections',2),
                    ('evidence','port_packet_deltas',{'4400':2}),('checks','no_reconnect',False),
                    ('identity','source_sha256','d'*64),('identity','recipe_sha256','d'*64),
                    ('identity','binding_sha256','d'*64),('identity','namespace_identity','17:43')]:
                changed=copy.deepcopy(proof);changed[section][key]=value;path.write_bytes(fixture.json_bytes(changed))
                with self.subTest(section=section,key=key),self.assertRaises(RuntimeError):
                    fixture.validate_hopping_proof(plan,descriptor,self.output,'17:42')

    def test_failed_continuity_probe_closes_only_its_managed_session(self):
        self.args.protocol_case='hysteria2-port-hopping';self.args.user='test-agent';self.render()
        plan,descriptor=fixture.load_recipe(self.args,self.output)
        fixture.save_state(self.output/'upstream-fixture-state.json',
            {'format':2,'source_sha256':descriptor['source_sha256'],'protocol_case':plan['case'],
             'units':{fixture.UNIT:True,fixture.ECHO_UNIT:True},'namespace_identity':'17:42'})
        fake_runtime=self.root/'runtime';(fake_runtime/'requests').mkdir(mode=0o700,parents=True)
        binding=SimpleNamespace(data={'source_sha256':descriptor['source_sha256']},policy=plan['policy'])
        session=SimpleNamespace(close=mock.Mock(),reader=SimpleNamespace(join=mock.Mock()),log=SimpleNamespace(close=mock.Mock()))
        def start(holder,name):holder.sessions.append(session);return session
        with mock.patch.object(host.Binding,'load',return_value=binding),\
             mock.patch.object(host,'RUNTIME',fake_runtime),mock.patch.object(host,'Session',side_effect=start),\
             mock.patch.object(host.Suite,'credentials'),mock.patch.object(fixture,'owned_namespace',return_value='17:42'),\
             mock.patch.object(fixture,'bound_policy_digest',return_value='b'*64),\
             mock.patch.object(fixture.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=1001,pw_gid=1001)),\
             mock.patch.object(fixture,'run',return_value=subprocess.CompletedProcess([],0,'','')) as command,\
             mock.patch.object(fixture,'hopping_window',side_effect=RuntimeError('injected reconnect refusal')):
            with self.assertRaisesRegex(RuntimeError,'injected reconnect refusal'):
                fixture.prove_hopping(self.args,self.output)
        session.close.assert_called_once_with(strict=False)
        session.log.close.assert_called_once()
        self.assertFalse((self.output/'hopping-continuity.json').exists())
        self.assertEqual(command.call_args_list,[mock.call('systemctl','list-units','--all','--plain','--no-legend','dev-session-*.service'),
                                                mock.call(host.DEV,'check')])


class NativeCLITests(unittest.TestCase):
    def test_new_commands_and_legacy_setup_dispatch(self):
        for action,protocol,target in [('render',True,'render'),('setup',True,'setup'),
                                       ('verify',True,'verify_recipe'),('serve',True,'serve_recipe'),
                                       ('prove-hopping',True,'prove_hopping'),
                                       ('setup',False,'setup')]:
            argv=['fixture',action,'--engine','/root/worker','--config','/root/network.json',
                  '--output','/root/fixture']
            if protocol:argv+=['--protocol-case','ssh','--python','/root/venv/bin/python']
            if action=='prove-hopping':argv+=['--user','test-agent']
            with self.subTest(action=action,protocol=protocol),\
                 mock.patch.object(fixture.sys,'argv',argv),mock.patch.object(fixture.os,'geteuid',return_value=0),\
                 mock.patch.object(fixture.os,'umask'),mock.patch.object(fixture,'output_directory',return_value=Path('/root/fixture')),\
                 mock.patch.object(fixture,target) as handler:
                fixture.main()
            self.assertEqual(handler.call_count,1)
            args,output=handler.call_args.args
            self.assertEqual(args.protocol_case,'ssh' if protocol else None)
            self.assertEqual(args.python,'/root/venv/bin/python' if protocol else None)


class NativeHelperTests(unittest.TestCase):
    def test_relay_counts_only_actual_frontend_traffic(self):
        class Datagram:
            def __init__(self):self.bound=None;self.sent=[];self.closed=False
            def bind(self,address):self.bound=address
            def connect(self,address):self.connected=address
            def getsockname(self):return self.bound
            def recvfrom(self,size):return b'frontend-packet',('198.19.254.10',12345)
            def recv(self,size):return b'backend-reply'
            def send(self,value):self.sent.append(value)
            def sendto(self,value,address):self.sent.append((value,address))
            def close(self):self.closed=True
        sockets=[Datagram() for _ in range(3)]
        inert=SimpleNamespace(start=lambda:None,join=lambda **kwargs:None)
        with mock.patch.object(fixture.socket,'socket',side_effect=sockets),\
             mock.patch.object(fixture.threading,'Thread',return_value=inert):
            with fixture.NativeMultiportRelay('192.0.2.1',[4400,4410],'127.0.0.1',443) as relay:
                self.assertEqual(relay.observed_ports,[])
                events=[[sockets[0]],[sockets[2]],[sockets[1]],[sockets[2]]]
                def readable(*args):
                    if events:return events.pop(0),[],[]
                    relay.stop.set();return [],[],[]
                with mock.patch.object(fixture.select,'select',side_effect=readable):relay._serve()
                self.assertEqual(relay.observed_ports,[4400,4410])
                self.assertEqual(relay.received_by_port,{'4400':1,'4410':1})
                self.assertEqual(sockets[2].sent,[b'frontend-packet',b'frontend-packet'])
                self.assertTrue(all(s.sent==[(b'backend-reply',('198.19.254.10',12345))] for s in sockets[:2]))
        self.assertTrue(all(s.closed for s in sockets))

    def test_cover_disables_tls13_session_tickets(self):
        context=SimpleNamespace(num_tickets=2)
        cover=SimpleNamespace(context=context)
        with mock.patch.object(runtime,'TLSCoverServer',return_value=cover):
            result=fixture.native_cover({'port':9443,'certificate':'/test/cert','key':'/test/key'})
        self.assertIs(result,cover)
        self.assertEqual(result.context.num_tickets,0)


class HoppingContinuityTests(unittest.TestCase):
    def plan(self):
        return fixture.native_recipe('hysteria2-port-hopping',Path('/root/fake'),'TEST CERT')

    def observation(self,sequence,counts):
        return {'format':1,'protocol_case':'hysteria2-port-hopping','ready':True,
                'sequence':sequence,'received_by_port':{str(port):counts.get(port,0) for port in fixture.HOP_PORTS}}

    def test_rotation_requires_new_packets_at_two_ports_inside_window(self):
        before=self.observation(10,{4400:8,4410:5})
        # Both ports were previously seen, but only one receives window traffic.
        after=self.observation(20,{4400:9,4410:5})
        with self.assertRaises(RuntimeError):fixture.hopping_delta(self.plan(),before,after)
        after['received_by_port']['4410']=6
        self.assertEqual(fixture.hopping_delta(self.plan(),before,after),{'4400':1,'4410':1})
        for changes in ({'sequence':10},{'sequence':1},{'received_by_port':{'4400':0}}):
            bad=copy.deepcopy(after);bad.update(changes)
            with self.subTest(changes=changes),self.assertRaises(RuntimeError):
                fixture.hopping_delta(self.plan(),before,bad)

    def execute_client(self,behavior='normal'):
        class Stream:
            def fileno(self):return 41
            def getpeername(self):return ('1.1.1.1',443)
        class Response:
            status=200
            will_close=behavior=='close'
            def read(self,size):return b'ip=203.0.113.7\n'
            def getheader(self,name,default=''):return 'close' if behavior=='close' else default
        class Connection:
            def __init__(self,*args,**kwargs):self.sock=None;self.requests=0;self.auto_open=1
            def connect(self):self.sock=Stream()
            def request(self,*args,**kwargs):
                self.requests+=1
                if behavior=='reconnect' and self.requests>1:self.connect()
            def getresponse(self):return Response()
            def close(self):self.sock=None
        scope={'state':{}}
        with mock.patch.object(http.client,'HTTPSConnection',Connection),\
             mock.patch.object(fixture.os,'fstat',return_value=SimpleNamespace(st_ino=1234)):
            exec(fixture.CONTINUITY_CONNECT,scope)
            exec(fixture.CONTINUITY_EXCHANGE,scope)
            if behavior=='normal':
                original=scope['state']['hop']['socket']
                exec(fixture.CONTINUITY_EXCHANGE,scope)
                self.assertIs(scope['state']['hop']['connection'].sock,original)
                self.assertEqual(scope['result']['connect_calls'],1)
                self.assertEqual(scope['result']['exchanges'],2)
                self.assertEqual(scope['state']['hop']['connection'].auto_open,0)
                self.assertNotIn('203.0.113.7',json.dumps(scope['result']))
            else:exec(fixture.CONTINUITY_EXCHANGE,scope)

    def test_continuity_client_retains_same_socket_and_disables_auto_reopen(self):
        self.execute_client()

    def test_continuity_client_refuses_reconnect_or_connection_close(self):
        for behavior in ('reconnect','close'):
            with self.subTest(behavior=behavior),self.assertRaises((RuntimeError,AssertionError)):
                self.execute_client(behavior)

    def test_counter_baseline_follows_first_exchange_and_final_exchange_follows_window(self):
        events=[];clock=[100.0];samples=[self.observation(10,{4400:8}),self.observation(50,{4400:9,4410:1})]
        class Session:
            exchanges=0
            def value(self,code,**kwargs):
                if code==fixture.CONTINUITY_CONNECT:events.append('connect');return True
                self.exchanges+=1;events.append('exchange')
                return {'same_socket':True,'connect_calls':1,'exchanges':self.exchanges}
        def observation():events.append('observe');return samples.pop(0)
        def sleep(seconds):clock[0]+=seconds
        result=fixture.hopping_window(self.plan(),Session(),observation,lambda:clock[0],sleep)
        self.assertEqual(events[:3],['connect','exchange','observe'])
        self.assertEqual(events[-2:],['observe','exchange'])
        self.assertGreaterEqual(result['window_seconds'],20)
        self.assertGreaterEqual(result['exchanges'],11)
        self.assertEqual(result['observed_hop_ports'],[4400,4410])


if __name__=='__main__':unittest.main()
