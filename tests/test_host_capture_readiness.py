"""Offline collector readiness regressions: no subprocesses or network sockets."""
import contextlib
from pathlib import Path
import signal
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import host_acceptance as host
import host_lifecycle as lifecycle


PCAP_HEADER = struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 512, 1)


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class Collector:
    def __init__(self, path, log, clock, plan=None):
        self.path, self.log = path, log
        self.clock, self.plan = clock, plan or {}
        self.returncode = None
        self.packets = 0
        self.signals = []

    def poll(self):
        return self.returncode

    def append(self, payload):
        # A real Ethernet/IPv4/UDP savefile record, written without opening a socket.
        ethernet = b'\0' * 12 + b'\x08\x00'
        udp = struct.pack('!HHHH', 21000, 44443, 8 + len(payload), 0) + payload
        ipv4 = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                           b'\xc0\x00\x02\xfe', b'\x09\x09\x09\x09')
        packet = ethernet + ipv4 + udp
        if not self.path.exists():
            self.path.write_bytes(PCAP_HEADER)
        with self.path.open('ab') as stream:
            stream.write(struct.pack('<IIII', 1 + self.packets, 0, len(packet), len(packet)) + packet)
        self.packets += 1

    def send_signal(self, value):
        self.signals.append(value)
        if value == signal.SIGUSR1:
            self.clock.now += self.plan.get('usr1_delay', 0)
            if self.plan.get('usr1') == 'missing': return
            message = ('tcpdump: {} packets captured, {} packets received by filter, '
                       '{} packets dropped by kernel\n').format(
                           self.packets, self.packets + self.plan.get('received_extra', 0),
                           self.plan.get('dropped', 0))
            self.log.write(message[:-1] if self.plan.get('usr1') == 'partial' else message)
            self.log.flush()
            return
        if value != signal.SIGINT:
            raise AssertionError('Unexpected collector signal')
        self.returncode = 0
        if self.plan.get('final') == 'missing': return
        message = '{} packets captured\n{} packets received by filter\n{} packets dropped by kernel\n'.format(
            self.packets, self.packets + self.plan.get('final_received_extra', self.plan.get('received_extra', 0)),
            self.plan.get('final_dropped', self.plan.get('dropped', 0)))
        if self.plan.get('final') == 'partial-interface':
            message += '1 packet dropped by interface'
        elif self.plan.get('final_interface_dropped'):
            message += '{} packets dropped by interface\n'.format(self.plan['final_interface_dropped'])
        self.log.write(message[:-1] if self.plan.get('final') == 'partial' else message)
        self.log.flush()

    def wait(self, timeout):
        if self.returncode is None: raise subprocess.TimeoutExpired('fake-tcpdump', timeout)
        return self.returncode

    def kill(self):
        self.returncode = -signal.SIGKILL


class CaptureReadinessTests(unittest.TestCase):
    @contextlib.contextmanager
    def runner(self, write_canary, *, initial_file=True, plans=(), suite_type=host.Suite):
        with tempfile.TemporaryDirectory() as directory:
            suite = suite_type.__new__(suite_type)
            suite.output, suite.interface = Path(directory), 'test-interface'
            suite.udp_echo, suite.captures = ('192.0.2.254', 40123), []
            clock = Clock()
            state = {'sent': [], 'collectors': [], 'events': []}

            def popen(argv, **options):
                self.assertEqual(argv[0], 'tcpdump')
                path = Path(argv[argv.index('-w') + 1])
                if state['collectors'] and state['collectors'][-1].path == path:
                    self.assertIsNotNone(state['collectors'][-1].returncode, 'Replaced a live collector')
                    self.assertTrue(state['collectors'][-1].log.closed, 'Replaced an open collector log')
                index = len(state['collectors'])
                plan = plans[index] if index < len(plans) else {}
                collector = Collector(path, options['stderr'], clock, plan)
                state['collectors'].append(collector)
                state['events'].append(('created', path.name))
                if plan.get('old_final_stats'):
                    collector.log.write('0 packets captured\n0 packets received by filter\n0 packets dropped by kernel\n')
                    collector.log.flush()
                if plan.get('old_usr1_stats'):
                    collector.log.write('tcpdump: 0 packets captured, 0 packets received by filter, 0 packets dropped by kernel\n')
                    collector.log.flush()
                if initial_file:
                    path.write_bytes(PCAP_HEADER)
                return collector

            def send(payload):
                state['sent'].append(payload)
                write_canary(state, payload)

            suite.physical_canary = send
            with mock.patch.object(host.subprocess, 'Popen', side_effect=popen), \
                    mock.patch.object(host.time, 'monotonic', side_effect=clock.monotonic), \
                    mock.patch.object(host.time, 'sleep', side_effect=clock.sleep):
                try:
                    yield suite, clock, state
                finally:
                    for collector in state['collectors']:
                        if not collector.log.closed:
                            collector.log.close()

    def test_waits_for_real_savefile_marker_when_the_first_canary_is_missed(self):
        def write(state, payload):
            if len(state['sent']) >= 2:
                state['collectors'][-1].append(payload)

        with self.runner(write, initial_file=False) as (suite, clock, state):
            path = suite.physical_capture('delayed')
            self.assertGreaterEqual(len(state['sent']), 2)
            self.assertEqual(len(set(state['sent'])), 1)
            self.assertIn(state['sent'][0], path.read_bytes())
            self.assertTrue(state['sent'][0].startswith(b'D8-START-'))
            self.assertLess(clock.now, 3.5)

    def test_absent_or_header_only_savefile_never_admits_a_workload(self):
        for exists in (False, True):
            with self.subTest(file_exists=exists), self.runner(lambda state, payload: None, initial_file=exists) as (suite, clock, state):
                with self.assertRaisesRegex(AssertionError, 'initial.*canary|canary.*initial'):
                    suite.physical_capture('never-ready')
                self.assertGreaterEqual(clock.now, 3)
                self.assertLess(clock.now, 3.5)
                self.assertGreater(len(state['sent']), 1)

        def late_marker(state, payload):
            clock.now += 4
            state['collectors'][-1].append(payload)

        with self.runner(late_marker) as (suite, clock, state):
            with self.assertRaisesRegex(AssertionError, 'initial.*canary|canary.*initial'):
                suite.physical_capture('late-marker')
            self.assertEqual(len(state['sent']), 1)

    def test_collector_exit_during_readiness_is_rejected_even_with_a_marker(self):
        for record_marker in (False, True):
            def write(state, payload):
                collector = state['collectors'][-1]
                if record_marker:
                    collector.append(payload)
                collector.returncode = 23

            with self.subTest(record_marker=record_marker), self.runner(write) as (suite, clock, state):
                with self.assertRaisesRegex(AssertionError, 'collector|capture'):
                    suite.physical_capture('collector-exit')
                self.assertEqual(len(state['sent']), 1)
                self.assertLess(clock.now, 1)

    def test_each_capture_has_a_new_initial_marker(self):
        with self.runner(lambda state, payload: state['collectors'][-1].append(payload)) as (suite, clock, state):
            first = suite.physical_capture('first')
            second = suite.physical_capture('second')
            self.assertEqual(len(state['sent']), 2)
            self.assertNotEqual(state['sent'][0], state['sent'][1])
            self.assertNotIn(state['sent'][0], second.read_bytes())
            self.assertNotIn(state['sent'][1], first.read_bytes())

    def test_final_readback_requires_this_start_both_ends_and_zero_direct(self):
        for mutation in ('none', 'different-start', 'missing-end', 'one-control', 'direct-workload'):
            with self.subTest(mutation=mutation), self.runner(lambda state, payload: state['collectors'][-1].append(payload)) as (suite, clock, state):
                path = suite.physical_capture('readback')
                collector = state['collectors'][-1]
                if mutation == 'different-start':
                    path.write_bytes(PCAP_HEADER)
                    collector.append(b'D8-START-' + b'0' * 32)
                if mutation == 'missing-end':
                    collector.append(state['sent'][0])
                elif mutation != 'one-control':
                    collector.append(b'D8-END-' + b'1' * 32)

                def command(*argv, **options):
                    if argv[-1] == 'src port 21000':
                        count = 1 if mutation == 'one-control' else 2
                        output = 'root canary\n' * count
                    elif argv[-1] == 'src portrange 21001-21199':
                        output = 'direct workload\n' if mutation == 'direct-workload' else ''
                    else:
                        raise AssertionError('Unexpected readback command')
                    return subprocess.CompletedProcess(argv, 0, output, '')

                with mock.patch.object(host, 'command', side_effect=command):
                    if mutation == 'none':
                        self.assertEqual(suite.verify_physical_capture(path),
                                         {'positive_control_packets': 2, 'direct_workload_packets': 0})
                    else:
                        with self.assertRaises(AssertionError):
                            suite.verify_physical_capture(path)

    def test_repeated_initial_packets_cannot_replace_the_trailing_canary(self):
        def write(state, payload):
            if not payload.startswith(b'D8-END-'):
                state['collectors'][-1].append(payload)
                state['collectors'][-1].append(payload)

        with self.runner(write) as (suite, clock, state):
            suite.physical_capture('missing-tail')
            with self.assertRaisesRegex(AssertionError, 'trailing canary missing'):
                suite.stop_captures()
            self.assertEqual(state['collectors'][-1].signals, [signal.SIGUSR1, signal.SIGINT])
            self.assertLess(clock.now, 3.5)

    def test_clean_preflight_observes_new_usr1_statistics_before_workload(self):
        with self.runner(lambda state, payload: state['collectors'][-1].append(payload)) as (suite, clock, state):
            path = suite.physical_capture('clean-preflight')
            collector = state['collectors'][0]
            self.assertEqual(collector.signals, [signal.SIGUSR1])
            self.assertIsNone(collector.returncode)
            self.assertEqual(path, suite.output / 'clean-preflight.pcap')
            suite.stop_captures()
            self.assertEqual(collector.signals, [signal.SIGUSR1, signal.SIGINT])
            self.assertEqual(collector.returncode, 0)
            self.assertTrue(collector.log.closed)

    def test_dirty_preflight_is_stopped_preserved_and_replaced_before_workload(self):
        with self.runner(lambda state, payload: state['collectors'][-1].append(payload),
                         plans=({'received_extra': 3}, {})) as (suite, clock, state):
            path = suite.physical_capture('replace-preflight')
            self.assertEqual(len(state['collectors']), 2)
            rejected, chosen = state['collectors']
            self.assertEqual(rejected.signals, [signal.SIGUSR1, signal.SIGINT])
            self.assertEqual(rejected.returncode, 0)
            self.assertTrue(rejected.log.closed)
            self.assertEqual(chosen.signals, [signal.SIGUSR1])
            self.assertEqual(path, suite.output / 'replace-preflight.pcap')
            self.assertNotEqual(state['sent'][0], state['sent'][1])
            rejected_pcaps = [item for item in suite.output.glob('*.pcap') if item != path]
            self.assertEqual(len(rejected_pcaps), 1)
            self.assertIn(state['sent'][0], rejected_pcaps[0].read_bytes())
            self.assertNotIn(state['sent'][0], path.read_bytes())
            rejected_logs = [item for item in suite.output.glob('*tcpdump.log') if item != Path(chosen.log.name)]
            self.assertEqual(len(rejected_logs), 1)
            self.assertIn('4 packets received by filter', rejected_logs[0].read_text())
            self.assertTrue(suite.captures[0]['stopped'])
            self.assertEqual(suite.captures[0]['path'], rejected_pcaps[0])
            suite.stop_captures()
            self.assertEqual(chosen.signals, [signal.SIGUSR1, signal.SIGINT])

    def test_preflight_exhaustion_is_bounded_and_preserves_each_failed_candidate(self):
        for plan in ({'received_extra': 3}, {'dropped': 1}):
            with self.subTest(plan=plan), self.runner(
                    lambda state, payload: state['collectors'][-1].append(payload), plans=(plan,) * 3) as (suite, clock, state):
                with self.assertRaisesRegex(AssertionError, 'preflight|statistics|capture'):
                    suite.physical_capture('exhausted')
                self.assertEqual(len(state['collectors']), 3)
                self.assertLessEqual(clock.now, 10)
                self.assertEqual(len(list(suite.output.glob('*.pcap'))), 3)
                self.assertEqual(len(list(suite.output.glob('*tcpdump.log'))), 3)
                self.assertFalse((suite.output / 'exhausted.pcap').exists())
                self.assertTrue(all(c.returncode is not None and c.log.closed for c in state['collectors']))

    def test_missing_partial_late_or_stale_usr1_statistics_never_admit(self):
        for plan in ({'usr1': 'missing'}, {'usr1': 'partial'}, {'usr1_delay': 4},
                     {'usr1': 'missing', 'old_usr1_stats': True}):
            with self.subTest(plan=plan), self.runner(
                    lambda state, payload: state['collectors'][-1].append(payload), plans=(plan,) * 3) as (suite, clock, state):
                with self.assertRaisesRegex(AssertionError, 'preflight|statistics|snapshot|deadline'):
                    suite.physical_capture('no-new-statistics')
                self.assertLessEqual(len(state['collectors']), 3)
                self.assertLessEqual(clock.now, 10)
                self.assertTrue(all(c.returncode is not None and c.log.closed for c in state['collectors']))

    def test_preflight_candidates_share_one_overall_deadline(self):
        def write(state, payload):
            clock.now += 2.3
            state['collectors'][-1].append(payload)
        with self.runner(write, plans=({'received_extra': 3, 'usr1_delay': 2.5},) * 3) as (suite, clock, state):
            with self.assertRaisesRegex(AssertionError, 'deadline'):
                suite.physical_capture('overall-deadline')
            self.assertEqual(len(state['collectors']), 2)
            self.assertLessEqual(clock.now, 10)
            self.assertTrue(all(c.returncode == 0 and c.log.closed for c in state['collectors']))

    def test_final_stats_must_be_fresh_and_complete_and_cannot_borrow_clean_preflight(self):
        for mode in ('missing', 'partial', 'partial-interface'):
            with self.subTest(mode=mode), self.runner(
                    lambda state, payload: state['collectors'][-1].append(payload),
                    plans=({'final': mode, 'old_final_stats': True},)) as (suite, clock, state):
                suite.physical_capture('fresh-final')
                with self.assertRaisesRegex(AssertionError, 'final.*stat|stat.*final'):
                    suite.stop_captures()
                self.assertEqual(len(state['collectors']), 1)
                self.assertTrue(state['collectors'][0].log.closed)

    def test_new_final_mismatch_or_drop_still_fails_without_restarting_the_collector(self):
        for plan in ({'final_received_extra': 3}, {'final_dropped': 1}, {'final_interface_dropped': 1}):
            with self.subTest(plan=plan), self.runner(
                    lambda state, payload: state['collectors'][-1].append(payload), plans=(plan,)) as (suite, clock, state):
                suite.physical_capture('late-loss')
                with self.assertRaises(AssertionError): suite.stop_captures()
                self.assertEqual(len(state['collectors']), 1)
                self.assertEqual(state['collectors'][0].signals, [signal.SIGUSR1, signal.SIGINT])

    def test_lifecycle_wrapper_kill_consumer_waits_for_clean_preflight_and_keeps_final_gate(self):
        for final_extra in (0, 3):
            with self.subTest(final_extra=final_extra), self.runner(
                    lambda state, payload: state['collectors'][-1].append(payload),
                    plans=({'received_extra': 3}, {'final_received_extra': final_extra}),
                    suite_type=lifecycle.Lifecycle) as (suite, clock, state):
                results = {}
                suite.namespace_fault = 'none'
                suite.descendants = mock.Mock(return_value=[])
                suite.credentials = mock.Mock()
                suite.reclaimed = mock.Mock()
                suite.gone = mock.Mock()
                suite.assert_rules = mock.Mock()
                def workload(session):
                    self.assertEqual(len(state['collectors']), 2)
                    self.assertEqual(state['collectors'][-1].signals, [signal.SIGUSR1])
                    state['events'].append(('workload', session.sid))
                suite.forced_egress = workload
                suite.record = lambda name, check: results.update({name: check()}) if name == 'wrapper_SIGKILL_documented_limit' else None
                session = SimpleNamespace(sid='a' * 32, p=mock.Mock(), close=mock.Mock())
                def command(*argv, **options):
                    if argv[:2] == ('systemctl', 'is-active'): output = 'active\n'
                    elif argv[:2] == (host.DEV, 'close'): output = ''
                    elif argv[0] == 'tcpdump' and argv[-1] == 'src port 21000': output = 'canary\ncanary\n'
                    elif argv[0] == 'tcpdump' and argv[-1] == 'src portrange 21001-21199': output = ''
                    else: raise AssertionError('Unexpected host command')
                    return subprocess.CompletedProcess(argv, 0, output, '')
                with mock.patch.object(lifecycle, 'Session', return_value=session), \
                        mock.patch.object(lifecycle, 'command', side_effect=command), \
                        mock.patch.object(host, 'command', side_effect=command):
                    if final_extra:
                        with self.assertRaises(AssertionError): suite.run_lifecycle()
                    else:
                        suite.run_lifecycle()
                        self.assertEqual(results['wrapper_SIGKILL_documented_limit']['direct_workload_packets'], 0)
                        self.assertTrue(results['wrapper_SIGKILL_documented_limit']['explicit_close_reclaimed'])
                self.assertEqual(len([event for event in state['events'] if event[0] == 'workload']), 1)
                self.assertEqual(len(state['collectors']), 2)


if __name__ == '__main__':
    unittest.main()
