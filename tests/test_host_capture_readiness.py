"""Offline collector readiness regressions: no subprocesses or network sockets."""
import contextlib
from pathlib import Path
import signal
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

import host_acceptance as host


PCAP_HEADER = struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 512, 1)


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class Collector:
    def __init__(self, path, log):
        self.path, self.log = path, log
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
        self.returncode = 0
        self.log.write('{} packets captured\n{} packets received by filter\n0 packets dropped by kernel\n'
                       .format(self.packets, self.packets))
        self.log.flush()

    def wait(self, timeout):
        return self.returncode


class CaptureReadinessTests(unittest.TestCase):
    @contextlib.contextmanager
    def runner(self, write_canary, *, initial_file=True):
        with tempfile.TemporaryDirectory() as directory:
            suite = host.Suite.__new__(host.Suite)
            suite.output, suite.interface = Path(directory), 'test-interface'
            suite.udp_echo, suite.captures = ('192.0.2.254', 40123), []
            clock = Clock()
            state = {'sent': [], 'collectors': []}

            def popen(argv, **options):
                self.assertEqual(argv[0], 'tcpdump')
                path = Path(argv[argv.index('-w') + 1])
                collector = Collector(path, options['stderr'])
                state['collectors'].append(collector)
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
            self.assertEqual(state['collectors'][-1].signals, [signal.SIGINT])
            self.assertLess(clock.now, 3.5)


if __name__ == '__main__':
    unittest.main()
