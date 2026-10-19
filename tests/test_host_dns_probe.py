"""Deterministic DNS wire/client tests; no network, privileges or live sessions."""
import hashlib
import json
from pathlib import Path
import socket
import struct
import tempfile
import time
import unittest
from unittest import mock

import host_acceptance as host


TARGET = '192.0.2.53'
NAME = 'd8-controlled.example.invalid'


def reply(query, flags=0x8180, answer=b'', authority=b''):
    return (struct.pack('!6H', 0x4d38, flags, 1, bool(answer), bool(authority), 0)
            + query[12:] + answer + authority)


def rr(kind=1, data=b'\xc0\x00\x02\x03', size=None):
    return b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 60, len(data) if size is None else size) + data


class Clock:
    def __init__(self):
        self.now = 100.0

    def monotonic(self):
        return self.now


class WireSocket:
    """A byte boundary, including packet/stream timing and identity changes."""
    def __init__(self, clock, events=None, response=None, connect_error=False, send_error=False,
                 connect_delay=0, tcp=False):
        self.clock = clock
        self.events = list(events or [('reply', 0.01)])
        self.response = response or (lambda query: reply(query))
        self.connect_error, self.send_error = connect_error, send_error
        self.connect_delay, self.tcp = connect_delay, tcp
        self.peer, self.port, self.fd = None, 32123, 77
        self.sent, self.timeouts, self.connects = [], [], []
        self.receives, self.closed = 0, False
        self.timeout = None
        self.stream = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def settimeout(self, value):
        self.timeout = value
        self.timeouts.append(value)

    def connect(self, peer):
        self.connects.append(peer)
        self.clock.now += self.connect_delay
        if self.connect_error:
            raise socket.timeout('private-fixture-connect-error')
        self.peer = peer

    def getpeername(self):
        return self.peer

    def getsockname(self):
        return ('192.0.2.50', self.port)

    def fileno(self):
        return self.fd

    def send(self, data):
        if self.send_error:
            raise socket.timeout('private-fixture-send-error')
        self.sent.append(data)
        return len(data)

    def sendall(self, data):
        self.send(data)
        answer = self.response(data[2:])
        self.stream = struct.pack('!H', len(answer)) + answer

    def recv(self, limit):
        self.receives += 1
        if not self.events:
            raise AssertionError('DNS client read beyond the scripted wire exchange')
        event = self.events.pop(0)
        kind, delay = event[:2]
        self.clock.now += self.timeout if delay is None else delay
        if kind == 'timeout':
            if len(event) > 2:
                event[2](self)
            raise socket.timeout('private-fixture-receive-timeout')
        if kind == 'error':
            raise OSError('private-fixture-receive-error')
        if kind == 'eof':
            return b''
        if kind == 'chunk':
            size = min(limit, event[2])
            data, self.stream = self.stream[:size], self.stream[size:]
            return data
        if self.tcp:
            data, self.stream = self.stream[:limit], self.stream[limit:]
            return data
        return self.response(self.sent[-1])


class InProcessSession:
    """Execute the actual workload code with only its socket/clock replaced."""
    def __init__(self, wire):
        self.wire = wire
        self.rpc_timeouts, self.created = [], []

    def call(self, code, timeout=20):
        self.rpc_timeouts.append(timeout)
        scope = {'state': {}}

        def create(family, kind):
            self.created.append((family, kind))
            return self.wire

        with mock.patch.object(socket, 'socket', create), mock.patch.object(time, 'monotonic', self.wire.clock.monotonic):
            try:
                exec(code, scope)
                return {'ok': True, 'result': scope.get('result')}
            except Exception as error:
                return {'ok': False, 'error': type(error).__name__ + ': ' + str(error)}

    def value(self, code, timeout=20):
        response = self.call(code, timeout)
        assert response['ok'], response
        return response['result']


class DNSProbeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.suite = object.__new__(host.Suite)
        self.suite.output = Path(self.directory.name)
        self.clock = Clock()

    def invoke(self, **kwargs):
        wire = WireSocket(self.clock, **kwargs)
        session = InProcessSession(wire)
        failure = None
        result = None
        try:
            result = self.suite.dns(session, TARGET, kwargs.get('tcp', False), NAME)
        except AssertionError as error:
            failure = str(error)
        path = self.suite.output / 'dns-attempts.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        self.assertEqual(len(rows), 1, 'complete DNS report must be persisted before success/failure escapes')
        report = rows[0]
        self.assertEqual(path.stat().st_mode & 0o077, 0)
        self.assertNotIn('private-fixture', json.dumps(report))
        self.assertNotIn(TARGET, json.dumps(report))
        self.assertNotIn(NAME, json.dumps(report))
        self.assertEqual(report['format'], 1)
        self.assertEqual(report['transport'], 'tcp' if kwargs.get('tcp') else 'udp')
        self.assertEqual(report['target_sha256'], hashlib.sha256((TARGET + ':53').encode('utf-8')).hexdigest())
        self.assertRegex(report['query_sha256'], r'^[0-9a-f]{64}$')
        self.assertTrue(all(value > 10 for value in session.rpc_timeouts))
        if result is not None:
            self.assertEqual(result, report)
        return report, wire, session, failure

    def test_first_response_uses_one_transmission_and_saves_full_report(self):
        report, wire, session, failure = self.invoke()
        self.assertIsNone(failure)
        self.assertTrue(report['ok'])
        self.assertEqual(report['transmissions'], 1)
        self.assertEqual(report['response'], {'rcode': 0, 'answers': 0})
        self.assertEqual([a['outcome'] for a in report['attempts']], ['response'])
        self.assertTrue(all(report['checks'].values()))
        self.assertEqual(report['query_sha256'], hashlib.sha256(wire.sent[0]).hexdigest())
        self.assertEqual(len(session.created), 1)

    def test_retransmission_is_observed_at_the_wire_boundary(self):
        wire = WireSocket(self.clock, events=[('timeout', None), ('reply', .02)])
        session = InProcessSession(wire)
        try:
            self.suite.dns(session, TARGET, False, NAME)
        except AssertionError:
            pass
        self.assertEqual(len(wire.sent), 2, 'a first receive timeout must permit exactly one same-query resend')
        self.assertEqual(wire.sent[0], wire.sent[1])

    def test_reply_with_a_different_question_is_actually_rejected(self):
        wire = WireSocket(self.clock, response=lambda q: reply(q)[:-4] + b'\x00\x1c\x00\x01')
        with self.assertRaises(AssertionError, msg='matching TID alone is not DNS reply validation'):
            self.suite.dns(InProcessSession(wire), TARGET, False, NAME)

    def test_first_receive_timeout_retransmits_same_wire_on_same_socket(self):
        report, wire, session, failure = self.invoke(events=[('timeout', None), ('reply', 0.02)])
        self.assertIsNone(failure)
        self.assertTrue(report['ok'])
        self.assertEqual(report['transmissions'], 2)
        self.assertEqual([a['outcome'] for a in report['attempts']], ['timeout', 'response'])
        self.assertEqual(report['attempts'][0]['error'], 'receive_timeout')
        self.assertAlmostEqual(report['attempts'][0]['elapsed_seconds'], 5)
        self.assertAlmostEqual(report['elapsed_seconds'], 5.02)
        self.assertEqual(wire.sent[0], wire.sent[1])
        self.assertEqual(len(session.created), 1)
        self.assertEqual(wire.connects, [(TARGET, 53)])
        self.assertTrue(all(report['checks'].values()))

    def test_permanent_timeout_preserves_both_attempts_before_assert(self):
        report, wire, _, failure = self.invoke(events=[('timeout', None), ('timeout', None)])
        self.assertIsNotNone(failure)
        self.assertFalse(report['ok'])
        self.assertEqual(report['error'], 'receive_timeout')
        self.assertEqual(report['transmissions'], 2)
        self.assertEqual([a['outcome'] for a in report['attempts']], ['timeout', 'timeout'])
        self.assertAlmostEqual(report['elapsed_seconds'], 10)
        self.assertEqual(len(wire.sent), 2)
        self.assertFalse(report['checks']['reply_validated'])

    def test_malformed_or_mismatched_reply_fails_without_retransmission(self):
        mutations = {
            'invalid_header': lambda q: b'short',
            'invalid_tid': lambda q: b'\x00\x01' + reply(q)[2:],
            'invalid_question': lambda q: reply(q)[:-4] + b'\x00\x1c\x00\x01',
            'truncated_response': lambda q: reply(q, flags=0x8380),
            'invalid_rcode': lambda q: reply(q, flags=0x8182),
            'invalid_name': lambda q: reply(q)[:12] + b'\xc0\x0c\x00\x01\x00\x01',
            'invalid_rr': lambda q: reply(q, answer=rr(data=b'abc', size=4)),
            'trailing_data': lambda q: reply(q) + b'padding',
        }
        for expected, response in mutations.items():
            with self.subTest(error=expected):
                (self.suite.output / 'dns-attempts.jsonl').unlink(missing_ok=True)
                report, wire, _, failure = self.invoke(response=response)
                self.assertIsNotNone(failure)
                self.assertEqual(report['error'], expected)
                self.assertEqual(report['transmissions'], 1)
                self.assertEqual(len(wire.sent), 1)
                self.assertEqual(wire.receives, 1)

    def test_invalid_fixed_width_rr_is_not_accepted(self):
        report, _, _, failure = self.invoke(response=lambda q: reply(q, answer=rr(data=b'abc')))
        self.assertIsNotNone(failure)
        self.assertEqual(report['error'], 'invalid_rr')

    def test_nxdomain_and_compressed_soa_authority_are_validated(self):
        data = b'\xc0\x0c\xc0\x0c' + struct.pack('!5I', 1, 2, 3, 4, 5)
        report, _, _, failure = self.invoke(response=lambda q: reply(q, flags=0x8183, authority=rr(kind=6, data=data)))
        self.assertIsNone(failure)
        self.assertEqual(report['response'], {'rcode': 3, 'answers': 0})
        self.assertTrue(report['checks']['reply_validated'])

    def test_connect_and_send_timeouts_are_not_receive_retries(self):
        for option, expected in [('connect_error', 'connect_error'), ('send_error', 'send_error')]:
            with self.subTest(phase=option):
                (self.suite.output / 'dns-attempts.jsonl').unlink(missing_ok=True)
                report, wire, session, failure = self.invoke(**{option: True})
                self.assertIsNotNone(failure)
                self.assertEqual(report['error'], expected)
                self.assertEqual(report['transmissions'], 0)
                self.assertEqual(len(report['attempts']), 1)
                self.assertEqual(len(session.created), 1)
                self.assertEqual(wire.receives, 0)

    def test_non_timeout_receive_error_is_not_retried(self):
        report, wire, _, failure = self.invoke(events=[('error', 0)])
        self.assertIsNotNone(failure)
        self.assertEqual(report['error'], 'receive_error')
        self.assertEqual(len(wire.sent), 1)

    def test_changed_socket_peer_or_source_port_cannot_start_second_transmission(self):
        for attribute, value, check in [('fd', 78, 'same_socket'), ('peer', ('192.0.2.54', 53), 'same_peer'),
                                        ('port', 32124, 'same_source_port')]:
            with self.subTest(identity=attribute):
                (self.suite.output / 'dns-attempts.jsonl').unlink(missing_ok=True)
                mutate = lambda wire, attr=attribute, new=value: setattr(wire, attr, new)
                report, wire, _, failure = self.invoke(events=[('timeout', None, mutate)])
                self.assertIsNotNone(failure)
                self.assertEqual(report['error'], 'identity_changed')
                self.assertEqual(len(wire.sent), 1)
                self.assertFalse(report['checks'][check])

    def test_late_response_does_not_pass_receive_deadline(self):
        report, wire, _, failure = self.invoke(events=[('reply', 5.001)])
        self.assertIsNotNone(failure)
        self.assertEqual(report['error'], 'deadline_exceeded')
        self.assertFalse(report['checks']['reply_validated'])
        self.assertEqual(len(wire.sent), 1)

    def test_connect_time_consumes_total_udp_budget(self):
        report, wire, _, failure = self.invoke(connect_delay=6, events=[('timeout', None)])
        self.assertIsNotNone(failure)
        self.assertAlmostEqual(report['elapsed_seconds'], 10)
        self.assertEqual(len(wire.sent), 1)
        self.assertLessEqual(wire.timeouts[-1], 4)

    def test_second_window_late_response_does_not_pass_total_deadline(self):
        report, _, _, failure = self.invoke(events=[('timeout', None), ('reply', 5.001)])
        self.assertIsNotNone(failure)
        self.assertEqual(report['error'], 'deadline_exceeded')
        self.assertEqual(report['transmissions'], 2)
        self.assertFalse(report['checks']['reply_validated'])

    def test_tcp_partial_header_and_body_share_single_exchange(self):
        report, wire, session, failure = self.invoke(tcp=True, events=[('chunk', .01, 1), ('chunk', .01, 1),
                                                                    ('chunk', .01, 3), ('chunk', .01, 65535)])
        self.assertIsNone(failure)
        self.assertTrue(report['ok'])
        self.assertEqual(report['transmissions'], 1)
        self.assertEqual(len(wire.sent), 1)
        self.assertEqual(len(session.created), 1)
        self.assertEqual(wire.receives, 4)
        self.assertTrue(all(0 < value <= 4 for value in wire.timeouts))

    def test_tcp_eof_in_header_or_body_fails_without_looping(self):
        for events in [[('eof', 0)], [('chunk', 0, 1), ('eof', 0)],
                       [('chunk', 0, 2), ('chunk', 0, 3), ('eof', 0)]]:
            with self.subTest(events=events):
                (self.suite.output / 'dns-attempts.jsonl').unlink(missing_ok=True)
                report, wire, _, failure = self.invoke(tcp=True, events=events)
                self.assertIsNotNone(failure)
                self.assertEqual(report['error'], 'tcp_eof')
                self.assertEqual(wire.receives, len(events))
                self.assertEqual(len(wire.sent), 1)

    def test_tcp_partial_reads_do_not_refresh_four_second_deadline(self):
        report, wire, _, failure = self.invoke(tcp=True, events=[('chunk', 1.5, 1), ('chunk', 1.5, 1), ('chunk', 1.001, 3)])
        self.assertIsNotNone(failure)
        self.assertEqual(report['error'], 'deadline_exceeded')
        self.assertEqual(len(wire.sent), 1)
        self.assertLessEqual(wire.timeouts[-1], 1)

    def test_tcp_receive_timeout_is_single_four_second_attempt(self):
        report, wire, _, failure = self.invoke(tcp=True, events=[('timeout', None)])
        self.assertIsNotNone(failure)
        self.assertEqual(report['error'], 'receive_timeout')
        self.assertAlmostEqual(report['elapsed_seconds'], 4)
        self.assertEqual(len(wire.sent), 1)

    def test_final_failure_is_fsynced_before_assertion(self):
        observed = []
        real_fsync = host.os.fsync

        def fsync(fd):
            real_fsync(fd)
            observed.append('synced')

        with mock.patch.object(host.os, 'fsync', fsync):
            report, _, _, failure = self.invoke(events=[('timeout', None), ('timeout', None)])
        observed.append('assertion observed')
        self.assertIsNotNone(failure)
        self.assertEqual(observed, ['synced', 'assertion observed'])
        self.assertEqual(len(report['attempts']), 2)

    def test_rpc_failure_saves_safe_failure_report(self):
        session = mock.Mock()
        session.call.side_effect = AssertionError('private-fixture-rpc-error')
        with self.assertRaises(AssertionError):
            self.suite.dns(session, TARGET, False, NAME)
        path = self.suite.output / 'dns-attempts.jsonl'
        self.assertTrue(path.exists(), 'RPC failures also require evidence before assertion')
        report = json.loads(path.read_text())
        self.assertEqual(report['error'], 'worker_rpc_failed')
        self.assertFalse(report['ok'])
        self.assertNotIn('private-fixture', path.read_text())

    def test_worker_execution_error_or_invalid_report_is_not_exposed(self):
        for response, expected in [({'ok': False, 'error': 'private-fixture-worker-error'}, 'worker_execution_failed'),
                                   ({'ok': True, 'result': {'ok': True, 'error': 'private-fixture-report'}}, 'invalid_worker_report')]:
            with self.subTest(expected=expected):
                session = InProcessSession(WireSocket(self.clock))
                session.call = mock.Mock(return_value=response)
                with self.assertRaises(AssertionError):
                    self.suite.dns(session, TARGET, False, NAME)
                path = self.suite.output / 'dns-attempts.jsonl'
                self.assertTrue(path.exists(), 'invalid worker outcomes require a safe durable report')
                report = json.loads(path.read_text())
                self.assertEqual(report['error'], expected)
                self.assertNotIn('private-fixture', path.read_text())
                path.unlink()

    def test_invalid_report_numbers_and_missing_error_are_safely_persisted(self):
        def missing_error(value):
            value.update(ok=False, response=None, error=None)
        mutations = [lambda value: value.update(elapsed_seconds=10 ** 400),
                     lambda value: value['attempts'][0].update(elapsed_seconds=10 ** 400),
                     missing_error]
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                session = InProcessSession(WireSocket(self.clock))
                call = session.call
                def mutate_report(code, timeout=20):
                    response = call(code, timeout)
                    mutation(response['result'])
                    return response
                session.call = mutate_report
                failure = None
                try:
                    self.suite.dns(session, TARGET, False, NAME)
                except Exception as error:
                    failure = error
                self.assertIsInstance(failure, AssertionError, 'invalid reports must reach the safe assertion after persistence')
                path = self.suite.output / 'dns-attempts.jsonl'
                self.assertTrue(path.exists())
                self.assertEqual(json.loads(path.read_text())['error'], 'invalid_worker_report')
                path.unlink()


if __name__ == '__main__':
    unittest.main()
