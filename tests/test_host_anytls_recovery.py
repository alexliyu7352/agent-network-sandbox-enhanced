"""A single cancelled-dial regression must not become a general retry loop."""
import http.client
import io
import os
import unittest
from unittest import mock

import host_acceptance as host


def healthy():
    return {'ok': True, 'result': {'status': 200, 'tls': True, 'body_length': 128}}


def failed(kind='SSLEOFError'):
    return {'ok': False, 'error': kind + ': diagnostic failure', 'errno': 8}


class AnyTLSRecoveryTests(unittest.TestCase):
    def suite(self, responses, times):
        suite = object.__new__(host.Suite)
        suite.anytls_reuse_check = True
        suite.anytls_new_https = mock.Mock(side_effect=responses)
        suite.anytls_warm_https = mock.Mock(return_value={'status': 200, 'tls': True, 'same_socket': True})
        suite.assert_rules = mock.Mock()
        self.clock = mock.patch.object(host.time, 'monotonic', side_effect=times)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        return suite

    def test_one_known_watchdog_failure_is_retained_then_one_new_connection_recovers(self):
        suite = self.suite([failed(), healthy()], [10, 13.002, 14, 14.06])
        result = suite.anytls_cancelled_dial_recovery()
        self.assertEqual(result['first_new_connection'], {
            'status': 'known_watchdog_failure', 'seconds': 3.002, 'error_type': 'SSLEOFError'})
        self.assertEqual(result['second_new_connection'], {'status': 'passed', 'seconds': 0.06})
        self.assertEqual(result['new_connection_attempts'], 2)
        for key in ('existing_tls_socket_preserved', 'policy_and_binding_unchanged',
                    'no_core_restart_or_pool_reset', 'recovered'):
            self.assertIs(result[key], True)
        self.assertEqual(suite.anytls_new_https.call_count, 2)
        self.assertEqual(suite.anytls_warm_https.call_count, 3)
        self.assertEqual(suite.assert_rules.call_count, 2)

    def test_healthy_first_attempt_needs_no_followup(self):
        suite = self.suite([healthy()], [10, 10.04])
        result = suite.anytls_cancelled_dial_recovery()
        self.assertEqual(result['first_new_connection'], {
            'status': 'passed', 'seconds': 0.04, 'error_type': None})
        self.assertEqual(result['second_new_connection'], {'status': 'not_needed'})
        self.assertEqual(result['new_connection_attempts'], 1)
        suite.anytls_new_https.assert_called_once_with()

    def test_unrelated_failure_never_gets_a_followup_attempt(self):
        for kind, seconds in (('TimeoutError', 3), ('SSLEOFError', 0.2),
                              ('ConnectionResetError', 5), ('PermissionError', 3)):
            with self.subTest(kind=kind, seconds=seconds):
                suite = self.suite([failed(kind)], [10, 10 + seconds])
                with self.assertRaises(AssertionError):
                    suite.anytls_cancelled_dial_recovery()
                suite.anytls_new_https.assert_called_once_with()
                self.clock.stop()

    def test_a_failed_second_attempt_is_terminal(self):
        suite = self.suite([failed(), failed()], [10, 13, 14, 17])
        with self.assertRaises(AssertionError):
            suite.anytls_cancelled_dial_recovery()
        self.assertEqual(suite.anytls_new_https.call_count, 2)

    def test_replaced_or_broken_existing_socket_fails_before_new_probe(self):
        suite = self.suite([healthy()], [])
        suite.anytls_warm_https.return_value = {'status': 200, 'tls': True, 'same_socket': False}
        with self.assertRaises(AssertionError):
            suite.anytls_cancelled_dial_recovery()
        suite.anytls_new_https.assert_not_called()


    def test_policy_change_cannot_be_reported_as_recovery(self):
        suite = self.suite([healthy()], [10, 10.04])
        suite.assert_rules.side_effect = [None, AssertionError('policy changed')]
        with self.assertRaises(AssertionError):
            suite.anytls_cancelled_dial_recovery()

    def test_bad_http_status_does_not_trigger_retry(self):
        response = healthy(); response['result']['status'] = 503
        suite = self.suite([response], [10, 10.04])
        with self.assertRaises(AssertionError):
            suite.anytls_cancelled_dial_recovery()
        suite.anytls_new_https.assert_called_once_with()

    def test_the_regression_requires_an_explicit_fixture_selection(self):
        suite = self.suite([healthy()], [])
        suite.anytls_reuse_check = False
        with self.assertRaises(AssertionError):
            suite.anytls_cancelled_dial_recovery()
        suite.anytls_new_https.assert_not_called()


class HTTPBodyEvidenceTests(unittest.TestCase):
    class Worker:
        def __init__(self, state):
            self.state = state

        def value(self, code):
            scope = {'state': self.state}
            exec(code, scope)
            return scope['result']

        def call(self, code, timeout):
            try:
                return {'ok': True, 'result': self.value(code)}
            except Exception as error:
                return {'ok': False, 'error': type(error).__name__ + ': ' + str(error)}

    class Socket:
        def __init__(self, content, fd):
            self.content, self.fd = content, fd

        def makefile(self, *args, **kwargs):
            return io.BytesIO(self.content)

        def fileno(self):
            return self.fd

        def getpeername(self):
            return ('1.1.1.1', 443)

        def sendall(self, content):
            pass

    def test_both_actual_worker_helpers_reject_a_truncated_content_length(self):
        fixtures = (
            (b'Content-Length: 100\r\n', b'short', False),
            (b'Content-Length: 5\r\n', b'short', True),
            (b'Transfer-Encoding: chunked\r\n', b'5\r\nshort\r\n0\r\n\r\n', True),
        )
        for header, body, complete in fixtures:
            for helper in ('warm', 'new'):
                with self.subTest(helper=helper, complete=complete, header=header), open(os.devnull, 'rb') as fd:
                    content = b'HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n' + header + b'\r\n' + body
                    original = self.Socket(content, fd.fileno())
                    connection = mock.Mock(sock=original)
                    def getresponse():
                        response = http.client.HTTPResponse(original);response.begin()
                        return response
                    connection.getresponse.side_effect = getresponse
                    worker = self.Worker({'https': connection, 'kept_socket': original,
                        'anytls_warm_identity': (original, original.fileno(),
                            os.fstat(original.fileno()).st_ino, original.getpeername())})
                    suite = object.__new__(host.Suite);suite.a = suite.b = worker
                    with mock.patch.object(http.client, 'HTTPSConnection', return_value=connection):
                        if helper == 'warm':
                            if complete:
                                self.assertTrue(suite.anytls_warm_https()['same_socket'])
                            else:
                                with self.assertRaises(AssertionError):suite.anytls_warm_https()
                        else:
                            result = suite.anytls_new_https()
                            self.assertEqual(result['ok'], complete)



if __name__ == '__main__':
    unittest.main()
