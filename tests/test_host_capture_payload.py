"""Routing evidence remains mandatory when a proxy exposes payload bytes."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import host_acceptance as host


class PayloadCaptureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.suite = object.__new__(host.Suite)
        self.suite.binding = host.Binding.from_text(json.dumps(host.BindingTests.document()))
        self.suite.payload_marker_policy = 'absent'
        self.suite.query_names = ['d8-payload.example.com']
        self.suite.udp_token = b'D8-UDP-PAYLOAD-CANARY'
        self.suite.wire = root / 'wire.pcap'
        self.suite.outer = root / 'outer.pcap'
        self.suite.dns_pcap = root / 'dns.pcap'
        self.suite.outer.write_bytes(b'opaque outer packet fixture')
        self.qname = b'\x0ad8-payload\x07example\x03com\0'
        self.unexpected_outer = ''
        self.unexpected_dns = ''
        self.suite.verify_physical_capture = mock.Mock(return_value={
            'positive_control_packets': 2, 'direct_workload_packets': 0})
        self.calls = []
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(host, 'command', side_effect=self.read_capture).start()

    def read_capture(self, *args, **kwargs):
        self.calls.append(args)
        self.assertEqual(args[:3], ('tcpdump', '-nn', '-r'))
        if args[3] == str(self.suite.outer):
            if len(args) == 4:
                output = 'allowed outer packet\n'
            elif args[4] == 'not ' + self.suite.binding.outer_bpf():
                output = self.unexpected_outer
            else:
                self.assertIn(args[4], [self.suite.binding.endpoint_bpf(endpoint)
                                       for endpoint in self.suite.binding.policy['outer_endpoints']])
                output = 'endpoint packet\n'
        else:
            self.assertEqual(args[3], str(self.suite.dns_pcap))
            if len(args) == 4:
                output = 'redirected DNS packet\n'
            else:
                self.assertEqual(args[4],
                    'not (ip and dst host 1.1.1.1 and (tcp or udp) and dst port 53)')
                output = self.unexpected_dns
        return subprocess.CompletedProcess(args, 0, output, '')

    def test_cleartext_proxy_reports_visible_markers_after_endpoint_validation(self):
        self.suite.payload_marker_policy = 'encapsulated'
        self.suite.outer.write_bytes(self.qname + self.suite.udp_token)
        result = self.suite.packet_capture_evidence()
        self.assertTrue(result['plaintext_dns_on_outer'])
        self.assertTrue(result['plaintext_udp_on_outer'])
        self.assertEqual(result['payload_marker_policy'], 'encapsulated')
        self.assertEqual(result['unexpected_outer_packets'], 0)
        self.suite.verify_physical_capture.assert_called_once_with(self.suite.wire)
        self.assertIn(('tcpdump', '-nn', '-r', str(self.suite.outer),
                       'not ' + self.suite.binding.outer_bpf()), self.calls)

    def test_absence_policy_still_rejects_either_visible_marker(self):
        for content in (self.qname, self.suite.udp_token):
            with self.subTest(content=content):
                self.suite.outer.write_bytes(content)
                with self.assertRaises(AssertionError):
                    self.suite.packet_capture_evidence()

    def test_opaque_capture_reports_actual_absence(self):
        result = self.suite.packet_capture_evidence()
        self.assertFalse(result['plaintext_dns_on_outer'])
        self.assertFalse(result['plaintext_udp_on_outer'])
        self.assertEqual(result['payload_marker_policy'], 'absent')
        self.assertEqual(result['unexpected_outer_packets'], 0)

    def test_encapsulation_never_allows_a_wrong_outer_endpoint(self):
        self.suite.payload_marker_policy = 'encapsulated'
        self.suite.outer.write_bytes(self.qname)
        for unexpected in ('direct DNS to 8.8.8.8:53\n', 'unexpected IPv6 packet\n',
                           'wrong port on allowed node\n'):
            with self.subTest(unexpected=unexpected):
                self.unexpected_outer = unexpected
                with self.assertRaises(AssertionError):
                    self.suite.packet_capture_evidence()

    def test_encapsulation_never_allows_dns_outside_the_redirect_target(self):
        self.suite.payload_marker_policy = 'encapsulated'
        self.unexpected_dns = 'DNS packet outside expected redirect\n'
        with self.assertRaises(AssertionError):
            self.suite.packet_capture_evidence()

    def test_unknown_marker_policy_is_rejected(self):
        self.suite.payload_marker_policy = 'ignore'
        with self.assertRaises(AssertionError):
            self.suite.packet_capture_evidence()

    def test_encapsulation_cannot_expose_managed_doh_or_unsupported_udp(self):
        self.suite.payload_marker_policy = 'encapsulated'
        self.suite.binding.policy.update(dns_transport='https', payload_networks=['tcp'])
        for content in (self.qname, self.suite.udp_token):
            with self.subTest(content=content):
                self.suite.outer.write_bytes(content)
                with self.assertRaises(AssertionError):
                    self.suite.packet_capture_evidence()


if __name__ == '__main__':
    unittest.main()
