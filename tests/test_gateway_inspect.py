"""Replay Docker's container configuration boundary without running Docker."""
import copy
import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class GatewayInspectTests(unittest.TestCase):
    def fixture(self):
        # Docker 26 and Docker 29 expose equivalent capability names differently.
        return [{
            'State': {'Running': True, 'Pid': 1234},
            'HostConfig': {
                'Privileged': False, 'NetworkMode': 'fixture_default',
                'ReadonlyRootfs': True, 'CapDrop': ['ALL'],
                'CapAdd': ['NET_ADMIN', 'NET_RAW'],
                'SecurityOpt': ['no-new-privileges:true'],
                'Sysctls': {
                    'net.ipv4.ip_forward': '0',
                    'net.ipv6.conf.all.disable_ipv6': '1',
                    'net.ipv6.conf.default.disable_ipv6': '1',
                    'net.ipv6.conf.lo.disable_ipv6': '1',
                },
            },
            'Mounts': [{'Destination': '/etc/worker/network.json',
                        'Source': str(ROOT / 'network.json'), 'RW': False, 'Type': 'bind'}],
            'NetworkSettings': {'Networks': {'fixture_default': {}}},
        }]

    def matches(self, value):
        return subprocess.run(
            ['bash', '-p', '-c',
             'set -euo pipefail; ROOT=$1; source "$ROOT/lib/network.sh"; '
             'gateway_container_config_matches', 'gateway-inspect-test', str(ROOT)],
            input=json.dumps(value), text=True, capture_output=True, timeout=10,
        )

    def test_docker_26_and_29_capability_names_are_equivalent(self):
        for capabilities in (['NET_ADMIN', 'NET_RAW'], ['CAP_NET_ADMIN', 'CAP_NET_RAW'],
                             ['CAP_NET_RAW', 'NET_ADMIN']):
            with self.subTest(capabilities=capabilities):
                value = self.fixture()
                value[0]['HostConfig']['CapAdd'] = capabilities
                result = self.matches(value)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_capability_normalization_cannot_add_or_hide_privileges(self):
        for capabilities in (['NET_ADMIN'], ['ALL'], ['NET_ADMIN', 'NET_RAW', 'SYS_ADMIN'],
                             ['CAP_NET_ADMIN', 'CAP_NET_RAW', 'CAP_SYS_ADMIN'],
                             ['NET_ADMIN', 'NET_RAW', 'CAP_NET_RAW'],
                             ['CAP_CAP_NET_ADMIN', 'CAP_NET_RAW'],
                             ['cap_net_admin', 'cap_net_raw'], [None, 'NET_RAW'],
                             [123, 'NET_RAW'], None, {},
                             {'first': 'CAP_NET_ADMIN', 'second': 'CAP_NET_RAW'},
                             'CAP_NET_ADMIN'):
            with self.subTest(capabilities=capabilities):
                value = self.fixture()
                value[0]['HostConfig']['CapAdd'] = capabilities
                self.assertNotEqual(self.matches(value).returncode, 0)

    def test_container_protection_requirements_remain_mandatory(self):
        for key, replacement in (
                ('CapDrop', []), ('CapDrop', ['ALL', 'NET_RAW']),
                ('Privileged', True), ('ReadonlyRootfs', False),
                ('NetworkMode', 'host'), ('SecurityOpt', []),
                ('SecurityOpt', ['no-new-privileges:false'])):
            with self.subTest(key=key, replacement=replacement):
                value = self.fixture()
                value[0]['HostConfig'][key] = replacement
                self.assertNotEqual(self.matches(value).returncode, 0)

    def test_readonly_source_and_network_constraints_remain_exact(self):
        cases = []
        for key, replacement in (('RW', True), ('Type', 'volume'), ('Source', '/tmp/network.json')):
            value = self.fixture()
            value[0]['Mounts'][0][key] = replacement
            cases.append(value)
        value = self.fixture()
        value[0]['Mounts'].append(copy.deepcopy(value[0]['Mounts'][0]))
        cases.append(value)
        for interfaces in ({}, {'first': {}, 'second': {}}):
            value = self.fixture()
            value[0]['NetworkSettings']['Networks'] = interfaces
            cases.append(value)
        for key in self.fixture()[0]['HostConfig']['Sysctls']:
            value = self.fixture()
            del value[0]['HostConfig']['Sysctls'][key]
            cases.append(value)
        cases.extend([[], self.fixture() * 2])
        for index, value in enumerate(cases):
            with self.subTest(index=index):
                self.assertNotEqual(self.matches(value).returncode, 0)


if __name__ == '__main__':
    unittest.main()
