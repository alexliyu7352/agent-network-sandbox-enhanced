"""Offline CI bootstrap checks. These tests never provision a host or launch QEMU."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "tests/ci-host.sh"
VM = ROOT / "tests/ci-vm.sh"
PARSER = ROOT / "gateway-policy.jq"


def shell(script, body, *args):
    return subprocess.run(
        ["bash", "-c", 'set -euo pipefail; source "$1"; shift; ' + body,
         "ci-test", str(script), *map(str, args)],
        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"}, timeout=20,
    )


class HostBootstrapTests(unittest.TestCase):
    def test_unmarked_host_is_rejected_before_provisioning(self):
        for script in (HOST, VM):
            with self.subTest(script=script.name):
                result = subprocess.run(
                    ["bash", str(script), "--protocol", "http", "--scenario", "healthy"],
                    capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"}, timeout=10,
                )
                self.assertEqual(result.returncode, 125, result.stderr)
                self.assertIn("disposable GitHub-hosted VM", result.stderr)
                self.assertNotIn("CI_STAGE=", result.stdout)

    def test_invalid_cases_are_rejected(self):
        for args in (("direct", "healthy", "100"), ("http", "unknown", "100"),
                     ("http", "healthy", "0"), ("http", "healthy", "-1"),
                     ("http", "healthy", "1000")):
            with self.subTest(args=args):
                self.assertNotEqual(shell(HOST, 'ci_validate_case "$@"', *args).returncode, 0)

    def test_nested_stage_failure_cannot_continue_setup(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "logs").mkdir()
            result = shell(
                HOST, 'CI_EVIDENCE=$1; bad_setup() { false; touch "$1/unprotected"; }; '
                      'ci_stage setup bad_setup "$1"', td,
            )
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertFalse(Path(td, "unprotected").exists())

    def test_fixture_uses_private_install_without_public_launcher(self):
        with tempfile.TemporaryDirectory() as td:
            installer = Path(td) / "install-dev-session.sh"
            installer.write_text(
                '#!/bin/bash\nprintf "%s\\n" "$@" >"${0%/*}/installer-args"\nexit 37\n'
            )
            installer.chmod(0o755)
            # The stub stops before account/container operations. Mutation
            # commands are also replaced so this remains a read-only test host.
            result = shell(
                HOST, 'CI_ROOT=$1; CI_PROTOCOL=http; ci_write_config() { :; }; '
                      'useradd() { return 98; }; passwd() { return 98; }; '
                      'docker() { return 98; }; ci_fixture', td,
            )
            self.assertEqual(result.returncode, 37, result.stderr)
            self.assertEqual((Path(td) / "installer-args").read_text().splitlines(), ["--no-link"])

    def test_failed_init_retains_failure_after_read_only_diagnostics(self):
        for status in (0, 73):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as td:
                manager = Path(td) / "dev-session"
                manager.write_text('#!/bin/bash\nexit ' + str(status) + '\n')
                manager.chmod(0o755)
                result = shell(
                    HOST, 'CI_ROOT=$1; ci_failed_init_diagnostics() { touch "$CI_ROOT/diagnosed"; }; '
                          'ci_initialize', td,
                )
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual((Path(td) / "diagnosed").exists(), status != 0)

    def test_failed_init_diagnostics_selects_metadata_and_stops_after_failed_phase(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "lib").mkdir()
            (root / "lib/host.sh").write_text("")
            (root / "lib/network.sh").write_text(
                'read_proxy_policy() { echo read_proxy_policy >>"$ROOT/phases"; '
                'echo DO_NOT_EXPORT_AUTH; return 0; }\n'
                'gateway_open() { echo gateway_open >>"$ROOT/phases"; '
                'echo DO_NOT_EXPORT_AUTH >&2; return 7; }\n'
                'gateway_verify() { echo gateway_verify >>"$ROOT/phases"; return 0; }\n'
            )
            helper = root / "bin"
            helper.mkdir()
            container = {
                "Id": "b" * 64, "State": {"Pid": os.getpid(), "Running": True},
                "Config": {"Env": ["PASSWORD=DO_NOT_EXPORT_AUTH"]},
                "HostConfig": {
                    "CapAdd": ["CAP_NET_ADMIN", "CAP_NET_RAW"], "CapDrop": ["ALL"],
                    "ReadonlyRootfs": True, "Privileged": False, "NetworkMode": "bridge",
                    "SecurityOpt": ["no-new-privileges=true"], "Sysctls": {"net.ipv4.ip_forward": "0"},
                },
                "Mounts": [{"Source": str(root / "network.json"), "Destination": "/etc/worker/network.json",
                            "Type": "bind", "RW": False}],
                "NetworkSettings": {"SandboxKey": "/run/docker/netns/absent-ci-test",
                                    "Networks": {"test": {"NetworkID": "a" * 64, "IPAddress": "172.18.0.2"}}},
            }
            docker = helper / "docker"
            docker.write_text(
                "#!/usr/bin/python3\nimport json,sys\n"
                "container=" + repr(container) + "\n"
                "print(json.dumps([container] if sys.argv[1]=='inspect' else "
                "[{'Driver':'bridge','EnableIPv6':False,'Options':{},'Containers':{}}]))\n"
            )
            docker.chmod(0o755)
            ip = helper / "ip"
            ip.write_text('#!/bin/sh\nprintf "%s\\n" "[]"\n')
            ip.chmod(0o755)
            evidence = root / "evidence"
            evidence.mkdir()
            result = shell(
                HOST, 'CI_ROOT=$1; CI_EVIDENCE=$2; PATH="$1/bin:/usr/bin:/bin"; '
                      'ci_failed_init_diagnostics', root, evidence,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            text = (evidence / "init-diagnostics.json").read_text()
            self.assertNotIn("DO_NOT_EXPORT_AUTH", text + result.stdout + result.stderr)
            data = json.loads(text)
            self.assertEqual(data["container"]["HostConfig"]["CapAdd"], ["CAP_NET_ADMIN", "CAP_NET_RAW"])
            self.assertEqual(data["phase_checks"]["gateway_open"]["exit_code"], 7)
            self.assertEqual(data["phase_checks"]["gateway_verify"]["status"], "not_run")
            self.assertEqual((root / "phases").read_text().splitlines(), ["read_proxy_policy", "gateway_open"])

    @unittest.skipUnless(shutil.which("jq"), "jq is required by the shared parser")
    def test_fake_sources_compile_to_the_expected_transport_and_dns(self):
        for protocol, outer, payload, dns in (
            ("http", "tcp", ["tcp"], "https"),
            ("hysteria2", "udp", ["tcp", "udp"], "udp"),
        ):
            with self.subTest(protocol=protocol), tempfile.TemporaryDirectory() as td:
                path = Path(td) / "network.json"
                result = shell(HOST, 'ci_write_config "$1" "$2"', protocol, path)
                self.assertEqual(result.returncode, 0, result.stderr)
                source = json.loads(path.read_text())
                self.assertEqual(source["outbounds"][0]["password"], "d8-fixture-only-password")
                self.assertEqual(source["outbounds"][0]["server"], "192.0.2.1")
                result = subprocess.run(
                    ["jq", "-ceS", "--arg", "mode", "policy", "-f", str(PARSER), str(path)],
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                policy = json.loads(result.stdout)
                self.assertEqual(policy["outer_endpoints"][0]["protocol"], outer)
                self.assertEqual(policy["payload_networks"], payload)
                self.assertEqual(policy["dns_transport"], dns)

    def test_unexecuted_suites_are_not_reported_passed(self):
        with tempfile.TemporaryDirectory() as td:
            result = shell(HOST, 'ci_write_manifest "$1" 1 http healthy 100 "$2"', td, "a" * 40)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads((Path(td) / "manifest.json").read_text())
            self.assertEqual(data["status"], "failed")
            self.assertEqual(data["suites"]["core"]["status"], "not_run")
            self.assertEqual(data["suites"]["lifecycle"]["status"], "not_run")

    def test_nonzero_exit_or_failed_result_cannot_become_success(self):
        for exit_code, test_pass in ((23, True), (0, False)):
            with self.subTest(exit_code=exit_code), tempfile.TemporaryDirectory() as td:
                for name in ("core", "lifecycle"):
                    path = Path(td) / name
                    path.mkdir()
                    (path / "results.json").write_text(json.dumps([{"passed": test_pass}]))
                result = shell(
                    HOST, 'ci_write_manifest "$1" "$2" http healthy 100 "$3"',
                    td, exit_code, "a" * 40,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads((Path(td) / "manifest.json").read_text())["status"], "failed")

    def test_result_validation_requires_completed_passing_suites(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertNotEqual(shell(HOST, 'ci_validate_results "$1"', td).returncode, 0)
            for name in ("core", "lifecycle"):
                path = Path(td) / name
                path.mkdir()
                (path / "results.json").write_text(json.dumps([{"passed": True}]))
            self.assertEqual(shell(HOST, 'ci_validate_results "$1"', td).returncode, 0)
            (Path(td) / "core/results.json").write_text(json.dumps([{"passed": False}]))
            self.assertNotEqual(shell(HOST, 'ci_validate_results "$1"', td).returncode, 0)


class VMChecks(unittest.TestCase):
    def test_image_requires_one_exact_checksum_and_matching_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            image = Path(td) / "fixture.qcow2"
            image.write_bytes(b"offline image test")
            sums, output = Path(td) / "SHA512SUMS", Path(td) / "image.json"
            digest = hashlib.sha512(image.read_bytes()).hexdigest()
            good = digest + "  fixture.qcow2\n"
            for content, allowed in (
                (good, True), (good + good, False),
                ("0" * 128 + "  fixture.qcow2\n", False),
                (digest + "  different.qcow2\n", False),
            ):
                with self.subTest(content=content):
                    sums.write_text(content)
                    result = shell(VM, 'ci_vm_verify_image "$@"', image, sums, output)
                    self.assertEqual(result.returncode == 0, allowed, result.stderr)
            sums.write_text(good)
            self.assertEqual(shell(VM, 'ci_vm_verify_image "$@"', image, sums, output).returncode, 0)
            self.assertEqual(json.loads(output.read_text())["sha512"], digest)

    def test_pinned_digest_is_required_even_if_downloaded_sum_matches(self):
        with tempfile.TemporaryDirectory() as td:
            image = Path(td) / "fixture.qcow2"
            image.write_bytes(b"changed image")
            sums, output = Path(td) / "SHA512SUMS", Path(td) / "image.json"
            sums.write_text(hashlib.sha512(image.read_bytes()).hexdigest() + "  fixture.qcow2\n")
            result = shell(VM, 'ci_vm_verify_image "$@"', image, sums, output, "0" * 128)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())

    def test_missing_or_failed_guest_is_not_reported_passed(self):
        for guest, status in (
            (None, 0), ({"status": "failed", "revision": "a" * 40}, 0),
            ({"status": "passed", "revision": "a" * 40}, 17),
        ):
            with self.subTest(guest=guest), tempfile.TemporaryDirectory() as td:
                if guest:
                    path = Path(td) / "guest"
                    path.mkdir()
                    (path / "manifest.json").write_text(json.dumps(guest))
                result = shell(VM, 'ci_vm_manifest "$@"', td, status, "http", "a" * 40)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads((Path(td) / "manifest.json").read_text())["status"], "failed")

    def test_only_a_matching_completed_guest_and_verified_image_can_pass(self):
        for revision, allowed in (("a" * 40, True), ("b" * 40, False)):
            with self.subTest(revision=revision), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                (root / "guest").mkdir()
                (root / "image.json").write_text(json.dumps({"verified": True, "sha512": "0" * 128}))
                (root / "stages.jsonl").write_text(
                    json.dumps({"name": "guest_acceptance", "exit_code": 0}) + "\n"
                )
                (root / "guest/manifest.json").write_text(json.dumps({
                    "status": "passed", "exit_code": 0, "revision": revision,
                    "protocol": "http", "scenario": "healthy", "required_cgroup": "v2",
                    "suites": {"core": {"status": "passed"}, "lifecycle": {"status": "passed"}},
                }))
                result = shell(VM, 'ci_vm_manifest "$@"', td, 0, "http", "a" * 40)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads((root / "manifest.json").read_text())["status"] == "passed", allowed)

    def test_kvm_variable_alone_cannot_enable_guest_provisioning(self):
        result = shell(
            VM, 'CI_DISPOSABLE_HOST=kvm-guest; CI_GITHUB_SHA=$1; ci_require_disposable', "a" * 40,
        )
        self.assertNotEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "openssh-client is required for the seed check")
    def test_cloud_seed_pins_host_key_without_printing_private_keys(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            private = root / "private"
            private.mkdir(mode=0o700)
            helper = root / "bin"
            helper.mkdir()
            stub = helper / "cloud-localds"
            stub.write_text('#!/bin/sh\n: > "$1"\n')
            stub.chmod(0o755)
            result = subprocess.run(
                ["bash", "-c", 'set -euo pipefail; umask 077; source "$1"; '
                 'CI_VM_PRIVATE=$2; CI_REVISION=$3; CI_PROTOCOL=http; ci_vm_seed',
                 "seed-test", str(VM), str(private), "a" * 40],
                capture_output=True, text=True,
                env={"PATH": str(helper) + ":/usr/bin:/bin"}, timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            seed = (private / "user-data").read_text()
            self.assertTrue(seed.startswith("#cloud-config\n"))
            data = json.loads(seed.split("\n", 1)[1])
            host_key = (private / "host_key.pub").read_text().strip()
            self.assertEqual(data["ssh_keys"]["ed25519_public"], host_key)
            self.assertEqual(data["ssh_keys"]["ed25519_private"], (private / "host_key").read_text())
            self.assertEqual((private / "known_hosts").read_text(), "[127.0.0.1]:22222 " + host_key + "\n")
            self.assertFalse(data["ssh_pwauth"])
            self.assertEqual(data["write_files"][0]["content"], "a" * 40 + "\n")
            self.assertEqual((private / "user-data").stat().st_mode & 0o777, 0o600)
            self.assertNotIn("PRIVATE KEY", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
