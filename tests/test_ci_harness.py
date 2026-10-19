"""Offline CI bootstrap checks. These tests never provision a host or launch QEMU."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import re

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

    def test_gateway_recreation_case_requires_a_disposable_host(self):
        for protocol in ("http", "hysteria2"):
            with self.subTest(protocol=protocol):
                result = shell(HOST, 'ci_validate_case "$@"', protocol, "gateway-recreate", "100")
                self.assertEqual(result.returncode, 0, result.stderr)
                result = subprocess.run(
                    ["bash", str(HOST), "--protocol", protocol, "--scenario", "gateway-recreate"],
                    capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"}, timeout=10,
                )
                self.assertEqual(result.returncode, 125, result.stderr)
                self.assertNotIn("CI_STAGE=", result.stdout)

    def test_gateway_recreation_runs_last_and_preserves_a_failed_suite(self):
        for core_exit in (0, 39):
            with self.subTest(core_exit=core_exit), tempfile.TemporaryDirectory() as td:
                # Intercept the suite boundary, so no sessions, Docker commands,
                # binding files, or real policy checks run on this test host.
                result = shell(
                    HOST, 'CI_ROOT=$1; CI_EVIDENCE=$1; CI_ACCOUNT=ci-test; CI_REPETITIONS=100; '
                          'CI_SCENARIO=gateway-recreate; CI_TEST_CORE_EXIT=$2; '
                          'ci_stage() { printf "%s\\n" "$*" >>"$CI_EVIDENCE/stage-calls"; '
                          'if [[ $1 == core ]]; then return "$CI_TEST_CORE_EXIT"; fi; }; '
                          'cmp() { printf "%s\\n" binding-checked >>"$CI_EVIDENCE/stage-calls"; }; '
                          'ci_suites', td, core_exit,
                )
                self.assertEqual(result.returncode, core_exit, result.stderr)
                calls = (Path(td) / "stage-calls").read_text().splitlines()
                self.assertTrue(calls[0].startswith("lifecycle "), calls)
                self.assertTrue(calls[0].endswith("--namespace-fault none"), calls)
                self.assertNotIn("--compose-project", calls[0])
                self.assertTrue(calls[1].startswith("core "), calls)
                self.assertIn("--compose-project repo", calls[1])
                self.assertTrue(calls[1].endswith("--namespace-fault gateway-recreate"), calls)
                self.assertEqual([row.split()[0] for row in calls],
                                 ["lifecycle", "core", "results", "binding-checked"]
                                 if core_exit == 0 else ["lifecycle", "core"])

    def test_nested_stage_failure_cannot_continue_setup(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "logs").mkdir()
            result = shell(
                HOST, 'CI_EVIDENCE=$1; bad_setup() { false; touch "$1/unprotected"; }; '
                      'ci_stage setup bad_setup "$1"', td,
            )
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertFalse(Path(td, "unprotected").exists())

    def test_inline_harness_regressions_run_and_fail_the_ci_stage(self):
        modules = ("host_acceptance", "host_upstream_fixture", "host_lifecycle")
        for failed in (None, *modules):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                (root / "tests").mkdir()
                (root / "logs").mkdir()
                for module in modules:
                    (root / "tests" / (module + ".py")).write_text(
                        "import unittest\nclass InlineRegression(unittest.TestCase):\n"
                        "    def test_inline_case(self):\n"
                        "        self.assertTrue(" + repr(module != failed) +
                        ", 'controlled inline failure')\n"
                    )
                result = shell(
                    HOST, 'CI_ROOT=$1; CI_EVIDENCE=$1; '
                          'ci_stage offline_helpers ci_offline_helpers', root,
                )
                self.assertEqual(result.returncode, 0 if failed is None else 1, result.stderr)
                self.assertIn("Ran 3 tests", result.stdout)
                if failed is not None:
                    self.assertIn("controlled inline failure", result.stdout)
                    self.assertFalse((root / "stages.jsonl").exists())

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


class ProtocolCaseChecks(unittest.TestCase):
    """Synthetic evidence exercises reporting; no real acceptance is claimed."""

    @staticmethod
    def completed_evidence(root, case="ssh"):
        names = (
            "two_session_credentials", "host_loopback", "public_https",
            "all_dns_destinations_redirected", "ordinary_udp_capability",
            "forced_physical_interface", "private_ipv6_privilege_denials",
            "controlled_upstream_node_outage", "gateway_TUN_link_down",
            "host_default_route_removed", "gateway_half_route_removed",
            "failed_probe_no_payload", "extra_policy_rule_rejected",
            "writable_policy_rejected", "gateway-kill", "packet_capture_evidence",
            "shared_rules_unchanged",
        )
        rows = [{"name": name, "passed": True, "detail": {}} for name in names]
        details = {row["name"]: row for row in rows}
        details["two_session_credentials"]["detail"] = [
            {"cgroup_mode": "v2", "socket_creation": {
                "inodes": [101 + index * 2, 102 + index * 2],
                "cgroup": "/devsession.slice/dev-session-" + str(index + 1) * 32 + ".service",
                "created_inside_service": True,
            }} for index in range(2)
        ]
        details["gateway-kill"]["detail"] = {
            "namespace_changed": True, "check_exit": 125, "init_exit": 125,
            "binding_and_guards_retained": True, "offline_rebind_required": True,
            "existing_connection_blocked_during_fault": True,
            "new_connection_blocked_during_fault": True,
            "other_session_loopback_alive": True,
        }
        details["packet_capture_evidence"]["detail"] = {
            "positive_control_packets": 2, "direct_workload_packets": 0,
            "outer_packets": 12, "redirected_dns_packets": 8,
            "plaintext_dns_on_outer": False,
            "plaintext_udp_on_outer": False, "unexpected_outer_packets": 0,
            "payload_marker_policy": "absent",
            "outer_endpoints": [{"address": "192.0.2.1", "protocol": "tcp",
                                 "port_ranges": [[443, 443]], "packets": 12}],
        }
        for name in ("core", "exit-ip"):
            (root / name).mkdir()
        (root / "core/results.json").write_text(json.dumps(rows))
        for name in ("physical-direct-probes", "gateway-outer", "redirected-dns"):
            (root / "core" / (name + ".pcap")).write_bytes(b"synthetic packet evidence" * 2)
        for name in ("session-A", "session-B"):
            (root / "core" / (name + "-socket-cgroups.log")).write_text("synthetic ss evidence\n")
        (root / "exit-ip/results.json").write_text(json.dumps({
            "format": 1, "passed": True,
            "exit_ip": {"valid_ipv4": True, "family": 4, "matches": True},
            "checks": {name: True for name in (
                "workload_identity", "workload_cgroup", "session_reclaimed", "postcheck",
                "binding_retained", "fixture_bound_to_source", "owned_upstream_namespace")},
        }))
        (root / "fixture-verification.json").write_text(json.dumps({
            "format": 1, "protocol_case": case, "passed": True,
            "checks": {name: True for name in (
                "source_unchanged", "recipe_unchanged", "namespace_owned",
                "services_active", "helper_evidence")},
        }))
        stages = ["dependencies", "offline", "offline_helpers", "docker_backend"]
        if case == "ssh":
            stages.append("fixture_python")
        stages += ["fixture_engine", "fixture_render", "fixture", "exit_ip", "core",
                   "fixture_verify", "results", "fixture_cleanup"]
        (root / "stages.jsonl").write_text("".join(
            json.dumps({"name": name, "exit_code": 0}) + "\n" for name in stages
        ))
        return rows

    def test_each_protocol_case_still_requires_a_disposable_host(self):
        result = subprocess.run(
            ["bash", str(HOST), "--protocol-case", "ssh"], capture_output=True, text=True,
            env={"PATH": "/usr/bin:/bin"}, timeout=10,
        )
        self.assertEqual(result.returncode, 125, result.stderr)
        self.assertIn("disposable GitHub-hosted VM", result.stderr)
        self.assertNotIn("CI_STAGE=", result.stdout)

    def test_case_inventory_and_workflow_cover_all_default_and_opt_in_recipes(self):
        inventory = subprocess.run(
            ["python3", str(ROOT / "tests/protocol_runtime.py"), "--list"],
            capture_output=True, text=True, timeout=10, check=True,
        )
        data = json.loads(inventory.stdout)
        expected = set(data["cases"] + data["experimental_cases"])
        workflow = (ROOT / ".github/workflows/host-acceptance.yml").read_text()
        block = workflow.split("  protocol-case:", 1)[1].split("    steps:", 1)[0]
        cases = re.findall(r"^          - ([a-z0-9-]+)$", block, re.MULTILINE)
        self.assertEqual(len(cases), 43)
        self.assertEqual(len(set(cases)), len(cases))
        self.assertEqual(set(cases), expected)
        for case in ("ssh", "shadowtls1", "shadowtls2", "shadowtls3", "hysteria-port-hopping", "unknown", "../ssh",
                     "trojan-httpupgrade", "vmess-httpupgrade", "vless-httpupgrade", "anytls"):
            with self.subTest(case=case):
                result = shell(HOST, 'CI_ROOT=$1; ci_validate_protocol_case "$2"', ROOT, case)
                self.assertEqual(result.returncode == 0, case in expected, result.stderr)

    def test_only_the_verified_public_source_is_archived_and_never_overwritten(self):
        for changed, linked, backup_present in ((False, False, False), (True, False, False),
                                               (False, True, False), (False, False, True)):
            with self.subTest(changed=changed, linked=linked, backup=backup_present), tempfile.TemporaryDirectory() as td:
                base = Path(td)
                checkout = base / "repo"
                checkout.mkdir(mode=0o700)
                subprocess.run(["git", "init", "-q", str(checkout)], check=True)
                source = checkout / "network.json"
                source.write_text('{"public_fixture":true}\n')
                subprocess.run(["git", "-C", str(checkout), "add", "network.json"], check=True)
                subprocess.run(["git", "-C", str(checkout), "-c", "user.name=CI test", "-c",
                                "user.email=ci@example.invalid", "commit", "-qm", "public fixture"], check=True)
                revision = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
                # Reading a verified file can update atime on a normal host;
                # that must not be mistaken for changing its contents/identity.
                os.utime(source, ns=(0, source.stat().st_mtime_ns))
                if changed:
                    source.write_text('{"unexpected_source":true}\n')
                if linked:
                    original = checkout / "linked-source"
                    source.rename(original)
                    source.symlink_to(original)
                backup = base / "public-network-example.json"
                if backup_present:
                    backup.write_text("do not overwrite\n")
                result = shell(
                    HOST, 'CI_ROOT=$1; CI_BASE=$2; CI_REVISION=$3; ci_archive_public_config',
                    checkout, base, revision,
                )
                allowed = not (changed or linked or backup_present)
                self.assertEqual(result.returncode == 0, allowed, result.stderr)
                self.assertEqual(source.exists(), not allowed)
                if allowed:
                    self.assertEqual(backup.read_text(), '{"public_fixture":true}\n')
                    self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
                elif backup_present:
                    self.assertEqual(backup.read_text(), "do not overwrite\n")

    def test_protocol_case_kills_last_without_running_lifecycle_or_rebinding(self):
        for failed_stage in (None, "core", "fixture_verify"):
            with self.subTest(failed_stage=failed_stage), tempfile.TemporaryDirectory() as td:
                result = shell(
                    HOST, 'CI_ROOT=$1; CI_EVIDENCE=$1; CI_ACCOUNT=ci-test; CI_PROTOCOL_CASE=ssh; '
                          'CI_TEST_FAIL=$2; ci_stage() { printf "%s\\n" "$*" >>"$CI_EVIDENCE/calls"; '
                          '[[ $1 != "$CI_TEST_FAIL" ]] || return 39; }; '
                          'cmp() { printf "%s\\n" binding-retained >>"$CI_EVIDENCE/calls"; }; '
                          'ci_protocol_suites', td, failed_stage or "",
                )
                self.assertEqual(result.returncode, 39 if failed_stage else 0, result.stderr)
                calls = (Path(td) / "calls").read_text().splitlines()
                self.assertTrue(calls[0].endswith("--namespace-fault gateway-kill"), calls)
                expected = ["core"] if failed_stage == "core" else ["core", "fixture_verify"]
                if failed_stage is None:
                    expected += ["results", "binding-retained"]
                    self.assertIn("protocol-case ssh", calls[2])
                self.assertEqual([row.split()[0] for row in calls], expected)
                self.assertNotIn("lifecycle", "\n".join(calls))

    def test_generic_fixture_phases_keep_the_case_and_explicit_ssh_interpreter(self):
        for case in ("http", "ssh"):
            for phase in ("render", "setup", "verify"):
                with self.subTest(case=case, phase=phase), tempfile.TemporaryDirectory() as td:
                    interpreter = str(Path(td) / "ssh-venv/bin/python") if case == "ssh" else ""
                    result = shell(
                        HOST, 'CI_ROOT=$1/repo; CI_BASE=$1; CI_FIXTURE=$1/private-fixture; '
                              'CI_PROTOCOL_CASE=$2; CI_FIXTURE_PYTHON=$3; '
                              'python3() { printf "%s\\n" "$@" >"$CI_BASE/argv"; return 39; }; '
                              'ci_protocol_fixture "$4"', td, case, interpreter, phase,
                    )
                    self.assertEqual(result.returncode, 39, result.stderr)
                    argv = (Path(td) / "argv").read_text().splitlines()
                    self.assertEqual(argv[:4], [str(Path(td) / "repo/tests/host_upstream_fixture.py"),
                                               phase, "--protocol-case", case])
                    if case == "ssh": self.assertEqual(argv[-2:], ["--python", interpreter])
                    else: self.assertNotIn("--python", argv)

    def test_failed_fixture_verification_never_exports_stale_helper_success(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = root / "private-fixture"
            fixture.mkdir()
            for name in ("runtime-state.json", "fixture-verification.json"):
                (fixture / name).write_text('{"passed":true}')
            result = shell(
                HOST, 'CI_EVIDENCE=$1; CI_FIXTURE=$1/private-fixture; '
                      'ci_protocol_fixture() { return 39; }; ci_protocol_fixture_verify', root,
            )
            self.assertEqual(result.returncode, 39, result.stderr)
            self.assertFalse((root / "runtime-state.json").exists())
            self.assertFalse((root / "fixture-verification.json").exists())

    def test_unpinned_python_is_rejected_before_executing_or_installing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            python = root / "python"
            python.write_text('#!/bin/sh\ntouch "${0%/*}/executed"\n')
            python.chmod(0o700)
            result = shell(
                HOST, 'CI_BASE=$1; CI_PYTHON_BOOTSTRAP=$1/python; '
                      'CI_FIXTURE_PYTHON=$1/ssh-venv/bin/python; ci_ssh_python', root,
            )
            self.assertEqual(result.returncode, 125, result.stderr)
            self.assertFalse((root / "executed").exists())
            self.assertFalse((root / "ssh-venv").exists())

    def test_finish_preserves_core_or_fixture_cleanup_failure(self):
        for status, cleanup in ((0, 0), (39, 0), (0, 23)):
            with self.subTest(status=status, cleanup=cleanup), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                self.completed_evidence(root, "http")
                stages = root / "stages.jsonl"
                stages.write_text("".join(line + "\n" for line in stages.read_text().splitlines()
                                          if json.loads(line)["name"] != "fixture_cleanup"))
                (root / "logs").mkdir()
                (root / "private-fixture").mkdir()
                result = shell(
                    HOST, 'CI_ROOT=$1; CI_EVIDENCE=$1; CI_FIXTURE=$1/private-fixture; '
                          'CI_STAGE=""; CI_STAGE_STARTED=$SECONDS; CI_PROFILE=protocol-case; '
                          'CI_PROTOCOL_CASE=http; CI_PROTOCOL=http; CI_SCENARIO=gateway-kill; '
                          'CI_REPETITIONS=0; CI_REVISION=$4; CI_TEST_CLEANUP=$3; '
                          'ci_snapshot() { :; }; python3() { '
                          'if [[ $1 == "$CI_ROOT/tests/host_upstream_fixture.py" ]]; then '
                          '[[ $2 == cleanup ]] || return 99; return "$CI_TEST_CLEANUP"; '
                          'else command python3 "$@"; fi; }; ci_finish "$2"',
                    root, status, cleanup, "a" * 40,
                )
                expected = status if cleanup == 0 else 1
                self.assertEqual(result.returncode, expected, result.stderr)
                manifest = json.loads((root / "manifest.json").read_text())
                self.assertEqual(manifest["status"], "passed" if expected == 0 else "failed")
                self.assertEqual(manifest["suites"]["lifecycle"]["status"], "not_requested")

    def test_protocol_manifest_can_pass_only_complete_core_and_external_proofs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.completed_evidence(root)
            result = shell(HOST, 'ci_validate_results "$1" protocol-case ssh', root)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = shell(
                HOST, 'ci_write_manifest "$1" 0 ssh gateway-kill 0 "$2" protocol-case ssh',
                root, "a" * 40,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads((root / "manifest.json").read_text())
            self.assertEqual(data["status"], "passed")
            self.assertEqual(data["acceptance_profile"], "protocol-case")
            self.assertEqual(data["protocol_case"], "ssh")
            self.assertEqual(data["suites"]["core"]["total"], 17)
            self.assertEqual(data["suites"]["lifecycle"]["status"], "not_requested")
            self.assertNotIn("passed", data["suites"]["lifecycle"])
            self.assertEqual(data["proofs"]["socket_origin"], True)
            self.assertEqual(data["proofs"]["packet_capture"], True)
            self.assertEqual(data["proofs"]["exit_ip"], True)
            self.assertEqual(data["proofs"]["fixture_verify"], True)

    def test_protocol_evidence_omissions_and_false_claims_fail_closed(self):
        mutations = (
            "missing_core", "duplicate_core", "failed_core", "missing_exit_ip", "exit_mismatch",
            "exit_check_missing", "missing_socket_birth", "same_socket_service", "missing_ss",
            "capture_no_control", "capture_direct_packet", "missing_pcap", "missing_helper",
            "wrong_helper_case", "helper_check_false", "kill_adopted_namespace", "missing_stage",
            "failed_stage", "unexpected_lifecycle", "unknown_profile",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                rows = self.completed_evidence(root)
                details = {row["name"]: row["detail"] for row in rows}
                if mutation == "missing_core": rows.pop()
                elif mutation == "duplicate_core": rows[-1] = rows[0]
                elif mutation == "failed_core": rows[-1]["passed"] = False
                elif mutation == "missing_socket_birth": details["two_session_credentials"][0]["socket_creation"] = None
                elif mutation == "same_socket_service":
                    details["two_session_credentials"][1]["socket_creation"]["cgroup"] = details["two_session_credentials"][0]["socket_creation"]["cgroup"]
                elif mutation == "capture_no_control": details["packet_capture_evidence"]["positive_control_packets"] = 0
                elif mutation == "capture_direct_packet": details["packet_capture_evidence"]["direct_workload_packets"] = 1
                elif mutation == "kill_adopted_namespace": details["gateway-kill"]["init_exit"] = 0
                (root / "core/results.json").write_text(json.dumps(rows))
                if mutation == "missing_exit_ip": (root / "exit-ip/results.json").unlink()
                if mutation in ("exit_mismatch", "exit_check_missing"):
                    path = root / "exit-ip/results.json"
                    value = json.loads(path.read_text())
                    if mutation == "exit_mismatch": value["exit_ip"]["matches"] = False
                    else: value["checks"].pop("fixture_bound_to_source")
                    path.write_text(json.dumps(value))
                if mutation == "missing_ss": (root / "core/session-A-socket-cgroups.log").unlink()
                if mutation == "missing_pcap": (root / "core/gateway-outer.pcap").unlink()
                if mutation == "missing_helper": (root / "fixture-verification.json").unlink()
                if mutation in ("wrong_helper_case", "helper_check_false"):
                    path = root / "fixture-verification.json"
                    value = json.loads(path.read_text())
                    if mutation == "wrong_helper_case": value["protocol_case"] = "http"
                    else: value["checks"]["helper_evidence"] = False
                    path.write_text(json.dumps(value))
                if mutation in ("missing_stage", "failed_stage"):
                    path = root / "stages.jsonl"
                    stages = [json.loads(line) for line in path.read_text().splitlines()]
                    if mutation == "missing_stage": stages = [stage for stage in stages if stage["name"] != "exit_ip"]
                    else: stages[0]["exit_code"] = 23
                    path.write_text("".join(json.dumps(stage) + "\n" for stage in stages))
                if mutation == "unexpected_lifecycle":
                    (root / "lifecycle").mkdir()
                    (root / "lifecycle/results.json").write_text('[{"passed":true}]')
                profile = "unknown" if mutation == "unknown_profile" else "protocol-case"
                result = shell(HOST, 'ci_validate_results "$1" "$2" ssh', root, profile)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                result = shell(
                    HOST, 'ci_write_manifest "$1" 0 ssh gateway-kill 0 "$2" "$3" ssh',
                    root, "a" * 40, profile,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads((root / "manifest.json").read_text())["status"], "failed")

    def test_cleartext_proxy_markers_need_exact_recipe_and_zero_escape_evidence(self):
        for mutation in ("none", "wrong_recipe_policy", "unexpected_outer", "direct_packet",
                         "untyped_dns", "untyped_udp"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                rows = self.completed_evidence(root, "vless")
                capture = next(row['detail'] for row in rows if row['name'] == 'packet_capture_evidence')
                capture.update(payload_marker_policy='encapsulated', plaintext_dns_on_outer=True,
                               plaintext_udp_on_outer=True)
                if mutation == 'wrong_recipe_policy': capture['payload_marker_policy'] = 'absent'
                elif mutation == 'unexpected_outer': capture['unexpected_outer_packets'] = 1
                elif mutation == 'direct_packet': capture['direct_workload_packets'] = 1
                elif mutation == 'untyped_dns': capture['plaintext_dns_on_outer'] = 'true'
                elif mutation == 'untyped_udp': capture['plaintext_udp_on_outer'] = 0
                (root / 'core/results.json').write_text(json.dumps(rows))
                result = shell(HOST, 'ci_validate_results "$1" protocol-case vless', root)
                self.assertEqual(result.returncode == 0, mutation == 'none', result.stderr)

    def test_encrypted_recipe_cannot_opt_into_visible_payloads(self):
        for mutation in ('visible_dns', 'visible_udp', 'weakened_policy'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                rows = self.completed_evidence(root, 'ssh')
                capture = next(row['detail'] for row in rows if row['name'] == 'packet_capture_evidence')
                if mutation == 'visible_dns': capture['plaintext_dns_on_outer'] = True
                elif mutation == 'visible_udp': capture['plaintext_udp_on_outer'] = True
                else: capture['payload_marker_policy'] = 'encapsulated'
                (root / 'core/results.json').write_text(json.dumps(rows))
                result = shell(HOST, 'ci_validate_results "$1" protocol-case ssh', root)
                self.assertNotEqual(result.returncode, 0, result.stderr)

    def test_marker_expectation_is_passed_to_each_native_recipe(self):
        for case in ('vless', 'vless-http', 'vless-ws', 'vless-grpc',
                     'socks5-uot', 'vless-quic', 'vmess', 'trojan', 'https', 'http'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                result = shell(
                    HOST, 'CI_ROOT=$1; CI_EVIDENCE=$1; CI_ACCOUNT=ci-test; CI_PROTOCOL_CASE=$2; '
                          'ci_stage() { printf "%s\\n" "$*" >>"$CI_EVIDENCE/stage-calls"; }; '
                          'cmp() { :; }; ci_protocol_suites', td, case)
                self.assertEqual(result.returncode, 0, result.stderr)
                core = next(line for line in (Path(td) / 'stage-calls').read_text().splitlines()
                            if line.startswith('core '))
                expected = 'encapsulated' if case in (
                    'socks5-uot', 'vless', 'vless-http', 'vless-ws', 'vless-grpc') else 'absent'
                self.assertIn('--payload-marker-policy ' + expected, core)

    @staticmethod
    def anytls_recovery_row(first_passed=False):
        return {"name": "anytls_cancelled_dial_recovery", "passed": True, "detail": {
            "format": 1,
            "first_new_connection": {"status": "passed" if first_passed else "known_watchdog_failure",
                                     "seconds": 0.05 if first_passed else 3.0,
                                     "error_type": None if first_passed else "SSLEOFError"},
            "second_new_connection": ({"status": "not_needed"} if first_passed else
                                      {"status": "passed", "seconds": 0.05}),
            "new_connection_attempts": 1 if first_passed else 2,
            "existing_tls_socket_preserved": True, "policy_and_binding_unchanged": True,
            "no_core_restart_or_pool_reset": True, "recovered": True,
        }}

    def test_anytls_requires_core18_and_records_only_the_declared_recovery_outcomes(self):
        outcomes = ((True, 0.05, None), (False, 2.5, "SSLEOFError"),
                    (False, 3.0, "ConnectionResetError"), (False, 4.0, "EOFError"))
        for first_passed, seconds, error_type in outcomes:
            with self.subTest(first_passed=first_passed, seconds=seconds, error_type=error_type), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                rows = self.completed_evidence(root, 'anytls')
                result = shell(HOST, 'ci_result_report "$1" protocol-case anytls', root)
                self.assertNotEqual(result.returncode, 0, 'Old core17 evidence must not prove AnyTLS recovery')
                row = self.anytls_recovery_row(first_passed)
                row['detail']['first_new_connection'].update(seconds=seconds, error_type=error_type)
                rows.insert(7, row)
                (root / 'core/results.json').write_text(json.dumps(rows))
                stages_path = root / 'stages.jsonl'
                stages = stages_path.read_text().splitlines()
                # The live results command runs before its own stage is
                # recorded; the final manifest runs after fixture cleanup.
                for finished in (len(stages) - 2, len(stages) - 1, len(stages)):
                    stages_path.write_text('\n'.join(stages[:finished]) + '\n')
                    result = shell(HOST, 'ci_result_report "$1" protocol-case anytls', root)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    report = json.loads(result.stdout)
                    self.assertIs(report['proofs']['core18'], True)
                    self.assertNotIn('core17', report['proofs'])
                    self.assertIs(report['proofs']['anytls_cancelled_dial_recovery'], True)
                    self.assertIs(report['proofs']['anytls_stage_order'], True)
                result = shell(HOST, 'ci_write_manifest "$1" 0 anytls gateway-kill 0 "$2" protocol-case anytls', root, 'a' * 40)
                self.assertEqual(result.returncode, 0, result.stderr)
                manifest = json.loads((root / 'manifest.json').read_text())
                self.assertEqual(manifest['status'], 'passed')
                self.assertEqual(manifest['suites']['core']['total'], 18)
                self.assertEqual(manifest['suites']['lifecycle']['status'], 'not_requested')

    def test_anytls_recovery_rejects_unbounded_untyped_or_incomplete_evidence(self):
        mutations = [
            ('format', True), ('format', 1.0), ('new_connection_attempts', 0),
            ('new_connection_attempts', 3), ('new_connection_attempts', True),
            ('new_connection_attempts', 2.0), ('new_connection_attempts', '2'),
            ('first_new_connection.seconds', 2.499), ('first_new_connection.seconds', 4.001),
            ('first_new_connection.seconds', float('nan')), ('first_new_connection.seconds', float('inf')),
            ('first_new_connection.seconds', True), ('first_new_connection.seconds', '3.0'),
            ('first_new_connection.seconds', 10 ** 1000),
            ('first_new_connection.error_type', 'TimeoutError'), ('first_new_connection.error_type', None),
            ('first_new_connection.status', 'failed'), ('first_new_connection.status', 'passed'),
            ('second_new_connection.status', 'failed'), ('second_new_connection.status', 'not_needed'),
            ('second_new_connection.seconds', -0.01), ('second_new_connection.seconds', 8),
            ('second_new_connection.seconds', float('nan')), ('second_new_connection.seconds', float('inf')),
            ('second_new_connection.seconds', True), ('second_new_connection.seconds', '0.05'),
            ('existing_tls_socket_preserved', False), ('policy_and_binding_unchanged', False),
            ('no_core_restart_or_pool_reset', False), ('recovered', False),
            ('extra_retry_allowed', True), ('first_new_connection.extra', True),
            ('second_new_connection.extra', True), ('missing_first_error', None), ('missing_flag', None),
        ]
        for key, value in mutations:
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                rows = self.completed_evidence(root, 'anytls')
                row = self.anytls_recovery_row()
                details = row['detail']
                if key == 'missing_first_error': details['first_new_connection'].pop('error_type')
                elif key == 'missing_flag': details.pop('no_core_restart_or_pool_reset')
                elif '.' in key:
                    parent, field = key.split('.')
                    details[parent][field] = value
                else: details[key] = value
                rows.insert(7, row)
                (root / 'core/results.json').write_text(json.dumps(rows))
                result = shell(HOST, 'ci_result_report "$1" protocol-case anytls', root)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                result = shell(HOST, 'ci_write_manifest "$1" 0 anytls gateway-kill 0 "$2" protocol-case anytls', root, 'a' * 40)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads((root / 'manifest.json').read_text())['status'], 'failed')

        for mutation in ('retry_after_success', 'error_after_success', 'second_has_timing', 'first_over_budget'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                rows = self.completed_evidence(root, 'anytls')
                row = self.anytls_recovery_row(True)
                details = row['detail']
                if mutation == 'retry_after_success': details['new_connection_attempts'] = 2
                elif mutation == 'error_after_success': details['first_new_connection']['error_type'] = 'SSLEOFError'
                elif mutation == 'second_has_timing': details['second_new_connection']['seconds'] = 0
                else: details['first_new_connection']['seconds'] = 8
                rows.insert(7, row)
                (root / 'core/results.json').write_text(json.dumps(rows))
                self.assertNotEqual(shell(HOST, 'ci_validate_results "$1" protocol-case anytls', root).returncode, 0)

    def test_anytls_recovery_cannot_move_after_faults_or_to_a_retry_stage(self):
        for mutation in ('missing_row', 'duplicate_row', 'before_private_denials', 'after_node_fault',
                         'failed_row', 'core_before_exit_ip', 'verify_before_core', 'extra_retry_stage'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                rows = self.completed_evidence(root, 'anytls')
                row = self.anytls_recovery_row()
                rows.insert(7, row)
                if mutation == 'missing_row': rows.pop(7)
                elif mutation == 'duplicate_row': rows.insert(8, row)
                elif mutation == 'before_private_denials': rows[6], rows[7] = rows[7], rows[6]
                elif mutation == 'after_node_fault': rows[7], rows[8] = rows[8], rows[7]
                elif mutation == 'failed_row': row['passed'] = False
                (root / 'core/results.json').write_text(json.dumps(rows))
                path = root / 'stages.jsonl'
                stages = [json.loads(line) for line in path.read_text().splitlines()]
                if mutation in ('core_before_exit_ip', 'verify_before_core'):
                    left, right = ('exit_ip', 'core') if mutation == 'core_before_exit_ip' else ('core', 'fixture_verify')
                    a, b = (next(index for index, stage in enumerate(stages) if stage['name'] == name) for name in (left, right))
                    stages[a], stages[b] = stages[b], stages[a]
                elif mutation == 'extra_retry_stage':
                    stages.insert(9, {'name': 'anytls_retry', 'exit_code': 0})
                path.write_text(''.join(json.dumps(stage) + '\n' for stage in stages))
                self.assertNotEqual(shell(HOST, 'ci_validate_results "$1" protocol-case anytls', root).returncode, 0)

    def test_other_protocols_keep_core17_without_anytls_recovery_exceptions(self):
        for case in ('http', 'ssh', 'trojan'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                rows = self.completed_evidence(root, case)
                result = shell(HOST, 'ci_result_report "$1" protocol-case "$2"', root, case)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertIs(report['proofs']['core17'], True)
                self.assertNotIn('anytls_cancelled_dial_recovery', report['proofs'])
                rows.insert(7, self.anytls_recovery_row())
                (root / 'core/results.json').write_text(json.dumps(rows))
                self.assertNotEqual(shell(HOST, 'ci_validate_results "$1" protocol-case "$2"', root, case).returncode, 0)

    def test_live_matrix_excludes_anytls_and_uses_no_recovery_exception(self):
        workflow = (ROOT / '.github/workflows/host-acceptance.yml').read_text()
        block = workflow.split('  protocol-case:', 1)[1].split('    steps:', 1)[0]
        cases = re.findall(r'^          - ([a-z0-9-]+)$', block, re.MULTILINE)
        self.assertNotIn('anytls', cases)
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                result = shell(
                    HOST, 'CI_ROOT=$1; CI_EVIDENCE=$1; CI_ACCOUNT=ci-test; CI_PROTOCOL_CASE=$2; '
                          'ci_stage() { printf "%s\\n" "$*" >>"$CI_EVIDENCE/calls"; }; '
                          'cmp() { :; }; ci_protocol_suites', td, case)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = (Path(td) / 'calls').read_text().splitlines()
                flagged = [line for line in calls if '--anytls-reuse-check' in line.split()]
                self.assertEqual(flagged, [])

    @staticmethod
    def add_hopping_window(root, case):
        """Synthetic healthy-window proof, distinct from post-fault port totals."""
        value = {
            "format": 1, "protocol_case": case, "passed": True,
            "checks": {name: True for name in (
                "single_tls_socket", "no_reconnect", "window_port_rotation", "workload_identity",
                "workload_cgroup", "session_reclaimed", "binding_retained", "namespace_retained",
                "recipe_unchanged")},
            "evidence": {"window_seconds": 20.1, "exchanges": 11,
                         "observed_hop_ports": [4400, 4410], "connections": 1},
            "identity": {"source_sha256": "a" * 64, "recipe_sha256": "b" * 64,
                         "binding_sha256": "c" * 64, "namespace_identity": "17:42"},
        }
        (root / "hopping-continuity.json").write_text(json.dumps(value))
        (root / "fixture-info.json").write_text(json.dumps({
            "format": 1, "protocol_case": case, "endpoints": [
                {"family": 4, "address": "192.0.2.1", "protocol": "udp", "port_start": start, "port_end": end}
                for start, end in ((4400, 4403), (4410, 4413))],
        }))
        stages = root / "stages.jsonl"
        rows = [json.loads(line) for line in stages.read_text().splitlines()]
        position = next(index for index, row in enumerate(rows) if row["name"] == "core")
        rows.insert(position, {"name": "fixture_continuity", "exit_code": 0})
        stages.write_text("".join(json.dumps(row) + "\n" for row in rows))
        return value

    def test_hopping_requires_healthy_single_socket_proof_beyond_cumulative_ports(self):
        for case in ("hysteria-port-hopping", "hysteria2-port-hopping"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                self.completed_evidence(root, case)
                # A fully successful core and post-fault helper report cannot
                # prove that port rotation occurred within one healthy flow.
                result = shell(HOST, 'ci_validate_results "$1" protocol-case "$2"', root, case)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.add_hopping_window(root, case)
                result = shell(HOST, 'ci_result_report "$1" protocol-case "$2"', root, case)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIs(json.loads(result.stdout)["proofs"]["hopping_continuity"], True)

    def test_hopping_window_missing_weak_or_post_fault_evidence_is_rejected(self):
        mutations = ("missing_proof", "wrong_case", "false_passed", "missing_check", "reconnected",
                     "short_window", "few_exchanges", "multiple_connections", "one_port",
                     "duplicate_ports", "undeclared_port", "missing_ranges", "failed_stage",
                     "missing_stage", "duplicate_stage", "after_core")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                case = "hysteria2-port-hopping"
                self.completed_evidence(root, case)
                value = self.add_hopping_window(root, case)
                if mutation == "wrong_case": value["protocol_case"] = "hysteria-port-hopping"
                elif mutation == "false_passed": value["passed"] = False
                elif mutation == "missing_check": value["checks"].pop("single_tls_socket")
                elif mutation == "reconnected": value["checks"]["no_reconnect"] = False
                elif mutation == "short_window": value["evidence"]["window_seconds"] = 19.9
                elif mutation == "few_exchanges": value["evidence"]["exchanges"] = 10
                elif mutation == "multiple_connections": value["evidence"]["connections"] = 2
                elif mutation == "one_port": value["evidence"]["observed_hop_ports"] = [4400]
                elif mutation == "duplicate_ports": value["evidence"]["observed_hop_ports"] = [4400, 4400]
                elif mutation == "undeclared_port": value["evidence"]["observed_hop_ports"] = [4400, 4443]
                path = root / "hopping-continuity.json"
                path.write_text(json.dumps(value))
                if mutation == "missing_proof": path.unlink()
                if mutation == "missing_ranges": (root / "fixture-info.json").unlink()
                if mutation in ("missing_stage", "failed_stage", "duplicate_stage", "after_core"):
                    stages = root / "stages.jsonl"
                    rows = [json.loads(line) for line in stages.read_text().splitlines()]
                    continuity = next(row for row in rows if row["name"] == "fixture_continuity")
                    if mutation == "missing_stage": rows.remove(continuity)
                    elif mutation == "failed_stage": continuity["exit_code"] = 23
                    elif mutation == "duplicate_stage": rows.append(continuity.copy())
                    else:
                        rows.remove(continuity)
                        rows.append(continuity)
                    stages.write_text("".join(json.dumps(row) + "\n" for row in rows))
                result = shell(HOST, 'ci_validate_results "$1" protocol-case "$2"', root, case)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                result = shell(
                    HOST, 'ci_write_manifest "$1" 0 "$2" gateway-kill 0 "$3" protocol-case "$2"',
                    root, case, "a" * 40,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads((root / "manifest.json").read_text())["status"], "failed")

    def test_continuity_precedes_core_faults_and_failure_stops_the_suite(self):
        for case in ("hysteria-port-hopping", "hysteria2-port-hopping"):
            for continuity_exit in (0, 39):
                with self.subTest(case=case, continuity_exit=continuity_exit), tempfile.TemporaryDirectory() as td:
                    result = shell(
                        HOST, 'CI_ROOT=$1; CI_EVIDENCE=$1; CI_ACCOUNT=ci-test; CI_PROTOCOL_CASE=$2; '
                              'CI_TEST_EXIT=$3; ci_stage() { printf "%s\\n" "$*" >>"$CI_EVIDENCE/calls"; '
                              'if [[ $1 == fixture_continuity ]]; then return "$CI_TEST_EXIT"; fi; }; '
                              'cmp() { :; }; ci_protocol_suites', td, case, continuity_exit,
                    )
                    self.assertEqual(result.returncode, continuity_exit, result.stderr)
                    names = [line.split()[0] for line in (Path(td) / "calls").read_text().splitlines()]
                    self.assertEqual(names, ["fixture_continuity"] if continuity_exit else
                                     ["fixture_continuity", "core", "fixture_verify", "results"])

    def test_hopping_prover_receives_user_and_never_exports_a_failed_attempt(self):
        for status in (0, 39):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                (root / "private-fixture").mkdir()
                proof = root / "private-fixture/hopping-continuity.json"
                proof.write_text('{"synthetic_hopping_proof":true}\n')
                result = shell(
                    HOST, 'CI_BASE=$1; CI_ROOT=$1/repo; CI_FIXTURE=$1/private-fixture; '
                          'CI_EVIDENCE=$1; CI_ACCOUNT=ci-test; CI_PROTOCOL_CASE=hysteria-port-hopping; '
                          'CI_TEST_EXIT=$2; python3() { printf "%s\\n" "$@" >"$CI_BASE/argv"; '
                          'return "$CI_TEST_EXIT"; }; ci_protocol_continuity', root, status,
                )
                self.assertEqual(result.returncode, status, result.stderr)
                argv = (root / "argv").read_text().splitlines()
                self.assertEqual(argv[1], "prove-hopping")
                self.assertEqual(argv[-2:], ["--user", "ci-test"])
                self.assertEqual((root / "hopping-continuity.json").exists(), status == 0)


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
