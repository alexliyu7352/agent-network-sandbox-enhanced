#!/bin/bash
# Real privileged acceptance, ONLY on a fresh disposable CI VM.
# Source this file to test the pure config/result helpers without touching a host.

ci_fail() { printf 'ci-host: %s\n' "$*" >&2; exit 125; }

ci_require_disposable() {
    [[ $EUID == 0 ]] || return 1
    if [[ ${CI_DISPOSABLE_HOST:-} == github-actions ]]; then
        [[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
    elif [[ ${CI_DISPOSABLE_HOST:-} == kvm-guest ]]; then
        # ci-vm.sh creates this guest, SMBIOS marker, and root-private seed.
        # An environment variable alone must never enable provisioning on a VPS.
        [[ ${CI_GITHUB_SHA:-} =~ ^[0-9a-f]{40}$ &&
           $(systemd-detect-virt --vm) == kvm &&
           $(cat /sys/class/dmi/id/product_name) == DevSessionCIVM &&
           ! -L /run/dev-session-ci-kvm &&
           $(stat -c '%u:%a' /run/dev-session-ci-kvm) == 0:600 &&
           $(cat /run/dev-session-ci-kvm) == "$CI_GITHUB_SHA" ]]
    else
        return 1
    fi
}

ci_validate_case() {
    [[ $1 == hysteria2 || $1 == http ]] || return 1
    case $2 in healthy|gateway-stop|gateway-kill|gateway-recreate|docker-restart) ;; *) return 1 ;; esac
    [[ $3 =~ ^[1-9][0-9]{0,2}$ ]] && (( 10#$3 <= 200 ))
}

ci_validate_protocol_case() {
    [[ $1 =~ ^[a-z][a-z0-9-]{0,63}$ ]] || return 1
    python3 "$CI_ROOT/tests/protocol_runtime.py" --list |
        jq -e --arg name "$1" '(.cases + .experimental_cases) | index($name) != null' >/dev/null
}

ci_needs_hopping_continuity() {
    [[ $1 == hysteria-port-hopping || $1 == hysteria2-port-hopping ]]
}

ci_archive_public_config() {
    # Only replace the committed, public example in this fresh private checkout.
    # Never inherit a configuration from the host or overwrite an existing backup.
    python3 - "$CI_ROOT" "$CI_BASE/public-network-example.json" "$CI_REVISION" <<'PY'
import os, pathlib, stat, subprocess, sys
checkout, backup = map(pathlib.Path, sys.argv[1:3])
source = checkout / "network.json"
metadata = source.lstat()
if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
    raise SystemExit("Refusing an untrusted or linked source")
expected = subprocess.check_output(["git", "-C", str(checkout), "show", sys.argv[3] + ":network.json"])
if source.read_bytes() != expected:
    raise SystemExit("Source differs from this commit's public example")
descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "wb") as stream:
    stream.write(expected)
def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)
if identity(source.lstat()) != identity(metadata) or source.read_bytes() != expected:
    raise SystemExit("Source changed during archival")
source.unlink()
PY
}

ci_write_config() {
    # Build a fixture source from literals, never from a user's proxy settings.
    # The self-signed Hy2 certificate belongs only to this disposable fixture.
    jq -n --arg protocol "$1" '
      {log:{level:"warn",timestamp:true},
       dns:{servers:[{type:"udp",tag:"upstream-dns",server:"1.1.1.1",
                     server_port:53,detour:"proxy"}],
            final:"upstream-dns",strategy:"ipv4_only",disable_cache:false,
            disable_expire:false,cache_capacity:4096},
       inbounds:[{type:"tun",tag:"tun-in",interface_name:"tun0",
                  address:["198.18.0.1/15"],mtu:1500,stack:"mixed",
                  auto_route:false,auto_redirect:false,dns_mode:"disabled"}],
       outbounds:[{type:$protocol,tag:"proxy",server:"192.0.2.1",
                   server_port:443,password:"d8-fixture-only-password",
                   bind_interface:"eth0"} +
                  (if $protocol=="hysteria2" then
                     {tls:{enabled:true,insecure:true,alpn:["h3"]}}
                   elif $protocol=="http" then {username:"d8-fixture"}
                   else error("unsupported CI fixture") end)],
       route:{rules:[{inbound:["tun-in"],port:53,action:"hijack-dns"}],final:"proxy"}}
    ' >"$2"
    chmod 600 "$2"
}

ci_record_stage() {
    python3 - "$1" "$2" "$3" "$4" <<'PY'
import datetime, json, pathlib, sys
path, name, status, seconds = sys.argv[1:]
row = {"name": name, "exit_code": int(status), "seconds": int(seconds),
       "status": "passed" if status == "0" else "failed",
       "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
with (pathlib.Path(path) / "stages.jsonl").open("a") as stream:
    stream.write(json.dumps(row) + "\n")
PY
}

ci_result_report() {
    python3 - "$1" "${2:-representative}" "${3:-}" <<'PY'
import json, math, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
profile, case = sys.argv[2:]
suites, proofs, loaded = {}, {}, {}
required = ("core", "lifecycle") if profile != "protocol-case" else ("core",)
for name in required:
    path = root / name / "results.json"
    try:
        if path.is_symlink(): raise ValueError("linked results")
        rows = json.loads(path.read_text())
        if not isinstance(rows, list) or not rows or not all(isinstance(row, dict) for row in rows):
            raise ValueError("empty or invalid results")
        loaded[name] = rows
        passed = sum(row.get("passed") is True for row in rows)
        suites[name] = {"status": "passed" if passed == len(rows) else "failed",
                        "passed": passed, "total": len(rows), "results": str(path.relative_to(root))}
    except FileNotFoundError:
        suites[name] = {"status": "not_run"}
    except (OSError, ValueError, TypeError, AttributeError):
        suites[name] = {"status": "invalid_results"}

def read_json(name):
    path = root / name
    if path.is_symlink(): raise ValueError("linked proof")
    return json.loads(path.read_text())

def artifact(name, minimum=1):
    path = root / name
    return path.is_file() and not path.is_symlink() and path.stat().st_size >= minimum

def proof(name, check):
    try: proofs[name] = check() is True
    except (OSError, ValueError, TypeError, AttributeError, KeyError, IndexError): proofs[name] = False

def flags(value, names):
    return (isinstance(value, dict) and set(names) <= value.keys()
            and all(flag is True for flag in value.values()))

stages = []
try:
    path = root / "stages.jsonl"
    if path.is_symlink(): raise ValueError("linked stages")
    stages = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    stages_valid = all(isinstance(row, dict) and isinstance(row.get("name"), str)
                       and type(row.get("exit_code")) is int and row["exit_code"] == 0 for row in stages)
except (OSError, ValueError, TypeError):
    stages_valid = False

if profile == "protocol-case":
    suites["lifecycle"] = {"status": "not_requested",
                           "scope": "This protocol job runs core faults; the representative jobs run lifecycle stress."}
    expected = (
        "two_session_credentials", "host_loopback", "public_https", "all_dns_destinations_redirected",
        "ordinary_udp_capability", "forced_physical_interface", "private_ipv6_privilege_denials",
        "controlled_upstream_node_outage", "gateway_TUN_link_down", "host_default_route_removed",
        "gateway_half_route_removed", "failed_probe_no_payload", "extra_policy_rule_rejected",
        "writable_policy_rejected", "gateway-kill", "packet_capture_evidence", "shared_rules_unchanged",
    )
    # Retain the strict historical AnyTLS evidence reader. The live inventory
    # and ci_validate_protocol_case reject this protocol after native recovery
    # failed; this branch cannot authorize provisioning or workload admission.
    if case == "anytls":
        expected = expected[:7] + ("anytls_cancelled_dial_recovery",) + expected[7:]
    core_key = "core18" if case == "anytls" else "core17"
    core = loaded.get("core", [])
    proofs[core_key] = tuple(row.get("name") for row in core) == expected
    if not proofs[core_key] and suites["core"]["status"] == "passed":
        suites["core"]["status"] = "invalid_results"
    details = {row.get("name"): row.get("detail") for row in core if isinstance(row.get("name"), str)}

    if case == "anytls":
        def anytls_recovery():
            value = details["anytls_cancelled_dial_recovery"]
            preserved = ("existing_tls_socket_preserved", "policy_and_binding_unchanged",
                         "no_core_restart_or_pool_reset", "recovered")
            if (not isinstance(value, dict) or set(value) != set(preserved) | {
                    "format", "first_new_connection", "second_new_connection", "new_connection_attempts"}
                    or type(value["format"]) is not int or value["format"] != 1
                    or not all(value[name] is True for name in preserved)
                    or type(value["new_connection_attempts"]) is not int): return False
            first, second = value["first_new_connection"], value["second_new_connection"]
            if (not isinstance(first, dict) or set(first) != {"status", "seconds", "error_type"}
                    or not isinstance(second, dict)): return False

            def within_budget(seconds):
                # Bound before isfinite so an arbitrarily large JSON integer
                # cannot overflow float conversion and prevent a failed manifest.
                return type(seconds) in (int, float) and 0 <= seconds < 8 and math.isfinite(seconds)

            if first["status"] == "passed":
                return (value["new_connection_attempts"] == 1 and within_budget(first["seconds"])
                        and first["error_type"] is None and second == {"status": "not_needed"})
            seconds = first["seconds"]
            return (first["status"] == "known_watchdog_failure"
                    and type(seconds) in (int, float) and 2.5 <= seconds <= 4.0 and math.isfinite(seconds)
                    and first["error_type"] in ("SSLEOFError", "ConnectionResetError", "EOFError")
                    and value["new_connection_attempts"] == 2
                    and set(second) == {"status", "seconds"} and second["status"] == "passed"
                    and within_budget(second["seconds"]))
        proof("anytls_cancelled_dial_recovery", anytls_recovery)

    def socket_origin():
        rows = details["two_session_credentials"]
        if not isinstance(rows, list) or len(rows) != 2: return False
        services, inodes = set(), set()
        for row in rows:
            birth = row["socket_creation"]
            if row["cgroup_mode"] != "v2" or birth["created_inside_service"] is not True: return False
            service = birth["cgroup"]
            if not isinstance(service, str) or not re.fullmatch(r"/devsession\.slice/dev-session-[0-9a-f]{32}\.service", service):
                return False
            values = birth["inodes"]
            if not isinstance(values, list) or len(values) != 2 or not all(type(value) is int and value > 0 for value in values):
                return False
            services.add(service); inodes.update(values)
        return (len(services) == 2 and len(inodes) == 4 and
                all(artifact("core/" + name + "-socket-cgroups.log") for name in ("session-A", "session-B")))
    proof("socket_origin", socket_origin)

    def packet_capture():
        capture = details["packet_capture_evidence"]
        # These exact fixtures have no encrypted carrier for UDP payloads.
        # Observed bytes still have to be inside the independently checked
        # authorized outer flow. WebSocket masking is not encryption.
        marker_policy = ("encapsulated" if case in ("socks5-uot", "vless", "vless-http", "vless-ws",
                                                    "vless-grpc") else "absent")
        counts = ("positive_control_packets", "direct_workload_packets", "outer_packets",
                  "redirected_dns_packets", "unexpected_outer_packets")
        return (all(type(capture[name]) is int for name in counts)
                and capture["positive_control_packets"] >= 2 and capture["direct_workload_packets"] == 0
                and capture["outer_packets"] > 0 and capture["redirected_dns_packets"] > 0
                and capture["unexpected_outer_packets"] == 0
                and capture["payload_marker_policy"] == marker_policy
                and all(type(capture[name]) is bool for name in ("plaintext_dns_on_outer", "plaintext_udp_on_outer"))
                and (marker_policy == "encapsulated" or
                     (capture["plaintext_dns_on_outer"] is False and capture["plaintext_udp_on_outer"] is False))
                and all(artifact("core/" + name + ".pcap", 25) for name in
                        ("physical-direct-probes", "gateway-outer", "redirected-dns")))
    proof("packet_capture", packet_capture)

    def exit_ip():
        value = read_json("exit-ip/results.json")
        address = value["exit_ip"]
        return (value["format"] == 1 and value["passed"] is True and address["valid_ipv4"] is True
                and type(address["family"]) is int and address["family"] == 4 and address["matches"] is True
                and flags(value["checks"], ("workload_identity", "workload_cgroup", "session_reclaimed",
                          "postcheck", "binding_retained", "fixture_bound_to_source", "owned_upstream_namespace")))
    proof("exit_ip", exit_ip)

    def fixture_verify():
        value = read_json("fixture-verification.json")
        return (value["format"] == 1 and value["protocol_case"] == case and value["passed"] is True
                and flags(value["checks"], ("source_unchanged", "recipe_unchanged", "namespace_owned",
                          "services_active", "helper_evidence")))
    proof("fixture_verify", fixture_verify)

    def namespace_fault():
        value = details["gateway-kill"]
        names = ("namespace_changed", "binding_and_guards_retained", "offline_rebind_required",
                 "existing_connection_blocked_during_fault", "new_connection_blocked_during_fault",
                 "other_session_loopback_alive")
        return all(value[name] is True for name in names) and value["check_exit"] == value["init_exit"] == 125
    proof("namespace_fault", namespace_fault)
    proofs["lifecycle_not_requested"] = not (root / "lifecycle").exists()
    required_stages = ["dependencies", "offline", "offline_helpers", "docker_backend", "fixture_engine",
                       "fixture_render", "fixture", "exit_ip", "core", "fixture_verify"]
    if case == "ssh": required_stages.append("fixture_python")
    recorded = [row.get("name") for row in stages if isinstance(row, dict)]
    if case == "anytls":
        # Recovery is one row inside the original core run. A separate retry
        # stage or a reordered healthy/fault phase cannot supply this proof.
        # The report also runs before results and fixture_cleanup are recorded.
        proofs["anytls_stage_order"] = stages_valid and recorded in (
            required_stages, required_stages + ["results"],
            required_stages + ["results", "fixture_cleanup"],
        )
    if case in ("hysteria-port-hopping", "hysteria2-port-hopping"):
        required_stages.append("fixture_continuity")
        def hopping_continuity():
            value = read_json("hopping-continuity.json")
            names = ("single_tls_socket", "no_reconnect", "window_port_rotation", "workload_identity",
                     "workload_cgroup", "session_reclaimed", "binding_retained", "namespace_retained",
                     "recipe_unchanged")
            if (type(value["format"]) is not int or value["format"] != 1 or value["protocol_case"] != case
                    or value["passed"] is not True or not flags(value["checks"], names)): return False
            evidence = value["evidence"]
            duration, exchanges, connections = (evidence[name] for name in ("window_seconds", "exchanges", "connections"))
            if not (type(duration) in (int, float) and math.isfinite(duration) and duration >= 20
                    and type(exchanges) is int and exchanges >= 11
                    and type(connections) is int and connections == 1): return False
            ports = evidence["observed_hop_ports"]
            if not (isinstance(ports, list) and len(ports) >= 2
                    and all(type(port) is int and 1 <= port <= 65535 for port in ports)
                    and len(set(ports)) == len(ports)): return False
            info = read_json("fixture-info.json")
            endpoints = info["endpoints"]
            if not (type(info["format"]) is int and info["format"] == 1 and info["protocol_case"] == case
                    and isinstance(endpoints, list) and endpoints): return False
            if not all(entry["family"] == 4 and entry["protocol"] == "udp"
                       and type(entry["port_start"]) is int and type(entry["port_end"]) is int
                       and 1 <= entry["port_start"] <= entry["port_end"] <= 65535 for entry in endpoints): return False
            return all(any(entry["port_start"] <= port <= entry["port_end"] for entry in endpoints) for port in ports)
        proof("hopping_continuity", hopping_continuity)
        proof("hopping_before_faults", lambda: recorded.index("exit_ip") < recorded.index("fixture_continuity") < recorded.index("core"))
    proofs["required_stages"] = stages_valid and all(recorded.count(name) == 1 for name in required_stages)

passed = (profile in ("representative", "protocol-case") and stages_valid
          and all(suites[name]["status"] == "passed" for name in required) and all(proofs.values()))
report = {"passed": passed, "suites": suites, "proofs": proofs, "stages": stages}
print(json.dumps(report))
raise SystemExit(0 if passed else 1)
PY
}

ci_validate_results() { ci_result_report "$@" >/dev/null; }

ci_write_manifest() {
    local report
    report=$(ci_result_report "$1" "${7:-representative}" "${8:-}") || :
    python3 - "$1" "$2" "$3" "$4" "$5" "$6" "${7:-representative}" "${8:-}" "$report" <<'PY'
import datetime, hashlib, json, pathlib, sys
directory, status, protocol, scenario, repetitions, revision, profile, case, report = sys.argv[1:]
root = pathlib.Path(directory)
report = json.loads(report)
suites, stages = report["suites"], report["stages"]
passed = status == "0" and report["passed"]
if profile == "protocol-case":
    names = [row.get("name") for row in stages if isinstance(row, dict)]
    passed = (passed and scenario == "gateway-kill" and repetitions == "0" and protocol == case
              and names.count("results") == names.count("fixture_cleanup") == 1)
files = []
for path in sorted(root.rglob("*")):
    if path.is_file() and not path.is_symlink() and path.name != "manifest.json":
        files.append({"path": str(path.relative_to(root)), "bytes": path.stat().st_size,
                      "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
manifest = {"format": 1, "status": "passed" if passed else "failed", "exit_code": int(status),
            "revision": revision, "protocol": protocol, "scenario": scenario,
            "acceptance_profile": profile, "protocol_case": case or None,
            "repetitions": int(repetitions), "required_cgroup": "v2",
            "suites": suites, "proofs": report["proofs"], "stages": stages, "evidence": files,
            "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "scope": "This job only; other operating systems and protocols are not implied."}
temp = root / ".manifest.tmp"
temp.write_text(json.dumps(manifest, indent=2) + "\n")
temp.replace(root / "manifest.json")
PY
}

ci_stage() {
    CI_STAGE=$1; shift
    CI_STAGE_STARTED=$SECONDS
    printf 'CI_STAGE=%s\n' "$CI_STAGE"
    # Do not put the tested command in if/||: doing so disables Bash errexit
    # inside shell functions and can turn a failed setup into a passing stage.
    "$@" 2>&1 | tee "$CI_EVIDENCE/logs/$CI_STAGE.log"
    ci_record_stage "$CI_EVIDENCE" "$CI_STAGE" 0 "$((SECONDS-CI_STAGE_STARTED))"
    CI_STAGE=''
}

ci_offline_helpers() {
    # unittest discovery only loads test_*.py. These host tools also contain
    # pure regression cases and must pass before any privileged fixture setup.
    env PYTHONPATH="$CI_ROOT/tests" timeout --signal=TERM --kill-after=10s 2m \
        python3 -m unittest -v host_acceptance host_upstream_fixture host_lifecycle
}

ci_packages() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl git jq python3 \
        iproute2 iptables util-linux procps sudo tcpdump openssl kmod
    # Ubuntu2604-Readme.md lists Docker Engine and Compose on the hosted image;
    # ci-vm.sh installs the official Docker packages before entering a guest.
    # Fail explicitly if that contract changes; never run a downloaded installer.
    command -v dockerd
    docker compose version
    [[ $(findmnt -n -o FSTYPE /sys/fs/cgroup) == cgroup2 ]]
    [[ -z $(findmnt -rn -t cgroup -o TARGET) ]]
    [[ $(cat /proc/1/comm) == systemd ]]
    modprobe tun
    modprobe xt_cgroup
    modprobe br_netfilter
}

ci_docker_legacy() {
    local containers
    containers=$(docker ps -aq)
    [[ -z $containers ]] || ci_fail 'Runner already contains containers; refusing to reuse it'
    systemctl stop docker.service docker.socket
    update-alternatives --set iptables /usr/sbin/iptables-legacy
    update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
    # A pristine hosted image can have Docker's earlier nft FORWARD policy.
    # It would still drop legacy forwarding even after switching alternatives.
    # Preserve every existing rule; change only this disposable VM's policy,
    # before creating any fixture, gateway, binding, or sandbox workload.
    iptables-nft -w 5 -S FORWARD >"$CI_EVIDENCE/initial-nft-forward.txt"
    iptables-nft -w 5 -P FORWARD ACCEPT
    python3 - <<'PY'
import json, pathlib
path = pathlib.Path("/etc/docker/daemon.json")
config = json.loads(path.read_text()) if path.exists() else {}
config.update({"firewall-backend": "iptables", "iptables": True, "ip6tables": True,
               "ip-forward": True, "live-restore": False})
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(config, indent=2) + "\n")
PY
    dockerd --validate --config-file=/etc/docker/daemon.json
    systemctl start docker.service
    docker info --format '{{.CgroupVersion}} {{.CgroupDriver}}' | tee "$CI_EVIDENCE/docker-cgroup.txt"
    [[ $(docker info --format '{{.CgroupVersion}}') == 2 ]]
    [[ $(iptables --version) == *legacy* && $(ip6tables --version) == *legacy* ]]
    iptables-legacy -w 5 -S DOCKER-USER
}

ci_failed_init_diagnostics() {
    # Inspect only the CI-owned gateway and already selected fake source.
    # This never retries init, creates a binding, or repairs rules/routes.
    python3 - "$CI_ROOT" "$CI_EVIDENCE" <<'PY'
import ipaddress, json, os, pathlib, re, subprocess, sys
checkout, evidence = map(pathlib.Path, sys.argv[1:])
data = {}

def read_json(argv):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, text=True,
                                capture_output=True, timeout=20)
        if result.returncode == 0:
            return json.loads(result.stdout), {"exit_code": 0}
        return None, {"exit_code": result.returncode}
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        return None, {"error": type(error).__name__}

def identity(path):
    try:
        status = path.stat()
        return {"device_inode": f"{status.st_dev}:{status.st_ino}"}
    except OSError as error:
        return {"error": type(error).__name__}

info, data["container_read"] = read_json(["docker", "inspect", "worker"])
if isinstance(info, list) and len(info) == 1 and isinstance(info[0], dict):
    source = info[0]
    host = source.get("HostConfig", {})
    settings = source.get("NetworkSettings", {})
    # Never retain Config.Env, command arguments, labels, or source credentials.
    data["container"] = {
        "Id": source.get("Id"),
        "State": {key: source.get("State", {}).get(key) for key in ("Running", "Pid", "Status")},
        "HostConfig": {key: host.get(key) for key in (
            "CapDrop", "CapAdd", "SecurityOpt", "Sysctls", "ReadonlyRootfs",
            "Privileged", "NetworkMode", "UsernsMode")},
        "Mounts": [{key: mount.get(key) for key in
                    ("Type", "Source", "Destination", "RW", "Mode", "Propagation")}
                   for mount in source.get("Mounts", [])],
        "NetworkSettings": {key: settings.get(key) for key in ("SandboxID", "SandboxKey", "Networks")},
    }
    pid = source.get("State", {}).get("Pid")
    if isinstance(pid, int) and pid > 0:
        proc = pathlib.Path("/proc") / str(pid)
        process = {"pid": pid, "net_namespace": identity(proc / "ns/net")}
        try:
            process["credentials"] = {
                key: value.strip() for key, value in
                (line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
                if key in ("Uid", "Gid", "CapEff", "NSpid", "Seccomp")
            }
            process["cgroup"] = (proc / "cgroup").read_text()
        except OSError as error:
            process["read_error"] = type(error).__name__
        data["process"] = process
    sandbox = settings.get("SandboxKey")
    if isinstance(sandbox, str) and re.fullmatch(r"/(?:var/)?run/docker/netns/[A-Za-z0-9_-]+", sandbox):
        data["sandbox_namespace"] = identity(pathlib.Path(sandbox))
    networks = settings.get("Networks")
    if isinstance(networks, dict) and len(networks) == 1:
        endpoint = next(iter(networks.values()))
        nid = endpoint.get("NetworkID")
        if isinstance(nid, str) and re.fullmatch(r"[0-9a-f]{64}", nid):
            net, data["network_read"] = read_json(["docker", "network", "inspect", nid])
            if isinstance(net, list) and len(net) == 1 and isinstance(net[0], dict):
                net = net[0]
                data["network"] = {key: net.get(key) for key in ("Id", "Driver", "EnableIPv6", "Options")}
                data["network"]["container_ids"] = sorted((net.get("Containers") or {}).keys())
                bridge = (net.get("Options") or {}).get("com.docker.network.bridge.name") or "br-" + nid[:12]
                if isinstance(bridge, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,15}", bridge):
                    data["bridge"] = {
                        "name": bridge,
                        "kernel_bridge_present": (pathlib.Path("/sys/class/net") / bridge / "bridge").is_dir(),
                    }
                    data["bridge"]["link"], data["bridge"]["read"] = read_json(
                        ["ip", "-j", "link", "show", "dev", bridge])
        try:
            address = str(ipaddress.IPv4Address(endpoint.get("IPAddress")))
        except (ValueError, TypeError):
            address = None
        if address is not None:
            data["host_route_get"], data["host_route_read"] = read_json(
                ["ip", "-j", "-4", "route", "get", address])
data["host_namespaces"] = {name: identity(pathlib.Path("/proc/1/ns") / name)
                           for name in ("net", "pid", "cgroup")}

# These library calls read configuration, hold a namespace FD, and verify
# existing state. None calls policy/cgroup installation or admits forwarding.
phases = ("read_proxy_policy", "gateway_open", "gateway_verify")
data["phase_checks"] = {name: {"status": "not_run"} for name in phases}
script = r'''
set -u -o pipefail
ROOT=$1
source "$ROOT/lib/host.sh" || exit 121
source "$ROOT/lib/network.sh" || exit 121
GATEWAY=worker
for phase in read_proxy_policy gateway_open gateway_verify; do
    if [[ $phase == read_proxy_policy ]]; then
        "$phase" "$ROOT/network.json" >/dev/null 2>&1
    else
        "$phase" >/dev/null 2>&1
    fi
    phase_status=$?
    printf '%s\t%s\n' "$phase" "$phase_status"
    (( phase_status == 0 )) || exit 0
done
'''
try:
    result = subprocess.run(
        ["/bin/bash", "-p", "-c", script, "ci-read-only-diagnostics", str(checkout)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, timeout=90, env={"PATH": os.environ["PATH"], "LC_ALL": "C", "HOME": "/root"})
    data["phase_runner_exit_code"] = result.returncode
    for line in result.stdout.splitlines():
        name, separator, status = line.partition("\t")
        if separator and name in phases and re.fullmatch(r"[0-9]{1,3}", status):
            data["phase_checks"][name] = {
                "exit_code": int(status), "status": "passed" if status == "0" else "failed"}
except (OSError, subprocess.TimeoutExpired) as error:
    data["phase_runner_error"] = type(error).__name__
(evidence / "init-diagnostics.json").write_text(json.dumps(data, indent=2) + "\n")
print("CI_INIT_DIAGNOSTICS=" + json.dumps(data["phase_checks"], sort_keys=True))
PY
}

ci_initialize() {
    local status=0
    "$CI_ROOT/dev-session" init || status=$?
    if (( status != 0 )); then ci_failed_init_diagnostics || :; fi
    return "$status"
}

ci_ssh_python() {
    # setup-python is pinned in the workflow. System Python 3.14 is kept intact;
    # cffi 1.17.1 publishes a regular CPython 3.13 wheel, not a 3.14 wheel.
    [[ $CI_PYTHON_BOOTSTRAP =~ ^/opt/hostedtoolcache/Python/3\.13\.16/x64/bin/python(3(\.13)?)?$ &&
       -x $CI_PYTHON_BOOTSTRAP && ! -e $CI_BASE/ssh-venv ]] || ci_fail 'Require the selected official Python 3.13.16 runtime'
    "$CI_PYTHON_BOOTSTRAP" -I -c 'import platform,sys,sysconfig; assert sys.version_info[:3]==(3,13,16) and platform.python_implementation()=="CPython" and not sysconfig.get_config_var("Py_GIL_DISABLED")'
    "$CI_PYTHON_BOOTSTRAP" -I -m venv --copies "$CI_BASE/ssh-venv"
    "$CI_FIXTURE_PYTHON" -I -m pip --isolated --disable-pip-version-check install \
        --only-binary=:all: --no-deps --no-cache-dir --index-url https://pypi.org/simple pip==25.1.1
    "$CI_FIXTURE_PYTHON" -I -m pip --isolated --disable-pip-version-check install \
        --only-binary=:all: --no-deps --no-cache-dir --index-url https://pypi.org/simple \
        --report "$CI_EVIDENCE/ssh-pip-report.json" \
        paramiko==3.5.1 cryptography==44.0.3 bcrypt==4.1.3 PyNaCl==1.5.0 cffi==1.17.1 pycparser==2.22
    "$CI_FIXTURE_PYTHON" -I -m pip --isolated --disable-pip-version-check check
    "$CI_FIXTURE_PYTHON" -I - "$CI_EVIDENCE/ssh-python.json" <<'PY'
import importlib.metadata, json, pathlib, sys, sysconfig
expected = {"pip": "25.1.1", "paramiko": "3.5.1", "cryptography": "44.0.3", "bcrypt": "4.1.3",
            "PyNaCl": "1.5.0", "cffi": "1.17.1", "pycparser": "2.22"}
versions = {name: importlib.metadata.version(name) for name in expected}
assert versions == expected and sys.version_info[:3] == (3, 13, 16)
assert sys.prefix != sys.base_prefix and not sysconfig.get_config_var("Py_GIL_DISABLED")
result = {"python_version": sys.version, "executable": sys.executable, "prefix": sys.prefix,
          "base_prefix": sys.base_prefix, "packages": versions, "isolated_venv": True}
pathlib.Path(sys.argv[1]).write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result))
PY
    timeout --signal=TERM --kill-after=10s 5m "$CI_FIXTURE_PYTHON" -I -m unittest discover \
        -s "$CI_ROOT/tests" -p 'test_protocol*.py' -v
}

ci_build_worker() {
    local extract
    docker compose --project-directory "$CI_ROOT" build --pull worker
    extract=$(docker create --name d8-ci-engine-extract --entrypoint /bin/true worker:1.14.2-v8)
    docker cp "$extract:/usr/local/bin/worker" "$CI_BASE/worker"
    docker rm "$extract"
    chmod 700 "$CI_BASE/worker"
    "$CI_BASE/worker" version | tee "$CI_EVIDENCE/worker-version.txt"
    [[ $(head -n 1 "$CI_EVIDENCE/worker-version.txt") == 'sing-box version 1.14.2' ]]
    python3 - "$CI_EVIDENCE/worker-version.txt" <<'PY'
import pathlib, sys
assert "af6e64c3b69e6132ebaee0e1a3d24e93903f6709" in pathlib.Path(sys.argv[1]).read_text()
PY
    sha256sum "$CI_BASE/worker" >"$CI_EVIDENCE/worker-sha256.txt"
}

ci_protocol_fixture() {
    local action=$1; shift
    local -a python_option=()
    if [[ -n ${CI_FIXTURE_PYTHON:-} ]]; then python_option=(--python "$CI_FIXTURE_PYTHON"); fi
    python3 "$CI_ROOT/tests/host_upstream_fixture.py" "$action" \
        --protocol-case "$CI_PROTOCOL_CASE" --config "$CI_ROOT/network.json" \
        --engine "$CI_BASE/worker" --output "$CI_FIXTURE" "${python_option[@]}" "$@"
}

ci_protocol_render() {
    ci_archive_public_config
    ci_protocol_fixture render
}

ci_protocol_fixture_verify() {
    ci_protocol_fixture verify
    # Only these documented, address/auth-free helper summaries are exported.
    # Server configs, host keys, certificates, and the descriptor stay private.
    install -m 600 "$CI_FIXTURE/runtime-state.json" "$CI_EVIDENCE/runtime-state.json"
    install -m 600 "$CI_FIXTURE/fixture-verification.json" "$CI_EVIDENCE/fixture-verification.json"
}

ci_protocol_continuity() {
    ci_needs_hopping_continuity "$CI_PROTOCOL_CASE" || ci_fail 'Continuity proof requires an explicit hopping case'
    ci_protocol_fixture prove-hopping --user "$CI_ACCOUNT"
    # This contains only flags, counts, hashes and namespace identity. A failed
    # prover cannot export a stale report or proceed into the fault suite.
    install -m 600 "$CI_FIXTURE/hopping-continuity.json" "$CI_EVIDENCE/hopping-continuity.json"
}

ci_fixture() {
    if [[ ${CI_PROFILE:-representative} == representative ]]; then
        ci_write_config "$CI_PROTOCOL" "$CI_ROOT/network.json"
    fi
    # Both real suites invoke this private manager by absolute path. Hosted
    # images may have a runner-writable /usr/local/bin; keep installer trust
    # checks intact and avoid publishing a launcher there.
    "$CI_ROOT/install-dev-session.sh" --no-link
    useradd --create-home --user-group --shell /bin/bash "$CI_ACCOUNT"
    passwd --lock "$CI_ACCOUNT"
    chmod 700 "/home/$CI_ACCOUNT"
    printf '%s ALL=(root) NOPASSWD: %s/dev-session *\n' "$CI_ACCOUNT" "$CI_ROOT" \
        >/etc/sudoers.d/dev-session-ci
    chmod 440 /etc/sudoers.d/dev-session-ci
    visudo -cf /etc/sudoers.d/dev-session-ci
    if [[ ${CI_PROFILE:-representative} == protocol-case ]]; then
        ci_protocol_fixture setup
    else
        ci_build_worker
        python3 "$CI_ROOT/tests/host_upstream_fixture.py" setup \
            --config "$CI_ROOT/network.json" --engine "$CI_BASE/worker" --output "$CI_FIXTURE" \
            --udp-echo-address 192.0.2.254 --udp-echo-port 40123
    fi
    cp "$CI_FIXTURE/fixture-info.json" "$CI_EVIDENCE/fixture-info.json"
    docker compose --project-directory "$CI_ROOT" up -d --no-build worker
    local ready=false attempt
    for ((attempt=0; attempt<90; attempt++)); do
        if docker exec worker test -s /run/worker/policy-ready 2>/dev/null; then ready=true; break; fi
        sleep 1
    done
    [[ $ready == true ]] || ci_fail 'Gateway never published readiness'
    ci_initialize
    if [[ ${CI_PROFILE:-representative} == protocol-case ]]; then
        local policy
        policy=$(jq -ceS --arg mode policy -f "$CI_ROOT/gateway-policy.jq" "$CI_ROOT/network.json")
        jq -e --argjson expected "$policy" \
            '.format==2 and .cgroup.mode=="v2" and .proxy_policy==$expected' \
            /run/dev-session-v8/binding >/dev/null
    else
        jq -e --arg protocol "$CI_PROTOCOL" '
          .format==2 and .cgroup.mode=="v2" and
          (if $protocol=="http" then .proxy_policy.payload_networks==["tcp"] and
                .proxy_policy.dns_transport=="https"
           else .proxy_policy.payload_networks==["tcp","udp"] and
                .proxy_policy.dns_transport=="udp" end)
        ' /run/dev-session-v8/binding >/dev/null
    fi
    cp /run/dev-session-v8/binding "$CI_EVIDENCE/binding-initial.json"
}

ci_suites() {
    local core_fault=none lifecycle_fault=none
    local -a core_options=()
    case $CI_SCENARIO in
        gateway-stop|gateway-kill|gateway-recreate) core_fault=$CI_SCENARIO ;;
        docker-restart) lifecycle_fault=docker-restart ;;
    esac
    if [[ $core_fault == gateway-recreate ]]; then
        # ci_fixture creates this single-service project in CI_ROOT=.../repo.
        # The core harness independently verifies its container ownership.
        core_options=(--compose-project repo)
    fi
    # A namespace-changing fault is always LAST. The process never removes a
    # binding or retries init to accept the replacement namespace afterward.
    if [[ $core_fault != none ]]; then
        ci_stage lifecycle timeout --signal=TERM --kill-after=30s 20m \
            python3 "$CI_ROOT/tests/host_lifecycle.py" --user "$CI_ACCOUNT" \
            --output "$CI_EVIDENCE/lifecycle" --repetitions "$CI_REPETITIONS" \
            --udp-echo 192.0.2.254:40123 --namespace-fault none
    fi
    ci_stage core timeout --signal=TERM --kill-after=30s 20m \
        python3 "$CI_ROOT/tests/host_acceptance.py" --user "$CI_ACCOUNT" \
        --output "$CI_EVIDENCE/core" "${core_options[@]}" \
        --udp-echo 192.0.2.254:40123 --namespace-fault "$core_fault"
    if [[ $core_fault == none ]]; then
        ci_stage lifecycle timeout --signal=TERM --kill-after=30s 20m \
            python3 "$CI_ROOT/tests/host_lifecycle.py" --user "$CI_ACCOUNT" \
            --output "$CI_EVIDENCE/lifecycle" --repetitions "$CI_REPETITIONS" \
            --udp-echo 192.0.2.254:40123 --namespace-fault "$lifecycle_fault"
    fi
    ci_stage results ci_validate_results "$CI_EVIDENCE"
    cmp /run/dev-session-v8/binding "$CI_EVIDENCE/binding-initial.json"
    if [[ $CI_SCENARIO == healthy ]]; then "$CI_ROOT/dev-session" check; fi
}

ci_protocol_suites() {
    local marker_policy=absent
    case "$CI_PROTOCOL_CASE" in
        socks5-uot|vless|vless-http|vless-ws|vless-grpc) marker_policy=encapsulated ;;
    esac
    # main has already completed exit-IP. Observe real rotation on one healthy
    # socket before a node outage or gateway kill could create another flow.
    if ci_needs_hopping_continuity "$CI_PROTOCOL_CASE"; then
        ci_stage fixture_continuity ci_protocol_continuity
    fi
    # All transport cases get node/TUN/route faults plus old/new connection
    # refusal on gateway kill. No lifecycle stress or namespace adoption follows.
    ci_stage core timeout --signal=TERM --kill-after=30s 20m \
        python3 "$CI_ROOT/tests/host_acceptance.py" --user "$CI_ACCOUNT" \
        --output "$CI_EVIDENCE/core" --udp-echo 192.0.2.254:40123 \
        --payload-marker-policy "$marker_policy" --namespace-fault gateway-kill
    ci_stage fixture_verify ci_protocol_fixture_verify
    ci_stage results ci_validate_results "$CI_EVIDENCE" protocol-case "$CI_PROTOCOL_CASE"
    cmp /run/dev-session-v8/binding "$CI_EVIDENCE/binding-initial.json"
}

ci_snapshot() {
    python3 - "$CI_EVIDENCE" <<'PY'
import json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
commands = [
    ["uname", "-a"], ["python3", "--version"], ["systemctl", "--version"], ["iptables-legacy", "--version"],
    ["ip6tables-legacy", "--version"], ["docker", "version"], ["docker", "compose", "version"],
    ["findmnt", "--json", "--list", "--types", "cgroup,cgroup2", "--output", "TARGET,FSTYPE,FSROOT,OPTIONS"],
    ["systemctl", "show", "devsession.slice", "--property=ActiveState,ControlGroup,FragmentPath"],
    ["systemctl", "list-units", "--all", "--plain", "--no-legend", "dev-session-*.service"],
    ["docker", "inspect", "-f", "{{.Id}} {{.State.Pid}} {{.State.Running}} {{.Image}}", "worker"],
    ["docker", "image", "inspect", "-f", "{{.Id}} {{json .RepoDigests}}", "ghcr.io/sagernet/sing-box:v1.14.2"],
    ["ip", "-N", "-j", "-4", "rule", "show"], ["ip", "-j", "-4", "route", "show", "table", "32190"],
    ["iptables-legacy-save"], ["ip6tables-legacy-save"], ["docker", "logs", "--tail=150", "worker"],
]
rows = []
for argv in commands:
    try:
        result = subprocess.run(argv, text=True, capture_output=True, timeout=20)
        rows.append({"argv": argv, "exit_code": result.returncode,
                     "stdout": result.stdout, "stderr": result.stderr})
    except (OSError, subprocess.TimeoutExpired) as error:
        rows.append({"argv": argv, "error": str(error)})
(root / "environment.json").write_text(json.dumps({
    "os_release": pathlib.Path("/etc/os-release").read_text(),
    "pid1_cgroup": pathlib.Path("/proc/1/cgroup").read_text(), "commands": rows}, indent=2) + "\n")
binding = pathlib.Path("/run/dev-session-v8/binding")
if binding.exists():
    (root / "binding-final.json").write_bytes(binding.read_bytes())
PY
}

ci_finish() {
    local status=$1 cleanup_status=0
    trap - EXIT HUP INT TERM
    set +e
    if [[ -n $CI_STAGE ]]; then
        ci_record_stage "$CI_EVIDENCE" "$CI_STAGE" "$status" "$((SECONDS-CI_STAGE_STARTED))"
    fi
    ci_snapshot
    if [[ -d $CI_FIXTURE ]]; then
        python3 "$CI_ROOT/tests/host_upstream_fixture.py" cleanup --output "$CI_FIXTURE" \
            >"$CI_EVIDENCE/logs/fixture-cleanup.log" 2>&1
        cleanup_status=$?
        ci_record_stage "$CI_EVIDENCE" fixture_cleanup "$cleanup_status" 0
    fi
    (( cleanup_status == 0 )) || status=1
    ci_validate_results "$CI_EVIDENCE" "$CI_PROFILE" "$CI_PROTOCOL_CASE" >/dev/null 2>&1 || status=1
    ci_write_manifest "$CI_EVIDENCE" "$status" "$CI_PROTOCOL" "$CI_SCENARIO" \
        "$CI_REPETITIONS" "$CI_REVISION" "$CI_PROFILE" "$CI_PROTOCOL_CASE" || status=1
    # Leave the gateway, slice, firewall and binding in place until the hosted
    # VM is destroyed. Cleanup only owns the separately created upstream fixture.
    exit "$status"
}

ci_main() {
    set -euo pipefail
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
    umask 077
    ci_require_disposable ||
        ci_fail 'This script requires an explicitly marked disposable GitHub-hosted VM'
    CI_PROTOCOL=''; CI_SCENARIO=''; CI_REPETITIONS=100; CI_PROTOCOL_CASE=''
    CI_PROFILE=representative; CI_PYTHON_BOOTSTRAP=''; CI_FIXTURE_PYTHON=''
    local repetitions_set=false
    while (( $# )); do
        case $1 in
            --protocol) [[ $# -ge 2 ]] || ci_fail 'Missing protocol'; CI_PROTOCOL=$2; shift 2 ;;
            --scenario) [[ $# -ge 2 ]] || ci_fail 'Missing scenario'; CI_SCENARIO=$2; shift 2 ;;
            --repetitions) [[ $# -ge 2 ]] || ci_fail 'Missing repetitions'; CI_REPETITIONS=$2; repetitions_set=true; shift 2 ;;
            --protocol-case) [[ $# -ge 2 && -z $CI_PROTOCOL_CASE ]] || ci_fail 'Missing or duplicate protocol case'; CI_PROTOCOL_CASE=$2; shift 2 ;;
            --fixture-python) [[ $# -ge 2 && -z $CI_PYTHON_BOOTSTRAP ]] || ci_fail 'Missing or duplicate fixture Python'; CI_PYTHON_BOOTSTRAP=$2; shift 2 ;;
            *) ci_fail 'Usage: ci-host.sh --protocol hysteria2|http --scenario healthy|gateway-stop|gateway-kill|gateway-recreate|docker-restart [--repetitions 1..200], or --protocol-case CASE [--fixture-python OFFICIAL_PYTHON_3_13_16]' ;;
        esac
    done
    CI_BASE=/root/dev-session-ci; CI_ROOT=$CI_BASE/repo
    if [[ -n $CI_PROTOCOL_CASE ]]; then
        [[ -z $CI_PROTOCOL && -z $CI_SCENARIO && $repetitions_set == false ]] ||
            ci_fail 'Protocol-case jobs fix the fault to gateway-kill and do not request lifecycle repetitions'
        if [[ $CI_PROTOCOL_CASE == ssh ]]; then
            [[ -n $CI_PYTHON_BOOTSTRAP ]] || ci_fail 'SSH requires an explicit official Python 3.13.16 runtime'
            CI_FIXTURE_PYTHON=$CI_BASE/ssh-venv/bin/python
        else
            [[ -z $CI_PYTHON_BOOTSTRAP ]] || ci_fail 'A fixture Python override is only used by the SSH case'
        fi
        CI_PROFILE=protocol-case; CI_PROTOCOL=$CI_PROTOCOL_CASE; CI_SCENARIO=gateway-kill; CI_REPETITIONS=0
    else
        [[ -z $CI_PYTHON_BOOTSTRAP ]] || ci_fail 'A fixture Python override requires the SSH protocol case'
        ci_validate_case "$CI_PROTOCOL" "$CI_SCENARIO" "$CI_REPETITIONS" || ci_fail 'Invalid CI case'
    fi
    CI_EVIDENCE=$CI_BASE/evidence; CI_FIXTURE=$CI_BASE/private-fixture
    CI_ACCOUNT=d8-ci-agent; CI_STAGE=''; CI_STAGE_STARTED=$SECONDS
    CI_REVISION=${CI_GITHUB_SHA:-}
    [[ $CI_REVISION =~ ^[0-9a-f]{40}$ &&
       $(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P) == "$CI_ROOT" &&
       $(git -C "$CI_ROOT" rev-parse HEAD) == "$CI_REVISION" &&
       -z $(git -C "$CI_ROOT" status --porcelain) ]] || ci_fail 'Require a fresh root-private exact-SHA checkout'
    [[ $(stat -c '%u:%a' "$CI_BASE") == 0:700 && $(stat -c '%u:%a' "$CI_ROOT") == 0:700 ]]
    if [[ $CI_PROFILE == protocol-case ]]; then
        ci_validate_protocol_case "$CI_PROTOCOL_CASE" || ci_fail 'Unknown protocol recipe'
    fi
    [[ ! -e /run/dev-session-v8 && ! -e /run/systemd/system/devsession.slice &&
       ! -e /sys/fs/cgroup/devsession.slice && ! -e $CI_EVIDENCE && ! -e $CI_FIXTURE ]]
    ! getent passwd "$CI_ACCOUNT" >/dev/null
    mkdir -m 700 "$CI_EVIDENCE" "$CI_EVIDENCE/logs"
    trap 'ci_finish $?' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # Pure-v2 is checked before any Docker or acceptance setup is attempted.
    ci_stage dependencies ci_packages
    ci_stage offline timeout --signal=TERM --kill-after=30s 10m \
        python3 -m unittest discover -s "$CI_ROOT/tests" -p 'test_*.py' -v
    ci_stage offline_helpers ci_offline_helpers
    ci_stage docker_backend ci_docker_legacy
    if [[ $CI_PROFILE == protocol-case ]]; then
        if [[ $CI_PROTOCOL_CASE == ssh ]]; then ci_stage fixture_python ci_ssh_python; fi
        ci_stage fixture_engine ci_build_worker
        ci_stage fixture_render ci_protocol_render
    fi
    ci_stage fixture ci_fixture
    ci_stage exit_ip timeout --signal=TERM --kill-after=30s 5m \
        python3 "$CI_ROOT/tests/host_exit_ip.py" --user "$CI_ACCOUNT" \
        --fixture-output "$CI_FIXTURE" --upstream-namespace d8-test-upstream \
        --output "$CI_EVIDENCE/exit-ip"
    if [[ $CI_PROFILE == protocol-case ]]; then ci_protocol_suites; else ci_suites; fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then ci_main "$@"; fi
