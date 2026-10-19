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

ci_validate_results() {
    python3 - "$1" <<'PY'
import json, pathlib, sys
for name in ("core", "lifecycle"):
    path = pathlib.Path(sys.argv[1]) / name / "results.json"
    rows = json.loads(path.read_text())
    if not isinstance(rows, list) or not rows or not all(row.get("passed") is True for row in rows):
        raise SystemExit("Missing or failed real acceptance results: " + name)
PY
}

ci_write_manifest() {
    python3 - "$@" <<'PY'
import datetime, hashlib, json, pathlib, sys
directory, status, protocol, scenario, repetitions, revision = sys.argv[1:]
root = pathlib.Path(directory)
suites = {}
for name in ("core", "lifecycle"):
    path = root / name / "results.json"
    try:
        rows = json.loads(path.read_text())
        if not isinstance(rows, list) or not rows:
            raise ValueError("empty or invalid results")
        passed = sum(row.get("passed") is True for row in rows)
        suites[name] = {"status": "passed" if passed == len(rows) else "failed",
                        "passed": passed, "total": len(rows), "results": str(path.relative_to(root))}
    except FileNotFoundError:
        suites[name] = {"status": "not_run"}
    except (ValueError, TypeError, AttributeError):
        suites[name] = {"status": "invalid_results"}
stages_path = root / "stages.jsonl"
stages = [json.loads(row) for row in stages_path.read_text().splitlines()] if stages_path.exists() else []
passed = (status == "0" and all(row["exit_code"] == 0 for row in stages)
          and all(suite["status"] == "passed" for suite in suites.values()))
files = []
for path in sorted(root.rglob("*")):
    if path.is_file() and not path.is_symlink() and path.name != "manifest.json":
        files.append({"path": str(path.relative_to(root)), "bytes": path.stat().st_size,
                      "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
manifest = {"format": 1, "status": "passed" if passed else "failed", "exit_code": int(status),
            "revision": revision, "protocol": protocol, "scenario": scenario,
            "repetitions": int(repetitions), "required_cgroup": "v2",
            "suites": suites, "stages": stages, "evidence": files,
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

ci_fixture() {
    local extract
    ci_write_config "$CI_PROTOCOL" "$CI_ROOT/network.json"
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
    docker compose --project-directory "$CI_ROOT" build --pull worker
    extract=$(docker create --name d8-ci-engine-extract --entrypoint /bin/true worker:1.14.2-v8)
    docker cp "$extract:/usr/local/bin/worker" "$CI_BASE/worker"
    docker rm "$extract"
    chmod 700 "$CI_BASE/worker"
    "$CI_BASE/worker" version | tee "$CI_EVIDENCE/worker-version.txt"
    [[ $(head -n 1 "$CI_EVIDENCE/worker-version.txt") == 'sing-box version 1.14.2' ]]
    sha256sum "$CI_BASE/worker" >"$CI_EVIDENCE/worker-sha256.txt"
    python3 "$CI_ROOT/tests/host_upstream_fixture.py" setup \
        --config "$CI_ROOT/network.json" --engine "$CI_BASE/worker" --output "$CI_FIXTURE" \
        --udp-echo-address 192.0.2.254 --udp-echo-port 40123
    cp "$CI_FIXTURE/fixture-info.json" "$CI_EVIDENCE/fixture-info.json"
    docker compose --project-directory "$CI_ROOT" up -d --no-build worker
    local ready=false attempt
    for ((attempt=0; attempt<90; attempt++)); do
        if docker exec worker test -s /run/worker/policy-ready 2>/dev/null; then ready=true; break; fi
        sleep 1
    done
    [[ $ready == true ]] || ci_fail 'Gateway never published readiness'
    ci_initialize
    jq -e --arg protocol "$CI_PROTOCOL" '
      .format==2 and .cgroup.mode=="v2" and
      (if $protocol=="http" then .proxy_policy.payload_networks==["tcp"] and
            .proxy_policy.dns_transport=="https"
       else .proxy_policy.payload_networks==["tcp","udp"] and
            .proxy_policy.dns_transport=="udp" end)
    ' /run/dev-session-v8/binding >/dev/null
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

ci_snapshot() {
    python3 - "$CI_EVIDENCE" <<'PY'
import json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
commands = [
    ["uname", "-a"], ["systemctl", "--version"], ["iptables-legacy", "--version"],
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
    ci_validate_results "$CI_EVIDENCE" >/dev/null 2>&1 || status=1
    ci_write_manifest "$CI_EVIDENCE" "$status" "$CI_PROTOCOL" "$CI_SCENARIO" \
        "$CI_REPETITIONS" "$CI_REVISION" || status=1
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
    CI_PROTOCOL=''; CI_SCENARIO=''; CI_REPETITIONS=100
    while (( $# )); do
        case $1 in
            --protocol) [[ $# -ge 2 ]] || ci_fail 'Missing protocol'; CI_PROTOCOL=$2; shift 2 ;;
            --scenario) [[ $# -ge 2 ]] || ci_fail 'Missing scenario'; CI_SCENARIO=$2; shift 2 ;;
            --repetitions) [[ $# -ge 2 ]] || ci_fail 'Missing repetitions'; CI_REPETITIONS=$2; shift 2 ;;
            *) ci_fail 'Usage: ci-host.sh --protocol hysteria2|http --scenario healthy|gateway-stop|gateway-kill|gateway-recreate|docker-restart [--repetitions 1..200]' ;;
        esac
    done
    ci_validate_case "$CI_PROTOCOL" "$CI_SCENARIO" "$CI_REPETITIONS" || ci_fail 'Invalid CI case'
    CI_BASE=/root/dev-session-ci; CI_ROOT=$CI_BASE/repo
    CI_EVIDENCE=$CI_BASE/evidence; CI_FIXTURE=$CI_BASE/private-fixture
    CI_ACCOUNT=d8-ci-agent; CI_STAGE=''; CI_STAGE_STARTED=$SECONDS
    CI_REVISION=${CI_GITHUB_SHA:-}
    [[ $CI_REVISION =~ ^[0-9a-f]{40}$ &&
       $(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P) == "$CI_ROOT" &&
       $(git -C "$CI_ROOT" rev-parse HEAD) == "$CI_REVISION" &&
       -z $(git -C "$CI_ROOT" status --porcelain) ]] || ci_fail 'Require a fresh root-private exact-SHA checkout'
    [[ $(stat -c '%u:%a' "$CI_BASE") == 0:700 && $(stat -c '%u:%a' "$CI_ROOT") == 0:700 ]]
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
    ci_stage fixture ci_fixture
    ci_stage exit_ip timeout --signal=TERM --kill-after=30s 5m \
        python3 "$CI_ROOT/tests/host_exit_ip.py" --user "$CI_ACCOUNT" \
        --fixture-output "$CI_FIXTURE" --upstream-namespace d8-test-upstream \
        --output "$CI_EVIDENCE/exit-ip"
    ci_suites
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then ci_main "$@"; fi
