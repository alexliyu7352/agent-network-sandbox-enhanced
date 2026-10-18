#!/bin/bash
# Real privileged acceptance, ONLY on a fresh disposable GitHub-hosted VM.
# Source this file to test the pure config/result helpers without touching a host.

ci_fail() { printf 'ci-host: %s\n' "$*" >&2; exit 125; }

ci_validate_case() {
    [[ $1 == hysteria2 || $1 == http ]] || return 1
    case $2 in healthy|gateway-stop|gateway-kill|docker-restart) ;; *) return 1 ;; esac
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

ci_packages() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl git jq python3 \
        iproute2 iptables util-linux procps sudo tcpdump openssl kmod
    # Ubuntu2604-Readme.md lists Docker Engine and Compose on the hosted image.
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

ci_fixture() {
    local extract
    ci_write_config "$CI_PROTOCOL" "$CI_ROOT/network.json"
    "$CI_ROOT/install-dev-session.sh"
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
    "$CI_ROOT/dev-session" init
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
    case $CI_SCENARIO in
        gateway-stop|gateway-kill) core_fault=$CI_SCENARIO ;;
        docker-restart) lifecycle_fault=docker-restart ;;
    esac
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
        --output "$CI_EVIDENCE/core" --udp-echo 192.0.2.254:40123 --namespace-fault "$core_fault"
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
    ["uname", "-a"], ["systemd", "--version"], ["iptables-legacy", "--version"],
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
    [[ $EUID == 0 && ${GITHUB_ACTIONS:-} == true &&
       ${RUNNER_ENVIRONMENT:-} == github-hosted &&
       ${CI_DISPOSABLE_HOST:-} == github-actions ]] ||
        ci_fail 'This script requires an explicitly marked disposable GitHub-hosted VM'
    CI_PROTOCOL=''; CI_SCENARIO=''; CI_REPETITIONS=100
    while (( $# )); do
        case $1 in
            --protocol) [[ $# -ge 2 ]] || ci_fail 'Missing protocol'; CI_PROTOCOL=$2; shift 2 ;;
            --scenario) [[ $# -ge 2 ]] || ci_fail 'Missing scenario'; CI_SCENARIO=$2; shift 2 ;;
            --repetitions) [[ $# -ge 2 ]] || ci_fail 'Missing repetitions'; CI_REPETITIONS=$2; shift 2 ;;
            *) ci_fail 'Usage: ci-host.sh --protocol hysteria2|http --scenario healthy|gateway-stop|gateway-kill|docker-restart [--repetitions 1..200]' ;;
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
    ci_stage docker_backend ci_docker_legacy
    ci_stage fixture ci_fixture
    ci_suites
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then ci_main "$@"; fi
