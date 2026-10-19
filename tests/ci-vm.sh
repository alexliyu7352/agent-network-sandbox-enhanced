#!/bin/bash
# Debian 13 acceptance inside a KVM guest owned by one disposable Actions job.
# This script never changes its outer host's Docker, firewall, or networking.
# Source it to test checksum and manifest helpers without launching a VM.

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/ci-host.sh"

ci_vm_verify_image() {
    python3 - "$@" <<'PY'
import hashlib, json, pathlib, re, sys
image, sums, output = map(pathlib.Path, sys.argv[1:4])
expected = sys.argv[4] if len(sys.argv) > 4 else None
matches = []
for line in sums.read_text().splitlines():
    match = re.fullmatch(r"([0-9a-fA-F]{128}) [ *](.+)", line)
    if match and match[2] == image.name:
        matches.append(match[1].lower())
if len(matches) != 1 or (expected is not None and matches[0] != expected):
    raise SystemExit("Require one exact, pinned image checksum")
digest = hashlib.sha512()
with image.open("rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
if digest.hexdigest() != matches[0]:
    raise SystemExit("Debian image SHA-512 mismatch")
output.write_text(json.dumps({"filename": image.name, "sha512": digest.hexdigest(),
                              "bytes": image.stat().st_size, "verified": True}, indent=2) + "\n")
PY
}

ci_vm_manifest() {
    python3 - "$@" <<'PY'
import datetime, hashlib, json, pathlib, sys
directory, status, protocol, revision = sys.argv[1:]
root = pathlib.Path(directory)
guest = {"status": "not_run"}
try:
    guest = json.loads((root / "guest/manifest.json").read_text())
    if not isinstance(guest, dict):
        raise ValueError("invalid guest manifest")
except FileNotFoundError:
    pass
except (ValueError, TypeError):
    guest = {"status": "invalid_results"}
stages_path = root / "stages.jsonl"
stages = [json.loads(row) for row in stages_path.read_text().splitlines()] if stages_path.exists() else []
guest_ok = (guest.get("status") == "passed" and guest.get("exit_code") == 0
            and guest.get("revision") == revision and guest.get("protocol") == protocol
            and guest.get("scenario") == "healthy" and guest.get("required_cgroup") == "v2"
            and all(guest.get("suites", {}).get(name, {}).get("status") == "passed"
                    for name in ("core", "lifecycle")))
image = json.loads((root / "image.json").read_text()) if (root / "image.json").exists() else {"verified": False}
passed = (status == "0" and guest_ok and image.get("verified") is True and stages
          and all(row["exit_code"] == 0 for row in stages))
files = []
for path in sorted(root.rglob("*")):
    if path.is_file() and not path.is_symlink() and path != root / "manifest.json":
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        files.append({"path": str(path.relative_to(root)), "bytes": path.stat().st_size,
                      "sha256": digest.hexdigest()})
manifest = {"format": 1, "status": "passed" if passed else "failed",
            "exit_code": int(status), "revision": revision, "platform": "debian-13-kvm",
            "protocol": protocol, "scenario": "healthy", "required_cgroup": "v2",
            "image": image, "guest": guest, "stages": stages, "evidence": files,
            "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "scope": "This Debian KVM guest only; namespace faults run in separate native Ubuntu jobs."}
temp = root / ".manifest.tmp"
temp.write_text(json.dumps(manifest, indent=2) + "\n")
temp.replace(root / "manifest.json")
PY
}

ci_vm_packages() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl python3 \
        qemu-system-x86 qemu-utils cloud-image-utils openssh-client
    [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] ||
        ci_fail 'KVM is unavailable; refusing to substitute emulation or skip acceptance'
    qemu-system-x86_64 --version
}

ci_vm_image() {
    # Debian Cloud Team official build, including its published SHA512SUMS:
    # https://cloud.debian.org/images/cloud/trixie/20261017-2634/
    # Current Debian cloud images publish HTTPS checksums, not detached signatures.
    local base=https://cloud.debian.org/images/cloud/trixie/20261017-2634
    local name=debian-13-generic-amd64-20261017-2634.qcow2
    local digest=62aa92aeff32cbf3fe6c01f410fef4035b1603a512f073c9f8889072168de9e49fa361ba48621359fc7608ad91225e823ea233feb33f612eb39e50aaf21957fe
    curl --proto '=https' --proto-redir '=https' --fail --location --retry 3 \
        --connect-timeout 30 --max-time 600 "$base/$name" -o "$CI_VM_PRIVATE/$name"
    curl --proto '=https' --proto-redir '=https' --fail --location --retry 3 \
        --connect-timeout 30 --max-time 120 "$base/SHA512SUMS" -o "$CI_VM_PRIVATE/SHA512SUMS"
    ci_vm_verify_image "$CI_VM_PRIVATE/$name" "$CI_VM_PRIVATE/SHA512SUMS" \
        "$CI_EVIDENCE/image.json" "$digest"
    python3 - "$CI_EVIDENCE/image.json" "$base/$name" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
row = json.loads(path.read_text())
row.update({"url": sys.argv[2], "build": "20261017-2634", "distribution": "Debian 13",
            "variant": "generic", "architecture": "amd64", "acceleration": "kvm"})
path.write_text(json.dumps(row, indent=2) + "\n")
PY
    qemu-img create -f qcow2 -F qcow2 -b "$CI_VM_PRIVATE/$name" "$CI_VM_PRIVATE/guest.qcow2" 22G
}

ci_vm_seed() {
    ssh-keygen -q -t ed25519 -N '' -C dev-session-ci-client -f "$CI_VM_PRIVATE/client_key"
    ssh-keygen -q -t ed25519 -N '' -C dev-session-ci-host -f "$CI_VM_PRIVATE/host_key"
    python3 - "$CI_VM_PRIVATE" "$CI_REVISION" "$CI_PROTOCOL" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
host_public = (root / "host_key.pub").read_text().strip()
config = {
    "users": [{"name": "root", "lock_passwd": True,
               "ssh_authorized_keys": [(root / "client_key.pub").read_text().strip()]}],
    "disable_root": False, "ssh_pwauth": False, "ssh_deletekeys": True,
    "ssh_keys": {"ed25519_private": (root / "host_key").read_text(),
                 "ed25519_public": host_public},
    "ssh_quiet_keygen": True, "ssh_publish_hostkeys": {"enabled": False},
    "write_files": [{"path": "/run/dev-session-ci-kvm", "owner": "root:root",
                     "permissions": "0600", "content": sys.argv[2] + "\n"}],
}
# JSON is a valid YAML document. Never print the seed or include it in artifacts.
(root / "user-data").write_text("#cloud-config\n" + json.dumps(config, indent=2) + "\n")
(root / "meta-data").write_text(json.dumps({
    "instance-id": "dev-session-ci-" + sys.argv[2] + "-" + sys.argv[3],
    "local-hostname": "dev-session-debian-ci"}) + "\n")
(root / "known_hosts").write_text("[127.0.0.1]:22222 " + host_public + "\n")
PY
    cloud-localds "$CI_VM_PRIVATE/seed.img" "$CI_VM_PRIVATE/user-data" "$CI_VM_PRIVATE/meta-data"
}

ci_vm_start() {
    # QEMU user networking needs no host TAP, bridge, route or firewall changes.
    # The only forwarded port is loopback SSH with an exact pre-generated host key.
    qemu-system-x86_64 -accel kvm -cpu host -smp 2 -m 6144 \
        -display none -monitor none -serial "file:$CI_EVIDENCE/serial.log" \
        -smbios type=1,manufacturer=DevSessionCI,product=DevSessionCIVM \
        -drive "if=virtio,format=qcow2,file=$CI_VM_PRIVATE/guest.qcow2" \
        -drive "if=virtio,format=raw,readonly=on,file=$CI_VM_PRIVATE/seed.img" \
        -netdev user,id=ci,hostfwd=tcp:127.0.0.1:22222-:22,ipv6=off \
        -device virtio-net-pci,netdev=ci \
        -daemonize -pidfile "$CI_VM_PRIVATE/qemu.pid"
}

ci_vm_ssh() {
    ssh -p 22222 -i "$CI_VM_PRIVATE/client_key" \
        -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
        -o "UserKnownHostsFile=$CI_VM_PRIVATE/known_hosts" \
        -o HostKeyAlgorithms=ssh-ed25519 -o ConnectTimeout=5 \
        -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o LogLevel=ERROR \
        root@127.0.0.1 "$@"
}

ci_vm_boot() {
    local attempt ready=false
    for ((attempt=0; attempt<120; attempt++)); do
        if ci_vm_ssh true; then ready=true; break; fi
        [[ -s $CI_VM_PRIVATE/qemu.pid ]] &&
            kill -0 "$(cat "$CI_VM_PRIVATE/qemu.pid")" ||
            ci_fail 'Debian QEMU exited before SSH became available'
        sleep 2
    done
    [[ $ready == true ]] || ci_fail 'Debian guest SSH never became ready'
    ci_vm_ssh timeout --signal=TERM --kill-after=10s 5m cloud-init status --wait
}

ci_vm_guest_packages() {
    # Official Docker apt repository, not a remotely downloaded installer:
    # https://docs.docker.com/engine/install/debian/#install-using-the-repository
    ci_vm_ssh bash -s <<'GUEST'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
. /etc/os-release
[[ $ID == debian && $VERSION_ID == 13 ]]
[[ $(systemd-detect-virt --vm) == kvm ]]
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl git
install -m 0755 -d /etc/apt/keyrings
curl --proto '=https' --proto-redir '=https' --fail --location --retry 3 \
    --connect-timeout 30 --max-time 120 \
    https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
cat >/etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: trixie
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
apt-get update
apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
docker compose version
GUEST
}

ci_vm_checkout() {
    ci_vm_ssh bash -s <<'GUEST'
set -euo pipefail
umask 077
test ! -e /root/dev-session-ci
mkdir -m 700 /root/dev-session-ci /root/dev-session-ci/repo
GUEST
    # Include the fetched .git metadata so ci-host verifies the identical SHA.
    tar -C "$CI_ROOT" -cf - . | ci_vm_ssh tar -C /root/dev-session-ci/repo -xf -
}

ci_vm_run_guest() {
    # Values have already passed closed enum/numeric/hex validation.
    ci_vm_ssh env CI_DISPOSABLE_HOST=kvm-guest "CI_GITHUB_SHA=$CI_REVISION" \
        bash /root/dev-session-ci/repo/tests/ci-host.sh \
        --protocol "$CI_PROTOCOL" --scenario healthy --repetitions "$CI_REPETITIONS"
}

ci_vm_collect() {
    mkdir -m 700 "$CI_EVIDENCE/guest" || return
    timeout --signal=TERM --kill-after=10s 2m \
        bash -c 'source "$1"; CI_VM_PRIVATE=$2; ci_vm_ssh tar -C /root/dev-session-ci/evidence -cf - .' \
        ci-vm-collect "$CI_ROOT/tests/ci-vm.sh" "$CI_VM_PRIVATE" \
        | tar -C "$CI_EVIDENCE/guest" -xf -
}

ci_vm_stop() {
    # Signal only our QEMU. A pidfd keeps PID reuse from changing the target.
    python3 - "$CI_VM_PRIVATE" <<'PY'
import os, pathlib, select, signal, sys
root = pathlib.Path(sys.argv[1])
pidfile = root / "qemu.pid"
if not pidfile.exists():
    raise SystemExit(0)
pid = int(pidfile.read_text())
if pid <= 1:
    raise SystemExit("invalid QEMU PID")
try:
    fd = os.pidfd_open(pid)
except ProcessLookupError:
    raise SystemExit(0)
try:
    argv = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    if os.fsencode(f"if=virtio,format=qcow2,file={root}/guest.qcow2") not in argv:
        raise SystemExit("QEMU ownership check failed; refusing to signal this PID")
    signal.pidfd_send_signal(fd, signal.SIGTERM)
    if not select.select([fd], [], [], 15)[0]:
        signal.pidfd_send_signal(fd, signal.SIGKILL)
        if not select.select([fd], [], [], 5)[0]:
            raise SystemExit("QEMU did not exit")
finally:
    os.close(fd)
PY
}

ci_vm_finish() {
    local status=$1 collected=1 stopped=0
    trap - EXIT HUP INT TERM
    set +e
    if [[ -n $CI_STAGE ]]; then
        ci_record_stage "$CI_EVIDENCE" "$CI_STAGE" "$status" "$((SECONDS-CI_STAGE_STARTED))"
    fi
    if [[ -s $CI_VM_PRIVATE/qemu.pid && -f $CI_VM_PRIVATE/known_hosts ]]; then
        ci_vm_collect >"$CI_EVIDENCE/logs/guest-evidence.log" 2>&1
        collected=$?
    fi
    ci_record_stage "$CI_EVIDENCE" guest_evidence "$collected" 0
    (( collected == 0 )) || status=1
    ci_vm_stop >"$CI_EVIDENCE/logs/guest-stop.log" 2>&1
    stopped=$?
    ci_record_stage "$CI_EVIDENCE" guest_stop "$stopped" 0
    (( stopped == 0 )) || status=1
    ci_vm_manifest "$CI_EVIDENCE" "$status" "$CI_PROTOCOL" "$CI_REVISION" || status=1
    python3 - "$CI_EVIDENCE/manifest.json" <<'PY'
import json, pathlib, sys
if json.loads(pathlib.Path(sys.argv[1]).read_text())["status"] != "passed":
    raise SystemExit(1)
PY
    (( $? == 0 )) || status=1
    # Disk overlays, SSH keys and private fixtures remain private until this
    # disposable outer runner is destroyed. Export only CI_EVIDENCE.
    exit "$status"
}

ci_vm_main() {
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
            *) ci_fail 'Usage: ci-vm.sh --protocol hysteria2|http --scenario healthy [--repetitions 1..200]' ;;
        esac
    done
    ci_validate_case "$CI_PROTOCOL" "$CI_SCENARIO" "$CI_REPETITIONS" &&
        [[ $CI_SCENARIO == healthy ]] || ci_fail 'Invalid Debian VM case'
    CI_BASE=/root/dev-session-ci; CI_ROOT=$CI_BASE/repo
    CI_EVIDENCE=$CI_BASE/evidence; CI_VM_PRIVATE=$CI_BASE/vm-private
    CI_REVISION=${CI_GITHUB_SHA:-}; CI_STAGE=''; CI_STAGE_STARTED=$SECONDS
    [[ $CI_REVISION =~ ^[0-9a-f]{40}$ &&
       $(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P) == "$CI_ROOT" &&
       $(git -C "$CI_ROOT" rev-parse HEAD) == "$CI_REVISION" &&
       -z $(git -C "$CI_ROOT" status --porcelain) ]] || ci_fail 'Require a fresh root-private exact-SHA checkout'
    [[ $(stat -c '%u:%a' "$CI_BASE") == 0:700 && $(stat -c '%u:%a' "$CI_ROOT") == 0:700 ]]
    [[ ! -e $CI_VM_PRIVATE && ! -e $CI_EVIDENCE ]]
    mkdir -m 700 "$CI_VM_PRIVATE" "$CI_EVIDENCE" "$CI_EVIDENCE/logs"
    trap 'ci_vm_finish $?' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    ci_stage vm_dependencies ci_vm_packages
    ci_stage vm_image ci_vm_image
    ci_stage vm_seed ci_vm_seed
    ci_stage vm_start ci_vm_start
    ci_stage vm_boot ci_vm_boot
    ci_stage guest_dependencies ci_vm_guest_packages
    ci_stage guest_checkout ci_vm_checkout
    ci_stage guest_acceptance ci_vm_run_guest
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then ci_vm_main "$@"; fi
