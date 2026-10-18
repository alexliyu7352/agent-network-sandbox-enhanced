#!/bin/bash -p
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset BASH_ENV ENV CDPATH GLOBIGNORE
umask 077
[[ $EUID == 0 ]] || { echo 'Use sudo session [-u ACCOUNT]' >&2; exit 125; }
readonly ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ $ROOT =~ ^/[A-Za-z0-9_/-]+$ ]] || exit 125
for file in "$ROOT/dev-session" "$ROOT/lib/host.sh" "$ROOT/lib/main.sh"; do
    p=$file
    while :; do
        [[ -e $p && ! -L $p ]] || exit 125
        read -r owner mode < <(stat -c '%u %a' -- "$p")
        [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 0022) == 0 )) || exit 125
        [[ $p == / ]] && break
        p=${p%/*}; p=${p:-/}
    done
done
[[ $(stat -c '%a' "$ROOT") == 700 ]] || exit 125
source "$ROOT/lib/host.sh"
for p in "$ROOT/lib/network.sh" "$ROOT/lib/session.sh" "$ROOT/lib/cli.sh" "$ROOT/lib/context.sh" "$ROOT/policy.json" "$ROOT/network.json"; do
    trusted_path "$p" || die "Untrusted installation path: $p"
done
source "$ROOT/lib/network.sh"
source "$ROOT/lib/session.sh"
source "$ROOT/lib/cli.sh"
source "$ROOT/lib/context.sh"
read_context "$@" || die 'Invalid entrypoint context'
shift "$CONTEXT_SHIFT"
unset CALLER_WORKDIR
if [[ ${1:-} == --caller-context ]]; then
    shift
    [[ $# -ge 4 && ( -z $2 || $2 == /* ) ]] || die 'Invalid launcher working directory or context'
    CALLER_WORKDIR=$2
    read_context "$1" "${@:3}" || die 'Invalid launcher context'
    shift "$((CONTEXT_SHIFT + 1))"
    [[ ${1:-} == -- ]] || die 'Missing launcher argument boundary'
    shift
fi

case ${1:-} in
    --internal-clean)
        [[ $# == 2 ]] && valid_session_id "$2" || die 'Invalid cleanup request'
        cleanup_status=0
        cleanup_group "$2" || cleanup_status=$?
        # v245 may still be about to kill descendants after ExecStopPost.
        # Only that explicit deferred result is accepted here.
        [[ $cleanup_status == 0 || $cleanup_status == 2 ]] || exit "$cleanup_status"
        rm -f -- "$RUNTIME/requests/$2"
        exit ;;
    --internal-child)
        [[ $# == 2 ]] && valid_session_id "$2" || die 'Invalid bootstrap request'
        trusted_path "$RUNTIME/requests/$2" || die 'Untrusted request'
        read_request "$2"
        bootstrap_workload "$2" || die 'Bootstrap failed; command was not started'
        exec "${DROP_ARGS[@]}" ;;
esac

parse_cli "$@"
case $command in
    help|--help|-h)
        echo 'Usage: session [-u ACCOUNT] [--cwd DIR] [--umask OCTAL] [-- COMMAND ARG...]'
        echo '       session init | check | status | close ID'
        echo 'Defaults: sudo caller account, current working directory, interactive shell.'
        echo 'The installed launcher invokes sudo and preserves caller locale/timezone/umask and desktop context.'
        echo 'Use session directly for automatic pre-sudo settings; explicit --umask remains optional.'
        echo "Installation: $ROOT"
        echo 'Legacy: session --user ACCOUNT run [--cwd DIR] [-- COMMAND ARG...]'
        exit ;;
    status) exec systemctl list-units --all --plain 'dev-session-*.service' ;;
    close)
        stop_status=0
        systemctl stop "dev-session-$close_id.service" || stop_status=$?
        reclaim_stopped_group "$close_id"
        exit "$stop_status" ;;
    init|check) : ;;
    run) resolve_account ;;
    *) die 'Unknown command; use --help' ;;
esac

host_preflight || die 'Requires host root, systemd, cgroup v1 net_cls, legacy iptables and required capabilities'
jq -e '.version==8 and .gateway_container=="worker" and
    (.probe_url|type=="string" and test("^https://[A-Za-z0-9.-]+(:[0-9]+)?/[^\\r\\n ]*$"))' \
    "$ROOT/policy.json" >/dev/null || die 'Invalid policy configuration'
GATEWAY=$(jq -r .gateway_container "$ROOT/policy.json")
PROBE=$(jq -r .probe_url "$ROOT/policy.json")
[[ ! -L $RUNTIME && ! -L $RUNTIME/requests ]] || die 'Untrusted runtime path'
mkdir -p -- "$RUNTIME/requests"
chmod 700 "$RUNTIME" "$RUNTIME/requests"
trusted_path "$RUNTIME/requests" || die 'Untrusted runtime directory'
exec {LOCKFD}>"$RUNTIME/policy.lock"
flock -w 30 "$LOCKFD" || die 'Another policy operation is still running'
prepare_policy "$command" || die 'Policy check/setup failed; no session was started (repair: init)'
if [[ $command != run ]]; then
    echo 'Local policy verified. No workload connectivity test was run.'
    exit
fi

if [[ ${#workload[@]} == 0 ]]; then
    [[ -t 0 && -t 1 && -t 2 ]] || die 'Interactive run needs a terminal'
    mode=pty; workload=(/bin/bash -i)
else
    mode=pipe
fi
wrap_workload_context "$uid" "${SUDO_UID:-}" "${workload_umask:-$CONTEXT_UMASK}" \
    "${CONTEXT_ENV[@]}" || die 'Invalid workload context; command was not started'
outer=none
[[ $mode != pty ]] || outer=$(stat -Lc '%d:%i:%t:%T' /proc/self/fd/0)
sid=$(tr -d '-' </proc/sys/kernel/random/uuid)
valid_session_id "$sid" || die 'Cannot allocate session ID'
write_request "$sid" "$user" "$uid" "$gid" "$home" "$workdir" "$mode" "$outer" \
    "${TERM:-xterm}" "$PROBE" "${workload[@]}"
unit_arguments "$sid" "$mode"
exec {GWFD}<&-
exec {LOCKFD}>&-
unit=dev-session-$sid.service
client=''
finish() {
    local result=$?
    trap - EXIT HUP INT TERM
    # Cancel a request that has not been consumed before stopping the unit;
    # this closes the stop-before-registration race on client interruption.
    timeout --signal=KILL 2s rm -f -- "$RUNTIME/requests/$sid" || true
    systemctl stop "$unit" >/dev/null 2>&1 || true
    if [[ -n $client ]]; then kill -TERM "$client" 2>/dev/null || true; wait "$client" 2>/dev/null || true; fi
    timeout --signal=KILL 2s rm -f -- "$RUNTIME/requests/$sid" || true
    # systemd 245 may run ExecStopPost before its final kill of remaining
    # descendants. Reclaim the empty net_cls group after the stop job completes.
    reclaim_stopped_group "$sid" || { (( result != 0 )) || result=125; }
    exit "$result"
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
echo "Session $sid; exit the shell to close it." >&2
# Explicit stdin preserves the terminal for the asynchronous native relay.
systemd-run "${UNIT_ARGS[@]}" "$ROOT/dev-session" --internal-child "$sid" <&0 >&1 2>&2 &
client=$!
wait "$client"
