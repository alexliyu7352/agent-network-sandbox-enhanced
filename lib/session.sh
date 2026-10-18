#!/bin/bash
# Pure definitions. Privileged orchestration is in dev-session.
valid_session_id() { [[ ${1:-} =~ ^[0-9a-f]{32}$ ]]; }

cleanup_group() {
    local sid=${1:-} path members
    valid_session_id "$sid" || return 1
    path=$CGROOT/$sid
    [[ ! -L $path ]] || return 1
    [[ -e $path ]] || return 0
    [[ -d $path && -r $path/cgroup.procs && ! -L $path/cgroup.procs ]] || {
        [[ ! -e $path && ! -L $path ]]; return;
    }
    members=$(cat "$path/cgroup.procs" 2>/dev/null) || {
        [[ ! -e $path && ! -L $path ]]; return;
    }
    if [[ -n $members ]]; then
        return 2
    fi
    # Explicit close and the launcher may both complete the same stop job.
    rmdir -- "$path" 2>/dev/null || [[ ! -e $path && ! -L $path ]]
    # Never delete a firewall rule, route, mark, or another session directory.
}

reclaim_stopped_group() {
    local sid=$1 attempt status
    # A completed systemd stop job may precede the kernel's final task release
    # by a scheduling tick. Wait only for this exact group's busy result.
    for ((attempt=0; attempt<40; attempt++)); do
        status=0
        cleanup_group "$sid" || status=$?
        (( status != 0 )) || return 0
        (( status == 2 )) || return "$status"
        sleep 0.05 || return
    done
    echo "Session group remains busy; network restrictions retained: $sid" >&2
    return 1
}

unit_arguments() {
    local sid=$1 mode=$2
    valid_session_id "$sid" || return 1
    [[ $mode == pty || $mode == pipe ]] || return 1
    UNIT_ARGS=(--quiet --system --wait --collect --service-type=exec
        "--unit=dev-session-$sid.service" "--$mode"
        --property=Restart=no --property=KillMode=control-group
        --property=TimeoutStopSec=10s --property=TimeoutStartSec=30s
        --property=SendSIGKILL=yes --property=SendSIGHUP=yes
        --property=UMask=0077 --property=NoNewPrivileges=yes
        '--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK'
        --property=SystemCallArchitectures=native
        "--property=ExecStopPost=$ROOT/dev-session --internal-clean $sid")
}

probe_network() {
    # No curlrc, proxy environment, insecure TLS, redirect, or direct fallback.
    timeout --signal=KILL 20s /usr/bin/curl -q --noproxy '*' \
        --proto '=https' --connect-timeout 5 --max-time 15 --fail --silent \
        --show-error --output /dev/null -- "$1"
}

enter_workload() {
    local probe=$1 workdir=$2
    shift 2
    cd -- "$workdir" || {
        printf 'Cannot enter working directory as %s: %s. Grant this account access or use --cwd DIR.\n' "${USER:-target user}" "$workdir" >&2
        return 125
    }
    probe_network "$probe" || { echo 'Session network probe failed; command was not started.' >&2; return 125; }
    exec "$@"
}

private_tty() {
    local outer=$1 uid=$2 gid=$3 name identity fd caller rest proc
    # Read with a Bash builtin before command substitution changes fd 1.
    # /proc may be mounted from an ancestor PID namespace, so $$ is not enough.
    read -r caller rest </proc/self/stat || return
    [[ $caller =~ ^[1-9][0-9]*$ ]] || return 1
    proc=/proc/$caller/fd
    [[ -t 0 && -t 1 && -t 2 ]] || return 1
    name=$(tty) || return
    [[ $name =~ ^/dev/pts/[0-9]+$ ]] || return 1
    # %t/%T are supported by Focal coreutils; its stat has no %r format.
    identity=$(stat -Lc '%d:%i:%t:%T' "$proc/0") || return
    [[ $identity != "$outer" ]] || return 1
    for fd in 1 2; do
        [[ $(stat -Lc '%d:%i:%t:%T' "$proc/$fd") == "$identity" ]] || return 1
    done
    # Operate on inherited descriptors, never a user-supplied tty pathname.
    chown "$uid:$gid" "$proc/0" || return
    chmod 600 "$proc/0" || return
    [[ $(stat -Lc '%u:%g:%a' "$proc/0") == "$uid:$gid:600" ]]
}

credentials_match() {
    [[ ${3:-} =~ ^[0-9a-f]{16}$ ]] || return 1
    awk -v uid="$2" -v bnd="$3" '
      /^Uid:/ {u=($2==uid && $3==uid && $4==uid && $5==uid && uid!=0)}
      /^Cap(Inh|Prm|Eff|Amb):/ {n++; if($2 !~ /^0+$/) bad=1}
      /^CapBnd:/ {n++; if(("x" $2)!=("x" bnd)) bad=1}
      /^NoNewPrivs:/ {p=($2==1)}
      /^Seccomp:/ {s=($2==2)}
      END {exit !(u && n==5 && !bad && p && s)}' <<<"$1"
}

user_checks() {
    local uid=$1 expected_bnd=${2:-} socket status='' line
    # Read in this Bash: an external cat would inspect its own post-exec caps.
    while IFS= read -r line; do
        status+="$line"$'\n'
    done </proc/self/status || return
    credentials_match "$status" "$uid" "$expected_bnd" || return 1
    for socket in /run/docker.sock /run/containerd/containerd.sock \
        /run/podman/podman.sock /run/libvirt/libvirt-sock \
        /var/lib/lxd/unix.socket /var/snap/lxd/common/lxd/unix.socket; do
        [[ ! -S $socket || ! -w $socket ]] || return 1
    done
}

attach_group() {
    local sid=$1 path=$CGROOT/$1
    valid_session_id "$sid" || return 1
    awk -F: -v p="/system.slice/dev-session-$sid.service" '
      $2 ~ /(^|,)name=systemd(,|$)/ && $3==p {found=1} END{exit !found}' /proc/self/cgroup || return
    mkdir -- "$path" || return
    chmod 700 "$path" || return
    printf '%s\n' "$CLASSID" >"$path/net_cls.classid" || return
    [[ $(cat "$path/net_cls.classid") == "$((CLASSID))" ]] || return 1
    printf '%s\n' "$$" >"$path/cgroup.procs" || return
    awk -F: -v p="/dev-session-v8/$sid" '
      $2 ~ /(^|,)net_cls(,|$)/ && $3==p {found=1} END{exit !found}' /proc/self/cgroup
}

bootstrap_workload() {
    local sid=$1 helper uid gid home fd last_cap cap drop_caps='' key value expected_bnd=''
    [[ ${#REQUEST[@]} -ge 10 ]] || return 1
    uid=${REQUEST[1]}; gid=${REQUEST[2]}; home=${REQUEST[3]}
    [[ $uid =~ ^[1-9][0-9]*$ && $gid =~ ^[0-9]+$ && $home == /* && ${REQUEST[4]} == /* ]] || return 1
    [[ ${REQUEST[5]} == pty || ${REQUEST[5]} == pipe ]] || return 1
    # Preserve the inherited ceiling, without granting any usable capability.
    while read -r key value; do
        if [[ $key == CapBnd: ]]; then expected_bnd=$value; fi
    done </proc/self/status || return
    [[ $expected_bnd =~ ^[0-9a-f]{16}$ ]] || return 1
    for fd in 0 1 2; do [[ ! -S /proc/self/fd/$fd ]] || return 1; done
    attach_group "$sid" || return
    if [[ ${REQUEST[5]} == pty ]]; then private_tty "${REQUEST[6]}" "$uid" "$gid" || return; fi
    helper=$(declare -f credentials_match user_checks probe_network enter_workload)
    helper+=$'\nset -euo pipefail\nuser_checks "$1" "$2" || { echo "Credential check failed; command was not started." >&2; exit 125; }\nshift 2\nenter_workload "$@"'
    # Focal setpriv rejects -all when the running kernel has capabilities
    # newer than its build-time headers. Enumerate the kernel's full set.
    read -r last_cap </proc/sys/kernel/cap_last_cap || return
    [[ $last_cap =~ ^[0-9]{1,2}$ ]] && (( 10#$last_cap <= 63 )) || return 1
    for ((cap=0; cap<=10#$last_cap; cap++)); do
        drop_caps+="${drop_caps:+,}-cap_$cap"
    done
    # Only public helper code/argv cross the privilege boundary.
    DROP_ARGS=(/usr/bin/setpriv --reuid "$uid" --regid "$gid" --clear-groups
        "--inh-caps=$drop_caps" "--ambient-caps=$drop_caps" --no-new-privs
        /usr/bin/env -i "HOME=$home" "USER=${REQUEST[0]}" "LOGNAME=${REQUEST[0]}"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$home/.local/bin" "TERM=${REQUEST[7]}"
        LANG=C.UTF-8 SHELL=/bin/bash /bin/bash -p -c "$helper" dev-session-user
        "$uid" "$expected_bnd" "${REQUEST[8]}" "${REQUEST[4]}" "${REQUEST[@]:9}")
}
