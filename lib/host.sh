#!/bin/bash
# Root-side helpers. No user-supplied text is evaluated or sourced.
die() { echo "dev-session: $*" >&2; exit 125; }

trusted_path() {
    local path=$1 owner mode
    [[ $path == /* ]] || return 1
    while :; do
        [[ -e $path && ! -L $path ]] || return 1
        read -r owner mode < <(stat -c '%u %a' -- "$path")
        [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] || return 1
        (( (8#$mode & 0022) == 0 )) || return 1
        [[ $path == / ]] && break
        path=${path%/*}; path=${path:-/}
    done
}

host_preflight() {
    local tool caps options
    [[ $EUID == 0 && -d /run/systemd/system && $(cat /proc/1/comm) == systemd ]] || return 1
    [[ $(readlink /proc/self/ns/net) == "$(readlink /proc/1/ns/net)" &&
       $(readlink /proc/self/ns/pid) == "$(readlink /proc/1/ns/pid)" ]] || return 1
    for tool in systemd-run systemctl setpriv ip sysctl jq docker curl flock nsenter timeout findmnt \
        iptables-legacy ip6tables-legacy iptables-legacy-restore ip6tables-legacy-restore; do
        command -v "$tool" >/dev/null || return
    done
    caps=$(awk '/^CapEff:/ {print $2}' /proc/self/status)
    (( (16#$caps & 0x2030c1) == 0x2030c1 )) || return 1
    [[ $(findmnt -n -o FSTYPE /sys/fs/cgroup/net_cls,net_prio) == cgroup ]] || return 1
    options=$(findmnt -n -o OPTIONS /sys/fs/cgroup/net_cls,net_prio) || return
    [[ ,$options, == *,rw,* && ,$options, == *,net_cls,* ]] || return 1
    [[ -f /sys/fs/cgroup/net_cls,net_prio/net_cls.classid ]] || return 1
    [[ $(iptables-legacy --version) == *legacy* && $(ip6tables-legacy --version) == *legacy* ]] || return 1
    [[ -r /proc/self/status ]] && awk '/^Seccomp:/ {seen=1} END {exit !seen}' /proc/self/status
}

write_request() {
    local sid=$1; shift
    [[ $sid =~ ^[0-9a-f]{32}$ ]] || return 1
    (set -o noclobber; umask 077; printf '%s\0' "$@" >"$RUNTIME/requests/$sid")
}

read_request() {
    local sid=$1 path
    [[ $sid =~ ^[0-9a-f]{32}$ ]] || return 1
    path=$RUNTIME/requests/$sid
    [[ -f $path && ! -L $path ]] || return 1
    mapfile -d '' -t REQUEST <"$path" || return
    rm -- "$path"
}

binding_text() { printf '%s\n' "$BRIDGE" "$GATEWAY_IP" "$NODE_IP" "$NODE_PORT"; }
binding_write() { (set -o noclobber; binding_text >"$RUNTIME/binding"); }
binding_verify() { [[ $(cat "$RUNTIME/binding") == "$(binding_text)" ]]; }

admit_gateway() {
    gateway_verify || return
    policy_verify || return
    route_verify || return
    gw sysctl -q -w net.ipv4.ip_forward=1 || return
    [[ $(gw sysctl -n net.ipv4.ip_forward) == 1 ]]
}

unused_policy() {
    local family table chain data
    for family in 4 6; do
        for table in mangle nat; do
            [[ $family == 6 && $table == nat ]] && continue
            data=$("$(firewall_tool "$family")" -w 5 -t "$table" -S) || return
            for chain in $(policy_chains "$family" "$table"); do
                ! awk -v c="$chain" '$2==c {found=1} END{exit !found}' <<<"$data" || return 1
            done
        done
    done
    data=$(ip -j -4 route show table all) || return
    jq -e --argjson t "$TABLE" 'all(.[]; (.table|tostring)!=($t|tostring))' <<<"$data" >/dev/null || return
    data=$(ip -j -4 rule show) || return
    jq -e --argjson p "$PRIORITY" --argjson t "$TABLE" --arg mark "$MARK" --argjson dec "$((MARK))" '
      all(.[];.priority!=$p and (.table|tostring)!=($t|tostring) and .fwmark!=$mark and .fwmark!=$dec)
    ' <<<"$data" >/dev/null || return
    [[ ! -e $CGROOT ]]
}

prepare_policy() {
    local action=$1 data
    read_node "$ROOT/network.json" || return
    gateway_open || return
    if [[ ! -e $RUNTIME/binding ]]; then
        unused_policy || { echo 'Policy namespace is occupied; refusing to overwrite it.' >&2; return 1; }
        binding_write || return
        action=init
    fi
    binding_verify || { echo 'Gateway identity changed; use the documented offline migration procedure.' >&2; return 1; }
    if [[ $action == init ]]; then
        data=$(systemctl list-units --all --plain --no-legend 'dev-session-*.service') || return
        [[ -z $data && -z $(find "$RUNTIME/requests" -mindepth 1 -maxdepth 1 -print -quit) ]] || {
            echo 'Sessions or pending starts exist; refusing policy repair.' >&2; return 1; }
        [[ ! -d $CGROOT || -z $(find "$CGROOT" -mindepth 1 -maxdepth 1 -type d -print -quit) ]] || return 1
        # A failed installation leaves the protections already installed.
        policy_install || return
        sysctl -q -w "net.ipv4.conf.$BRIDGE.route_localnet=1" "net.ipv4.conf.$BRIDGE.rp_filter=2" || return
        data=$(ip -j -4 rule show) || return
        jq -e --argjson p "$PRIORITY" --arg mark "$MARK" --argjson dec "$((MARK))" --argjson t "$TABLE" '
          all(.[]; .priority!=$p or ((.fwmark==$mark or .fwmark==$dec) and (.table|tostring)==($t|tostring)))
        ' <<<"$data" >/dev/null || return
        # Removing this exact owned lookup cannot permit direct egress: the
        # permanent POSTROUTING guard is already active. No foreign rule flush.
        while ip -4 rule del priority "$PRIORITY" fwmark "$MARK/0xffffffff" table "$TABLE" 2>/dev/null; do :; done
        route_install || return
        mkdir -p -- "$CGROOT" || return
        chmod 700 "$CGROOT" || return
    fi
    admit_gateway
}
