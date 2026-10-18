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
    local tool caps
    [[ $EUID == 0 && -d /run/systemd/system && $(cat /proc/1/comm) == systemd ]] || return 1
    [[ $(readlink /proc/self/ns/net) == "$(readlink /proc/1/ns/net)" &&
       $(readlink /proc/self/ns/pid) == "$(readlink /proc/1/ns/pid)" &&
       $(readlink /proc/self/ns/cgroup) == "$(readlink /proc/1/ns/cgroup)" ]] || return 1
    for tool in systemd-run systemctl setpriv ip sysctl jq docker curl flock nsenter timeout findmnt \
        iptables-legacy ip6tables-legacy iptables-legacy-restore ip6tables-legacy-restore sha256sum; do
        command -v "$tool" >/dev/null || return
    done
    caps=$(awk '/^CapEff:/ {print $2}' /proc/self/status)
    (( (16#$caps & 0x2030c1) == 0x2030c1 )) || return 1
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

binding_text() {
    local group
    group=$(cgroup_state_json) || return
    jq -cnSe --argjson group "$group" --argjson policy "$PROXY_POLICY_JSON" \
        --arg bridge "$BRIDGE" --arg address "$GATEWAY_IP" \
        --arg cid "$GATEWAY_ID" --arg nid "$GATEWAY_NETWORK_ID" --arg ns "$GATEWAY_NS_ID" \
        --arg source "$SOURCE_SHA256" --arg effective "$EFFECTIVE_SHA256" \
        --arg parser "$POLICY_PARSER_SHA256" \
        '{format:2,cgroup:$group,gateway:{bridge:$bridge,address:$address,
          container_id:$cid,network_id:$nid,namespace_identity:$ns},
          proxy_policy:$policy,source_sha256:$source,effective_sha256:$effective,
          policy_parser_sha256:$parser}'
}

binding_write() {
    local state
    state=$(binding_text) || return
    # A partial write is never accepted as a valid state. noclobber also
    # prevents following a path that appeared since the locked existence check.
    (set -o noclobber; umask 077; printf '%s\n' "$state" >"$RUNTIME/binding")
}

binding_read() {
    [[ -f $RUNTIME/binding && ! -L $RUNTIME/binding ]] || return 1
    trusted_path "$RUNTIME/binding" || return
    jq -sceS '
      def hash: type=="string" and test("\\A[0-9a-f]{64}\\z");
      if length==1 then .[0] else error("one binding required") end | . as $state |
      type=="object" and .format==2 and
      (keys==["cgroup","effective_sha256","format","gateway","policy_parser_sha256","proxy_policy","source_sha256"]) and
      (.source_sha256|hash) and (.effective_sha256|hash) and (.policy_parser_sha256|hash) and
      (.gateway|type=="object" and
        keys==["address","bridge","container_id","namespace_identity","network_id"] and
        (.bridge|type=="string" and test("\\A[A-Za-z0-9_-]{1,15}\\z")) and
        (.address|type=="string" and test("\\A[0-9]+(\\.[0-9]+){3}\\z")) and
        (.container_id|hash) and (.network_id|hash) and
        (.namespace_identity|type=="string" and test("\\A[0-9]+:[0-9]+\\z"))) and
      (.cgroup|type=="object" and .format==1 and (.mode=="v1" or .mode=="v2")) and
      (.proxy_policy|type=="object" and .format==1)
      | if . then $state else empty end
    ' "$RUNTIME/binding" 2>/dev/null
}

binding_load() {
    local state group
    state=$(binding_read) || {
        echo 'Invalid or legacy binding; close sessions and follow the offline upgrade procedure.' >&2
        return 1
    }
    group=$(jq -ceS '.cgroup' <<<"$state") || return
    cgroup_load_state "$group"
}

binding_verify() {
    local actual expected
    actual=$(binding_read) || return
    expected=$(binding_text) || return
    [[ $actual == "$expected" ]]
}

admit_gateway() {
    cgroup_verify || return
    binding_verify || return
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
    data=$(ip -N -j -4 route show table all) || return
    jq -e --argjson t "$TABLE" 'all(.[]; (.table|tostring)!=($t|tostring))' <<<"$data" >/dev/null || return
    data=$(ip -N -j -4 rule show) || return
    jq -e --argjson p "$PRIORITY" --argjson t "$TABLE" --arg mark "$MARK" --argjson dec "$((MARK))" '
      all(.[];.priority!=$p and (.table|tostring)!=($t|tostring) and .fwmark!=$mark and .fwmark!=$dec)
    ' <<<"$data" >/dev/null || return
    cgroup_unused
}

prepare_policy() {
    local action=$1 data
    read_proxy_policy "$ROOT/network.json" || return
    gateway_open || return
    if [[ -e $RUNTIME/binding || -L $RUNTIME/binding ]]; then
        binding_load || return
        cgroup_verify || {
            echo 'The bound cgroup is unavailable or changed; existing restrictions retained.' >&2
            return 1
        }
    else
        sessions_idle || return
        cgroup_detect || return
        unused_policy || { echo 'Policy namespace is occupied; refusing to overwrite it.' >&2; return 1; }
        # In v2 the parent must exist before netfilter resolves --path. The
        # identity saved here must outlive all services and installed rules.
        cgroup_prepare || return
        binding_write || return
        action=init
    fi
    binding_verify || { echo 'Configuration or gateway identity changed; use the documented offline migration procedure.' >&2; return 1; }
    if [[ $action == init ]]; then
        sessions_idle || return
        cgroup_sessions_empty || return
        # A failed installation leaves the protections already installed.
        policy_install || return
        sysctl -q -w "net.ipv4.conf.$BRIDGE.route_localnet=1" "net.ipv4.conf.$BRIDGE.rp_filter=2" || return
        data=$(ip -N -j -4 rule show) || return
        jq -e --argjson p "$PRIORITY" --arg mark "$MARK" --argjson dec "$((MARK))" --argjson t "$TABLE" '
          all(.[]; .priority!=$p or ((.fwmark==$mark or .fwmark==$dec) and (.table|tostring)==($t|tostring)))
        ' <<<"$data" >/dev/null || return
        # Removing this exact owned lookup cannot permit direct egress: the
        # permanent POSTROUTING guard is already active. No foreign rule flush.
        while ip -4 rule del priority "$PRIORITY" fwmark "$MARK/0xffffffff" table "$TABLE" 2>/dev/null; do :; done
        route_install || return
    fi
    admit_gateway
}

sessions_idle() {
    local units
    units=$(systemctl list-units --all --plain --no-legend 'dev-session-*.service') || return
    [[ -z $units && -z $(find "$RUNTIME/requests" -mindepth 1 -maxdepth 1 -print -quit) ]] || {
        echo 'Sessions or pending starts exist; refusing policy repair or migration.' >&2
        return 1
    }
}
