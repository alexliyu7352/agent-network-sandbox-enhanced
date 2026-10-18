#!/bin/bash
# Sourced by the root entry point. No side effects at source time.
readonly CLASSID=0x6d730001 MARK=0x6d730001 TABLE=32190 PRIORITY=1190
readonly CGROOT=/sys/fs/cgroup/net_cls,net_prio/dev-session-v8
readonly RUNTIME=/run/dev-session-v8

policy_chains() {
    case "$1:$2" in
        4:mangle) echo 'D8OUT D8POST D8DEST D8GW' ;;
        6:mangle) echo 'D8OUT6 D8POST6 D8GW6' ;;
        4:nat) echo 'D8DNS D8SNAT' ;;
        *) return 1 ;;
    esac
}

policy_hooks() {
    case "$1:$2" in
        4:mangle) printf '%s\n' 'OUTPUT D8OUT' 'POSTROUTING D8POST' 'FORWARD D8GW' ;;
        6:mangle) printf '%s\n' 'OUTPUT D8OUT6' 'POSTROUTING D8POST6' 'FORWARD D8GW6' ;;
        4:nat) printf '%s\n' 'OUTPUT D8DNS' 'POSTROUTING D8SNAT' ;;
        *) return 1 ;;
    esac
}

policy_emit() {
    local family=$1 table=$2 chain prefix
    case "$family:$table" in
    4:mangle)
        for chain in D8OUT D8POST; do
            # The only class is shared by all sessions. Historical sockets
            # retain this same restriction; no identities are ever recycled.
            printf '%s\n' "-A $chain -m cgroup --cgroup $CLASSID -j MARK --set-xmark $MARK/0xffffffff"
            printf '%s\n' "-A $chain -m mark --mark $MARK/0xffffffff -j CONNMARK --set-xmark $MARK/0xffffffff"
            printf '%s\n' "-A $chain -m connmark --mark $MARK/0xffffffff -j MARK --set-xmark $MARK/0xffffffff"
        done
        # Let NAT redirect DNS even when its original address is private.
        for prefix in tcp udp; do
            printf '%s\n' "-A D8OUT -m mark --mark $MARK/0xffffffff -p $prefix -m $prefix --dport 53 -j RETURN"
        done
        printf '%s\n' "-A D8OUT -m mark --mark $MARK/0xffffffff -j D8DEST"
        for prefix in tcp udp; do
            printf '%s\n' "-A D8DEST -o lo -d 127.0.0.0/8 -p $prefix -j RETURN"
        done
        for prefix in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
            printf '%s\n' "-A D8DEST -d $prefix -j DROP"
        done
        printf '%s\n' "-A D8POST -m mark --mark $MARK/0xffffffff -j D8DEST"
        for prefix in tcp udp; do
            printf '%s\n' "-A D8POST -m mark --mark $MARK/0xffffffff -o lo -d 127.0.0.0/8 -p $prefix -j RETURN"
        done
        printf '%s\n' "-A D8POST -m mark --mark $MARK/0xffffffff -o $BRIDGE -j RETURN"
        printf '%s\n' "-A D8POST -m mark --mark $MARK/0xffffffff -j DROP"
        printf '%s\n' "-A D8GW -i $BRIDGE -s $GATEWAY_IP/32 -d $NODE_IP/32 -p udp -m udp --dport $NODE_PORT -j RETURN"
        printf '%s\n' "-A D8GW -i $BRIDGE -j DROP"
        ;;
    6:mangle)
        for chain in D8OUT6 D8POST6; do
            printf '%s\n' "-A $chain -m cgroup --cgroup $CLASSID -j DROP"
            printf '%s\n' "-A $chain -m mark --mark $MARK/0xffffffff -j DROP"
            printf '%s\n' "-A $chain -m connmark --mark $MARK/0xffffffff -j DROP"
        done
        printf '%s\n' "-A D8GW6 -i $BRIDGE -j DROP"
        ;;
    4:nat)
        for prefix in tcp udp; do
            printf '%s\n' "-A D8DNS -m mark --mark $MARK/0xffffffff -p $prefix -m $prefix --dport 53 -j DNAT --to-destination 1.1.1.1:53"
        done
        printf '%s\n' "-A D8SNAT -m mark --mark $MARK/0xffffffff -o $BRIDGE -j MASQUERADE"
        ;;
    *) return 1 ;;
    esac
}

firewall_tool() {
    [[ $1 == 4 ]] && printf '%s\n' iptables-legacy || printf '%s\n' ip6tables-legacy
}

canonical_rule() {
    # iptables -S reorders options and prints classids in decimal. Compare
    # normalized option/value pairs, preserving the order BETWEEN rules.
    # Focal's mawk does not parse hexadecimal strings in numeric coercion.
    awk 'function decimal(s, n,j) {
      if(s !~ /^0[xX]/) return s+0;
      s=tolower(substr(s,3)); n=0;
      for(j=1;j<=length(s);j++) n=n*16+index("0123456789abcdef",substr(s,j,1))-1;
      return n;
    }
    {for(i=1;i<=NF;i+=2) {
      k=$i; v=$(i+1);
      if(k=="-m" && (v=="tcp" || v=="udp")) continue;
      if(k=="--cgroup") v=sprintf("%.0f",decimal(v));
      if((k=="--mark" || k=="--set-xmark") && v !~ /\//) v=v "/0xffffffff";
      if((k=="-s" || k=="-d") && v !~ /\//) v=v "/32";
      print k " " v;
    }}' | sort
}

rules_equal() {
    local i
    local -a wanted found
    mapfile -t wanted <<<"$1"
    mapfile -t found <<<"$2"
    [[ ${#wanted[@]} == "${#found[@]}" ]] || return 1
    for i in "${!wanted[@]}"; do
        [[ $(canonical_rule <<<"${wanted[i]}") == "$(canonical_rule <<<"${found[i]}")" ]] || return 1
    done
}

policy_verify() {
    local family table bin chain expected actual hook first count row
    local -a words
    for family in 6 4; do
        for table in mangle nat; do
            [[ $family == 6 && $table == nat ]] && continue
            bin=$(firewall_tool "$family")
            expected=$(policy_emit "$family" "$table") || return
            for chain in $(policy_chains "$family" "$table"); do
                actual=$("$bin" -w 5 -t "$table" -S "$chain") || return
                count=$(awk -v c="$chain" '$1=="-A" && $2==c {n++} END {print n+0}' <<<"$actual")
                [[ $count == "$(awk -v c="$chain" '$2==c {n++} END {print n+0}' <<<"$expected")" ]] || return 1
                rules_equal "$(awk -v c="$chain" '$2==c' <<<"$expected")" \
                    "$(awk -v c="$chain" '$1=="-A" && $2==c' <<<"$actual")" || return
            done
            while IFS= read -r row; do
                read -r -a words <<<"$row"
                words[0]=-C
                "$bin" -w 5 -t "$table" "${words[@]}" || return
            done <<<"$expected"
            while read -r hook chain; do
                actual=$("$bin" -w 5 -t "$table" -S "$hook") || return
                first=$(awk '$1=="-A" {print;exit}' <<<"$actual")
                [[ $first == "-A $hook -j $chain" ]] || return 1
                count=$(awk -v c="$chain" '$NF==c {n++} END {print n+0}' <<<"$actual")
                [[ $count == 1 ]] || return 1
            done < <(policy_hooks "$family" "$table")
        done
    done
}

policy_install() {
    local family table chain hook bin current row
    local -a hook_edits
    # Never flush built-in chains. Each owned table update is atomic; the
    # launcher admits no workload until all families and routes are verified.
    for family in 6 4; do
        for table in mangle nat; do
            [[ $family == 6 && $table == nat ]] && continue
            bin=$(firewall_tool "$family")
            hook_edits=()
            while read -r hook chain; do
                current=$("$bin" -w 5 -t "$table" -S "$hook") || return
                while IFS= read -r row; do
                    [[ $row == "-A $hook -j $chain" ]] && hook_edits+=("-D $hook -j $chain")
                done <<<"$current"
                hook_edits+=("-I $hook 1 -j $chain")
            done < <(policy_hooks "$family" "$table")
            {
                printf '*%s\n' "$table"
                for chain in $(policy_chains "$family" "$table"); do
                    printf ':%s - [0:0]\n-F %s\n' "$chain" "$chain"
                done
                policy_emit "$family" "$table"
                printf '%s\n' "${hook_edits[@]}"
                printf 'COMMIT\n'
            } | "${bin}-restore" --wait 5 --noflush || return
        done
    done
}

read_node() {
    jq -e '
      def ipv4: type=="string" and (split(".") | length==4 and all(.[];
        test("\\A(0|[1-9][0-9]{0,2})\\z") and tonumber<=255));
      (.outbounds | type=="array" and length==1) and
      (.outbounds[0] | .type=="hysteria2" and .tag=="proxy" and
        .bind_interface=="eth0" and (.detour//"")=="" and (.server|ipv4) and
        (.server_ports==null or .server_ports==[]) and
        (.server_port|type=="number" and .>=1 and .<=65535 and .==floor)) and
      .dns.servers==[{"type":"udp","tag":"upstream-dns","server":"1.1.1.1",
                      "server_port":53,"detour":"proxy"}] and
      .dns.final=="upstream-dns" and .dns.disable_cache==false and .dns.disable_expire==false
    ' "$1" >/dev/null || return
    NODE_IP=$(jq -r '.outbounds[0].server' "$1") || return
    NODE_PORT=$(jq -r '.outbounds[0].server_port' "$1")
}

gateway_open() {
    local info net nid cid pid again netpath expected
    info=$(timeout --signal=KILL 10s docker inspect "$GATEWAY") || return
    jq -e 'length==1 and (.[0] | .State.Running==true and .State.Pid>0 and
      .HostConfig.Privileged==false and .HostConfig.NetworkMode!="host" and
      .HostConfig.Sysctls["net.ipv4.ip_forward"]=="0" and
      .HostConfig.Sysctls["net.ipv6.conf.all.disable_ipv6"]=="1" and
      .HostConfig.Sysctls["net.ipv6.conf.default.disable_ipv6"]=="1" and
      .HostConfig.Sysctls["net.ipv6.conf.lo.disable_ipv6"]=="1" and
      (.NetworkSettings.Networks|length==1))' <<<"$info" >/dev/null || return
    cid=$(jq -r '.[0].Id' <<<"$info")
    pid=$(jq -r '.[0].State.Pid' <<<"$info")
    nid=$(jq -r '.[0].NetworkSettings.Networks[].NetworkID' <<<"$info")
    GATEWAY_IP=$(jq -r '.[0].NetworkSettings.Networks[].IPAddress' <<<"$info")
    netpath=$(jq -r '.[0].NetworkSettings.SandboxKey' <<<"$info")
    [[ $cid =~ ^[0-9a-f]{64}$ && $nid =~ ^[0-9a-f]{64}$ && $pid =~ ^[1-9][0-9]*$ ]] || return 1
    [[ $netpath =~ ^/(var/)?run/docker/netns/[A-Za-z0-9_-]+$ ]] || return 1
    [[ $GATEWAY_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    net=$(timeout --signal=KILL 10s docker network inspect "$nid") || return
    jq -e --arg cid "$cid" 'length==1 and (.[0]|.Driver=="bridge" and
      .EnableIPv6==false and (.Containers|keys)==[$cid])' <<<"$net" >/dev/null || return
    BRIDGE=$(jq -r '.[0].Options["com.docker.network.bridge.name"]//empty' <<<"$net")
    BRIDGE=${BRIDGE:-br-${nid:0:12}}
    [[ $BRIDGE =~ ^[A-Za-z0-9_-]{1,15}$ && $BRIDGE != lo ]] || return 1
    [[ -d /sys/class/net/$BRIDGE/bridge ]] || return 1
    # A namespace handle, rather than a numeric PID, pins subsequent reads.
    exec {GWFD}<"$netpath" || return
    [[ $(stat -Lc '%d:%i' "/proc/$$/fd/$GWFD") == "$(stat -Lc '%d:%i' "/proc/$pid/ns/net")" ]] || return 1
    again=$(timeout --signal=KILL 10s docker inspect -f '{{.Id}} {{.State.Pid}} {{.State.Running}}' "$GATEWAY") || return
    [[ $again == "$cid $pid true" ]] || return 1
    expected=$(ip -j -4 route get "$GATEWAY_IP") || return
    jq -e --arg d "$BRIDGE" 'length==1 and .[0].dev==$d and (.[0]|has("gateway")|not)' <<<"$expected" >/dev/null
}

# Only enter the network namespace: tools still come from the host filesystem.
# The entrypoint fixes PATH to system directories, including separate /sbin and
# /bin on hosts without merged /usr. Do not assume tools live in /usr/sbin.
gw() { timeout --signal=KILL 10s nsenter --net="/proc/$$/fd/$GWFD" -- "$@"; }

gateway_verify() {
    local chain count rules default_gateway routes value
    [[ $(timeout --signal=KILL 10s docker exec "$GATEWAY" cat /run/worker/policy-ready) == worker-policy-v8 ]] || return 1
    for chain in OUTPUT FORWARD INPUT; do
        case $chain in OUTPUT) count=3;; FORWARD) count=2;; INPUT) count=4;; esac
        rules=$(gw iptables-legacy -w 5 -S "$chain") || return
        awk -v c="$chain" -v n="$count" '
          $1=="-P" && $2==c && $3=="DROP" && NF==3 {p++;next}
          $1=="-A" && $2==c {r++;next} {bad=1}
          END{exit !(p==1 && r==n && !bad)}' <<<"$rules" || return
    done
    gw iptables-legacy -w 5 -C OUTPUT -o lo -j ACCEPT || return
    gw iptables-legacy -w 5 -C OUTPUT -o tun0 -j ACCEPT || return
    gw iptables-legacy -w 5 -C OUTPUT -o eth0 -d "$NODE_IP/32" -p udp --dport "$NODE_PORT" -j ACCEPT || return
    gw iptables-legacy -w 5 -C FORWARD -i eth0 -o tun0 -j ACCEPT || return
    gw iptables-legacy -w 5 -C FORWARD -i tun0 -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || return
    gw iptables-legacy -w 5 -C INPUT -i lo -j ACCEPT || return
    gw iptables-legacy -w 5 -C INPUT -i tun0 -j ACCEPT || return
    gw iptables-legacy -w 5 -C INPUT -i eth0 -s "$NODE_IP/32" -p udp --sport "$NODE_PORT" -m conntrack --ctstate ESTABLISHED -j ACCEPT || return
    gw iptables-legacy -w 5 -C INPUT -i eth0 -p icmp -m conntrack --ctstate RELATED -j ACCEPT || return
    for value in all default lo; do
        [[ $(gw sysctl -n "net.ipv6.conf.$value.disable_ipv6") == 1 ]] || return 1
    done
    gw ip -d -j link show dev tun0 | jq -e 'length==1 and
      (.[0]|.linkinfo.info_kind=="tun" and .linkinfo.info_data.type=="tun" and
      .mtu==1500 and (.flags|index("UP")!=null))' >/dev/null || return
    gw ip -j -4 addr show dev tun0 | jq -e 'length==1 and
      any(.[0].addr_info[];.local=="198.18.0.1" and .prefixlen==15)' >/dev/null || return
    default_gateway=$(gw ip -j -4 route show default dev eth0 | jq -er 'if length==1 then .[0].gateway else error("ambiguous gateway") end') || return
    for value in 0.0.0.0/1 128.0.0.0/1; do
        routes=$(gw ip -j -4 route show table main exact "$value") || return
        jq -e --arg d "$value" 'length==1 and (.[0]|.dst==$d and .dev=="tun0" and
          (.type//"unicast")=="unicast" and (has("gateway")|not))' <<<"$routes" >/dev/null || return
    done
    routes=$(gw ip -j -4 route show table main exact "$NODE_IP/32") || return
    jq -e --arg ip "$NODE_IP" --arg gw "$default_gateway" 'length==1 and
      (.[0]|(.dst==$ip or .dst==($ip+"/32")) and .gateway==$gw and .dev=="eth0" and
      (.type//"unicast")=="unicast")' <<<"$routes" >/dev/null
}

route_install() {
    # Missing bridge/default route can never make RPDB fall back to main.
    ip -4 route replace unreachable default metric 32760 table "$TABLE" || return
    ip -4 route replace "$GATEWAY_IP/32" dev "$BRIDGE" scope link table "$TABLE" || return
    ip -4 route replace default via "$GATEWAY_IP" dev "$BRIDGE" table "$TABLE" || return
    ip -4 rule add priority "$PRIORITY" fwmark "$MARK/0xffffffff" table "$TABLE"
}

routes_match() {
    jq -e --arg ip "$GATEWAY_IP" --arg dev "$BRIDGE" '
      length==3 and
      ([.[]|select(.dst=="default" and .type=="unreachable" and .metric==32760)]|length)==1 and
      ([.[]|select((.dst==$ip or .dst==($ip+"/32")) and .dev==$dev and .scope=="link" and
        (.type//"unicast")=="unicast" and (has("gateway")|not))]|length)==1 and
      ([.[]|select(.dst=="default" and .gateway==$ip and .dev==$dev and
        (.type//"unicast")=="unicast" and (.metric//0)==0)]|length)==1
    ' <<<"$1" >/dev/null
}

route_verify() {
    local data
    data=$(ip -j -4 route show table "$TABLE") || return
    routes_match "$data" || return
    data=$(ip -j -4 rule show) || return
    jq -e --arg tag "$MARK" --argjson tagdec "$((MARK))" --argjson p "$PRIORITY" --argjson t "$TABLE" '
      [.[]|select(.priority==$p)] | length==1 and
      (.[0]|(.fwmark==$tag or .fwmark==$tagdec) and
        ((.fwmask//"0xffffffff")=="0xffffffff" or .fwmask==4294967295) and (.table|tostring)==($t|tostring))
    ' <<<"$data" >/dev/null || return
    [[ $(sysctl -n "net.ipv4.conf.$BRIDGE.route_localnet") == 1 ]] || return 1
    [[ $(sysctl -n "net.ipv4.conf.$BRIDGE.rp_filter") == 2 ]]
}
