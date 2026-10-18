#!/bin/bash
# Sourced by the root entry point. No side effects at source time.
readonly CLASSID=0x6d730001 MARK=0x6d730001 TABLE=32190 PRIORITY=1190
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
    local family=$1 table=$2 chain prefix match endpoints address protocol start end port
    match=$(cgroup_match) || return
    case "$family:$table" in
    4:mangle)
        for chain in D8OUT D8POST; do
            # The only class is shared by all sessions. Historical sockets
            # retain this same restriction; no identities are ever recycled.
            printf '%s\n' "-A $chain $match -j MARK --set-xmark $MARK/0xffffffff"
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
        endpoints=$(proxy_endpoint_rows) || return
        while IFS=$'\t' read -r address protocol start end; do
            port=$start; [[ $start == "$end" ]] || port=$start:$end
            printf '%s\n' "-A D8GW -i $BRIDGE -s $GATEWAY_IP/32 -d $address/32 -p $protocol -m $protocol --dport $port -j RETURN"
        done <<<"$endpoints"
        printf '%s\n' "-A D8GW -i $BRIDGE -j DROP"
        ;;
    6:mangle)
        for chain in D8OUT6 D8POST6; do
            printf '%s\n' "-A $chain $match -j DROP"
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
      if(k=="--path" && v ~ /^"[A-Za-z0-9_.\/-]+"$/) v=substr(v,2,length(v)-2);
      if(k=="--ctstate" && v=="RELATED,ESTABLISHED") v="ESTABLISHED,RELATED";
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
    local -A rendered
    # Render every table before touching netfilter. A parser/selector failure
    # must not be hidden by a later successful printf in the restore pipeline.
    for family in 6 4; do
        for table in mangle nat; do
            [[ $family == 6 && $table == nat ]] && continue
            rendered[$family:$table]=$(policy_emit "$family" "$table") || return
        done
    done
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
                printf '%s\n' "${rendered[$family:$table]}"
                printf '%s\n' "${hook_edits[@]}"
                printf 'COMMIT\n'
            } | "${bin}-restore" --wait 5 --noflush || return
        done
    done
}

read_proxy_policy() {
    local config=$1 parser source_before source_after policy effective parser_hash
    unset PROXY_POLICY_JSON SOURCE_SHA256 EFFECTIVE_SHA256 POLICY_PARSER_SHA256
    parser=$ROOT/gateway-policy.jq
    [[ -f $config && ! -L $config && -f $parser && ! -L $parser ]] || return 1
    source_before=$(sha256sum -- "$config") || return
    parser_hash=$(sha256sum -- "$parser") || return
    # Only the parser's static, nonsecret failure reasons may reach the user.
    # JSON syntax diagnostics could otherwise quote source lines with secrets.
    local error_file
    error_file=$(mktemp) || return
    if ! policy=$(jq -ceS --arg mode policy -f "$parser" "$config" 2>"$error_file"); then
        awk '/^gateway-policy: [A-Za-z0-9][A-Za-z0-9 .,:()_\/-]*$/ {print; found=1; exit}
             END {if(!found) print "Proxy configuration rejected; check its JSON and supported options."}' "$error_file" >&2
        rm -f -- "$error_file"
        return 1
    fi
    rm -f -- "$error_file"
    effective=$(jq -ceS --arg mode effective -f "$parser" "$config" 2>/dev/null) || return
    source_after=$(sha256sum -- "$config") || return
    [[ $source_before == "$source_after" && $parser_hash == "$(sha256sum -- "$parser")" ]] || return 1
    effective=$(printf '%s\n' "$effective" | sha256sum) || return
    PROXY_POLICY_JSON=$policy
    SOURCE_SHA256=${source_before%% *}
    EFFECTIVE_SHA256=${effective%% *}
    POLICY_PARSER_SHA256=${parser_hash%% *}
}

proxy_endpoint_rows() {
    [[ -n ${PROXY_POLICY_JSON:-} ]] || return 1
    jq -er '
      def port: type=="number" and .>=1 and .<=65535 and .==floor;
      def ipv4: type=="string" and (split(".") | length==4 and all(.[];
        test("\\A(0|[1-9][0-9]{0,2})\\z") and tonumber<=255));
      if .format==1 and (.outer_endpoints|type=="array" and length>0 and all(.[];
          .family==4 and (.address|ipv4) and (.protocol=="tcp" or .protocol=="udp") and
          (.port_start|port) and (.port_end|port) and .port_start<=.port_end))
      then .outer_endpoints[] | [.address,.protocol,.port_start,.port_end] | @tsv
      else error("Invalid normalized proxy endpoints") end
    ' <<<"$PROXY_POLICY_JSON" 2>/dev/null
}

gateway_open() {
    local info net nid cid pid again netpath expected
    info=$(timeout --signal=KILL 10s docker inspect "$GATEWAY") || return
    jq -e --arg config "$ROOT/network.json" 'length==1 and (.[0] | .State.Running==true and .State.Pid>0 and
      .HostConfig.Privileged==false and .HostConfig.NetworkMode!="host" and
      .HostConfig.ReadonlyRootfs==true and (.HostConfig.CapDrop==["ALL"]) and
      (.HostConfig.CapAdd|sort)==["NET_ADMIN","NET_RAW"] and
      any(.HostConfig.SecurityOpt[]; .=="no-new-privileges:true" or .=="no-new-privileges") and
      ([.Mounts[]|select(.Destination=="/etc/worker/network.json")]|length==1 and
        .[0].Source==$config and .[0].RW==false and .[0].Type=="bind") and
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
    # Remapped/rootless Docker needs a separate capability model; do not
    # silently treat its container root as the required host-owned gateway.
    awk '/^Uid:/ {found=1; ok=($2==0 && $3==0 && $4==0 && $5==0)} END{exit !(found && ok)}' \
        "/proc/$pid/status" || return
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
    jq -e --arg d "$BRIDGE" 'length==1 and .[0].dev==$d and (.[0]|has("gateway")|not)' <<<"$expected" >/dev/null || return
    GATEWAY_ID=$cid
    GATEWAY_PID=$pid
    GATEWAY_NETWORK_ID=$nid
    GATEWAY_NS_ID=$(stat -Lc '%d:%i' "/proc/$$/fd/$GWFD")
}

# Only enter the network namespace: tools still come from the host filesystem.
# The entrypoint fixes PATH to system directories, including separate /sbin and
# /bin on hosts without merged /usr. Do not assume tools live in /usr/sbin.
gw() { timeout --signal=KILL 10s nsenter --net="/proc/$$/fd/$GWFD" -- "$@"; }

gateway_ready_text() {
    jq -cnSe --arg source "$SOURCE_SHA256" --arg effective "$EFFECTIVE_SHA256" \
        --arg parser "$POLICY_PARSER_SHA256" --argjson policy "$PROXY_POLICY_JSON" \
        '{format:2,source_sha256:$source,effective_sha256:$effective,
          policy_parser_sha256:$parser,policy:$policy}'
}

gateway_rules() {
    local chain=$1 endpoints address protocol start end port
    endpoints=$(proxy_endpoint_rows) || return
    case $chain in
        OUTPUT)
            printf '%s\n' '-A OUTPUT -o lo -j ACCEPT' '-A OUTPUT -o tun0 -j ACCEPT'
            while IFS=$'\t' read -r address protocol start end; do
                port=$start; [[ $start == "$end" ]] || port=$start:$end
                printf '%s\n' "-A OUTPUT -o eth0 -d $address/32 -p $protocol -m $protocol --dport $port -j ACCEPT"
            done <<<"$endpoints"
            ;;
        FORWARD)
            printf '%s\n' '-A FORWARD -i eth0 -o tun0 -j ACCEPT' \
                '-A FORWARD -i tun0 -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
            ;;
        INPUT)
            printf '%s\n' '-A INPUT -i lo -j ACCEPT' '-A INPUT -i tun0 -j ACCEPT'
            while IFS=$'\t' read -r address protocol start end; do
                port=$start; [[ $start == "$end" ]] || port=$start:$end
                printf '%s\n' "-A INPUT -i eth0 -s $address/32 -p $protocol -m $protocol --sport $port -m conntrack --ctstate ESTABLISHED -j ACCEPT"
            done <<<"$endpoints"
            printf '%s\n' '-A INPUT -i eth0 -p icmp -m conntrack --ctstate RELATED -j ACCEPT'
            ;;
        *) return 1 ;;
    esac
}

gateway_node_routes_match() {
    jq -e --argjson policy "$PROXY_POLICY_JSON" '
      ($policy.outer_endpoints|map(.address)|unique) as $nodes |
      type=="array" and
      ([.[]|select(.dst!="default" and (.dst|test("^[0-9]+(\\.[0-9]+){3}(/32)?$")))
        |.dst|split("/")[0]]|sort)==$nodes and
      all(.[]; if .dev=="eth0" and has("gateway") and .dst!="default"
        then (.dst|split("/")[0]) as $dst | ($nodes|index($dst))!=null
        else true end)
    ' <<<"$1" >/dev/null
}

gateway_verify() {
    local chain count rules expected actual default_gateway routes value endpoints hashes wanted_hashes
    actual=$(timeout --signal=KILL 10s docker exec "$GATEWAY" cat /run/worker/policy-ready) || return
    actual=$(jq -ceS . <<<"$actual" 2>/dev/null) || return
    expected=$(gateway_ready_text) || return
    [[ $actual == "$expected" ]] || return 1
    # Read actual files independently of ready. Password-only changes must be
    # caught even when the parsed endpoint set has not changed.
    hashes=$(timeout --signal=KILL 10s docker exec "$GATEWAY" sha256sum \
        /etc/worker/network.json /run/worker/config.json /usr/local/lib/worker/gateway-policy.jq) || return
    wanted_hashes=$(printf '%s  %s\n' "$SOURCE_SHA256" /etc/worker/network.json \
        "$EFFECTIVE_SHA256" /run/worker/config.json \
        "$POLICY_PARSER_SHA256" /usr/local/lib/worker/gateway-policy.jq)
    [[ $hashes == "$wanted_hashes" ]] || return 1
    for chain in OUTPUT FORWARD INPUT; do
        expected=$(gateway_rules "$chain") || return
        count=$(awk 'END{print NR}' <<<"$expected")
        rules=$(gw iptables-legacy -w 5 -S "$chain") || return
        awk -v c="$chain" -v n="$count" '
          $1=="-P" && $2==c && $3=="DROP" && NF==3 {p++;next}
          $1=="-A" && $2==c {r++;next} {bad=1}
          END{exit !(p==1 && r==n && !bad)}' <<<"$rules" || return
        actual=$(awk '$1=="-A"' <<<"$rules") || return
        rules_equal "$expected" "$actual" || return
    done
    for value in all default lo; do
        [[ $(gw sysctl -n "net.ipv6.conf.$value.disable_ipv6") == 1 ]] || return 1
    done
    gw ip -d -j link show dev tun0 | jq -e 'length==1 and
      (.[0]|.linkinfo.info_kind=="tun" and .linkinfo.info_data.type=="tun" and
      .linkinfo.info_data.persist==true and .mtu==1500 and (.flags|index("UP")!=null))' >/dev/null || return
    gw ip -j -4 addr show dev tun0 | jq -e 'length==1 and
      any(.[0].addr_info[];.local=="198.18.0.1" and .prefixlen==15)' >/dev/null || return
    default_gateway=$(gw ip -j -4 route show default dev eth0 | jq -er 'if length==1 then .[0].gateway else error("ambiguous gateway") end') || return
    for value in 0.0.0.0/1 128.0.0.0/1; do
        routes=$(gw ip -j -4 route show table main exact "$value") || return
        jq -e --arg d "$value" 'length==1 and (.[0]|.dst==$d and .dev=="tun0" and
          (.type//"unicast")=="unicast" and (has("gateway")|not))' <<<"$routes" >/dev/null || return
    done
    endpoints=$(proxy_endpoint_rows) || return
    endpoints=$(cut -f1 <<<"$endpoints" | sort -u) || return
    while IFS= read -r value; do
        routes=$(gw ip -j -4 route show table main exact "$value/32") || return
        jq -e --arg ip "$value" --arg gw "$default_gateway" 'length==1 and
          (.[0]|(.dst==$ip or .dst==($ip+"/32")) and .gateway==$gw and .dev=="eth0" and
          (.type//"unicast")=="unicast")' <<<"$routes" >/dev/null || return
    done <<<"$endpoints"
    routes=$(gw ip -j -4 route show table main) || return
    gateway_node_routes_match "$routes" || return
    # A restarted/replaced container must not be admitted using a pinned old
    # namespace and a new container's ready file.
    actual=$(timeout --signal=KILL 10s docker inspect -f '{{.Id}} {{.State.Pid}} {{.State.Running}}' "$GATEWAY") || return
    [[ $actual == "$GATEWAY_ID $GATEWAY_PID true" ]]
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
    data=$(ip -N -j -4 rule show) || return
    jq -e --arg tag "$MARK" --argjson tagdec "$((MARK))" --argjson p "$PRIORITY" --argjson t "$TABLE" '
      [.[]|select(.priority==$p)] | length==1 and
      (.[0]|(.fwmark==$tag or .fwmark==$tagdec) and
        ((.fwmask//"0xffffffff")=="0xffffffff" or .fwmask==4294967295) and (.table|tostring)==($t|tostring))
    ' <<<"$data" >/dev/null || return
    [[ $(sysctl -n "net.ipv4.conf.$BRIDGE.route_localnet") == 1 ]] || return 1
    [[ $(sysctl -n "net.ipv4.conf.$BRIDGE.rp_filter") == 2 ]]
}
