#!/bin/sh
# 專用網關啟動器：本機檢查不等於健康檢查；任何失敗均不啟用直連備援。
set -eu

die() { echo "[Error] $*" >&2; exit 1; }

case "${1:-}" in
    ""|--check) ;;
    *) die "Usage: /entrypoint.sh [--check]" ;;
esac

CONFIG_TEMPLATE="${CONFIG_TEMPLATE:-/etc/worker/network.json}"
RUNTIME_DIR="${GATEWAY_RUNTIME_DIR:-/run/worker}"
umask 077

if [ "${1:-}" = --check ]; then
    # Check mode uses only a disposable config. It never changes networking,
    # overwrites a running core's config, or publishes/removes readiness.
    CONFIG_FILE="$(mktemp "${TMPDIR:-/tmp}/gateway-check.XXXXXX")"
    trap 'rm -f "$CONFIG_FILE"' 0
    trap 'exit 1' HUP INT TERM
else
    # 清除上次 ready，再建立 DROP。主機的 mangle FORWARD guard 另外涵蓋重啟早期。
    mkdir -p "$RUNTIME_DIR"
    chmod 700 "$RUNTIME_DIR"
    CONFIG_FILE="$RUNTIME_DIR/config.json"
    READY_FILE="$RUNTIME_DIR/policy-ready"
    READY_TEMP="$RUNTIME_DIR/.policy-ready.tmp"
    rm -f "$READY_FILE" "$READY_TEMP"
    trap 'rm -f "$READY_FILE" "$READY_TEMP"' 0
    trap 'exit 1' HUP INT TERM

    # This is a dedicated gateway network namespace. Set fail-closed defaults
    # before removing stale rules, inspecting routes, or invoking worker.
    # There is deliberately no broad established-flow OUTPUT exception.
    POLICY_FAILED=0
    for CHAIN in OUTPUT FORWARD INPUT; do
        if iptables-legacy -w -P "$CHAIN" DROP; then
            iptables-legacy -w -F "$CHAIN" || POLICY_FAILED=1
        else
            POLICY_FAILED=1
        fi
    done
    # If one operation is denied, still close every independently writable
    # chain. The host guard must remain closed when this setup cannot finish.
    [ "$POLICY_FAILED" = 0 ] || die "Cannot establish gateway DROP policies; refusing startup."

    # Container /proc/sys can remain read-only. Only the trusted host manager
    # may enable forwarding, after its own independent local verification.
    [ "$(sysctl -n net.ipv4.ip_forward)" = 0 ] || die "Gateway already forwards traffic. Recreate it with the supplied Compose configuration."
fi

jq --arg level "${LOG_LEVEL:-info}" '.log.level = $level' \
   "$CONFIG_TEMPLATE" > "$CONFIG_FILE"

# DNS 新式 dialer 省略 detour 可能直連，不能只依賴 route.final。
# 配置不符就停在封鎖狀態；不自動補一個未經同意的備用解析器。
jq -e '
    .dns.servers == [{"type":"udp","tag":"upstream-dns","server":"1.1.1.1",
                      "server_port":53,"detour":"proxy"}] and
    .dns.final == "upstream-dns" and .dns.disable_cache == false and .dns.disable_expire == false
' "$CONFIG_FILE" >/dev/null || die "Expected cached UDP DNS through proxy only."

# Only the supplied single IPv4 Hysteria2 node is supported. Validate JSON
# before shell extraction can strip a trailing newline. No lookup is needed.
# Port hopping overrides server_port in the core, but policy permits one port.
jq -e '
    def ipv4:
        type == "string" and
        (split(".") | length == 4 and all(.[];
            test("\\A(0|[1-9][0-9]{0,2})\\z") and tonumber <= 255));
    (.outbounds | type == "array" and length == 1) and
    (.outbounds[0] |
        .type == "hysteria2" and .tag == "proxy" and
        .bind_interface == "eth0" and (.detour // "") == "" and
        (.server | ipv4) and
        (.server_ports == null or .server_ports == []) and
        (.server_port | type == "number" and . >= 1 and . <= 65535 and . == floor))
' "$CONFIG_FILE" >/dev/null || die "Expected one Hysteria2 outbound tagged proxy, bound to eth0, with a numeric IPv4 server and integer server_port (1..65535); server_ports must be absent, null, or []."
worker check -c "$CONFIG_FILE"
NODE_IP="$(jq -r '.outbounds[0].server' "$CONFIG_FILE")"
NODE_PORT="$(jq -r '.outbounds[0].server_port' "$CONFIG_FILE")"

if [ "${1:-}" = --check ]; then
    echo "[+] Configuration valid; no network state was changed and no connectivity probe was sent."
    exit 0
fi

ORIG_GATEWAY="$(ip -4 route show default dev eth0 | awk '/^default via/ {print $3; exit}')"
[ -n "$ORIG_GATEWAY" ] || die "Cannot find the original eth0 gateway; refusing to guess an on-link route."

policy_rules() {
    # 本機／TUN 與唯一節點 UDP 是外層出口；不加入寬泛 ESTABLISHED OUTPUT 例外。
    # The identical rule set is installed with -A and verified with -C.
    # Keep each invocation standalone: set -e must abort on any failure.
    iptables-legacy -w "$1" OUTPUT -o lo -j ACCEPT
    iptables-legacy -w "$1" OUTPUT -o tun0 -j ACCEPT
    iptables-legacy -w "$1" OUTPUT -o eth0 -d "${NODE_IP}/32" -p udp --dport "$NODE_PORT" -j ACCEPT

    iptables-legacy -w "$1" FORWARD -i eth0 -o tun0 -j ACCEPT
    iptables-legacy -w "$1" FORWARD -i tun0 -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    iptables-legacy -w "$1" INPUT -i lo -j ACCEPT
    iptables-legacy -w "$1" INPUT -i tun0 -j ACCEPT
    iptables-legacy -w "$1" INPUT -i eth0 -s "${NODE_IP}/32" -p udp --sport "$NODE_PORT" -m conntrack --ctstate ESTABLISHED -j ACCEPT
    iptables-legacy -w "$1" INPUT -i eth0 -p icmp -m conntrack --ctstate RELATED -j ACCEPT
}

read_tun_link() {
    LINK_JSON="$(ip -d -j link show dev tun0)"
    printf '%s\n' "$LINK_JSON" | jq -e '
        type == "array" and length == 1 and
        (.[0] | .ifname == "tun0" and .linkinfo.info_kind == "tun" and
            .linkinfo.info_data.type == "tun")
    ' >/dev/null || die "tun0 is not a TUN device; refusing traffic allowances."
}

if ! ip link show tun0 >/dev/null 2>&1; then
    # 先建立 persistent TUN；核心程式死亡時不把路由自動退回普通 eth0。
    ip tuntap add dev tun0 mode tun
fi
# A link name alone must not authorize traffic to a TAP, dummy, or veth peer.
read_tun_link
ip -4 addr replace 198.18.0.1/15 dev tun0
ip link set dev tun0 mtu 1500 up
policy_rules -A

# Only the core's native Hysteria2 outer UDP socket may use this eth0 /32.
# Forwarded packets taking the same /32 are eth0 -> eth0 and hit default DROP.
ip -4 route replace "${NODE_IP}/32" via "$ORIG_GATEWAY" dev eth0

# Preserve the original default to recover the Docker gateway on restart.
# If either TUN route disappears, OUTPUT/FORWARD still prohibit direct egress.
ip -4 route replace 0.0.0.0/1 dev tun0
ip -4 route replace 128.0.0.0/1 dev tun0

verify_chain() {
    # 不只確認允許規則存在，還核對 DROP 預設及規則數，拒絕額外放行。
    CHAIN_RULES="$(iptables-legacy -w -S "$1")"
    printf '%s\n' "$CHAIN_RULES" | awk -v chain="$1" -v expected="$2" '
        $1 == "-P" && $2 == chain && $3 == "DROP" && NF == 3 { policies++; next }
        $1 == "-A" && $2 == chain { rules++; next }
        { invalid = 1 }
        END { exit !(policies == 1 && rules == expected && !invalid) }
    ' || die "Unexpected $1 policy or rule count; refusing readiness."
}
verify_chain OUTPUT 3
verify_chain FORWARD 2
verify_chain INPUT 4
policy_rules -C

verify_route() {
    ROUTE_JSON="$(ip -j -4 route show table main exact "$1")"
    printf '%s\n' "$ROUTE_JSON" | jq -e \
        --arg prefix "$1" --arg device "$2" --arg gateway "$3" '
        type == "array" and length == 1 and
        (.[0] |
            (.dst == $prefix or (.dst + "/32") == $prefix) and
            .dev == $device and (.type // "unicast") == "unicast" and
            (if $gateway == "" then (has("gateway") | not) else .gateway == $gateway end))
    ' >/dev/null || die "Unexpected local route for $1; refusing readiness."
}
verify_route "${NODE_IP}/32" eth0 "$ORIG_GATEWAY"
verify_route 0.0.0.0/1 tun0 ""
verify_route 128.0.0.0/1 tun0 ""

read_tun_link
printf '%s\n' "$LINK_JSON" | jq -e '
    type == "array" and length == 1 and
    (.[0] | .ifname == "tun0" and .mtu == 1500 and (.flags | index("UP") != null))
' >/dev/null || die "TUN is not administratively up with the expected MTU; refusing readiness."
ADDR_JSON="$(ip -j -4 addr show dev tun0)"
printf '%s\n' "$ADDR_JSON" | jq -e '
    type == "array" and length == 1 and
    (.[0] | .ifname == "tun0" and any(.addr_info[];
        .family == "inet" and .local == "198.18.0.1" and .prefixlen == 15))
' >/dev/null || die "TUN address does not match; refusing readiness."
[ "$(sysctl -n net.ipv4.ip_forward)" = 0 ] || die "Forwarding changed before local setup completed; refusing readiness."

# Host interface: root-owned /run/worker/policy-ready, mode 0600,
# exact bytes "worker-policy-v8\n". This attests only local setup, not
# core/DNS/Internet reachability. The host must independently read back the
# rules/routes and enable forwarding only after its cgroup guard is active.
# A persistent TUN safely drops packets until the core attaches; core failure
# remains offline. There are no periodic checks or automatic direct fallback.
printf 'worker-policy-v8\n' > "$READY_TEMP"
mv -f "$READY_TEMP" "$READY_FILE"
echo "[+] Local fail-closed gateway policy verified; starting native Hysteria2."
echo "[+] Forwarding remains disabled until the trusted host manager verifies local isolation."
# The executable is renamed at build time; the runtime root is read-only.
exec worker run -c "$CONFIG_FILE"
