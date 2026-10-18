#!/bin/sh
# 專用網關啟動器：本機檢查不等於健康檢查；任何失敗均不啟用直連備援。
set -eu

die() { echo "[Error] $*" >&2; exit 1; }

case "${1:-}" in
    ""|--check) ;;
    *) die "Usage: /entrypoint.sh [--check]" ;;
esac

CONFIG_TEMPLATE="${CONFIG_TEMPLATE:-/etc/worker/network.json}"
POLICY_FILE="${GATEWAY_POLICY_FILE:-/usr/local/lib/worker/gateway-policy.jq}"
RUNTIME_DIR="${GATEWAY_RUNTIME_DIR:-/run/worker}"
CHECK_MODE=0
DIAGNOSTIC_FILE=
CONFIG_STAGING=
umask 077

cleanup() {
    [ -z "$DIAGNOSTIC_FILE" ] || rm -f "$DIAGNOSTIC_FILE"
    [ -z "$CONFIG_STAGING" ] || rm -f "$CONFIG_STAGING"
    if [ "$CHECK_MODE" = 1 ]; then
        rm -f "$CONFIG_FILE"
    else
        rm -f "$READY_FILE" "$READY_TEMP"
    fi
}

if [ "${1:-}" = --check ]; then
    # Read-only validation uses a disposable effective configuration. It does
    # not inspect, overwrite, remove, or publish an existing runtime/ready file.
    CHECK_MODE=1
    CONFIG_FILE="$(mktemp "${TMPDIR:-/tmp}/gateway-check.XXXXXX")"
    CONFIG_STAGING="$CONFIG_FILE"
else
    mkdir -p "$RUNTIME_DIR"
    chmod 700 "$RUNTIME_DIR"
    CONFIG_FILE="$RUNTIME_DIR/config.json"
    CONFIG_STAGING="$RUNTIME_DIR/.config.tmp"
    READY_FILE="$RUNTIME_DIR/policy-ready"
    READY_TEMP="$RUNTIME_DIR/.policy-ready.tmp"
    rm -f "$READY_FILE" "$READY_TEMP" "$CONFIG_STAGING"
fi
trap cleanup 0
trap 'exit 1' HUP INT TERM

if [ "$CHECK_MODE" = 0 ]; then
    # The host guard covers the container's early restart window. Inside this
    # dedicated namespace, close every writable chain before any configuration
    # is read, any route is inspected, or the core is invoked.
    POLICY_FAILED=0
    for CHAIN in OUTPUT FORWARD INPUT; do
        if iptables-legacy -w -P "$CHAIN" DROP; then
            iptables-legacy -w -F "$CHAIN" || POLICY_FAILED=1
        else
            POLICY_FAILED=1
        fi
    done
    [ "$POLICY_FAILED" = 0 ] || die "Cannot establish gateway DROP policies; refusing startup."
    [ "$(sysctl -n net.ipv4.ip_forward)" = 0 ] || die "Gateway already forwards traffic. Recreate it with the supplied Compose configuration."
fi

DIAGNOSTIC_FILE="$(mktemp "${TMPDIR:-/tmp}/gateway-policy-error.XXXXXX")"

hash_file() {
    # Hash stdin so filenames cannot change sha256sum's output encoding.
    HASH_OUTPUT="$(sha256sum < "$1")" || return 1
    printf '%s\n' "${HASH_OUTPUT%% *}"
}

parse_policy() {
    if jq -ceS --arg mode "$1" -f "$POLICY_FILE" "$2" 2> "$DIAGNOSTIC_FILE"; then
        return 0
    fi
    # The trusted parser emits static one-line reasons with this prefix.
    # Native jq syntax/type errors can contain source text: never publish them.
    awk 'NR == 1 && /^gateway-policy: / { reason = $0; next }
         { bad = 1 }
         END { if (NR == 1 && !bad) print reason }' "$DIAGNOSTIC_FILE" >&2
    return 1
}

SOURCE_SHA256="$(hash_file "$CONFIG_TEMPLATE")" || die "Cannot read the source configuration."
POLICY_PARSER_SHA256="$(hash_file "$POLICY_FILE")" || die "Cannot read the shared gateway policy parser."
PROXY_POLICY_JSON="$(parse_policy policy "$CONFIG_TEMPLATE")" || die "Gateway policy rejected the source configuration."
parse_policy effective "$CONFIG_TEMPLATE" > "$CONFIG_STAGING" || die "Cannot produce the managed runtime configuration."
EFFECTIVE_SHA256="$(hash_file "$CONFIG_STAGING")" || die "Cannot identify the managed runtime configuration."
if [ "$CHECK_MODE" = 0 ]; then
    mv -f "$CONFIG_STAGING" "$CONFIG_FILE"
    CONFIG_STAGING=
fi

verify_config_identity() {
    [ "$(hash_file "$CONFIG_TEMPLATE")" = "$SOURCE_SHA256" ] || die "Source configuration changed during local setup; refusing readiness."
    [ "$(hash_file "$POLICY_FILE")" = "$POLICY_PARSER_SHA256" ] || die "Gateway policy parser changed during local setup; refusing readiness."
    [ "$(hash_file "$CONFIG_FILE")" = "$EFFECTIVE_SHA256" ] || die "Effective configuration changed during local setup; refusing readiness."
}

EFFECTIVE_POLICY_JSON="$(parse_policy policy "$CONFIG_FILE")" || die "Gateway policy rejected the effective configuration."
[ "$EFFECTIVE_POLICY_JSON" = "$PROXY_POLICY_JSON" ] || die "Source and effective gateway policies disagree."
verify_config_identity
# A native core error may include authentication fields. Keep all such output
# private; readiness proves a successful core check without exposing its input.
worker check -c "$CONFIG_FILE" >/dev/null 2>&1 || die "The pinned core rejected the effective configuration. Validate it in a root-private environment."
verify_config_identity

if [ "$(printf '%s\n' "$PROXY_POLICY_JSON" | jq -r '.dns_transport')" = https ]; then
    echo "[!] This proxy policy does not support UDP on every selectable path; UDP applications may be unavailable."
fi
if [ "$CHECK_MODE" = 1 ]; then
    echo "[+] Configuration valid; no network state was changed and no connectivity probe was sent."
    exit 0
fi

ENDPOINT_ROWS="$(printf '%s\n' "$PROXY_POLICY_JSON" | jq -er '
    .outer_endpoints[] | [.address, .protocol, .port_start, .port_end] | @tsv')"
NODE_ADDRESSES="$(printf '%s\n' "$PROXY_POLICY_JSON" | jq -er '[.outer_endpoints[].address] | unique | .[]')"
# iproute2 may omit .dev when the query already filters on that device. Read
# the complete default set, then verify the unique route's device explicitly.
DEFAULT_ROUTES="$(ip -j -4 route show default)"
ORIG_GATEWAY="$(printf '%s\n' "$DEFAULT_ROUTES" | jq -er '
    def ipv4: type == "string" and (split(".") | length == 4 and all(.[];
      test("\\A(0|[1-9][0-9]{0,2})\\z") and tonumber <= 255));
    if type == "array" and length == 1 and
       (.[0] | .dst == "default" and .dev == "eth0" and
        (.type // "unicast") == "unicast" and (.gateway | ipv4))
    then .[0].gateway else empty end
')" || die "Cannot find one unambiguous original eth0 gateway; refusing an on-link fallback."

firewall_rule() {
    RULE_OPERATION="$1"
    shift
    if [ "$RULE_OPERATION" = emit ]; then
        printf '%s' '-A'
        printf ' %s' "$@"
        printf '\n'
    else
        iptables-legacy -w "$RULE_OPERATION" "$@"
    fi
}

policy_rules() {
    RULE_ACTION="$1"
    firewall_rule "$RULE_ACTION" OUTPUT -o lo -j ACCEPT
    firewall_rule "$RULE_ACTION" OUTPUT -o tun0 -j ACCEPT
    while IFS="$(printf '\t')" read -r NODE_ADDRESS NODE_PROTOCOL PORT_START PORT_END; do
        NODE_PORTS="$PORT_START"
        [ "$PORT_START" = "$PORT_END" ] || NODE_PORTS="$PORT_START:$PORT_END"
        firewall_rule "$RULE_ACTION" OUTPUT -o eth0 -d "$NODE_ADDRESS/32" -p "$NODE_PROTOCOL" --dport "$NODE_PORTS" -j ACCEPT
    done <<EOF
$ENDPOINT_ROWS
EOF

    # Node exceptions belong only to the core's local OUTPUT. Agent packets
    # taking a node /32 or a missing-TUN default are eth0 -> eth0 and stay DROP.
    firewall_rule "$RULE_ACTION" FORWARD -i eth0 -o tun0 -j ACCEPT
    firewall_rule "$RULE_ACTION" FORWARD -i tun0 -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    firewall_rule "$RULE_ACTION" INPUT -i lo -j ACCEPT
    firewall_rule "$RULE_ACTION" INPUT -i tun0 -j ACCEPT
    while IFS="$(printf '\t')" read -r NODE_ADDRESS NODE_PROTOCOL PORT_START PORT_END; do
        NODE_PORTS="$PORT_START"
        [ "$PORT_START" = "$PORT_END" ] || NODE_PORTS="$PORT_START:$PORT_END"
        firewall_rule "$RULE_ACTION" INPUT -i eth0 -s "$NODE_ADDRESS/32" -p "$NODE_PROTOCOL" --sport "$NODE_PORTS" -m conntrack --ctstate ESTABLISHED -j ACCEPT
    done <<EOF
$ENDPOINT_ROWS
EOF
    firewall_rule "$RULE_ACTION" INPUT -i eth0 -p icmp -m conntrack --ctstate RELATED -j ACCEPT
}

read_tun_link() {
    LINK_JSON="$(ip -d -j link show dev tun0)"
    printf '%s\n' "$LINK_JSON" | jq -e '
        type == "array" and length == 1 and
        (.[0] | .ifname == "tun0" and .linkinfo.info_kind == "tun" and
            .linkinfo.info_data.type == "tun" and .linkinfo.info_data.persist == true)
    ' >/dev/null || die "tun0 is not a persistent TUN device; refusing traffic allowances."
}

if ! ip link show tun0 >/dev/null 2>&1; then
    ip tuntap add dev tun0 mode tun
fi
read_tun_link
ip -4 addr replace 198.18.0.1/15 dev tun0
ip link set dev tun0 mtu 1500 up
policy_rules -A

while IFS= read -r NODE_ADDRESS; do
    ip -4 route replace "$NODE_ADDRESS/32" via "$ORIG_GATEWAY" dev eth0
done <<EOF
$NODE_ADDRESSES
EOF
# Keep the original Docker default for restart discovery. Firewall rules still
# prohibit direct egress if either of these persistent TUN routes disappears.
ip -4 route replace 0.0.0.0/1 dev tun0
ip -4 route replace 128.0.0.0/1 dev tun0

canonical_rules() {
    # Kernel -S output can reorder option/value pairs and add -m tcp/udp.
    # Normalize only within each rule; never sort the rule sequence itself.
    awk '
      NF % 2 || $1 != "-A" { exit 1 }
      {
        for (key in fields) delete fields[key]; count = 0;
        for (i = 1; i <= NF; i += 2) {
          key = $i; value = $(i + 1);
          if (key == "-m" && (value == "tcp" || value == "udp")) continue;
          if ((key == "-s" || key == "-d") && value !~ /\//) value = value "/32";
          if (key == "--ctstate" && value == "RELATED,ESTABLISHED") value = "ESTABLISHED,RELATED";
          fields[++count] = key " " value;
        }
        for (i = 2; i <= count; i++) {
          value = fields[i]; j = i - 1;
          while (j > 0 && fields[j] > value) { fields[j + 1] = fields[j]; j--; }
          fields[j + 1] = value;
        }
        for (i = 1; i <= count; i++) printf "%s%s", (i == 1 ? "" : " | "), fields[i];
        printf "\n";
      }'
}

EXPECTED_RULES="$(policy_rules emit)"
verify_chain() {
    CHAIN_RULES="$(iptables-legacy -w -S "$1")"
    printf '%s\n' "$CHAIN_RULES" | awk -v chain="$1" '
        $1 == "-P" && $2 == chain && $3 == "DROP" && NF == 3 && NR == 1 { policies++; next }
        $1 == "-A" && $2 == chain { next }
        { invalid = 1 }
        END { exit !(policies == 1 && !invalid) }
    ' || die "Unexpected $1 chain policy; refusing readiness."
    EXPECTED_CHAIN="$(printf '%s\n' "$EXPECTED_RULES" | awk -v chain="$1" '$2 == chain' | canonical_rules)"
    ACTUAL_CHAIN="$(printf '%s\n' "$CHAIN_RULES" | awk '$1 == "-A"' | canonical_rules)" || die "Malformed $1 rules; refusing readiness."
    [ "$ACTUAL_CHAIN" = "$EXPECTED_CHAIN" ] || die "Unexpected $1 rule sequence; refusing readiness."
}
verify_chain OUTPUT
verify_chain FORWARD
verify_chain INPUT
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
while IFS= read -r NODE_ADDRESS; do
    verify_route "$NODE_ADDRESS/32" eth0 "$ORIG_GATEWAY"
done <<EOF
$NODE_ADDRESSES
EOF
verify_route 0.0.0.0/1 tun0 ""
verify_route 128.0.0.0/1 tun0 ""

# Verify the whole host-route set, so an old or additional node route is never
# silently retained. Docker's connected subnet and the connected TUN subnet
# are not node exceptions and remain in place.
ALL_ROUTES="$(ip -j -4 route show table main)"
printf '%s\n' "$ALL_ROUTES" | jq -e --argjson policy "$PROXY_POLICY_JSON" '
    ($policy.outer_endpoints | map(.address) | unique) as $nodes |
    type == "array" and
    ([.[] | select(.dst != "default" and
       ((.dst | contains("/") | not) or (.dst | endswith("/32")))) |
       .dst | sub("/32$"; "")] | sort) == $nodes and
    all(.[] | select(.dev == "eth0" and .dst != "default" and has("gateway"));
      (.dst | sub("/32$"; "")) as $address | ($nodes | index($address)) != null)
' >/dev/null || die "Unexpected gateway node route set; refusing readiness."

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
verify_config_identity

# Private, versioned identities bind authentication and TLS as well as the
# endpoints. The host independently recomputes every identity, reads actual
# container files/rules/routes, and only then enables gateway forwarding.
jq -ncS --arg source "$SOURCE_SHA256" --arg effective "$EFFECTIVE_SHA256" \
    --arg parser "$POLICY_PARSER_SHA256" --argjson policy "$PROXY_POLICY_JSON" '
    {format: 2, source_sha256: $source, effective_sha256: $effective,
     policy_parser_sha256: $parser, policy: $policy}
' > "$READY_TEMP"
chmod 600 "$READY_TEMP"
mv -f "$READY_TEMP" "$READY_FILE"
rm -f "$DIAGNOSTIC_FILE"
DIAGNOSTIC_FILE=
echo "[+] Local fail-closed gateway policy and configuration identities verified; starting the pinned core."
echo "[+] Forwarding remains disabled until the trusted host manager verifies local isolation."
exec worker run -c "$CONFIG_FILE"
