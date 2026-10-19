# Shared pure configuration compiler for the pinned sing-box 1.14.2 image.
# Invocation: jq -ceS --arg mode policy|effective -f gateway-policy.jq CONFIG
# stdout is one complete JSON object. Every validation diagnostic is static;
# never interpolate tags, addresses, credentials, headers, or source fragments.

def fail($reason): ("gateway-policy: " + $reason + "\n") | halt_error(2);
def ensure($condition; $reason): if $condition then . else fail($reason) end;
def allowed($names; $reason):
  ensure(type == "object"; $reason)
  | ensure((keys_unsorted - $names | length) == 0; $reason);
def optional_type($names; $kind; $reason):
  . as $object
  | ensure(all($names[]; . as $key |
      ($object[$key] == null or ($object[$key] | type) == $kind)); $reason);
def integer($min; $max): type == "number" and . == floor and . >= $min and . <= $max;
def optional_integers($names; $reason):
  . as $object | ensure(all($names[]; . as $key |
      ($object[$key] == null or ($object[$key] | integer(0; 9007199254740991)))); $reason);
def string_list:
  type == "string" or (type == "array" and all(.[]; type == "string"));
def optional_lists($names; $reason):
  . as $object | ensure(all($names[]; . as $key |
      ($object[$key] == null or ($object[$key] | string_list))); $reason);
def optional_sizes($names; $reason):
  . as $object | ensure(all($names[]; . as $key |
      ($object[$key] == null or ($object[$key] | type) == "string"
       or ($object[$key] | integer(0; 9007199254740991)))); $reason);
def tag: type == "string" and test("\\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\\z");
def ipv4:
  type == "string" and (split(".") | length == 4 and all(.[];
    test("\\A(0|[1-9][0-9]{0,2})\\z") and tonumber <= 255));
def group: .type == "selector" or .type == "urltest";
def enabled: . == true or (type == "object" and .enabled == true);
def networks:
  .network as $network
  | if $network == null or $network == [] then ["tcp", "udp"]
    elif ($network | type) == "string" then [$network]
    elif ($network | type) == "array" then $network
    else fail("network must be tcp, udp, or a list of those values") end
  | ensure(length > 0 and all(.[]; . == "tcp" or . == "udp");
           "network must be tcp, udp, or a list of those values") | unique;
def subset($small; $large): ($small - $large | length) == 0;

def udp_dns:
  {type:"udp", tag:"upstream-dns", server:"1.1.1.1", server_port:53, detour:"proxy"};
def https_dns:
  {type:"https", tag:"upstream-dns", server:"1.1.1.1", server_port:443,
   path:"/dns-query", detour:"proxy", tls:{enabled:true, server_name:"cloudflare-dns.com"}};

def check_headers($reason):
  ensure(type == "object"; $reason)
  | ensure(all(to_entries[]; (.key | test("\\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\\z"))
      and (.value | string_list)); $reason);

def check_tls:
  allowed(["enabled","engine","disable_sni","server_name","insecure","alpn",
    "min_version","max_version","cipher_suites","curve_preferences","certificate",
    "certificate_public_key_sha256","client_certificate","client_key","fragment",
    "fragment_fallback_delay","record_fragment","kernel_tx","kernel_rx",
    "handshake_timeout","utls","reality"];
    "unsupported TLS option. External files, ECH discovery, and packet spoofing are not managed")
  | optional_type(["enabled","disable_sni","insecure","fragment","record_fragment",
                   "kernel_tx","kernel_rx"]; "boolean"; "invalid TLS boolean option")
  | optional_type(["engine","server_name","min_version","max_version",
                   "fragment_fallback_delay","handshake_timeout"]; "string"; "invalid TLS string option")
  | optional_lists(["alpn","cipher_suites","curve_preferences","certificate",
      "certificate_public_key_sha256","client_certificate","client_key"]; "invalid TLS list option")
  | ensure(.engine == null or .engine == "" or .engine == "go"; "TLS engine is not available in the pinned Linux image")
  | if .utls != null then .utls |= (
      allowed(["enabled","fingerprint"]; "unknown TLS uTLS option")
      | optional_type(["enabled"]; "boolean"; "invalid TLS uTLS enabled value")
      | optional_type(["fingerprint"]; "string"; "invalid TLS uTLS fingerprint")) else . end
  | if .reality != null then .reality |= (
      allowed(["enabled","public_key","short_id"]; "unknown TLS Reality option")
      | optional_type(["enabled"]; "boolean"; "invalid TLS Reality enabled value")
      | optional_type(["public_key","short_id"]; "string"; "invalid TLS Reality key value")) else . end;

def check_transport:
  ensure(type == "object"; "transport must be an object")
  | .type as $type
  | ensure($type != "httpupgrade";
           "HTTPUpgrade is not accepted for pinned core 1.14.2 after paired reliability failures. Use native TCP (omit transport), ws, http, grpc, or quic")
  | ensure(["http","ws","grpc","quic"] | index($type) != null;
           "unsupported V2Ray transport. Use http, ws, grpc, or quic. Omit transport for native TCP")
  | allowed(["type"] + (if $type == "http" then
       ["host","path","method","headers","idle_timeout","ping_timeout"]
     elif $type == "ws" then ["path","headers","max_early_data","early_data_header_name"]
     elif $type == "grpc" then ["service_name","idle_timeout","ping_timeout","permit_without_stream"] else [] end);
     "unknown V2Ray transport option")
  | optional_type(["path","method","idle_timeout","ping_timeout","service_name",
                   "early_data_header_name"]; "string"; "invalid transport string option")
  | optional_type(["permit_without_stream"]; "boolean"; "invalid transport boolean option")
  | optional_integers(["max_early_data"]; "invalid transport early data size")
  | if .host != null then
      ensure((if $type == "http" then (.host | string_list) else (.host | type) == "string" end);
             "invalid transport host option") else . end
  | if .headers != null then .headers |= check_headers("invalid transport headers") else . end;

def check_uot:
  if type == "boolean" then .
  else allowed(["enabled","version"]; "unknown UDP over TCP option")
    | optional_type(["enabled"]; "boolean"; "UDP over TCP enabled must be boolean")
    | ensure(.version == null or .version == 0 or .version == 1 or .version == 2;
             "UDP over TCP version must be 1 or 2") end;
def check_mux:
  allowed(["enabled","protocol","max_connections","min_streams","max_streams","padding","brutal"];
          "unknown multiplex option")
  | optional_type(["enabled","padding"]; "boolean"; "invalid multiplex boolean option")
  | optional_integers(["max_connections","min_streams","max_streams"]; "invalid multiplex stream limit")
  | ensure(.protocol == null or .protocol == "" or .protocol == "h2mux" or .protocol == "smux" or .protocol == "yamux";
           "unknown multiplex protocol")
  | if .brutal != null then .brutal |= (
      allowed(["enabled","up_mbps","down_mbps"]; "unknown multiplex TCP Brutal option")
      | optional_type(["enabled"]; "boolean"; "invalid TCP Brutal enabled value")
      | optional_integers(["up_mbps","down_mbps"]; "invalid TCP Brutal bandwidth")
      | ensure(.enabled != true; "TCP Brutal requires a separately verified kernel module and is not supported")) else . end;

def port_ranges:
  (if .type == "hysteria" or .type == "hysteria2" then .server_ports else null end) as $ports
  | if $ports == null or $ports == [] then
      ensure(.server_port | integer(1;65535); "server_port must be an integer in 1..65535")
      | [[.server_port,.server_port]]
    else
      (if ($ports | type) == "string" then [$ports]
       elif ($ports | type) == "array" then $ports
       else fail("server_ports must contain explicit bounded port ranges") end)
      | map(ensure(type == "string" and test("\\A[1-9][0-9]{0,4}:[1-9][0-9]{0,4}\\z");
                   "server_ports entries require explicit start:end port ranges")
        | split(":") | map(tonumber)
        | ensure(.[0] <= .[1] and .[1] <= 65535;
                 "server_ports range is reversed or outside 1..65535")) end;

def common_fields:
  ["type","tag","server","server_port","detour","bind_interface","connect_timeout",
   "tcp_fast_open","disable_tcp_keep_alive","tcp_keep_alive","tcp_keep_alive_interval",
   "udp_fragment","reuse_addr","bind_address_no_port"];
def quic_fields:
  ["idle_timeout","keep_alive_period","stream_receive_window","connection_receive_window",
   "max_concurrent_streams","initial_packet_size","disable_path_mtu_discovery"];
def protocol_fields($type):
  if $type == "hysteria2" then ["server_ports","hop_interval","hop_interval_max","up_mbps","down_mbps",
     "obfs","password","network","tls","bbr_profile","brutal_debug","disable_chrome_parrot"] + quic_fields
  elif $type == "hysteria" then ["server_ports","hop_interval","up","up_mbps","down","down_mbps",
     "obfs","auth","auth_str","recv_window_conn","recv_window","disable_mtu_discovery","network","tls"] + quic_fields
  elif $type == "tuic" then ["uuid","password","congestion_control","udp_relay_mode","udp_over_stream",
     "zero_rtt_handshake","heartbeat","network","tls"] + quic_fields
  elif $type == "shadowsocks" then ["method","password","plugin","plugin_opts","network","udp_over_tcp","multiplex"]
  elif $type == "trojan" then ["password","network","tls","multiplex","transport"]
  elif $type == "vmess" then ["uuid","security","alter_id","global_padding","authenticated_length",
     "network","tls","packet_encoding","multiplex","transport"]
  elif $type == "vless" then ["uuid","flow","network","tls","multiplex","transport","packet_encoding"]
  elif $type == "anytls" then fail("AnyTLS is not accepted for pinned core 1.14.2 after native fault-recovery failure. Use another validated proxy protocol")
  elif $type == "snell" then ["version","psk","userkey","reuse","network","obfs_mode","obfs_host","mode"]
  elif $type == "http" then ["username","password","tls","path","headers"]
  elif $type == "socks" then ["version","username","password","network","udp_over_tcp"]
  elif $type == "ssh" then ["user","password","private_key","private_key_passphrase","host_key","host_key_algorithms",
     "client_version","cipher","mac","kex_algorithm"]
  elif $type == "shadowtls" then ["version","password","tls"]
  elif $type == "naive" then ["username","password","insecure_concurrency","extra_headers","stream_receive_window",
     "udp_over_tcp","quic","quic_congestion_control","quic_session_receive_window","tls"]
  else fail("unsupported outbound type. Direct exits, endpoints, Tor, removed protocols, and unknown types are not managed") end;

def check_group:
  .type as $type
  | allowed(["type","tag","outbounds","interrupt_exist_connections"] +
       (if $type == "selector" then ["default"] else ["url","interval","tolerance","idle_timeout"] end);
       "unknown selector or urltest option")
  | ensure((.outbounds | type) == "array" and (.outbounds | length) > 0 and all(.outbounds[]; tag);
           "selector and urltest require a nonempty list of valid outbound references")
  | ensure((.outbounds | length) == (.outbounds | unique | length); "duplicate selector or urltest reference")
  | ensure(.default == null or .default == "" or (.default as $default | .outbounds | index($default) != null);
           "selector default must be one of its outbound references")
  | optional_type(["default","url","interval","idle_timeout"]; "string"; "invalid selector or urltest string option")
  | optional_type(["interrupt_exist_connections"]; "boolean"; "invalid selector or urltest boolean option")
  | optional_integers(["tolerance"]; "invalid urltest tolerance")
  | ensure(.url == null or .url == "" or (.url | test("\\Ahttps?://[^\\s]+\\z"));
           "urltest URL must use HTTP or HTTPS through its candidate proxies");

def check_node:
  ensure(type == "object"; "each outbound must be an object")
  | ensure(.tag | tag; "outbound tags must be unique simple identifiers")
  | ensure(.type | type == "string"; "outbound type must be a string")
  | if group then check_group else
      .type as $type
      | allowed(common_fields + protocol_fields($type);
          "unknown or unsupported outbound option. Dynamic discovery, routing overrides, and extra dialers are not managed")
      | ensure(.server | ipv4; "proxy server requires a canonical fixed IPv4 address. Retain TLS names separately")
      | ensure(.server_port == null or (.server_port | integer(1;65535)); "server_port must be an integer in 1..65535")
      | ensure(.detour == null or .detour == "" or (.detour | tag); "detour must be a valid outbound tag")
      | ensure(.bind_interface == null or .bind_interface == "" or .bind_interface == "eth0";
               "bind_interface must be eth0 or omitted")
      | optional_type(["connect_timeout","tcp_keep_alive","tcp_keep_alive_interval","hop_interval","hop_interval_max",
           "idle_timeout","keep_alive_period","heartbeat","password","uuid","method","security","auth","auth_str",
           "plugin","plugin_opts","flow","packet_encoding","bbr_profile","congestion_control","udp_relay_mode",
           "username","user","private_key_passphrase","client_version","psk","userkey","obfs_mode","obfs_host","mode",
           "path","idle_session_check_interval","idle_session_timeout","client_metadata","quic_congestion_control"];
           "string"; "outbound string option has an invalid type")
      | optional_type(["tcp_fast_open","disable_tcp_keep_alive","udp_fragment","reuse_addr","bind_address_no_port",
           "disable_path_mtu_discovery","disable_mtu_discovery","brutal_debug","disable_chrome_parrot","udp_over_stream",
           "zero_rtt_handshake","global_padding","authenticated_length","reuse","quic"];
           "boolean"; "outbound boolean option has an invalid type")
      | optional_integers(["up_mbps","down_mbps","recv_window_conn","recv_window","max_concurrent_streams",
           "initial_packet_size","alter_id","min_idle_session","insecure_concurrency"];
           "outbound numeric option must be a nonnegative integer")
      | optional_sizes(["up","down","stream_receive_window","connection_receive_window","quic_session_receive_window"];
           "invalid bandwidth or receive window option")
      | optional_lists(["private_key","host_key","host_key_algorithms","cipher","mac","kex_algorithm"];
           "invalid SSH key or algorithm list")
      | . as $outbound | (networks | length) as $network_count | $outbound
      | . as $outbound | (port_ranges | length) as $port_count | $outbound
      | if .tls != null then .tls |= check_tls else . end
      | if .transport != null then .transport |= check_transport else . end
      | ensure(.transport.type != "quic" or .tls.enabled == true; "QUIC transport requires TLS")
      | if .udp_over_tcp != null then .udp_over_tcp |= check_uot else . end
      | if .multiplex != null then .multiplex |= check_mux else . end
      | if .headers != null then .headers |= check_headers("invalid HTTP proxy headers") else . end
      | if .extra_headers != null then .extra_headers |= check_headers("invalid Naive proxy headers")
          | ensure(all(.extra_headers | keys[]; startswith("-") | not);
                   "Naive internal headers cannot override its transport or destination") else . end
      | ensure(.plugin == null or .plugin == ""; "Shadowsocks plugin options require a separate audited transport adapter")
      | ensure(.plugin_opts == null or .plugin_opts == ""; "Shadowsocks plugin options require a separate audited transport adapter")
      | ensure(([$type] - ["hysteria","hysteria2","tuic","anytls","shadowtls","naive"] | length) > 0
               or .tls.enabled == true; "this outbound protocol requires enabled TLS")
      | if $type == "socks" then
          ensure(.version == null or .version == "" or .version == "4" or .version == "4a" or .version == "5";
                 "SOCKS version must be 4, 4a, or 5")
          | if (.udp_over_tcp | enabled) then
              ensure(.version == null or .version == "" or .version == "5"; "SOCKS UDP over TCP requires SOCKS5 and a compatible server")
            else ensure(networks == ["tcp"]; "native SOCKS UDP relay is negotiated. Set network to tcp or enable compatible UDP over TCP") end
        elif $type == "shadowtls" then
          ensure(.version == null or .version == 0 or .version == 1 or .version == 2 or .version == 3;
                 "ShadowTLS version must be 1, 2, or 3")
        elif $type == "snell" then
          ensure(.version == 4 or .version == 6; "pinned Snell outbound supports versions 4 and 6")
          | ensure((.version == 4 and .mode == null) or (.version == 6 and .obfs_mode == null and .obfs_host == null);
                   "Snell option belongs to a different protocol version")
        elif $type == "anytls" then ensure(.tcp_fast_open != true; "AnyTLS does not support TCP Fast Open")
        elif $type == "naive" then
          ensure(.tls.insecure != true and .tls.disable_sni != true and (.tls.alpn == null or .tls.alpn == [])
                 and (.tls.min_version == null or .tls.min_version == "") and (.tls.max_version == null or .tls.max_version == "")
                 and ((.tls.cipher_suites // [] | length) == 0) and ((.tls.curve_preferences // [] | length) == 0)
                 and ((.tls.client_certificate // [] | length) == 0) and ((.tls.client_key // [] | length) == 0)
                 and .tls.fragment != true and .tls.record_fragment != true and .tls.kernel_tx != true and .tls.kernel_rx != true
                 and (.tls.utls.enabled != true) and (.tls.reality.enabled != true);
                 "Naive TLS options are incompatible with the pinned core")
        else . end
      | if $type == "hysteria2" and .obfs != null then .obfs |= (
          allowed(["type","password","min_packet_size","max_packet_size"]; "unknown Hysteria2 obfs option")
          | ensure(.type == "salamander" or .type == "gecko"; "unknown Hysteria2 obfs type")
          | optional_type(["password"]; "string"; "invalid Hysteria2 obfs password type")
          | optional_integers(["min_packet_size","max_packet_size"]; "invalid Hysteria2 obfs packet size")
          | ensure(.type == "gecko" or (.min_packet_size == null and .max_packet_size == null);
                   "packet size options require Hysteria2 gecko obfs"))
        elif $type == "hysteria" then optional_type(["obfs"]; "string"; "Hysteria obfs must be a string") else . end
    end;

def check_source:
  allowed(["log","dns","inbounds","outbounds","route"];
          "only managed log, DNS, TUN, outbound, and route sections are supported. Additional exit services are forbidden")
  | if .log != null then .log |= (
      allowed(["level","timestamp","disabled"]; "unsupported log option")
      | optional_type(["timestamp","disabled"]; "boolean"; "invalid log boolean option")
      | .level as $level
      | ensure($level == null or (["trace","debug","info","warn","error","fatal","panic"] | index($level)) != null;
               "invalid log level")) else . end
  | .dns |= (allowed(["servers","final","strategy","disable_cache","disable_expire","cache_capacity"];
                      "DNS must use the managed cached proxy resolver")
      | ensure(.servers == [udp_dns] or .servers == [https_dns]; "DNS server must be the managed resolver with explicit proxy detour")
      | ensure(.final == "upstream-dns" and .strategy == "ipv4_only" and .disable_cache == false and .disable_expire == false;
               "DNS requires the managed final resolver, IPv4 strategy, and enabled cache with expiry")
      | optional_integers(["cache_capacity"]; "invalid DNS cache capacity"))
  | ensure((.inbounds | type) == "array" and (.inbounds | length) == 1;
           "exactly one managed TUN inbound is required")
  | .inbounds[0] |= (allowed(["type","tag","interface_name","address","mtu","stack","auto_route","auto_redirect","dns_mode"];
                            "unknown managed TUN option")
      | ensure(.type == "tun" and .tag == "tun-in" and .interface_name == "tun0" and .address == ["198.18.0.1/15"]
          and .mtu == 1500 and (.stack == "mixed" or .stack == "system" or .stack == "gvisor")
          and .auto_route == false and .auto_redirect == false and .dns_mode == "disabled";
          "TUN interface, address, MTU, and disabled automatic routing must match the managed gateway"))
  | ensure(.route == {rules:[{inbound:["tun-in"],port:53,action:"hijack-dns"}],final:"proxy"};
           "route must contain only managed DNS hijacking and final proxy. Remote rules and alternate exits are unsupported")
  | ensure((.outbounds | type) == "array" and (.outbounds | length) > 0 and (.outbounds | length) <= 128;
           "outbounds must be a nonempty list with at most 128 nodes")
  | .outbounds |= map(check_node)
  | ensure((.outbounds | map(.tag) | unique | length) == (.outbounds | length); "duplicate outbound tag");

# A protocol transforms requested payload networks into its dialer's networks.
# This demand is propagated through detours instead of opening each inner server.
def intrinsic:
  if .type == "http" or .type == "ssh" or .type == "shadowtls" then ["tcp"]
  elif .type == "anytls" then ["tcp","udp"]
  elif .type == "naive" then if (.udp_over_tcp | enabled) then ["tcp","udp"] else ["tcp"] end
  else networks end;
def channels($wanted):
  . as $outbound | ($wanted - ($wanted - intrinsic)) as $payload
  | if ($payload | length) == 0 then []
    elif .type == "hysteria" or .type == "hysteria2" or .type == "tuic" then ["udp"]
    elif .type == "shadowsocks" then
      if (.udp_over_tcp | enabled) or (.multiplex | enabled) then ["tcp"] else $payload end
    elif .type == "naive" and .quic == true then ["udp"]
    elif .transport.type == "quic" then ["udp"]
    else ["tcp"] end;
def references:
  if group then .outbounds else if .detour != null and .detour != "" then [.detour] else [] end end;

# Validate the graph and compute a leaves-first order before evaluating it.
# Shared DAG branches must not expand into every possible path: all subsequent
# passes use one cached capability and one combined demand per node.
def graph_order($map):
  ensure($map | has("proxy"); "outbound reference is missing")
  | ensure(all($map[]; all(references[]; . as $name | $map | has($name)));
           "outbound reference is missing")
  | reduce range(0; $map | length) as $iteration
      ({pending:$map,order:[],depth:{}};
       if (.pending | length) == 0 then . else
         . as $state
         | [.pending | keys[] | . as $name
            | select(all($map[$name] | references[]; $state.depth[.] != null))] as $ready
         | ensure(($ready | length) > 0; "outbound reference cycle is forbidden")
         | reduce $ready[] as $name (.;
             ($map[$name] | references | map($state.depth[.]) | (max // 0) + 1) as $depth
             | ensure($depth <= 32; "outbound reference depth exceeds 32 hops")
             | .depth[$name] = $depth | .order += [$name] | del(.pending[$name]))
       end)
  | .order;

def graph_roles($map; $order):
  reduce ($order | reverse[]) as $name
    ({reachable:{proxy:true},final:{proxy:true}};
     if .reachable[$name] then
       reduce ($map[$name] | references[]) as $reference (.; .reachable[$reference] = true)
     else . end
     # URLTest probes need a forwarding protocol too, even when the group is
     # used only as a detour. A forwarding leaf may itself detour via ShadowTLS.
     | if (.final[$name] and ($map[$name] | group)) or
          (.reachable[$name] and $map[$name].type == "urltest") then
         reduce $map[$name].outbounds[] as $reference (.; .final[$reference] = true)
       else . end);

def capabilities($map; $order; $roles):
  reduce $order[] as $name ({};
    . as $known | $map[$name] as $node
    | ensure(($roles.final[$name] | not) or $node.type != "shadowtls";
             "ShadowTLS is a transport wrapper and cannot be a final or URLTest proxy candidate")
    | (if ($node | group) then
         reduce $node.outbounds[] as $reference (["tcp","udp"]; . - (. - $known[$reference]))
       else $node | intrinsic end) as $payload
    | if $node.detour != null and $node.detour != "" then
        ensure(subset(($node | channels($payload)); $known[$node.detour]);
               "detour cannot carry the configured protocol transport. Use a compatible carrier or restrict payload network")
      else . end
    | if $node.type == "urltest" then
        ensure(all($node.outbounds[]; ($known[.] | index("tcp")) != null);
               "urltest TCP health probes require TCP-capable candidate paths. Use compatible carriers")
      else . end
    | .[$name] = $payload);

def add_demand($name; $wanted):
  .wanted[$name] = ((.wanted[$name] // []) + $wanted | unique);
def endpoints($map; $order):
  reduce ($order | reverse[]) as $name
    ({wanted:{proxy:["tcp","udp"]},outer:[]};
     .wanted[$name] as $wanted | $map[$name] as $node
     | if $wanted == null then .
       elif ($node | group) then
         ($wanted + (if $node.type == "urltest" then ["tcp"] else [] end) | unique) as $branch_wanted
         | reduce $node.outbounds[] as $reference (.; add_demand($reference;$branch_wanted))
       else ($node | channels($wanted)) as $channels
         | if $node.detour != null and $node.detour != "" then add_demand($node.detour;$channels)
           else ($node | port_ranges) as $ports
             | .outer += [$channels[] as $protocol | $ports[] |
                 {family:4,address:$node.server,protocol:$protocol,port_start:.[0],port_end:.[1]}]
           end
       end)
  | .outer;
def normalize_endpoints:
  sort_by(.family, (.address | split(".") | map(tonumber)), .protocol, .port_start, .port_end)
  | reduce .[] as $endpoint ([];
      if length > 0 and .[-1].family == $endpoint.family and .[-1].address == $endpoint.address
          and .[-1].protocol == $endpoint.protocol and $endpoint.port_start <= .[-1].port_end + 1
      then .[-1].port_end = ([.[-1].port_end,$endpoint.port_end] | max)
      else . + [$endpoint] end);

try (
  . as $first | [inputs] as $remaining
  | ensure(($remaining | length) == 0; "exactly one JSON configuration document is required")
  | $first | check_source as $source
  | ($source.outbounds | map({key:.tag,value:.}) | from_entries) as $map
  | graph_order($map) as $order
  | graph_roles($map;$order) as $roles
  | ensure(($roles.reachable | length) == ($map | length);
           "unreferenced outbounds are unsupported. All configured nodes must belong to the proxy graph")
  | (capabilities($map;$order;$roles) | .proxy) as $payload
  | ensure(($payload | length) > 0; "proxy candidates have no common usable payload network")
  | ensure(($payload | index("tcp")) != null;
           "final proxy must guarantee TCP for session readiness. UDP-only detour carriers are allowed")
  | (endpoints($map;$order) | normalize_endpoints) as $outer
  | ensure(($outer | length) > 0; "proxy graph has no controlled outer endpoint")
  | (if ($payload | index("udp")) != null then "udp" else "https" end) as $dns
  | if $mode == "policy" then
      {format:1,proxy_tag:"proxy",outer_endpoints:$outer,payload_networks:$payload,dns_transport:$dns}
    elif $mode == "effective" then
      $source | .dns.servers = [if $dns == "udp" then udp_dns else https_dns end]
      | .outbounds |= map(if (group | not) and (.detour == null or .detour == "")
                           then .bind_interface = "eth0" else . end)
    else fail("compiler mode must be policy or effective") end
) catch fail("configuration has an invalid structure or value type")
