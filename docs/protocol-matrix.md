# 固定核心的代理協議與網絡政策

本頁記錄 `gateway-policy.jq` 已實作的**靜態配置適配範圍**，並在末節列出已執行的核心配置檢查與真實協議 loopback 測試。解析成功表示可以從設定推導受控外層端點，還必須通過同一映像的 `worker check`、主機／容器政策核對及運行時探測，才會建立可用會話。假認證範例、單元測試與核心配置檢查均不能代替實際轉發及故障阻斷驗收；loopback 結果也不代替使用者遠端節點和主機防火牆的驗收。

## 版本依據

本次依據為官方 [sing-box v1.14.2 發行](https://github.com/SagerNet/sing-box/releases/tag/v1.14.2)，對應提交 `af6e64c3b69e6132ebaee0e1a3d24e93903f6709`。2026-10-18 在測試 VPS 上讀取現有映像內的 `worker version`，確認版本、提交一致，架構為 `linux/amd64`，並包含 `with_quic`、`with_gvisor`、`with_utls`、`with_naive_outbound` 等建置標籤，CGO 已啟用。

協議清單以該提交的 [出口註冊表](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/include/registry.go)、[QUIC 註冊表](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/include/quic.go) 及 [Naive 建置條件](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/include/naive_outbound.go) 為準。官方網站會更新到其他版本，不能把新版本文件中的類型或欄位直接加入本映像。Naive 的可用性仍取決於實際架構及建置；另一個同版本但未包含其建置標籤的映像會在核心檢查時拒絕啟動。

## 協議矩陣

「內層」是代理替應用程式轉發的 TCP／UDP；「外層」是容器向代理節點真正建立的 IP 傳輸。下表先描述沒有 `detour` 時的外層。加上 detour 後，外層須沿引用圖重新計算，不能把所有 `server` 都直接放行。

`network` 僅能用在核心提供該欄位的協議；省略、`null` 或空陣列表示核心預設的 TCP 與 UDP，`"tcp"`／`"udp"` 或對應陣列則限制內層能力。HTTP、SSH、AnyTLS、ShadowTLS、Naive 不接受自行添加的 `network` 欄位。其核心語義見 [NetworkList](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/option/types.go)。

最終 `proxy` 必須保證 TCP，配合現有會話的 HTTPS readiness 檢查；`payload_networks` 因此固定為 `["tcp"]` 或 `["tcp","udp"]`。只提供 UDP 的節點仍可作相容的 detour carrier，例如以 UDP-only Shadowsocks 承載 Hysteria2 的外層 QUIC，但不能單獨作最終代理。

| 出口 | 內層能力 | 沒有 detour 時的外層 | 本專案適配與限制 |
| --- | --- | --- | --- |
| Hysteria 1 | TCP、UDP，可用 network 限制 | UDP | 固定埠、明確的跳埠區間、認證、TLS 與核心支援的混淆參數。即使 network 只有 TCP，外層仍為 UDP。 |
| Hysteria 2 | TCP、UDP，可用 network 限制 | UDP | 固定埠／跳埠、salamander／gecko 混淆。realm／STUN 發現不在支援範圍。 |
| TUIC | TCP、UDP，可用 network 限制 | UDP | native／quic UDP relay 與 udp_over_stream 都保留 UDP 外層；它們不是把整個 QUIC 通道改成 TCP。 |
| Shadowsocks 原生 | TCP、UDP，可用 network 限制 | TCP 內層需要 TCP；UDP 內層需要 UDP | 只放行實际使用的通道。拒絕 SIP003 plugin／plugin_opts。 |
| Shadowsocks + UDP over TCP 或 multiplex | TCP、UDP，可用 network 限制 | TCP | 啟用 UoT 或多路複用時，UDP 也經 TCP；明確 disabled 的選項不改變原生外層。服務端須相容。 |
| Trojan | TCP、UDP，可用 network 限制 | 預設 TCP；V2Ray QUIC 為 UDP | 支援下節列出的五種 V2Ray transport。 |
| VMess | TCP、UDP，可用 network 限制 | 預設 TCP；V2Ray QUIC 為 UDP | 服務端認證、security、packet_encoding、multiplex 與 TLS 仍由核心檢查。 |
| VLESS | TCP、UDP，可用 network 限制 | 預設 TCP；V2Ray QUIC 為 UDP | 保留 flow、packet_encoding、TLS、Reality 等原始值；不猜測服務端需求。 |
| AnyTLS | TCP、UDP | TCP | 核心自動使用 UoT 承載 UDP；禁止該核心不支援的 tcp_fast_open。 |
| Snell 4／6 | TCP、UDP，可用 network 限制 | TCP | UDP 透過 TCP 通道承載。版本 4 的 obfs 與版本 6 的 mode 分開核對；不能把入口版本 5 當作出口版本。 |
| HTTP／HTTPS CONNECT | TCP | TCP | 同為 type:http，HTTPS 使用 tls.enabled。會自動配套經 proxy 的 HTTPS DNS。 |
| SOCKS4／4a | TCP | TCP | 必須明確 network:tcp；不能啟用 SOCKS5 的 UoT 擴充。 |
| SOCKS5，network:tcp | TCP | TCP | 原生 UDP relay 不作靜態猜測。 |
| SOCKS5 + UDP over TCP | TCP、UDP，可用 network 限制 | TCP | 明確啟用 UoT，且服務端必須支援相同版本。 |
| SSH | TCP | TCP | 允許密碼或內嵌私鑰、host_key／演算法設定；拒絕外部 private_key_path。 |
| ShadowTLS 1／2／3 | TCP 傳輸包裝 | TCP | 只能作另一個真正轉發協議的 detour，不能單獨作 proxy 或最終候選。 |
| Naive | TCP；啟用 UoT 後增加 UDP | quic:false 為 TCP；quic:true 為 UDP | 已確認測試映像含該出口。QUIC 開關與 UoT 分別控制外層和內層，不能混為一談。拒絕核心不相容 TLS 選項及可覆寫內部目的地／QUIC 開關的保留 headers。 |
| selector | 所有候選保證能力的交集 | 所有可能候選的受控端點聯集 | 核對 default、所有引用和每個分支，不僅目前選中的出口。 |
| urltest | 本專案以所有候選保證能力的交集決定 DNS | 候選端點聯集，另計每個候選的 TCP 健康探測 | 探測目的網站經候選代理，沒有額外直連放行。 |

上表的協議行依據固定版本的各個出口實作：[Hysteria](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/hysteria/outbound.go)、[Hysteria2](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/hysteria2/outbound.go)、[TUIC](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/tuic/outbound.go)、[Shadowsocks](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/shadowsocks/outbound.go)、[Trojan](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/trojan/outbound.go)、[VMess](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/vmess/outbound.go)、[VLESS](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/vless/outbound.go)、[AnyTLS](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/anytls/outbound.go)、[Snell](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/snell/outbound.go)、[HTTP](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/http/outbound.go)、[SOCKS](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/socks/outbound.go)、[SSH](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/ssh/outbound.go)、[ShadowTLS](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/shadowtls/outbound.go)、[Naive](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/naive/outbound.go)、[selector](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/group/selector.go) 及 [urltest](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/group/urltest.go)。

### V2Ray transport、UoT 與 multiplex

| 功能 | 外層判定 | 支援邊界 |
| --- | --- | --- |
| transport 省略 | TCP | 使用協議本身的 TCP stream。 |
| http、ws、grpc、httpupgrade | TCP | 僅接受固定版本對應 transport 的欄位。Host、path、headers、SNI 不改寫固定節點 IP。 |
| quic | UDP | 要求啟用 TLS；不因內層 network:tcp 放行 TCP。 |
| 未知 transport，例如 kcp、tcp、xhttp | 拒絕 | 核心的枚舉不是任意 V2Ray／Xray transport 名稱。預設 TCP 以省略 transport 表達。 |
| udp_over_tcp | 依承載協議轉成 TCP | SOCKS5、Shadowsocks、Naive 支援；接受布林或 enabled／version 物件，版本為核心支援的 1／2，0 表示預設。 |
| multiplex | 依實際 transport | 支援 h2mux／smux／yamux；Shadowsocks 的 UDP 變成 TCP。Trojan／VMess／VLESS 的 QUIC transport 仍是 UDP。 |
| multiplex.brutal.enabled | 拒絕 | 需要另外驗證主機核心模組；目前沒有該驗收。Hysteria 的內建擁塞控制不是此選項。 |

來源：[V2Ray transport 類型及欄位](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/option/v2ray_transport.go)、[QUIC client 的 UDP 撥號](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/transport/v2rayquic/client.go)、[UoT 選項](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/option/udp_over_tcp.go)、[multiplex 選項](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/option/multiplex.go)。Shadowsocks 的 [內建 v2ray-plugin](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/transport/sip003/v2ray.go) 本身也可能改成 QUIC；本專案未實作插件適配，因而明確拒絕，不能將所有插件當成 TCP。

### 跳埠

Hysteria 1／2 的 `server_ports` 支援明確的 `"起點:終點"` 字串或字串陣列，例如 `["443:443", "8443:8445"]`。非空列表會取代 `server_port`；政策只包含真正可能使用的埠。重疊或相鄰區間會合併，區間之間的空隙不會放寬。只設定 `server_ports` 時可以省略 `server_port`。

本專案要求 1–65535 的明確邊界，拒絕 `"443"`、`"443-445"`、`":443"`、`"443:"`、零、越界與倒置區間。固定核心所用的 [ParsePorts 與連線實作](https://github.com/SagerNet/sing-quic/blob/6a3a24d65b99/hysteria/client.go) 按冒號解析區間；[Hysteria2](https://github.com/SagerNet/sing-quic/blob/6a3a24d65b99/hysteria2/client.go) 使用同一解析器。這也是為何單一埠要寫成 `"443:443"`。跳埠並不授權向同一 IP 的其他埠連線。

### detour、selector 與 urltest

解析器沿 `proxy` 的完整引用圖，將內層需求逐跳轉換成承載通道。例子：

- Trojan → Hysteria2：最外層只放行 Hysteria2 節點的 UDP，不放行 Trojan 節點。
- Trojan → 原生 Shadowsocks：Trojan 需要一條 TCP stream，因此只放行 Shadowsocks 的 TCP；不因 Shadowsocks 本身支援 UDP 而多放行 UDP。
- Hysteria2 → SOCKS5 UoT：QUIC 的 UDP 可由相容的 UoT 承載，實際外層是 SOCKS 節點的 TCP。
- Hysteria2 → HTTP：HTTP CONNECT 不承載該 UDP 通道，配置被拒絕。
- urltest 作 Hysteria2 的 detour：除了承載 QUIC 所需的 UDP，還要推導 urltest 各候選的 TCP 健康探測，不能漏掉它自己的活動。

selector 的所有候選都必須接受相同的必要通道。urltest 核心會分別選擇支援 TCP／UDP 的出口，本專案仍使用所有候選能力交集來選 DNS，讓改選候選不會令既定 DNS 通道失效。每條 urltest 候選路徑還必須保證 TCP，因為健康探測會建立 TCP 連線；目前明確拒絕只宣告 UDP 的候選路徑，不能接受配置後漏掉探測所需的外層端點。候選必須是可轉發目的地的代理，不能直接以 ShadowTLS 包裝回應健康探測；正常代理再經 ShadowTLS detour 的形式不受影響。UDP 能力表示靜態配置允許，不代表遠端已開啟 UDP 轉發。

重複 tag、遺失引用、引用循環、無共同能力、detour 不相容、無關且未引用的出口，都會拒絕啟動。限制為最多 128 個節點、32 層引用；這些是專案的可審查範圍限制。解析器先建立拓撲順序，每個節點只計算一次能力，再合併傳入的 TCP／UDP 需求；多個群組共用下層節點不會重複列舉所有路徑。撥號行為依據 [dialer](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/common/dialer/dialer.go) 與 [detour dialer](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/common/dialer/detour.go)。

### SOCKS 原生 UDP 的邊界

SOCKS5 的 UDP ASSOCIATE 回應會提供 relay 的地址及埠，未必等於設定中的代理 server／server_port。固定版本所用 [SOCKS client](https://github.com/SagerNet/sing/blob/87c33f17688f/protocol/socks/client.go) 先建立 TCP 控制連線，再向回應的 `Bind` 建立 UDP；規範見 [RFC 1928 第 6、7 節](https://www.rfc-editor.org/rfc/rfc1928.html)。只放行設定的 server_port 會漏掉真實 relay，放行任意 UDP 又破壞端點限制。

因此目前必須選擇明確 `network:"tcp"`，或啟用服務端也支援的 `udp_over_tcp`。動態 relay 授權、變更與回收尚未實作；不聲稱支援原生 SOCKS UDP。

## DNS 與有效配置

原始設定維持單一受管 DNS、DNS hijack 路由與 TUN 形狀。有效配置按 `proxy` 的保證能力選擇：

| proxy 的保證能力 | 有效上游 | 外層防火牆新增 DNS 端點 |
| --- | --- | --- |
| 所有候選均可承載 UDP | `type:udp`，1.1.1.1:53，detour:proxy | 無 |
| 僅保證 TCP | `type:https`，1.1.1.1:443，`/dns-query`，detour:proxy，驗證 cloudflare-dns.com TLS 名稱 | 無 |

HTTPS 上游的確切形狀如下：

```json
{
  "type": "https",
  "tag": "upstream-dns",
  "server": "1.1.1.1",
  "server_port": 443,
  "path": "/dns-query",
  "detour": "proxy",
  "tls": {"enabled": true, "server_name": "cloudflare-dns.com"}
}
```

保留 IPv4 查詢策略、啟用的快取與到期處理。無論 DNS 使用 UDP 或 HTTPS，1.1.1.1 都是代理內部目的地，不能加入外層直連端點。固定版本的 [HTTPS DNS](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/dns/transport/https.go) 與 [HTTPS transport](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/dns/transport/https_transport.go) 使用配置的 dialer；明確 detour 是必要條件。

編譯器的有效配置只改受管 DNS 上游，以及實際直接撥號葉節點的 `bind_interface:"eth0"`。認證、TLS 檢驗策略、SNI、headers、傳輸參數與 log 都保留原值，不覆寫 `LOG_LEVEL`。原始配置和其有效配置再次解析時得到同一政策；有效配置再次編譯也不改變內容。

## 共用 JSON 介面

主機與容器使用同一份純 jq 程式：

```sh
jq -ceS --arg mode policy -f gateway-policy.jq network.json
jq -ceS --arg mode effective -f gateway-policy.jq network.json
```

輸入必須是恰好一份 JSON 文件。成功輸出完整的一個物件；格式錯誤、第二份文件、未知選項或無法受控的引用圖都不留下部分政策。政策範例如下：

```json
{
  "format": 1,
  "proxy_tag": "proxy",
  "outer_endpoints": [
    {"family": 4, "address": "192.0.2.1", "protocol": "udp", "port_start": 443, "port_end": 443},
    {"family": 4, "address": "192.0.2.1", "protocol": "udp", "port_start": 8443, "port_end": 8445}
  ],
  "payload_networks": ["tcp", "udp"],
  "dns_transport": "udp"
}
```

端點依數值 IPv4、協議及埠排序，去除重複及合併相連區間。政策不包含密碼、UUID、憑證、headers 或私鑰。靜態驗證錯誤只輸出 `gateway-policy: ` 開頭的一行固定原因，不插入使用者欄位值；JSON 解析器或核心本身的其他錯誤應由呼叫者轉成通用訊息，避免錯誤片段包含憑證。

政策由相同來源推導，身份核對另外使用原始設定 SHA-256、canonical effective JSON SHA-256（`jq -cS` 的完整輸出，包含結尾換行）及解析檔 SHA-256。修改設定後沿用舊容器或舊解析檔不能當成同一份有效政策。

## 明確拒絕及尚未適配的能力

| 能力 | 固定核心狀態／專案拒絕理由 | 可行配置方式 |
| --- | --- | --- |
| domain／IPv6 節點、動態 domain_resolver／domain_strategy | 尚未實作地址發現、變更及雙棧政策生命週期 | 使用固定 IPv4；TLS server_name 仍可保留網域。 |
| Hysteria2 realm、STUN、port mapping | 會引入額外發現服務及動態端點 | 使用固定 server／server_ports。 |
| Shadowsocks SIP003 plugins | 插件可改傳输甚至啟動額外程序；尚未實作適配器 | 使用內建協議／transport 或已支持的 UoT／multiplex。 |
| direct、bridge | 與只允許受控代理出口的路由模型不相容 | 使用真正代理出口及受管 route.final。 |
| block 作出口候選 | 不提供可供會話與 DNS 使用的轉發通道 | 封鎖由受管網絡政策處理。 |
| Tor | bootstrap、relay 發現及外部 Tor 程序不在固定端點模型內 | 若另外部署已管理的 SOCKS 代理，可使用固定 IPv4 的 SOCKS TCP。 |
| WireGuard outbound、DNS outbound、ShadowsocksR | 核心已移除；WireGuard／DNS 有其他替代 API，不能當作舊出口使用 | 本專案只支援表中出口；DNS 使用受管 DNS server。 |
| WireGuard／Tailscale／OpenConnect／OpenVPN endpoints | 固定核心有對應入口；本專案未實作其端點、控制面及路由生命週期防護 | 明確拒絕整個 endpoints 區段。 |
| API、Clash API、NTP、certificate providers、額外 services | 引入監聽服務、額外連線或動態資料，不屬於受管 TUN 路徑 | 保持受管頂層結構。 |
| 自訂 inbounds、route rules、remote rule_set、其他 DNS server | 可能建立未納入政策的路由、監聽或下載通道 | 保留範例的受管 TUN／DNS／route。 |
| routing_mark、netns、protect_path、額外 bind address、TCP multipath、network_strategy／fallback | 可改變出口介面、地址選擇或 socket 路徑 | 使用解析器管理的 eth0 葉節點。 |
| 外部 TLS／SSH credential paths | 有效內容可能在原始 JSON 不變時變更，現行身份核對未包含外部檔案 | 憑證或金鑰需要時放在私有設定的內嵌欄位。 |
| TLS ECH、packet spoofing、非 go TLS engine | 額外 DNS 發現、封包目的地或未驗證引擎超出模型 | 使用已列入 allowlist 的普通 TLS／uTLS／Reality 欄位。 |
| 新版本才有的類型、未知 transport／dialer 欄位 | 不能從名稱猜測 TCP／UDP，亦不能靜默忽略 | 固定版本新增適配器及測試後才接納。 |

移除類型依據 [註冊表](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/include/registry.go) 和 [出口解析器](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/option/outbound.go)；撥號／TLS 欄位依據 [DialerOptions](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/option/outbound.go) 及 [TLS options](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/option/tls.go)。這些拒絕包括部分核心有效的配置；原因是目前缺少對應政策適配，並非聲稱核心沒有該能力。

## 範例與驗證層次

[`examples/proxies/`](../examples/proxies/) 包含 24 份完整配置：Hysteria 1／2、Hysteria2 跳埠、TUIC、Shadowsocks 原生／UoT／multiplex、Trojan、VMess QUIC、VLESS WebSocket、AnyTLS、Snell 4／6、HTTP／HTTPS、SOCKS TCP／UoT、SSH、Naive TCP／QUIC、selector、urltest、detour 及 ShadowTLS detour。它們只使用文件保留地址、範例名稱與假認證；不代表可用節點。依服務端要求修改原始配置，再交給程式生成有效配置。Hysteria1 跳埠不在這 24 份範例內。

靜態驗證由 [`tests/test_proxy_policy.py`](../tests/test_proxy_policy.py) 覆蓋：內層／外層分離、傳輸封裝、精確跳埠、圖引用、detour 通道相容、urltest 健康探測、DNS 自動選擇、未知出口通道拒絕、身份相關冪等性、多文件拒絕及錯誤不回顯憑證。24／24 份範例已通過兩種 jq 模式，也全部通過測試 VPS 的固定 `worker 1.14.2 check`。各次命令、版本與主機層證據另見 [2026-10-18 起的驗證紀錄](validation-20261018.md)。

### 已完成的 41 組真實協議 loopback 測試

[`tests/protocol_runtime.py`](../tests/protocol_runtime.py) 的首批 40 組配置已在測試 VPS 上通過獨立固定核心檢查 **40／40**，也通過實際 client／server 轉發及故障測試 **40／40**。第 41 組 Hysteria2 跳埠隨後單獨執行，通過實際執行前的 client／server 核心配置檢查及全部轉發／故障斷言；合計 **41／41 組 runtime 通過**。每組的 client 與 server 都使用同一個 sing-box 1.14.2 執行檔，版本及提交必須與本頁固定值一致。這是本次已執行案例的數量，不是所有可能配置組合的數量。

| 已通過的組別 | 案例與實際範圍 |
| --- | --- |
| Hysteria／TUIC，4 組 | Hysteria1 固定埠、Hysteria2 固定埠、TUIC 原生、TUIC udp_over_stream；均驗證 TCP 與 UDP。 |
| Hysteria2 跳埠，1 組 | 八個宣告埠中實際觀察到兩個不同目的埠；同一 TCP stream 在切換後繼續轉發，並通過 UDP、DNS 與停止 server 的檢查。 |
| Shadowsocks，3 組 | chacha20-ietf-poly1305 的原生 TCP／UDP、UoT，以及 smux；沒有把其他 cipher 或 multiplex 實作算入本次結果。 |
| AnyTLS，1 組 | TCP 與核心自動提供的 UoT UDP。 |
| HTTP／HTTPS CONNECT，2 組 | 認證 CONNECT、普通 UDP 拒絕、經代理且驗證憑證的 HTTPS DNS。 |
| SOCKS，4 組 | SOCKS4、SOCKS4a、SOCKS5 的明確 TCP 模式，以及 SOCKS5 UoT；TCP 模式均檢查普通 UDP 拒絕。 |
| Naive，3 組 | TCP 外層、QUIC 外層、TCP 外層加 UoT；前兩者的普通 UDP 被拒絕，UoT 案例可轉發 UDP。 |
| Snell，1 組 | Snell6 的 TCP 與 UDP；不涵蓋 Snell4。 |
| Trojan，6 組 | 預設傳輸及 http、ws、grpc、httpupgrade、quic，各自驗證 TCP 與 UDP。 |
| VMess，6 組 | 預設傳輸及相同五種 transport，使用 security:auto，各自驗證 TCP 與 UDP。 |
| VLESS，6 組 | 預設傳輸及相同五種 transport，各自驗證 TCP 與 UDP；沒有測試額外 flow 或 Reality 組合。 |
| 代理圖，4 組 | selector 分別預設選中 Trojan／Hysteria2；urltest 兩個候選的健康請求實際到達目的地；Trojan 經 Hysteria2 detour。 |

每組先編譯正式 policy／effective 配置，再把 TUN 改成 loopback 入口、移除 fixture 不適用的 eth0 綁定，並將 DNS 邊界替換成本機測試地址。只有代理 server 可以把 `127.0.0.2` 的測試目的地轉到真正的 listener；server 的出口綁定 `127.0.0.3`。TCP／UDP 回應須帶有這個來源地址，原始目的地上的 canary 不能收到直連；TCP canary 即使只收到連線而沒有完整請求也會失敗。這個地址證明本機代理路徑，並非公網出口 IP。

DNS 使用解析器選出的 UDP 或 HTTPS，檢查首次查詢、UDP／TCP 查詢共用快取及 TTL 到期後再次請求上游。HTTPS 以臨時可信憑證驗證名稱，沒有停用 TLS 驗證。停止 proxy server 後，既有 TCP、新 TCP、UDP 都必須失敗；再重新啟動 client 清除快取，未快取的 DNS 查詢也不得抵達上游。代理圖另核對預期入口的認證後轉發記錄；僅有 listener 啟動記錄不能通過。

這些 fixture 不修改主機防火牆、全局路由或 resolver，也沒有測試 cgroup 匹配、TUN 隔離、容器故障政策、實體介面封包或實際 WAN 出口。JSON 結果中的 `configured_outer_endpoints` 是編譯結果，不是抓包觀測。主機層驗收必須另外依 [實機驗收清單](host-validation.md) 執行。

### 跳埠的實際觀測及邊界

第 41 個 `hysteria2-port-hopping` 案例已在固定核心上實際通過。八個明確 UDP 埠共用一個 QUIC backend，當次真正觀察到兩個不同目的埠，既有 TCP stream 在切換後仍可轉發，UDP、DNS 快取／TTL 及停止 server 後的阻斷也全部通過。`observed_hop_ports` 只列真正收到流量的埠；不能把完整配置列表當作八個埠都已輪轉。

這組 loopback relay 結果仍不能代替實體介面上對允許區間、間隙、區間兩端及越界埠的主機防火牆驗證。Hysteria1 跳埠也必須另行驗收。

### 已適配但仍未完成對應 runtime 的範圍

| 範圍 | 已有證據 | 尚缺的證據 |
| --- | --- | --- |
| SSH | 靜態政策適配；公開 SSH 範例通過固定核心配置檢查。 | 固定核心沒有 SSH server inbound，尚未建立獨立 SSH 伺服器 fixture；TCP、HTTPS DNS 與故障阻斷未由該協議實測。 |
| Snell4 | 靜態政策適配；公開 version:4 範例通過固定核心配置檢查。 | 核心提供 version:5／6 的 server inbound，本次尚未驗證可與 version:4 client 互通的服務端。這不宣稱 version:5 必定不相容；Snell6 通過也不能代替 Snell4。 |
| ShadowTLS 1／2／3 detour | 靜態包裝／引用圖適配；公開的 version:3 detour 範例通過固定核心配置檢查。 | 尚缺 TLS cover server 加內層轉發協議的成對 fixture；各包裝版本、UDP 封裝及停止 server 後的行為均未實測。 |
| Hysteria1 跳埠 | 靜態明確埠區間適配；固定埠的 Hysteria1 已完成上述 runtime。 | 本次沒有 Hysteria1 跳埠範例的獨立核心檢查或實際輪轉結果，不能沿用 Hysteria2 的證據。 |

核心邊界依據固定版本的 [註冊表](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/include/registry.go)、[Snell outbound](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/snell/outbound.go)、[Snell inbound](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/snell/inbound.go)、[ShadowTLS inbound](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/protocol/shadowtls/inbound.go) 及固定 sing-quic 的 [hopping 實作](https://github.com/SagerNet/sing-quic/blob/6a3a24d65b99/hysteria/hop.go)。未列為已測的 cipher、認證模式、TLS／uTLS／Reality 設定、flow、混淆、UoT 版本或其他 multiplex 組合，仍只能按靜態適配及實際配置檢查的證據描述。

### 重跑命令

需要 Python 3、jq、openssl，以及可執行的固定核心。`--artifacts` 目錄須尚不存在，程式會以私有權限建立並保留假配置與詳細 log；省略時在結束後刪除暫存資料。輸出只包含固定階段原因及經整理的結果，不回顯原始配置或核心錯誤。

```sh
python3 tests/protocol_runtime.py --list
python3 tests/protocol_runtime.py --engine /absolute/path/to/pinned-worker --check-only --artifacts /tmp/protocol-config-check
python3 tests/protocol_runtime.py --engine /absolute/path/to/pinned-worker --artifacts /tmp/protocol-runtime-check
python3 tests/protocol_runtime.py --engine /absolute/path/to/pinned-worker --case hysteria2-port-hopping --artifacts /tmp/protocol-hopping-check
```

目前不指定 `--case` 會執行全部 41 組，包含跳埠案例；使用 `--case` 可指定一組或重複指定多組。`--check-only` 只回報 `CONFIG_PASS`，不啟動代理核心進行轉發，不能計作 runtime 通過。這些命令不建立受管會話。

任何新增「已實測支援」宣稱都應列出協議、transport、認證方式、實際 TCP／UDP、DNS、代理出口 IP，以及停止／中斷代理後無直連的證據，並註明是在 loopback 還是受管主機上執行；有 port hopping、selector 或 detour 時，完整主機驗收還需要實體介面端點觀測。既有結果只涵蓋當次列出的案例，不能外推到未測的協議或選項。
