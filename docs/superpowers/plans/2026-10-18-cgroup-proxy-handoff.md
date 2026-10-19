# tun3：cgroup 與 sing-box 自動適配交接文件

> **交接狀態：尚未實作。** 本次只編寫交接文件，沒有修改執行程式，也沒有執行專案、部署或測試腳本。接手者應先閱讀本文件與現有程式，再依使用者後續授權進行實作。
>
> **For agentic workers:** 實作時可使用 `superpowers:executing-plans`，依下列未勾選項目逐項處理。本文件不授權在目前主機部署或執行故障測試。

**Goal:** 讓 tun3 自動選擇可用的 cgroup v1／v2，優先使用 v1；並根據使用者的 sing-box 設定，自動配套不同代理協議需要的網絡規則，保留代理故障時阻止直連的能力。

**Architecture:** 保留「普通帳戶的程式 → 主機上的限制與轉發 → Docker 內的 sing-box → 代理節點」架構。cgroup 部分替換識別這組程式的方法；代理部分把寫死的單一 Hysteria2 節點，改為從設定產生明確的節點與通信需求，供主機、容器安裝並核對規則。

**Tech Stack:** Bash、POSIX sh、jq、systemd、cgroup v1／v2、legacy iptables、rootful Docker、目前固定的 sing-box 1.14.2，以及既有 Python unittest 與實機驗收工具。

**Spec:** 使用者在本次交接中確定兩項要求：① v1／v2 自動適配，優先 v1；② sing-box 支援多種協議並自動適配。相關既有要求以 [README](../../../README.md)、[驗證摘要](../../VERIFICATION.md) 與本文件的全局限制為準。

## 一、先讀懂目前的版本

基準提交：`aac516d650a8150282b3a96633af6f5f7d7830d7`。本文件按這個版本的程式整理，不代表下列新功能已存在。

| 目前位置 | 目前做法與需要改動的原因 |
| --- | --- |
| [`lib/host.sh`](../../../lib/host.sh) 的 `host_preflight()` | 寫死檢查 `/sys/fs/cgroup/net_cls,net_prio`，只接受 v1。 |
| [`lib/network.sh`](../../../lib/network.sh) 的 `CLASSID`、`CGROOT`、`policy_emit()` | 以 v1 的 `net_cls.classid` 識別會話流量；IPv4 和 IPv6 都需要新增 v2 分支。 |
| [`lib/session.sh`](../../../lib/session.sh) 的 `unit_arguments()`、`attach_group()`、清理函式 | 固定檢查 v1 的 systemd 路徑，另建 net_cls 子目錄；v2 應讓 systemd 管理程式分組。 |
| `lib/network.sh` 的 `read_node()` | 要求只有一個 Hysteria2 出口、固定 IPv4、固定埠，且綁定 `eth0`。 |
| [`entrypoint-gateway.sh`](../../../entrypoint-gateway.sh) | 重複上述協議檢查，僅放行該節點的外層 UDP，核對固定規則數和單條節點路由。 |
| `lib/network.sh` 的 `gateway_verify()`、`policy_emit()` | 主機也只認同一組節點 IPv4／UDP 埠；只改容器會被主機拒絕。 |
| `lib/host.sh` 的 `binding_*()` | 目前只保存四行：橋接網卡、網關 IP、節點 IP、節點埠，容納不了多節點與 cgroup 模式。 |
| [`network.json`](../../../network.json) | Hysteria2 範例；DNS 固定用 UDP 經 `proxy`，不能直接套在只支援 TCP 的代理上。 |
| [`Dockerfile.gateway`](../../../Dockerfile.gateway)、[Compose](../../../docker-compose.yml) | 固定核心版本、唯讀容器、最少權限；應保留這些安排。 |

現有主機是 v1／v2 混合模式，tun3 使用其中的 v1。歷史驗收主要是 Ubuntu 20.04、systemd 245、cgroup v1；維護者使用 Claude Code 數月的穩定經驗也屬於原有方案，不能當作新增 v2 或其他協議已通過驗收。

## 二、全局限制

- **代理或網絡故障時，沙盒中的程式應斷網，不得改走主機真實出口。** 不加入 `direct` 備援，不暫時全面放行來等待代理恢復。
- 保留永久的出站阻擋、連線標記、不可達預設路由，以及啟動前逐項核對。退出單一會話時不移除共用網絡限制。
- Agent 仍以普通帳戶運行，保留現有降權、能力限制、私有終端、systemd 子程式收尾，以及 root 私有安裝目錄。不要要求 Agent 帳戶加入 Docker 群組。
- 保留普通帳戶直接執行 `session`、自動 sudo、目前工作目錄、GUI、語言、時區與 umask 傳遞，以及舊 CLI 語法。
- 保留 Ubuntu 20.04／systemd 245 可用的 v1 路徑，不為支援 v2 而提高所有使用者的最低 systemd 版本。
- 繼續使用目前的 legacy iptables 與 rootful Docker。v2 適配不等於已支援所有發行版的 Docker、防火牆或核心配置，這些條件仍須檢查。
- 目前對 Agent 的 IPv6、內網與本機服務限制維持原有範圍。若要增加 IPv6 代理節點，需要另外完成整條 IPv6 出口防護，不能順便解除目前的封鎖。
- 保留固定版本的 sing-box；以該版本及映像實際包含的協議為準，不照最新網頁加入舊核心沒有的欄位，也不順便升級核心。
- 設定中的密碼、金鑰、帳號及真實節點資料不能出現在公開範例、測試輸出、交接文件或映像層。測試使用文件保留地址與假憑證。
- **目前使用者只要求交接文件。** 不執行現有腳本，不調整目前主機的 Docker、cgroup、路由或防火牆。以下驗收步驟供另行獲准的測試環境使用。

## 三、cgroup：啟動時自動選擇，優先 v1

### 3.1 選擇規則

檢查實際掛載、權限、systemd 管理方式，以及核心和 iptables 是否能使用對應匹配功能。不能只看發行版名稱、核心版本，或 `/sys/fs/cgroup` 的單一檔案系統類型。

| 檢查結果 | 選擇 |
| --- | --- |
| v1 的 net_cls 與相關規則確實可用 | 使用 v1，包括可用的混合模式。 |
| v1 不可用，而 v2 的分組和 `--path` 匹配可用 | 使用 v2。 |
| 兩者都不能確認可用 | 拒絕啟動會話，說明缺少的條件。 |

「優先 v1」不代表自行修改全機啟動參數、重新掛載控制器或降級 systemd。有 v1 掛載但缺少權限／匹配功能，也不能假裝可用。

選擇在安裝共用政策前完成，並寫入執行狀態。後續 `check` 和新會話必須確認仍是同一模式。已有會話或既有政策時，不因檢查失敗就偷偷換成另一模式；保留原有限制並拒絕新會話，待所有會話結束後再按明確程序處理。

### 3.2 v1：保留目前已驗證的做法

保留共用 `CLASSID`、每個會話自己的 net_cls 子目錄，以及目前的 `--cgroup CLASSID` 流量識別。偵測實際的 net_cls 掛載點，避免另一台主機把它掛在 `net_cls` 而非 `net_cls,net_prio` 就被誤判。

net_cls 可用仍不足以保證整條 v1 路徑可用：也要確認 systemd 的服務歸屬能按現有方式核對。

### 3.3 v2：使用 systemd 專用分組

建議使用一個專用 slice，例如 `devsession.slice`，每個會話的暫時服務都放在它下面：

```text
devsession.slice
├── dev-session-<會話 A>.service
└── dev-session-<會話 B>.service
```

父分組由可信管理程式透過 systemd 建立並保持有效；服務由既有的 `systemd-run` 加上 `--slice=devsession.slice` 啟動。不要在 systemd 管理的 v2 根目錄自行搬移 PID 或刪除其服務目錄。[systemd 分組管理說明](https://systemd.io/CGROUP_DELEGATION/)

專用分組由 root 管理，不授權普通帳戶管理或移出受控分組。若同名 slice 已被其他程式使用，應拒絕接管，而非將無關程式一起納入本工具；目前 `unused_policy()` 的衝突檢查也需要按 v2 調整。

iptables 使用 `-m cgroup --path devsession.slice` 匹配整個子樹，再沿用目前的流量標記與路由。IPv6 的阻擋也要換成對應匹配，不能只處理 IPv4。`--path` 相對於 v2 掛載根目錄，不是完整檔案系統路徑。[iptables 說明](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)

必須處理的順序與生命週期：

1. 建立並確認父分組，再安裝引用它的規則；確認規則與路由正確後，才允許啟動會話。
2. 服務必須從一開始就在該子樹中，再進行連線探測及啟動 Agent。v2 的匹配依據是建立 socket 時的分組，不能把已上網的程式搬進去就當作保護完成。
3. 子服務退出時由 systemd 收尾。共用父分組與規則不能隨最後一個 Shell 退出而拆除、重建，避免舊 socket 或規則仍引用舊分組。
4. 核對 `/proc/self/cgroup` 的 `0::` 路徑與實際服務歸屬。保存並核對共用分組的實際身分，不能只確認同名目錄存在；父分組意外消失或被重建時拒絕新會話。
5. `close`、正常退出及異常終止均保留共用網絡限制；清理函式不能把 v1 的 `rmdir` 方法直接套到 v2。

建議集中在新增的 `lib/cgroup.sh`，提供模式偵測、匹配參數、會話歸屬確認及清理方法。只抽出這些確實不同的行為，不重寫其他網絡模組。

## 四、sing-box：按設定自動配套不同代理協議

### 4.1 「自動適配」的意思

使用者依服務端要求填寫 `network.json`。程式讀取出口類型、傳輸方式與節點資料，自動生成必要的路由和放行規則，使用者不必為更換協議手改兩套防火牆。

這裡不要求掃描遠端伺服器、猜密碼或輪流嘗試協議。伺服器用什麼協議、憑證與認證，仍由使用者正確填寫。Hysteria2 繼續作為可用範例，不能再作為唯一允許的類型。

目標是接納固定核心所支援、並能納入本專案防護範圍的代理配置。接手者應依 [sing-box 出口文件](https://sing-box.sagernet.org/configuration/outbound/) 與 1.14.2 對應原始碼整理完整清單；不能只新增兩個類型，就把「所有 sing-box 協議均支援」寫進 README。核心有效但目前無法安全配套的設定，必須明確列為尚未支援，提示原因與可行設定方式。

### 4.2 分清楚兩種 TCP／UDP

| 概念 | 例子 | 如何處理 |
| --- | --- | --- |
| Agent 發出的通信 | 網頁 TCP、Agent 的 UDP 通信、DNS | 由所選代理的實際轉發能力決定；不支援時應失敗，不能直接送出。 |
| 容器連到代理節點的通信 | Hysteria2／TUIC 的外層 UDP；一般 Trojan 的外層 TCP | 防火牆需要準確放行的部分。 |

不能把 `.network: "tcp"` 一律解讀為「節點使用 TCP」。例如 Hysteria2 可只轉發應用程式的 TCP，而節點連線仍使用 UDP。傳輸封裝、UDP over TCP、multiplex 與 `detour` 也會改變外層需求，不能只按 `.type` 做粗略判斷。[Hysteria2 設定](https://sing-box.sagernet.org/configuration/outbound/hysteria2/)、[傳輸封裝](https://sing-box.sagernet.org/configuration/shared/v2ray-transport/)、[撥號設定](https://sing-box.sagernet.org/configuration/shared/dial/)

### 4.3 共用一份設定解析規則

建議新增 `gateway-policy.jq`，由主機和容器共用其中的純設定解析邏輯；主機及容器仍分別讀回實際規則、路由和狀態，不能只相信對方傳回「成功」。不增加常駐服務，也不把 Python 變成日常啟動依賴。

解析結果應為排序、去重、經嚴格型別校驗的 JSON，例如：

```json
{
  "format": 1,
  "proxy_tag": "proxy",
  "outer_endpoints": [
    {"family": 4, "address": "192.0.2.1", "protocol": "udp", "port_start": 443, "port_end": 443}
  ],
  "payload_networks": ["tcp", "udp"],
  "dns_transport": "udp"
}
```

這是建議的內部資料格式，不是要求使用者另外填一份節點清單。`outer_endpoints` 描述容器真正需要連出去的位置；不得把 Agent 任意要訪問的網站列入其中。結果不得包含密碼、私鑰或認證標頭。

建議介面：`read_proxy_policy CONFIG_FILE` 使用共用 jq 程式產生上述結果，成功時設置 `PROXY_POLICY_JSON`，失敗時回傳非零且不留下半份結果。取代目前只有 `NODE_IP`、`NODE_PORT` 的單節點介面，所有呼叫者和測試一起調整。

另外保存來源設定與有效執行設定的身分，讓主機確認容器跑的是同一份設定，而非僅有相同節點地址。含敏感設定的執行檔和識別資料只存放在 root 私有位置，不輸出到公開日誌。

### 4.4 協議、封裝與多出口的處理

接手實作時，先建立協議／功能矩陣，再逐項實作和驗證：

| 類型或功能 | 必須處理的重點 |
| --- | --- |
| Hysteria2、Hysteria、TUIC | 外層 UDP；Hysteria2 有跳埠時，按實際 `server_ports` 列表／範圍處理，不能仍只讀 `server_port`。 |
| Shadowsocks | 核對 TCP／UDP、UDP over TCP、multiplex 與插件的實際效果；不能永遠同時放行 TCP 和 UDP。 |
| Trojan、VMess、VLESS、AnyTLS、SSH、HTTP／HTTPS 等 | 按固定核心支援的配置和傳輸方式推導外層連線，不一律假設「所有協議都是 UDP」或「所有 HTTP 永遠一樣」。 |
| SOCKS | TCP 控制連線與 UDP relay 分開處理；原生 SOCKS5 UDP 的地址／埠可能由服務端協商，不能假設等於 `server_port`。 |
| `detour`／封裝鏈 | 沿引用關係追到真正從容器對外撥號的一跳；內層節點不應因此獲得額外直接出口。缺少引用、重複 tag、循環引用均拒絕。 |
| `selector`／`urltest` | 核對全部可能選中的分支並取必要節點集合，不能只放行第一個節點；不加入直連候選，也不因此公開管理 API。 |
| WireGuard 等 endpoint、需要額外控制服務的配置 | 依 1.14.2 的實際設定結構評估，不能硬套 `.outbounds[0].server_port`。沒有完成端點與控制連線限制前，不得宣稱已支援。 |

原生 SOCKS5 UDP 要按實際協商結果限制 relay，或使用服務端確實支援的 UDP over TCP。若未實作安全的動態 relay 管理，可明確提供 TCP 模式並阻擋 UDP，不能全面放行 UDP 掩蓋差異。[SOCKS 設定](https://sing-box.sagernet.org/configuration/outbound/socks/)、[RFC 1928 的 UDP 協商](https://www.rfc-editor.org/rfc/rfc1928.html#section-6)

未知協議、未知且會影響外層連線的選項，不能默認為 TCP 或 UDP 後繼續啟動。可擴充協議能力描述，但不把防火牆放行範圍交給使用者輸入的任意 shell 文字。

### 4.5 DNS 也要跟著適配

**這是多協議實作的必要部分。** 目前 DNS 固定使用 UDP 經代理；如果換成只支援 TCP 的 HTTP 代理，即使 TCP 通道正常，也可能因 DNS 失敗而完全無法使用。

對專案管理的 DNS 設定，建議按實際代理能力生成執行配置：

- 所有可選代理分支均支援應用層 UDP 時，保留目前的 UDP DNS、快取與強制經代理設定。
- 出口只有 TCP，或候選分支中有 TCP-only 出口時，DNS 改用經同一代理的 HTTPS DNS，避免依賴 UDP。可使用 `1.1.1.1:443`、`/dns-query`，並按服務要求設定及驗證 TLS 名稱；須以 1.14.2 的欄位實際驗證。
- 不論 Agent 查詢 TCP 53 或 UDP 53，都由目前的攔截機制交給容器 DNS；上游使用 HTTPS 不代表應用程式必須自行改設定。
- 明確設置 DNS 的 `detour` 到受控代理。新版 DNS 省略它可能直接撥號，不能只相信 `route.final`。[HTTPS DNS 說明](https://sing-box.sagernet.org/configuration/dns/server/https/)
- TCP-only 出口仍可啟動並使用 TCP；診斷需清楚提示「這個出口不支援 UDP；需要 UDP 的應用可能無法使用」。不要把 DNS 能用寫成 Agent 的 UDP 已能轉發。

來源設定保持唯讀，只調整專案管理的執行配置。不重寫使用者的密碼、TLS 驗證要求、傳輸認證或私鑰；不自動開啟 `tls.insecure`。

### 4.6 節點地址與動態功能的邊界

目前只支援固定 IPv4；多協議不等於可立即安全使用任意地址發現方式。必須把下列情況列入功能矩陣，不可默默忽略：

- **節點域名**：若要接納，需在可信管理階段解析、固定結果，並讓主機規則、容器規則與核心實際撥號使用同一組地址，保留原有 TLS／HTTP 名稱。不可任由核心自行解析到另一個未受核對的 IP，也不能臨時全面放行 DNS。未實作前，提示使用固定 IPv4 及必要的 TLS 名稱。
- **跳埠與多節點**：按明確的配置產生埠範圍和節點集合，主機與容器同步核對；不能把單埠擴成全埠，也不能把明確 IP 擴成任意地址。
- **動態發現、realm、STUN、遠端規則下載等**：盤點額外通信及配置變動，只有能限制、核對並維持斷線保護的部分才接納。未實作的部分應報出具體原因，不以「核心配置檢查通過」代替防護確認。
- **IPv6 節點**：目前保留阻擋與明確錯誤；不得為了接納 IPv6 字串就放開全部 IPv6。

這些邊界不能藏在籠統的「sing-box 全部支援」承諾裡。交付時應提供「已驗收」「尚未實作」「本版明確限制」的清單，未驗收項目不算完成。

### 4.7 主機、容器與執行狀態必須一起改

1. 容器先建立預設 DROP，再依解析結果生成精確的 OUTPUT／INPUT 規則及每個實際節點的路由，保留 TUN 的兩條半段預設路由。
2. 主機 FORWARD guard 同樣使用節點、外層 TCP／UDP 及埠集合；仍只允許專用網關的必要流量。
3. 容器自身 OUTPUT 的節點例外，不能順便允許轉發進來的 Agent 封包走 `eth0 → eth0` 直出。代理停止、TUN 路由缺少或目的地恰好等於節點地址時，也要保留這層區分。
4. 規則數不再寫死成 OUTPUT 3 條等固定值；從預期政策計算並逐條核對，仍拒絕額外放行、漏項及錯誤順序。不能改成「需要的幾條存在就算通過」。
5. 有效設定與規則核對成功後才發布新版 ready 狀態。主機拒絕舊版／不相符狀態，並獨立讀回規則和路由，最後才啟用網關 forwarding。
6. `binding` 改為有格式版本的 JSON，包含 cgroup 模式與共用分組身分、網關資料、規範化代理政策及設定身分。不要保存或打印整份含憑證的設定。
7. 識別現有四行 binding 與舊 ready 標記，拒絕當作新版直接沿用。升級必須先結束全部會話，再依文件遷移；不能刪除舊狀態就讓新版本覆蓋仍被使用的保護。
8. 初版採明確的離線配置更新流程，不增加運行中偷偷改節點／換模式的行為。檔案改動、核心與政策不一致時拒絕新會話；既有保護保留。

## 五、接手時的實作順序

兩項功能分開交付，先完成 cgroup，再處理多協議；最後驗收兩者的組合。每項先補有意義的失敗案例，再實作，並保留現有回歸檢查。此處的「執行」僅指日後另行獲准的環境，本次未執行。

### 任務 A：cgroup 模式偵測與會話管理

**檔案：** 新增 `lib/cgroup.sh`；修改 `lib/host.sh`、`lib/network.sh`、`lib/session.sh`、`lib/main.sh` 與安裝器的可信檔案清單；擴充 `tests/test_v8_platform.py`、`tests/test_v8_session.py`、`tests/test_installation.py`。

**介面：** 模式偵測產生 `CGROUP_MODE=v1|v2`、實際掛載點與受控分組資訊；網絡模組只取得相應匹配參數，會話模組只呼叫加入／核對／清理介面。內部子程序及清理入口也必須讀取並核對可信狀態，不能只依賴父程序未匯出的變數。

- [ ] 先以模擬掛載與工具邊界測試 v1、純 v2、混合模式、不同 net_cls 掛載位置、缺少匹配功能與權限不足；混合模式應優先 v1。
- [ ] 實作模式選擇與 v2 slice，確認不修改全機 cgroup 配置；失敗時使用者命令完全不執行。
- [ ] 測試 v2 服務在建立 socket 前已歸入專用子樹，以及正常退出、延遲停止、並行會話和父分組異常重建。
- [ ] 執行獲准的相關離線回歸，確認原 v1、CLI、降權、終端與 GUI 環境傳遞均維持原有行為。

### 任務 B：兩套 cgroup 都維持相同網絡保護

**檔案：** `lib/network.sh`、`lib/host.sh`、`lib/main.sh`；`tests/test_v8_network.py`、`tests/test_v8_platform.py`、`tests/test_v8_launcher.py`；實機工具 `tests/host_acceptance.py`、`tests/host_lifecycle.py`。

**介面：** 所選模式產生 IPv4／IPv6 規則；binding、規則比較與狀態核對均識別模式，現有 MARK、CONNMARK、路由表及最終出站阻擋繼續共用。

- [ ] 擴充規則測試模型，使其真正理解 `--path` 的子樹與 socket 歸屬，而不是把它當成 v1 classid 的別名。
- [ ] 測試兩種模式的 TCP、UDP、DNS、IPv6、強制綁定實體網卡及舊連線，並拒絕額外／重排規則。
- [ ] 實作狀態綁定與清理分支，測試已有會話時不切換模式、不拆共用分組或防火牆。
- [ ] 在獲准的 v1 與純 v2 測試機完成故障阻斷驗收，之後才把 cgroup 功能記為完成。

### 任務 C：共用代理解析與 DNS 適配

**檔案：** 新增 `gateway-policy.jq`；修改 `lib/network.sh`、`entrypoint-gateway.sh`、`Dockerfile.gateway`、`.dockerignore`、`lib/main.sh`、`install-dev-session.sh`；新增 `tests/test_proxy_policy.py`，擴充 `tests/test_dns_runtime.py` 與 `tests/test_entrypoint.py`。

**介面：** `read_proxy_policy CONFIG_FILE` 產生第 4.3 節的政策；主機與容器使用相同解析檔。Docker 只 COPY 無憑證的解析程式，`network.json` 繼續只在運行時唯讀掛入。

- [ ] 以假節點建立固定核心的協議／功能矩陣與範例；逐項測試外層 TCP／UDP、內層能力、傳輸封裝、跳埠、多候選、detour、錯誤引用和未知選項。
- [ ] 實作嚴格解析與排序去重，確認密碼／TLS／私鑰不因轉換而改變，惡意字串不會變成 shell 命令或防火牆參數。
- [ ] 實作 UDP DNS 與經代理的 HTTPS DNS 選擇；驗證只支援 TCP 的出口仍能解析及使用 HTTPS，而 UDP 應用明確失敗且無直出。
- [ ] 用固定核心的配置檢查驗證輸出設定；這只證明配置有效，不能代替防火牆或真實連線驗收。

### 任務 D：多節點規則、交叉核對與安全升級

**檔案：** `entrypoint-gateway.sh`、`lib/network.sh`、`lib/host.sh`、`lib/main.sh`；`tests/test_entrypoint.py`、`tests/test_gateway_review.py`、`tests/test_v8_network.py`、`tests/test_v8_launcher.py`、`tests/host_upstream_fixture.py` 及相關實機工具。

**介面：** 容器與主機從同一代理政策生成各自規則，從實際狀態獨立核對；使用有版本的 binding／ready 資料確認配置身分。ready 仍只代表本地配置已準備，外網連線仍由會話探測確認。

- [ ] 測試精確節點集合、每種傳輸、返回流量、必要路由、不同規則數，以及額外放行必須被拒絕。
- [ ] 測試新舊 binding／ready 混用、來源設定與執行設定不一致、安裝中斷，以及並行 init／run；全部保持拒絕新會話與既有阻擋。
- [ ] 實作新版狀態與離線遷移程序，不清空外部防火牆、不將解析失敗變成寬鬆規則。
- [ ] 擴充測試代理 fixture，完成所宣稱協議的實際轉發和故障測試，再完成 cgroup v1／v2 的交叉組合。

### 任務 E：文件與交付

**檔案：** `README.md`、`README.zh-CN.md`、`README.en.md`、`docs/host-validation.md`、`docs/VERIFICATION.md`、公開範例與 `MANIFEST.sha256`。

- [ ] 實作後更新三語 README，說清楚自動選擇、代理設定、TCP-only 出口、UDP 要求、未支援功能及實際系統條件；未實作前維持原說明。
- [ ] 提供以固定核心驗證的多協議公開範例，使用文件保留地址與假認證；範例不是可連線節點。
- [ ] 記錄實際核心／systemd／Docker／iptables 版本、cgroup 模式與協議／傳輸組合，不以舊版驗收結果替新功能背書。
- [ ] 更新雜湊清單與文件連結，完成獲准的完整離線回歸及實機清單；只把確實通過的項目標為完成。

## 六、驗收時必須看得到的證據

### Review Focus

| 容易漏掉的情況 | 需要的證據／負責任務 |
| --- | --- |
| v1 掛載存在但不能用，或只有 v2 根目錄卻無法匹配 | 偵測測試與實機拒絕啟動紀錄；不得只靠目錄存在。任務 A／B。 |
| 父 slice 被重建、舊 socket 留存、單個會話退出 | 分組身分、長連線及並行會話紀錄；共用限制不被拆除。任務 A／B。 |
| 協議名稱相同但傳輸、跳埠或 detour 不同 | 解析案例及實體網卡封包，確認只到必要外層端點。任務 C／D。 |
| TCP 代理可用但固定 UDP DNS 不通 | TCP-only 代理的域名 HTTPS 實測，以及 DNS、UDP 無直出證據。任務 C／D。 |
| 主機與容器認同不同設定，或換配置時留下寬鬆窗口 | 配置錯配／中斷升級測試、規則讀回與連續封包紀錄。任務 D。 |

最低實機環境包含：目前支援的 v1／混合模式、Ubuntu 26.04 LTS 的純 v2，以及一個採用新版 systemd 的另一發行版。測試前仍須確認 legacy iptables 與 Docker 條件，不能因 cgroup 通過就宣稱整個發行版已支援。

每種宣稱支援的協議／封裝都要驗證 TCP、實際支援的 UDP、DNS，以及代理出口 IP。對不支援 UDP 的出口，失敗是預期結果，但必須證明沒有改走真實出口。不能只測網頁能開啟。

依 [既有實機清單](../../host-validation.md) 補上：代理核心停止、節點中斷、容器重建、Docker 重啟、TUN 路由缺失、自有轉發路由缺失、既有長連線與新連線。所有故障期間持續觀察實體網卡，不能出現 Agent 直接連往任意外部目標的封包。

測試使用可回復、有控制台的專用測試機。不得在使用者日常主機注入故障，也不得把單元測試、語法檢查或核心配置檢查寫成已完成實機驗收。

## 七、背景資料與適用範圍

- [systemd 258 移除 v1／混合模式](https://github.com/systemd/systemd/releases/tag/v258)。這是 systemd 的支援變更，不代表 Linux 核心已移除所有 v1 程式碼。
- [Ubuntu 26.04 LTS 移除 v1 支援](https://documentation.ubuntu.com/release-notes/26.04/changes-since-previous-interim/#cgroup-v1-support-has-been-removed)。這使 v2 適配成為新主機的實際需求。
- [核心 cgroup v2 文件](https://docs.kernel.org/admin-guide/cgroup-v2.html)。分組、子程序繼承與生命週期以核心及實際 systemd 行為為準。
- [sing-box 1.14.2 原始碼](https://github.com/SagerNet/sing-box/tree/v1.14.2)。目前官方網站已包含較新版本的欄位；實作及範例必須以固定版本為準。

上述設計是按現有程式與官方文件提出的交接建議，不是已完成的相容性保證。最終交付應同時包含程式、測試、可讀的限制說明與實際驗收紀錄。
