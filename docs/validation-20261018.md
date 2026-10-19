# cgroup／代理自動適配：2026-10-18–19 驗證紀錄

本頁只記錄本次實際執行的結果。配置解析、核心配置檢查、真實代理傳輸、完整主機故障驗收是不同層次；任何一層通過都不能代替其餘層。

## 可重現的版本與環境

- 原始基準：`aac516d650a8150282b3a96633af6f5f7d7830d7`。
- 首個整合 checkpoint：`616943ce46999c17066a6b3be4db8acf8993fc0d`，Git tree `c0b50a065d421f16c44681e314bd1a68f3f5d180`。
- VPS：Ubuntu 20.04.6、Linux 5.15.0-1117-aws、systemd 245、Docker 26.1.3、legacy iptables 1.8.4；cgroup v1／v2 混合掛載。
- 核心：官方 sing-box 1.14.2，提交 `af6e64c3b69e6132ebaee0e1a3d24e93903f6709`，`linux/amd64`。映像內的實際 ELF 名稱為 `worker`；測試執行檔從已存在的映像複製，未重編譯核心。
- 原生偵測使用實際可寫 net_cls 及兩個 IP family 的獨立未掛接測試鏈，結果為 `v1`、`/sys/fs/cgroup/net_cls,net_prio`、`name=systemd`。沒有改動控制器掛載或開機參數。
- 原生純 v2 checkpoint：`58dcfad596856fc3696d138f84d1c0f37e6e0ebd`，Git tree `16502b62ed8fcf190f86cc8ed4a0dc8e753af6a4`；[CI 39182626891](https://github.com/alexliyu7352/agent-network-sandbox-enhanced/actions/runs/39182626891) 的 12 個工作全部成功。

| 原生純 v2 環境 | Ubuntu runner | Debian KVM guest |
| --- | --- | --- |
| 發行版 | Ubuntu 26.04.1 LTS | Debian 13.7，trixie |
| Linux | 7.0.0-1017-azure | 6.12.113+deb13-amd64 |
| systemd 套件 | 259.5-0ubuntu3.4 | 257.13-1~deb13u1 |
| Docker Engine | 29.4.2 | 29.9.1 |
| Docker Compose | 5.1.3 | 5.6.0 |
| iptables／ip6tables | 1.8.11 legacy | 1.8.11 legacy |

兩個環境都實際使用唯一的 cgroup2 掛載，`devsession.slice` 由 systemd 保持有效；這些是當次環境回讀值，不是對所有 Ubuntu／Debian 安裝方式的保證。

測試配置使用文件保留地址與假認證。公開報告不附生產節點、密碼、主機出口 IP 或可能含私人流量的原始 pcap。

## 已執行的檢查

| 層次 | 實際結果 | 能證明的範圍 |
| --- | --- | --- |
| 原始版本 VPS 回歸 | 127 項，126 通過、1 跳過 | 建立同一主機的舊版基準。 |
| 首個整合 checkpoint VPS 完整回歸 | 198 項，197 通過、1 跳過 | 含真實 root 私有安裝測試；沒有 assertion failure。唯一跳過是未以環境變數指定核心路徑的選用二進位身分測試。 |
| 整合修正後 VPS 完整回歸 | 204／204 通過，零跳過 | 包含真實核心身分檢查、binding 單一物件、路由表別名、容器 default route 格式及最後三個代理圖測試；後續新增的 CI／協議驗收工具另有針對性回歸。 |
| 同 checkpoint 本機回歸 | 198 項，183 通過、13 環境錯誤、2 跳過 | 13 個錯誤全部是安裝測試無法在本機唯讀 `/root` 建立 fixture；這些項目已在 VPS 通過。 |
| 公開配置 | 24／24 | 兩個 jq 模式可編譯且有效配置冪等；全部通過 VPS 的固定核心 `worker check`。尚不能據此宣稱每種協議都已實測轉發。 |
| 真實 Hysteria2 DNS | 通過 | UDP DNS 經本機真實 Hysteria2 連線，UDP／TCP 查詢共用快取，TTL 到期會再次請求上游。 |
| 真實 HTTP CONNECT DNS | 通過 | 認證後的 CONNECT 承載經憑證驗證的 HTTPS DNS；UDP／TCP 查詢共用快取，TTL 重新查詢，普通 UDP 沒有 direct fallback。 |
| DNS 反向測試 | 按預期失敗 | 關閉快取後觀察到第二次上游請求；去除 DNS detour 後首個查詢逾時。測試可以偵測其聲稱保護的行為。 |
| 真實容器本機政策＋主機獨立核對 | 通過 | 最少 capabilities、唯讀根目錄與設定掛載下，真實 TUN、完整有序規則、節點路由及三份配置雜湊可被兩端獨立確認。首次只檢查本機政策並保持 forwarding 關閉；其後已另外執行下表的受管 workload 與抓包驗收。 |
| 最後代理圖修正的本機回歸 | 33／33 通過 | 包含 URLTest 的 TCP 探測能力拒絕及共享下層圖的執行時間上限回歸；50 節點共享圖實測約 0.020 秒。 |
| 成對協議配置／真實轉發 | 首批 40／40；Hysteria2 跳埠 1／1；Snell4／Hysteria1 跳埠 2／2；SSH／ShadowTLS 1／2／3 4／4 | 合計 47 組 runtime 通過，包含實際 TCP、UDP 或拒絕、DNS、共用快取／TTL、代理本機來源及停止 server 後的阻斷。46 組使用同一固定核心 client／server；SSH 使用核心 client 與獨立 Paramiko 3.5.1 server。Snell4 為 v4 client／v5 inbound；兩種跳埠各實際觀察到 8 個宣告埠中的 2 個。屬 loopback fixture，具體組合與未覆蓋項目見[協議矩陣](protocol-matrix.md)。 |
| VPS v1 Hysteria2 主機完整網絡與故障 | 17／17 通過 | 真實 systemd 會話、Docker／TUN／legacy 防火牆、節點中斷、TUN down/up、兩種路由缺失、容器 SIGKILL／namespace 變更、既有與新連線及持續抓包。 |
| VPS v1 HTTP CONNECT 主機完整網絡與故障 | 17／17 通過 | TCP-only 出口、驗證憑證的 HTTPS DNS、普通 UDP 拒絕，以及相同的節點、TUN、路由和容器 SIGKILL 故障；抓包證明沒有受管流量直出。 |
| VPS v1 生命週期 | 10／10 通過，包含 100／100 短會話 | concurrency 3；100 次短會話約 400 秒，零殘留 session／request，55 條共用規則與同一父 cgroup 身分保留。另測實際 PTY、Unicode／readline、Ctrl-C、Ctrl-Z／fg、resize、終端 hangup、並行會話及子程序清理。 |
| VPS 權限及 CLI | capability 13／13；CLI 9／9 通過 | 普通 UID、零可用能力、NoNewPrivs／seccomp、檔案 capability 執行、原始 socket 拒絕、普通帳戶 launcher、工作目錄、參數及清理。 |
| VPS Hysteria2／HTTP 出口 IP | 兩者各 7 項身分／清理檢查通過，IPv4 出口一致 | 獨立上游 namespace 的 HTTPS trace 與真正受管 workload 比對；只記錄 family／一致性，不保留觀測到的 IP。受控同主機 NAT fixture 的一致性不證明遠端匿名性。 |
| Ubuntu 26.04 原生純 v2 | 10／10 jobs 通過 | HTTP／Hysteria2 各測 healthy、gateway-stop、gateway-kill、gateway-recreate 和 Docker restart。 |
| Debian 13 KVM 純 v2 | 2／2 jobs 通過 | HTTP／Hysteria2 healthy；各核心 16／16、生命週期 10／10。包含節點、TUN、路由故障，不含 Debian 容器／Docker namespace 故障。 |
| 上述 CI 的離線回歸 | 各工作 discover 248 項：247 通過、1 跳過；inline helpers 25／25 通過 | offline 階段尚未建置核心，未指定 `DEV_NETWORK_TEST_ENGINE`，所以真實 ELF 的 stdin-hold 檢查跳過；後續實際容器及工作負載驗收另行通過。 |

完整回歸命令：

```sh
sudo env DEV_NETWORK_TEST_ENGINE=/root/TEST_ENGINE python3 -m unittest discover -s /root/TEST_CHECKOUT/tests </dev/null
```

將 stdin 指向 `/dev/null` 是必要的測試邊界：遠端命令傳輸的 socket 不能被繼承成受限 workload 的 stdin。安裝源先以 root 擁有且無 group/world write 權限的副本準備；產品沒有放寬 FD 或信任路徑檢查。

DNS 命令（`ENGINE` 指向私有測試核心）：

```sh
python3 tests/test_dns_runtime.py --engine "$ENGINE" --proxy http --check-only
python3 tests/test_dns_runtime.py --engine "$ENGINE" --proxy http
python3 tests/test_dns_runtime.py --engine "$ENGINE" --proxy hysteria2
# 下列兩次必須失敗，並確認失敗原因：
python3 tests/test_dns_runtime.py --engine "$ENGINE" --proxy http --negative-control
python3 tests/test_dns_runtime.py --engine "$ENGINE" --proxy http --negative-detour
```

這組 DNS fixture 僅使用隨機 loopback 埠、臨時憑證與假認證，不改主機防火牆、路由或全局 resolver。

## v1 實體網絡與故障證據

最後一輪 Hysteria2 主機驗收共有 17 個通過項目。抓包正向對照觀察到 2 個封包；受管 workload 在實體介面直接出站的封包為 0。網關外層擷取到的 125 個封包全部符合當次 policy 中唯一的文件地址／UDP 443 端點；另觀察到 34 個被導向受管 DNS 的封包，外層沒有測試 DNS 名稱或普通 UDP token 的明文。

HTTP CONNECT 隨後以新的獨立 binding 執行相同 17 項主機驗收。抓包正向對照為 2，受管直連為 0，外層 173 個封包全部符合唯一的文件地址／TCP 443 端點；另有 30 個被導向受管 DNS 的封包，外層沒有明文測試 DNS 名稱。有效 DNS 為 HTTPS，普通 UDP 按能力拒絕。該次容器 SIGKILL 也實際改變 namespace，後續入場拒絕且保留 binding 和 55 條共用規則。

節點中斷、TUN 關閉、TUN 半段路由缺失和主機 policy table unicast default 缺失時，既有及新 HTTPS 連線都失敗，另一會話的 IPv4 loopback 仍可使用。故障期間的 forced-interface 探測同樣納入持續封包擷取；程式的 `connect()` 結果不能替代封包判斷，因為 TUN stack 可能先完成本機 TCP 握手。

容器 SIGKILL 後由測試明確重啟，實際 namespace 身分已變。`check`、`init` 及新 workload 入場均回傳 125，測試 payload 未執行；原 binding、55 條共用限制及父 cgroup 身分保留。這項結果是拒絕沿用舊 namespace，沒有透過刪除 binding 自動恢復。VPS 沒有執行 Docker daemon restart 或整機 reboot；這兩者的範圍不能由此結果推得。

生命週期中的 launcher SIGKILL 是單獨的限制案例：可能留下 unit，但該 unit 仍受限制，明確 `close` 後成功回收。正常退出、TERM、relay KILL、終端 hangup 與一般子程序清理另行驗證，沒有把這個限制當成正常退出行為。

兩輪測試結束後，先核對所有測試會話、子程序、request 及 cgroup 都已閒置，再直接讀回核心 TCP socket 狀態。兩次均在 pending external socket 為 0、共用 guards 仍存在時，才移除本次建立的 fixture、容器、精確規則／路由、空 cgroup 和專用 bridge。原容器在整個測試期間保持運行，最後以原 ID 恢復原名稱；只刪除本次建立的普通測試帳戶、home 與測試 launcher。未重啟 VPS 的 Docker daemon 或主機。

## 原生純 v2 的 socket、生命週期與故障證據

[12-job CI](https://github.com/alexliyu7352/agent-network-sandbox-enhanced/actions/runs/39182626891) 於 2026-10-19 00:51:10–01:00:15 UTC 執行，全部成功。各工作均完成 100 次短會話，並行數 3，零殘留 session，55 條共同規則與同一父 slice 身分保留。

每個工作在兩個受管 service 內實際建立共四個 TCP／UDP socket，將 socket inode 與 root 回讀的 cgroup socket 資料逐一比對。四個 socket 都屬於各自的 `devsession.slice/dev-session-…service`，提供建立 socket 時已位於受控子樹的證據。

所有工作的持續抓包都有 2 個正對照封包、0 個受管 workload 直連封包，外層只命中當次指定節點及協議／埠。HTTP 和 Hysteria2 的容器重建案例均實際換了容器 ID 與 namespace；原 binding 保留，`check`、`init`、新工作啟動皆回傳 125，payload 沒有執行。既有和新建外部連線被阻擋，另一會話的 loopback 仍可使用。

代表性 artifact 的內容與完整 SHA-256 見[驗證摘要](VERIFICATION.md)：Ubuntu HTTP recreate 的核心 17／17、生命週期 10／10；Ubuntu Hysteria2 recreate 同為 17／17、10／10；Debian HTTP healthy 為 16／16、10／10。全部出口 IP 身分及清理檢查成功。這一輪主機矩陣使用 HTTP／Hysteria2 單葉固定埠，其他協議、detour 和跳埠的逐项實體出口驗收另列，不能由 12 個工作直接外推。

## 整合時修正的問題

1. legacy iptables 回讀可能將 `ESTABLISHED,RELATED` 寫成 `RELATED,ESTABLISHED`。兩端現在只正規化該等價值，仍保留整條規則的先後次序核對。
2. `ip -j` 可能把路由表 ID 顯示成 `rt_tables` 別名。涉及表身分的讀回使用 numeric 輸出，避免誤判外部表為空閒；按數字選表的路由細節仍保留 `scope:link` 語義。
3. 多份串接 JSON binding 不得只取第一份。binding 必須恰好是一份完整物件，否則在載入 cgroup 前拒絕。
4. VPS 的映像內 iproute2 在 `route show default dev eth0` 回讀中省略 `.dev`。容器改讀完整 default 集合，再驗證只有一條且明確屬於 eth0；沒有放寬 gateway 條件。
5. URLTest 即使被當成 UDP 承載路徑，仍會對候選建立 TCP 健康探測。解析器現在明確拒絕不保證 TCP 的候選路徑，避免接受後才由封鎖規則阻止必要探測；探測候選也不能直接使用 ShadowTLS 包裝，經正常代理的 ShadowTLS detour 則保留。
6. 多層 selector 共用下層節點時，遞迴列舉可能隨路徑數急遽增加。改用拓撲排序、每節點能力快取與合併需求，保留循環、深度及相容性檢查。
7. Ubuntu／Debian 原生 CI 的 Docker 29 將 `CapAdd` 回報為 `CAP_NET_ADMIN`、`CAP_NET_RAW`，舊版 Docker 使用不含前綴的名稱。實際安全化 inspect replay 證明這是首次拒絕的唯一差異；現在只移除一次 `CAP_` 前綴，要求值為陣列且完整排序結果仍恰好是兩項能力。額外、重複、未知、非字串與物件值均被拒絕，其他容器信任檢查保留。
8. TUN 故障測試最初只把介面 down/up；實機核心在 down 時移除了兩條 `/1` 路由，因此測試的恢復階段失敗。修正只影響測試：先捕捉可完整重建的路由快照，恢復時只 `add` 已消失的兩條路由，拒絕被修改、重複或其他路由變更，最後核對完整快照。產品没有增加自動修復或放行。修正後實機重測通過。
9. 前一輪 Debian HTTP 已完成核心驗收，卻在生命週期 fixture 讀到剛建立、尚未寫入 PID 的空檔。現在發布完整換行結尾的 PID，reader 在原有期限內等待完整正整數行；回歸測試強制先讀到空檔再發布。修正後 Debian HTTP 原生重跑全部通過，產品清理程式未改動。
10. ShadowTLS 2 的首個實際 fixture 請求到達了內層服務，但第一個回應發生 AEAD 驗證失敗。固定依賴的 v2 在 TLS 握手後直接把後續 record 交給內層代理；真實 TLS MemoryBIO 測試證明 Python cover 額外產生 510 bytes 的 session tickets。將這個不使用 resumption 的私有 cover 設為 `num_tickets=0` 後，握手後額外資料為 0；VPS 的 18 項 fixture 回歸與 ShadowTLS 2／1／3 三項真實重跑全部通過。每項都有 3 次 cover 握手、wrapper／內層轉發及完整正負向流量證據。這是 fixture 的精確相容性條件，沒有修改固定核心或停用 TLS 憑證驗證，也不能據此保證任意真實 cover 站點。

上述問題均先以針對性測試重現失敗，再修正並重跑。default route 問題同時在真實 Docker 容器重現，修正後容器與主機獨立核對均通過。

## 接受範圍與後續證據

三個最低實機環境已取得上述實際結果。逐協議矩陣仍必須分清楚固定核心配置、loopback 成對互通與完整受管主機出口驗收；後兩者不能互相替代。尚未完成的協議／封裝和實體出口組合保持明列，不記為已驗收。

容器停止／重建／daemon restart 若改變 namespace 身分，預期行為是保留 binding 和共用封鎖、拒絕新會話，關閉既有會話後依[離線升級流程](offline-upgrade.md)處理。不能將直接刪掉 binding 後重新啟動記作故障恢復通過。

任何合併仍須由使用者審閱最終測試結果後明確同意；本次提交只位於工作分支。


逐協議原生矩陣、歷史 47 組之後發現的 HTTPUpgrade 可靠性反例、現行 44 組 inventory、AnyTLS 有界限制及後續關卡，另記於 [2026-10-19 追加驗證](validation-20261019-followup.md)。本頁早期通過紀錄保留，不用來抵銷後續失敗。
