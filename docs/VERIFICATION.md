# 驗證紀錄（公開版摘要）

本頁記錄截至 **2026-10-19** 已實際執行的範圍。最新純 cgroup v2 驗收為 [CI 39182626891](https://github.com/alexliyu7352/agent-network-sandbox-enhanced/actions/runs/39182626891)，提交 [`58dcfad596856fc3696d138f84d1c0f37e6e0ebd`](https://github.com/alexliyu7352/agent-network-sandbox-enhanced/commit/58dcfad596856fc3696d138f84d1c0f37e6e0ebd)，**12／12 jobs 通過**。這些 jobs 在原生 Ubuntu 與真正啟動的 Debian KVM 測試主機執行受管會話、Docker、TUN、legacy netfilter、systemd、代理 fixture 與封包觀測。

配置、真實 loopback 傳輸和完整主機驗收分開記錄。較窄的檢查不能代替較廣的證據，也不能把一組協議選項的結果外推到所有組合。VPS 的整合過程、固定核心與早期結果見 [2026-10-18 起的驗證紀錄](validation-20261018.md)，逐項協議範圍見 [協議矩陣](protocol-matrix.md)。公開摘要不包含私人節點、憑證、實際出口 IP 或原始封包。

## 本次結果與證據層次

| 層次 | 已執行的結果 | 適用範圍 |
| --- | --- | --- |
| 公開配置 | 24／24 通過共用解析器與固定核心配置檢查 | policy／effective 編譯與 sing-box 1.14.2 接受配置；不會連線到假節點。 |
| 成對協議 loopback | 47／47 runtime 通過 | 真正 client／server 的 TCP、UDP 或能力不足時的拒絕、DNS 共用快取／TTL、停止 server 後的阻斷，包含 Hysteria1／2 跳埠、Snell4、SSH 與 ShadowTLS 1／2／3。正式 TUN／介面／DNS 邊界被替換為本機 fixture，不包含主機 cgroup 或實體防火牆路徑。 |
| VPS hybrid／v1 核心與故障 | Hysteria2 17／17；HTTP CONNECT 17／17；兩者出口 IP 比對通過 | Ubuntu 20.04.6／systemd 245 的實際 v1 選擇、受管流量、上游中斷、TUN down/up、主機及容器路由故障；兩者均確認 gateway kill 後的 namespace 拒絕。VPS 未執行 Docker daemon restart 或 Compose recreation。 |
| VPS v1 生命週期與入口 | 生命週期 10／10，含 100 個短會話；能力 13／13；CLI 9／9 | 正常退出及子孫回收、100 次短會話與並行、實際 PTY、權限及原 CLI 邊界。這些是獨立 v1 套件結果，不重複計作每種代理都執行全部入口套件。 |
| 原生 Ubuntu 純 v2 | Hysteria2／HTTP × 5 種情境，10／10 CI jobs 通過 | healthy、gateway-stop、gateway-kill、gateway-recreate、docker-restart；各有核心、生命週期、socket 建立身分、出口 IP 及封包證據。 |
| Debian KVM 純 v2 | Hysteria2／HTTP healthy，2／2 CI jobs 通過 | 各核心 16／16、生命週期 10／10、100 個短會話、socket 建立身分及出口 IP 通過；含核心套件的路由、TUN、上游中斷，不含容器／Docker namespace 故障。 |
| 最新 CI 離線回歸 | 每 job 的 discover 為 248 項：247 通過、1 跳過；inline helpers 25／25 通過 | 唯一跳過項目需要 `DEV_NETWORK_TEST_ENGINE`；offline 階段早於 worker build，未執行真實 ELF 的 stdin-hold 身分測試。後續真實容器與主機驗收另行執行，不能將該 skip 記作通過。 |

固定核心為 sing-box **1.14.2**，revision `af6e64c3b69e6132ebaee0e1a3d24e93903f6709`。47 組 loopback 中，Hysteria1／2 跳埠各實際觀察到八個宣告埠中的兩個不同目的埠，以及切換後仍可轉發的既有 TCP stream；沒有把配置列表計作八個埠都已輪轉。Snell4 使用 v4 client／v5 inbound；SSH 使用固定核心 client 與獨立 Paramiko 3.5.1 server；ShadowTLS 1／2／3 使用 SS／UoT 和不發送 session ticket 的私有 TLS cover，憑證驗證保持啟用。主機層的完整代理矩陣目前限於上述 Hysteria2 與 HTTP fixture。

## 純 v2 CI 的版本與矩陣

本輪各 job 的原始執行結果、套件退出碼與上傳 artifact 均已核對；結果不是只依 workflow 的綠色狀態判定。Ubuntu jobs 使用新建原生 runner；Debian jobs 使用在 runner 上真正啟動的獨立 KVM guest，guest 內有自己的 systemd、Docker 與 cgroup。已核對的代表性 manifest 版本如下：

| 系統 | Kernel | systemd | Docker Engine／Compose | 防火牆與 cgroup |
| --- | --- | --- | --- | --- |
| Ubuntu 26.04.1 LTS | `7.0.0-1017-azure` | `259.5-0ubuntu3.4` | `29.4.2`／`5.1.3` | iptables／ip6tables 1.8.11 legacy；純 v2 |
| Debian 13.7（trixie），KVM | `6.12.113+deb13-amd64` | `257.13-1~deb13u1` | `29.9.1`／`5.6.0` | iptables／ip6tables 1.8.11 legacy；純 v2 |

兩者使用實際 `/sys/fs/cgroup` 的 v2 hierarchy 與常駐 `/devsession.slice`。hybrid VPS 的 Ubuntu 20.04.6／Linux 5.15.0-1117-aws／systemd 245／Docker 26.1.3／legacy iptables 1.8.4 則仍優先選擇可用 v1；沒有為取得 v2 結果修改該 VPS 的開機或控制器掛載。

| CI 環境與情境 | 代理 | Jobs | 每 job 核心套件 | 每 job 生命週期套件 |
| --- | --- | --- | --- | --- |
| Ubuntu／healthy | Hysteria2、HTTP | 2／2 | 16／16 | 10／10 |
| Ubuntu／gateway-stop | Hysteria2、HTTP | 2／2 | 17／17 | 10／10 |
| Ubuntu／gateway-kill | Hysteria2、HTTP | 2／2 | 17／17 | 10／10 |
| Ubuntu／gateway-recreate | Hysteria2、HTTP | 2／2 | 17／17 | 10／10 |
| Ubuntu／docker-restart | Hysteria2、HTTP | 2／2 | 16／16 | 11／11 |
| Debian KVM／healthy | Hysteria2、HTTP | 2／2 | 16／16 | 10／10 |

healthy 是 job 的附加故障模式名稱，不代表完全沒有故障注入：16 項核心套件本身包括主機 default route 缺失、TUN `/1` 缺失、所有外層節點中斷和 TUN link down/up。容器 stop／kill／recreate 在核心套件最後新增一項；Docker restart 在生命週期套件最後新增一項。不同套件的數量不能混記。

所有 12 jobs 均完成 100 個短會話、concurrency 3、零殘留 session，55 條共同規則的數量保持不變。v2 驗證在兩個受管 service 內實際建立共四個 TCP／UDP socket，以 inode 對應 root 的 cgroup socket 資料，確認各自屬於正確 service；沒有只依 `/proc/PID/cgroup` 的路徑文字宣稱 socket 入場正確。

### 封包、DNS 與出口 IP

每 job 均觀察到 **2 個抓包正對照、0 個受管外網直連封包**。所有觀察到的 gateway 外層流量符合當次假節點的精確 IPv4、協議和埠：Hysteria2 使用 UDP 443，HTTP 使用 TCP 443。這些單葉固定埠 CI fixtures 不能代替 selector、多跳或所有跳埠區間的實體介面驗證。

Hysteria2 的普通 UDP echo 確實收到回應；HTTP 的普通 UDP 按能力拒絕，沒有直連回退。兩者分別使用 UDP DNS 與經代理、驗證 TLS 的 HTTPS DNS，抓包未見測試 DNS 在外層明文直出。獨立 DNS／loopback 套件另測跨 TCP／UDP 查詢共用 cache、TTL 到期重查，以及停用 cache、移除 HTTPS DNS detour 的預期失敗負對照。

各 job 的出口 IP 結果均為有效 IPv4 且一致，七項配套檢查全部為 true：工作負載身分、cgroup、會話回收、後續政策檢查、原 binding 保留、fixture source 綁定及上游 namespace 所有權。工具分別從受管工作負載和指定 fixture namespace 取得 HTTPS trace，只在記憶體中比對，不公開實際 IP。**同機 NAT fixture 的一致性證明指定測試路徑，不能證明遠端匿名性、跨網絡品質或使用者生產代理已可用。**

### 故障後保留綁定的證據

Ubuntu 的 container stop／kill／recreate 與 Docker restart jobs 均實際觀察到 namespace 改變，`check` 和 `init` 均回傳 125，原 binding／共同 guards 保留，結果標明 `offline_rebind_required`。容器故障期間既有與新外網連線被阻斷，另一受管會話的 loopback 仍可使用；Docker restart 的生命週期結果另確認會話仍受限制、能力未改變且最後關閉所有測試會話。

兩個 recreate jobs 都由明確授權的 fresh Compose 專案建立新容器，確認 **container ID 和 namespace 均改變**、原映像／source 身分及 replacement ready 驗證通過。新 workload 入場仍回傳 125，測試 payload 沒有執行。測試沒有刪 binding、修改 guards 或自動接納新 namespace；這是故障阻斷與拒絕重新入場的通過結果，並非無縫恢復網絡。

同 namespace 的 route／TUN 暫時故障則只撤銷測試自己的精確變更。TUN down/up 會移除兩條 `/1`，harness 只補回故障前已捕捉且確實缺失的原條目，拒絕篡改或其他路由變化，再核對完整 snapshot 和原 binding。產品沒有增加自動修復或放行。

### 可核對的代表性 artifacts

下列三份 ZIP 已讀取實際 suite 結果並核對 SHA-256；其餘九份可從同一 workflow run 的 artifacts 取得。這些是只用假認證的測試證據，不含生產配置或實際出口 IP。

| Artifact | 已核對的主要結果 | ZIP SHA-256 |
| --- | --- | --- |
| [Ubuntu HTTP recreation，12157545163](https://github.com/alexliyu7352/agent-network-sandbox-enhanced/actions/runs/39182626891/artifacts/12157545163) | 核心 17／17、生命週期 10／10；177 個外層 TCP 443 封包、直連 0；新 CID／namespace 拒絕及出口 IP 檢查通過。 | `bf27a4f1737a86ed174c28b9e47384c4ca8c3686bf207a0ed566f5edeb1c2523` |
| [Ubuntu Hysteria2 recreation，12157336191](https://github.com/alexliyu7352/agent-network-sandbox-enhanced/actions/runs/39182626891/artifacts/12157336191) | 核心 17／17、生命週期 10／10；124 個外層 UDP 443 封包、直連 0；新 CID／namespace 拒絕及出口 IP 檢查通過。 | `e672b2d43f16ac1d08982de55beaac5a1d2f4cd66914130b5d871f09d107277d` |
| [Debian HTTP healthy，12156612831](https://github.com/alexliyu7352/agent-network-sandbox-enhanced/actions/runs/39182626891/artifacts/12156612831) | 核心 16／16、生命週期 10／10；163 個外層 TCP 443 封包、直連 0；100 個短會話、socket 身分及出口 IP 檢查通過。 | `e59d31d54619bb81e006b3b5a3ad1bfb7e2e4dd4c678d8269daf9dd79dc99dff` |

前一輪 [CI 39181240484](https://github.com/alexliyu7352/agent-network-sandbox-enhanced/actions/runs/39181240484)（`7048a679a2e4573e243dc952b6058b23b886f4f2`）為 9／10 jobs 通過：Ubuntu 八個 jobs 與 Debian Hysteria2 通過；Debian HTTP 的核心 16／16、出口 IP 和 socket 身分通過，但生命週期 fixture 遇到 PID 檔案已建立、內容尚未發布的競態。修正已納入本輪公開且驗證通過的 `58dcfad596856fc3696d138f84d1c0f37e6e0ebd`：在原有期限內只接受完整 PID 行，測試強制先觀察空檔後才發布內容。最新 Debian HTTP 重跑已通過，沒有改動產品清理邏輯，也沒有把前一輪失敗抹去。

## 歷史紀錄

以下表格保留專案原有結果，不能用來證明後續新增 v2 或其他代理的行為。原始私人主機日誌、終端錄製、封包及部署資料不附於公開摘要。

| 日期與項目 | 歷史結果 | 適用範圍 |
| --- | --- | --- |
| 2026-10-11，自動保存終端設定的啟動器 | 127 項：125 通過、2 跳過、零失敗 | 啟動器、字面參數、工作目錄、安裝升級及權限邊界；部分 sudo 邊界由測試替代，沒有完整桌面驗收。 |
| 2026-10-11，GUI／語言／時區／umask | 112 項：110 通過、2 跳過、零失敗 | 執行環境傳遞、檔案建立權限與啟動順序；不能當作真實 GUI 視窗驗收。 |
| 2026-10-11，Ubuntu 20.04 普通帳戶的執行環境測試 | 17 通過、3 個需要 root 的項目跳過、零失敗 | Bash 5.0／Python 3.8 相容性；未涵蓋完整 root 入口和網絡鏈路。 |
| 2026-10-10，能力上限相容性 | 完整回歸 88/88；能力檢查 11/11；核心網絡 15/15；CLI 9/9 | 普通帳戶、可用能力為零、網絡限制及實際終端；不是 ICMP 轉發驗證。 |
| 2026-10-10，單一目錄安裝與實機整合 | 完整回歸 79/79；核心網絡 15/15；生命週期 11/11；短會話 100/100；CLI 9/9 | Ubuntu 20.04、systemd 245、cgroup v1、legacy 防火牆及 rootful Docker。 |

這些歷史實機網絡測試使用同一測試主機內的臨時 Hysteria2 伺服器，經真正的 Docker、netfilter、systemd 及代理核心處理流量。它們只適用於各次記錄的版本與範圍。

## 需要保留的限制

- 真正的 X11 視窗與 Wayland 桌面完整驗收尚未完成。環境變數能傳遞，不代表所有 GUI 程式都能使用。
- 24 份配置及 47 組 loopback 的通過範圍不能外推到未測的 cipher、TLS／Reality、flow、multiplex、selector／detour、ShadowTLS cover 站點或主機端點組合。逐協議實體出口矩陣完成前，不以成對互通替代完整主機驗收。
- Debian KVM 本輪只執行兩個 healthy jobs；Ubuntu 的容器與 Docker namespace 故障結果不能記成 Debian 已測。這三種主機環境也不涵蓋所有 Linux／systemd、rootless Docker 或防火牆 backend。
- 啟動器被 SIGKILL 時，會話可能留存；歷史測試確認當時仍受限制，需用 `session close ID` 處理。
- Docker 服務重新啟動後，若規則順序改變，檢查會拒絕啟動。container ID、network ID、namespace 或配置／解析器身分改變時，舊 binding 不能由 `session init` 自動更新；須關閉全部會話並依 [離線升級流程](offline-upgrade.md) 處理。不要刪除 `/run/dev-session-v8` 或清空共同 guards 強迫接納新身分。
- 本機服務、桌面通信及會話外同帳戶程序不會自動加入限制；歷史通過結果不構成完整惡意程式沙箱保證。
- 公開範例中的代理地址與密碼不能使用；上述結果不代表範例節點已連通。
- 本次變更仍在工作分支，尚未合併 `main`。CI 通過是審閱證據，不能代替明確的合併批准。

## 重驗與技術說明

需要重新驗收時，使用 [實機驗收清單](host-validation.md)，並先閱讀 [README](../README.md) 的測試注意事項。`tests/host_*.py` 可能中斷測試機網絡，只能在可回復的測試環境執行。

保留的歷史技術說明：

- [能力上限相容性](capability-validation-20261010.md)
- [GUI 與執行環境](gui-environment-20261011.md)
- [單一目錄實機整合](host-acceptance-20261010.md)
- [早期實機驗收](host-acceptance-20261009.md)
- [原生會話架構](v8-plan.md)

這些文件已移除原始資料的公開連結，部分版本識別及操作描述仍按歷史背景保留；目前使用方式以 README 和現行程式為準。
