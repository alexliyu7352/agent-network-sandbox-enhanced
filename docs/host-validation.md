# cgroup 與代理政策的實機驗收程序

本文件是目前版本的重驗清單，**不是宣稱所有項目已通過的結果表**。只在有控制台、可以回復、可接受網絡與服務中斷的測試主機執行。`tests/host_*.py` 會啟動會話、修改路由與規則，部分項目停止網關或重新啟動 Docker；不要直接在日常工作主機執行整套故障測試。

截至 2026-10-19，歷史證據包括 24／24 公開配置檢查、初輪 47／47 協議 loopback 案例，以及 Ubuntu 20.04.6 hybrid／v1 上 Hysteria2 和 HTTP 的核心／故障套件各 17／17。[CI 39182626891](https://github.com/alexliyu7352/agent-network-sandbox-enhanced/actions/runs/39182626891) 在 `58dcfad596856fc3696d138f84d1c0f37e6e0ebd` 通過 12／12 jobs：Ubuntu 26.04.1 原生純 v2 的兩個協議各測 healthy、stop、kill、recreate、Docker restart；Debian 13.7 KVM 純 v2 的兩個協議各測 healthy。Debian 的兩個 jobs 仍含路由、TUN 及受控上游中斷測試，但不含容器／Docker namespace 故障。

後續逐協議 CI 的第一輪為 50／59，未全數通過；HTTPUpgrade 追加重測失敗後已明確拒絕，現行必需矩陣為 44 個逐協議 jobs 加原有 12 個代表性 jobs。AnyTLS 另含一項有界限制與恢復驗證，第一條失敗保留，不在通用故障測試或產品探測加入重試。完整失敗紀錄與後續結果見[追加驗證](validation-20261019-followup.md)。

各次版本、套件數量、封包與 socket 身分證據見 [驗證摘要](VERIFICATION.md)。以下清單也列出尚待擴充的測試範圍，不能把它的每個項目都當成已通過。配置／loopback 結果不代替主機層驗收，已測主機也不能代替其他協議、transport 或使用者實際遠端節點。歷史結果另保留於 [2026-10-10](host-acceptance-20261010.md) 與 [2026-10-09](host-acceptance-20261009.md)。

## 1. 記錄環境與當次範圍

至少記錄以下資訊，放在 root 專用驗收目錄：

- repository 提交、發佈清單、原始／有效配置／解析器的 SHA-256；不公開原始認證資料。
- kernel、systemd、Docker／Compose 版本、iptables/ip6tables backend 與對應核心模組能力。
- `findmnt -t cgroup,cgroup2`、`/proc/1/cgroup`、`session init` 選定模式，以及 binding 中的 mount／parent／boot 身分。
- `docker exec worker worker version` 的版本、revision、架構及建置標籤；使用的 proxy type、transport、network、UoT／multiplex、跳埠與引用圖。
- Docker container/network ID、網絡 namespace 身分、測試介面、流量辨識方式、退出碼和明確的 PASS／FAIL／SKIP 原因。

不要只記「支援 cgroup v2」或「支援 UDP」。必須指明當次到底執行哪個模式、哪個 protocol／transport 組合，以及證據是純解析、core check、loopback fixture，還是真實受管會話與封包觀測。

## 2. cgroup 選擇與會話身分

以下是需要完成的交叉驗收範圍：

| 主機模式 | 預期選擇 | 至少交叉驗證的代理 |
| --- | --- | --- |
| v1 或 hybrid，net_cls 可寫且兩個 IP family 的 legacy classid match 可用 | v1，保留優先順序 | QUIC／UDP 外層代理，以及 TCP-only HTTP CONNECT |
| v1 不可用而 systemd v2 與兩個 IP family 的 path match 可用 | v2 | 同上；另測常駐 slice／service 子孫匹配及清理 |
| 兩種模式皆不符合 | 拒絕入場 | 使用假工作負載，確認未執行、未開放 fallback |

首次選擇需要真正的核心匹配探測；僅看到 cgroup mount 或 `iptables --help` 有欄位不能當作可用。程式的探測會短暫建立未掛入 live hooks 的獨立規則鏈，v1 另測試自己的暫存群組，不移動呼叫程序。驗證探測結束後沒有殘留，不要為了測試盲目切換全機 backend 或修改開機參數。[實作依據](../lib/cgroup.sh)

在無其他會話時 `session init`，再開啟會話 A/B。核對：

| 項目 | v1 | v2 |
| --- | --- | --- |
| systemd ControlGroup | `/system.slice/dev-session-ID.service` | `/devsession.slice/dev-session-ID.service` |
| 網絡分類 | 在實際探測到的 net_cls mount 下，`dev-session-v8/ID` 的 classid 為 `0x6d730001` | legacy `-m cgroup --path devsession.slice` 匹配子孫 |
| 入場順序 | 在權限下降及任何測試／工作負載連線前加入 classid 群組 | systemd 直接在目標 slice 下啟動，不能先開 socket 再搬 PID |
| service delegation | `Delegate=no` | `Delegate=no`，普通帳戶不能改父群組或 service 子群組 |
| 最後一個會話退出 | 回收該會話空子群組；父群組及共同規則保留 | systemd 回收 service；常駐父 slice 的身分及共同規則保留 |

會話內 `/proc/self/cgroup` 要和 systemd ControlGroup／bound hierarchy 一致，不能只核對路徑文字。`/proc/self/status` 中 UID 是目標帳戶，`CapPrm`／`CapEff`／`CapInh`／`CapAmb` 為零，`CapBnd` 與可信啟動器繼承上限一致，`NoNewPrivs=1`、`Seccomp=2`；`id -G` 只保留 primary group。核對普通帳戶無權寫 cgroup 控制檔及安裝目錄。[入場與權限實作](../lib/session.sh)

v2 還須核對 **socket 建立時的 cgroup**：在兩個受管 service 內各建立 TCP／UDP socket，以工作負載的 socket inode 對應 root 讀取的 `ss -e --cgroup` 結果，確認四個 inode 都屬於各自 service 的完整 cgroup 路徑。相同的 cgroup 欄位重複出現可以接受，未知或不同的路徑不能接受；只有 `/proc/PID/cgroup` 或 systemd 屬性一致不足以證明 socket 在入場後建立。[可執行核對](../tests/host_acceptance.py)及最新 CI 的代表性 artifacts 已保存這項證據。

分別測掛載／父群組 inode 替換、錯誤 slice unit 或 drop-in、模式／boot 身分不符，以及仍有 socket 時企圖重新綁定。預期拒絕新工作負載、保留原規則、不切換模式、不重建一個同名父群組來冒充舊身分。這些破壞性項目只在可回復 VM 執行。

## 3. 配置、有效配置與 ready／binding

先以 [共用解析器](../gateway-policy.jq) 對假配置做 policy／effective 檢查，再由**同一個固定映像**的核心檢查有效配置。所有 [公開範例](../examples/proxies/) 應逐一執行，不能只測 Hysteria2 和 HTTP。核心配置檢查不連線到假節點，也不證明認證或服務端 UDP 功能有效。

主機與容器需得到同一政策；原始及再次編譯的有效配置政策一致，effective canonical bytes 冪等。原始檔的 TLS、auth、headers、log 保留不變；僅受管 DNS 和真正直接撥號葉節點的 `bind_interface` 改變。`LOG_LEVEL` 不再覆寫 source。捕捉一般錯誤输出時不得包含假密碼、UUID、憑證或 header canary。

至少驗證以下拒絕案例，確認沒有可用的新 ready，且不執行工作負載：

- 缺少／重複／循環 outbound 引用、未知 transport／dialer 選項、native SOCKS UDP、無法承載 QUIC UDP 的 TCP-only detour、UDP-only final proxy。
- domain／IPv6 node、未知協議、direct／bridge／未管理 endpoints／services／API、remote ruleset、額外 DNS／route／inbound、外部 credential 檔案路徑。
- 無效 JSON、連續兩份 JSON、缺少 managed 欄位、舊版四行 binding、舊 ready marker、ready 欄位或雜湊被改動。
- 僅密碼、TLS 或 log 變更而端點不變；僅 parser 變更；effective runtime 被改動；生成／check 過程中 source 或 parser 變動。
- 同名容器被重建，container/network ID 或 network namespace 變更；主機綁定舊 namespace 而容器 ready 已來自新 namespace。

核心啟動前應是容器 INPUT／OUTPUT／FORWARD 的 DROP 政策，`ip_forward=0`；主機核對實際檔案、exact rules、路由、namespace 和版本 2 ready／binding 後才啟用 forwarding。`/entrypoint.sh --check` 應只使用暫存有效配置，不修改現存 runtime／ready，也不做網絡探測。[主機核對](../lib/network.sh)／[容器核對](../entrypoint-gateway.sh)

## 4. 協議、外層端點與 DNS

以 [協議矩陣](protocol-matrix.md) 列出的每個聲稱支援組合分開記錄結果。每組要測 TCP、實際提供的 UDP、DNS、代理出口 IP 和故障時不直連；只有配置解析或 `worker check` 的組合，狀態保留為「靜態適配／核心配置已檢查」。

外層端點證據至少包括：

| 組合 | 實體介面上應觀察到的本次受管流量 |
| --- | --- |
| Hysteria2 network:tcp | 節點 UDP；不能因內層 TCP 多放行節點 TCP |
| Shadowsocks 原生、UoT、multiplex | 分別驗證 native TCP／UDP 和封裝後只需 TCP 的差異 |
| Trojan／VMess／VLESS 的 http、ws、grpc、quic | 三種 TCP transport 與 QUIC UDP 分開驗證；HTTPUpgrade 必須在編譯時明確拒絕 |
| Hysteria 跳埠 | 只在正規化聯集內出站，測區間兩端、區間間隙和超出邊界的埠 |
| selector／urltest | 所有可能候選的端點；urltest 另有每個候選的健康探測需求，探測網站本身不能直連 |
| 多跳 detour | 只見真正最外層葉節點，不能直接連到內層 server；包括 UDP 經 UoT carrier 的組合 |
| HTTP／SSH／其他 TCP-only 最終出口 | DNS 使用經代理的 HTTPS，普通 UDP 失敗且不能回退到宿主實際出口 |

外層不一定加密，例如普通 HTTP CONNECT 或 SOCKS 控制流量；這類代理可能讓目的主機名出現在代理連線的協商中。判斷是否 DNS 直漏，要核對 socket 的外層目的 IP／協議／埠、實際 DNS 路徑及 payload，不能一律要求所有協議抓包都看不到任何網域文字。

DNS 測試對 localhost、8.8.8.8、內網 DNS 等目的地發送 TCP／UDP 53，確認都被 hijack 並經 proxy。能力保證 UDP 時有效上游為 UDP `1.1.1.1:53`；只保證 TCP 時為 HTTPS `1.1.1.1:443`、`/dns-query`、TLS server_name `cloudflare-dns.com`。1.1.1.1 不應取得外層直連 allow rule；混合候選群組以共同能力選 DNS，不能把其中某個候選的 UDP 能力當成全組保證。

使用可計數、可改 TTL 的受控 DNS fixture，測第一次查詢、跨 TCP／UDP 共用快取、到期重新查詢。HTTP fixture 必須驗證測試憑證而不是停用 TLS 驗證；負對照分別停用 cache 和移除 detour，要求對應斷言失敗。可執行的 loopback 合約見 [`tests/test_dns_runtime.py`](../tests/test_dns_runtime.py)：

```bash
python3 tests/test_dns_runtime.py --help
python3 tests/test_dns_runtime.py --engine /absolute/path/to/pinned-worker --proxy hysteria2
python3 tests/test_dns_runtime.py --engine /absolute/path/to/pinned-worker --proxy http
python3 tests/test_dns_runtime.py --engine /absolute/path/to/pinned-worker --proxy http --negative-control
python3 tests/test_dns_runtime.py --engine /absolute/path/to/pinned-worker --proxy http --negative-detour
```

先把範例中的 engine 路徑換成已核對版本的測試 binary。最後兩行是預期非零的負對照，不能當作整套測試失敗或以 `--check-only` 取代。loopback fixture 使用臨時服務、假認證及測試憑證；完整主機驗收仍需實際會話／防火牆／路由／封包證據。

更廣的成對協議測試由 [`tests/protocol_runtime.py`](../tests/protocol_runtime.py) 執行。初輪 47 組曾在固定核心各至少一次通過，三個 HTTPUpgrade 隨後因可靠性反例而拒絕；現行預設為 44 組。每組先做正式 policy／effective 編譯，再將 TUN、介面與 DNS 邊界替換為 loopback fixture。這些替換表示結果沒有執行正式主機的 cgroup、TUN 或 firewall 路徑。SSH 另需在私有 Python 環境安裝固定 Paramiko 3.5.1 依賴。可重跑：

```bash
python3 tests/protocol_runtime.py --list
python3 tests/protocol_runtime.py --engine /absolute/path/to/pinned-worker --check-only --artifacts /tmp/protocol-config-check
python3 tests/protocol_runtime.py --engine /absolute/path/to/pinned-worker --artifacts /tmp/protocol-runtime-check
```

`--artifacts` 必須指定尚不存在的私有目錄；`--check-only` 只產生配置結果，不能計作 runtime 通過。Hysteria1／2 跳埠各有實際兩個不同目的埠及既有 TCP stream 繼續轉發的證據，仍需另外驗證主機允許區間、間隙和越界埠。Snell4 使用 v4 client／v5 inbound；SSH 使用獨立 Paramiko server；ShadowTLS 1／2／3 使用內層 SS／UoT 和不發送 session ticket 的 TLS cover。後者保持憑證驗證，沒有修改固定核心。未測的 cipher、TLS／Reality、flow、cover 站點或 multiplex 組合不能沿用其他案例的狀態。[逐項協議範圍](protocol-matrix.md)

### 代理出口 IP 的獨立比對

[`tests/host_exit_ip.py`](../tests/host_exit_ip.py) 只接受已由測試 runner 明確建立的受控 fixture。先用 [`tests/host_upstream_fixture.py`](../tests/host_upstream_fixture.py) 的假認證配置完成 setup，再提供它的 root 私有輸出目錄與固定 namespace 名稱。工具核對 fixture 的 source 雜湊、systemd unit PID 與 network namespace 所有權；不會自動尋找或附著真實代理。以下路徑和帳戶須改成該次測試已建立的值：

```bash
sudo python3 tests/host_exit_ip.py --user testagent \
  --fixture-output /root/dev-session-validation/fixture \
  --upstream-namespace d8-test-upstream \
  --output /root/dev-session-validation/exit-ip
```

工具分別在已驗證的 fixture namespace 與受管工作負載查詢 HTTPS trace，將有效 IPv4 在記憶體中比較，核對工作負載／cgroup 身分、會話回收及原 binding 保留。公開結果記錄 IP family、是否一致及身分／清理檢查狀態，不輸出實際 IP 或原始 trace。同機 NAT fixture 的一致結果證明該指定測試路徑，不能當成遠端匿名性或生產代理已驗收。

## 5. 正常連線與故障阻斷

在宿主先開 IPv4 loopback TCP／UDP 測試服務。受管會話可使用不同埠、`127.0.0.1` 及 `127.0.0.2`，但目的埠 53 要被攔截。測公網 TCP／適用的 UDP、`curl --interface <實體介面>`，以及能力允許時的 SO_BINDTODEVICE／IP_UNICAST_IF。強制實體介面也不能直接出站；內網、link-local、組播、IPv6 公網與 `::1` 都應拒絕。

辨識受管流量時使用隔離測試帳戶、唯一目的 IP／port 或可對應的封包標記。宿主背景流量不會自動加入會話，不能將其算成洩漏，也不能讓背景查詢掩蓋受管 DNS 直出。

每個故障項目前先建立長連線，再測既有及新連線：

1. 只移除本工具 table 的 unicast default，保留 unreachable fallback。
2. 移除 TUN 的一條 `/1` 路由。
3. 阻斷所有正規化外層節點 IP：在已綁定 gateway namespace 的 OUTPUT 插入測試專用 DROP，避免 selector 切換到未阻斷候選；最後精確刪除這次新增的規則。
4. 將 `tun0` link down，再恢復 link up。
5. 插入、刪除或重排一條本工具規則，核對 exact-rule 檢查拒絕入場；這類完整性案例需按個別測試記錄，不因正常連線通過而視為已測。
6. 停止或終止 gateway core，並在獨立測試主機分開執行 container stop/start、kill/start、recreate 或 Docker daemon restart。會改變 namespace 的故障放在最後；後續不能自動恢復成可入場狀態。

PCAP 的開始必須由本次唯一 root canary 實際入檔證明，結束也要另有本次唯一末端 canary；重複的起始封包不能代替末端證據。對未加密 SOCKS5 UoT／VLESS，DNS 或 UDP marker 可以出現在精確允許的代理流內，測試須如實記錄可見性；這不允許其他外層端點、直連 DNS 或實體介面 workload 直連。DoH 及不支援 UDP 的出口仍不允許相應 marker。

故障期間抓實體介面，確認不使用原本的直連出口；既有及新受管外網連線應失敗或中斷，另一會話的 loopback 仍可用。抓包必須有能被觀察到的正對照，再核對受管直連數為零，並逐一比對真正的外層 IP／TCP 或 UDP／埠區間。HTTP 的普通 UDP 拒絕與 Hysteria2 的實際 UDP echo 必須分開判定。**不要以清空 mangle 或全機防火牆注入故障。**

同一 namespace 內的暫時故障只撤銷測試自己的精確變更，再由 `check` 核對原規則、路由與 binding。TUN down/up 在已測核心上會移除 `0.0.0.0/1` 和 `128.0.0.0/1`；harness 先保存兩條原路由及其餘 route snapshot，恢復 link 後只以 `ip route add` 補回缺失的原條目。若任一現存條目被改動、重複或其他路由改變，就拒絕復原；不能以 `replace`、重跑 `init` 或刪 binding 掩蓋問題。[故障與精確復原實作](../tests/host_acceptance.py)

`gateway-recreate` 只用於明確授權的 fresh Compose 測試專案，harness 需傳 `--compose-project repo --namespace-fault gateway-recreate`，其中 project 名稱必須與實際測試專案一致。它先核對 bound container ID／namespace、Compose labels、專案所有權、root 私有 Compose／source 檔案及 source 雜湊，再對單一 gateway service 執行 force-recreate。新 container ID 必須不同，映像與配置身分必須符合原測試，replacement ready 也要通過獨立核對。最新 Ubuntu 的 HTTP／Hysteria2 recreation jobs 已實際通過這些斷言；Debian 的這項故障仍未在本次矩陣執行。

namespace 變更後，`check`、`init` 和新 workload 入場都應拒絕，原 binding／共同 guards 保留。測試關閉自己建立的會話，記錄 `offline_rebind_required`，不刪 binding、不修 guards、不自動重新綁定。如果操作沒有改變任何身分、只有規則順序需人工修復，仍須先關閉全部會話才可 `session init`；若 container／network namespace 或配置身分改變，按 [離線重新綁定](offline-upgrade.md)。

## 6. 生命周期、CLI 與 GUI 回歸

- 在 A 啟動 `nohup`、double-fork、忽略 HUP／TERM 的程序，分別測正常 `exit` 和直接關閉 A 的終端。停止期限後 A 的 service／程序／會話子群組應消失，B 繼續工作；共同 D8 規則與父 cgroup 身分保留。
- 對外層 launcher 送 TERM、對 systemd-run 送 KILL，再分開測 launcher SIGKILL。若強制殺死 launcher 留下 unit，該 unit 必須仍受限，且 `session close ID` 可終止；這是已公開的限制，不能記成正常關閉通過。
- 同時啟動、退出及關閉 A/B/C，反覆執行短命令會話。核對 request／service 子群組無殘留，規則與 ip rules 的數量不隨會話數增長，v2 父 slice 不被清理。
- 故意讓 probe URL 不可用，確認測試 workload 的檔案副作用未發生，保存外層退出碼。Docker 未 ready、binding／配置身分錯誤、權限不可信時亦應如此；失敗後外層 shell 仍未受管。
- 驗證原 CLI、`--cwd`、字面參數、普通帳戶、root 工作負載拒絕、primary group、locale／timezone／umask、同帳戶桌面授權與跨帳戶不傳遞授權。
- 真實 PTY 驗證 Ctrl-C、Ctrl-Z／fg、resize、Unicode、readline 及退出後終端恢復。GUI 用獨立瀏覽器實例或 profile，證明程序實際在會話內，再檢查公共 IP／DNS／WebRTC；只開環境變數測試不能當作 X11／Wayland 視窗驗收。

生命週期 fixture 的 PID 檔案需要完整發布後才能使用，不能把「檔案已存在」當作內容已寫入。前一輪 Debian HTTP 在這個 harness 競態失敗；修正後會在原有有界期限內等待一行完整、帶換行的正整數 PID，並有強制先觀察空檔的回歸測試。最新 CI 的 Debian HTTP 已重新通過核心 16／16、生命週期 10／10 與 100 個短會話；這次修正沒有改動產品的工作負載清理邏輯。

## 7. 通過條件與公開證據

每個結果都需有命令、退出碼、對應版本、unit/cgroup 身分、規則／路由核對及必要的故障前後 packet capture。公開摘要移除節點密碼、私鑰、認證 headers、私人主機及部署資料。原始證據由 root 私下保存。

任何受管外網直出、身份失配後仍啟動工作負載、正常終端關閉留下未停止的工作程序，都應記為未通過。跳過項目要寫清原因；不能改成 unfiltered fallback，也不能以舊版結果、解析器通過或某個 HTTP 請求成功替代缺失的驗收。

12-job 基線 CI 的離線 discover 是 248 項中的 247 通過、1 跳過：當時尚未建置 worker，也未設定 `DEV_NETWORK_TEST_ENGINE`，所以真實 ELF 的 stdin-hold 回歸跳過。另有 25／25 inline helper 測試通過；後續真實容器／主機套件另行記錄，不能把 offline skip 記成通過。完整結果、代表性 artifact SHA-256 和已知限制見 [驗證摘要](VERIFICATION.md)。本次工作分支尚未合併 `main`，測試通過不代表已取得合併批准。

Ubuntu Focal 官方依據（文件依據不等於實機結果）：

- [systemd-run(1)](https://manpages.ubuntu.com/manpages/focal/man1/systemd-run.1.html)
- [systemd.kill(5)](https://manpages.ubuntu.com/manpages/focal/man5/systemd.kill.5.html)
- [systemd.exec(5)](https://manpages.ubuntu.com/manpages/focal/man5/systemd.exec.5.html)
