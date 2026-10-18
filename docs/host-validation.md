# cgroup 與代理政策的實機驗收程序

本文件是目前版本的重驗清單，**不是宣稱所有項目已通過的結果表**。只在有控制台、可以回復、可接受網絡與服務中斷的測試主機執行。`tests/host_*.py` 會啟動會話、修改路由與規則，部分項目停止網關或重新啟動 Docker；不要直接在日常工作主機執行整套故障測試。

本次已在 Ubuntu 20.04 hybrid／v1 基線執行回歸，全部公開代理範例已通過真正 sing-box 1.14.2 的配置檢查。受控 Hysteria2／UDP DNS 與 HTTP CONNECT／驗證 TLS 的 HTTPS DNS fixture 已測跨 TCP／UDP 查詢快取、TTL 到期重新查詢、HTTP 普通 UDP 無直連回退；停用快取及移除 HTTPS DNS detour 的負對照按預期失敗。這些結果不代替完整實體網絡、所有協議／transport 或純 cgroup v2 的驗收；純 v2 實機／CI 證據仍待完成。具體版本、命令、測試數與跳過原因以當次證據文件為準。

歷史結果保留於 [驗證摘要](VERIFICATION.md)、[2026-10-10](host-acceptance-20261010.md) 與 [2026-10-09](host-acceptance-20261009.md)。歷史 Hysteria2 結果不能外推成所有新協議通過。

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
| Trojan／VMess／VLESS 的 http、ws、grpc、httpupgrade、quic | 四種 TCP transport 與 QUIC UDP 分開驗證 |
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

## 5. 正常連線與故障阻斷

在宿主先開 IPv4 loopback TCP／UDP 測試服務。受管會話可使用不同埠、`127.0.0.1` 及 `127.0.0.2`，但目的埠 53 要被攔截。測公網 TCP／適用的 UDP、`curl --interface <實體介面>`，以及能力允許時的 SO_BINDTODEVICE／IP_UNICAST_IF。強制實體介面也不能直接出站；內網、link-local、組播、IPv6 公網與 `::1` 都應拒絕。

辨識受管流量時使用隔離測試帳戶、唯一目的 IP／port 或可對應的封包標記。宿主背景流量不會自動加入會話，不能將其算成洩漏，也不能讓背景查詢掩蓋受管 DNS 直出。

每個故障項目前先建立長連線，再測既有及新連線：

1. 停止或終止 gateway core，或阻斷代理通道。
2. 容器 stop/start、recreate，以及 Docker daemon restart。
3. 移除 TUN 的一條 `/1` 路由。
4. 只移除本工具 table 的 unicast default，保留 unreachable fallback。
5. 插入、刪除或重排一條本工具規則，核對 exact-rule 檢查拒絕入場。

故障期間抓實體介面，確認不使用原本的直連出口；受管連線應失敗或中斷。**不要以清空 mangle 或全機防火牆注入故障。** 修復時，若綁定身分完全相同，全部會話關閉後才可 `session init`；若容器／網絡 namespace 或配置身分已變，按 [離線重新綁定](offline-upgrade.md)，不能把 restart 誤記成可無縫沿用舊 binding。

## 6. 生命周期、CLI 與 GUI 回歸

- 在 A 啟動 `nohup`、double-fork、忽略 HUP／TERM 的程序，分別測正常 `exit` 和直接關閉 A 的終端。停止期限後 A 的 service／程序／會話子群組應消失，B 繼續工作；共同 D8 規則與父 cgroup 身分保留。
- 對外層 launcher 送 TERM、對 systemd-run 送 KILL，再分開測 launcher SIGKILL。若強制殺死 launcher 留下 unit，該 unit 必須仍受限，且 `session close ID` 可終止；這是已公開的限制，不能記成正常關閉通過。
- 同時啟動、退出及關閉 A/B/C，反覆執行短命令會話。核對 request／service 子群組無殘留，規則與 ip rules 的數量不隨會話數增長，v2 父 slice 不被清理。
- 故意讓 probe URL 不可用，確認測試 workload 的檔案副作用未發生，保存外層退出碼。Docker 未 ready、binding／配置身分錯誤、權限不可信時亦應如此；失敗後外層 shell 仍未受管。
- 驗證原 CLI、`--cwd`、字面參數、普通帳戶、root 工作負載拒絕、primary group、locale／timezone／umask、同帳戶桌面授權與跨帳戶不傳遞授權。
- 真實 PTY 驗證 Ctrl-C、Ctrl-Z／fg、resize、Unicode、readline 及退出後終端恢復。GUI 用獨立瀏覽器實例或 profile，證明程序實際在會話內，再檢查公共 IP／DNS／WebRTC；只開環境變數測試不能當作 X11／Wayland 視窗驗收。

## 7. 通過條件與公開證據

每個結果都需有命令、退出碼、對應版本、unit/cgroup 身分、規則／路由核對及必要的故障前後 packet capture。公開摘要移除節點密碼、私鑰、認證 headers、私人主機及部署資料。原始證據由 root 私下保存。

任何受管外網直出、身份失配後仍啟動工作負載、正常終端關閉留下未停止的工作程序，都應記為未通過。跳過項目要寫清原因；不能改成 unfiltered fallback，也不能以舊版結果、解析器通過或某個 HTTP 請求成功替代缺失的驗收。

Ubuntu Focal 官方依據（文件依據不等於實機結果）：

- [systemd-run(1)](https://manpages.ubuntu.com/manpages/focal/man1/systemd-run.1.html)
- [systemd.kill(5)](https://manpages.ubuntu.com/manpages/focal/man5/systemd.kill.5.html)
- [systemd.exec(5)](https://manpages.ubuntu.com/manpages/focal/man5/systemd.exec.5.html)
