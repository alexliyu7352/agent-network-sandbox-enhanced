> 公開版說明：以下為歷史技術／驗證紀錄，並非本次重新執行的測試。含主機資訊的原始日誌、封包擷取及測試輸出僅留在私人存檔，不隨公開版提供；代理設定已改為範例。歷史版本識別與流程描述僅供追溯，不代表公開版包含舊 Git 歷史。

# Ubuntu 20.04 實機驗收 — 2026-10-09

本次使用使用者提供的 AWS 測試機及自行建立的 Hysteria2 節點。測試節點建立在同一台機器的獨立 network namespace，沒有新增 AWS instance。核心網絡 15/15、生命週期 11/11、完整回歸 65/65，以及 100 次短會話均通過。此結論限於本文記錄的環境、測試項目與信任邊界。

## 環境與測試節點

Ubuntu 20.04.6、kernel `5.15.0-1092-aws`、systemd `245.4-4ubuntu3.24+esm1`、Docker `26.1.3`、Compose `1.25.0`、iptables-legacy `1.8.4`、cgroup v1 `net_cls,net_prio`，sing-box `1.14.2`。kernel 5.4 沒有在本次測試。

會話流量經宿主 D8 政策、Docker 網關、真正的 Hysteria2 client/server，再由測試節點連到 Internet。測試節點使用獨立 veth/NAT；一條精確的宿主 /32 route 將原配置中的節點 IP 暫時指向它。正式 `network.json`、Compose、Dockerfile、網關程式與節點密碼均未修改。測試使用原本已有的 `tls.insecure=true` 配置，不代表已驗證遠端節點身分。

因測試伺服器也在此宿主，實體介面會看見**測試伺服器**解密後向 Internet 的連線，不能將它們誤認為會話直出。驗收分別觀察 Docker bridge 上網關的外送流量，以及實體介面上具有指定 source port 的會話強制直出探測。此拓撲驗證實際 netfilter、systemd、Docker 和 Hysteria2 整合，沒有驗證跨主機 WAN 延遲、丟包或真實遠端節點。

## 實際發現並修正

1. Focal 的 mawk 不會把十六進位字串自動轉成數字，導致合法 cgroup 規則被判錯。改為明確解析十六進位，仍核對規則順序。
2. Focal setpriv 的 `-all` 遇到較新 kernel capability 編號會拒絕執行。改為依 `cap_last_cap` 列舉全部數字編號；實機五個 Cap 欄位均為零。
3. Focal coreutils 的 stat 不支援 `%r`。內外 PTY 身分統一使用 `%d:%i:%t:%T`，測試仍拒絕重用外層 slave。
4. systemd 245 的 ExecStopPost 可能在最後 KILL 後代之前執行。由入口及 `close` 在 stop 完成後回收空目錄，容忍另一方已移除目錄的競態；只對「仍有 task」最多檢查 40 次、間隔 50ms（約兩秒）。真正錯誤仍失敗，不刪非空 cgroup，也不改共用防火牆。

Docker daemon restart 插入 NAT 規則，令 D8SNAT 不再是首條 hook，屬於正確拒絕的政策漂移。沒有為了恢復連線放寬驗證或加入常駐修復程序；全部會話關閉後顯式 `init` 才恢復。

## 驗證紀錄

| 項目 | 已取得結果 |
|---|---|
| 完整回歸測試 | 65/65，零跳過，81.874 秒 |
| 真實 DNS/Hysteria2 契約 | TCP/UDP 共用快取、TTL 到期重查均通過；停用快取的負對照按預期失敗 |
| 普通使用者邊界 | UID/GID 1000，附加群組空，五項 Cap=0，NoNewPrivs=1，Seccomp=2；無 proxy 環境變數 |
| 宿主 loopback | 127.0.0.1 與 127.0.0.2 的 TCP/UDP 服務可用；53 埠被攔截 |
| DNS 攔截 | TCP/UDP × 127.0.0.1、127.0.0.53、8.8.8.8、10.0.0.53，全部改經網關 |
| 網關停止、核心 SIGKILL、兩種路由刪除 | 既有／新連線受阻、B 的 loopback 存活、入場失敗不執行 payload；最終抓包受管直出為 0 |
| 私有／link-local IPv4 | 172.16/12、169.254/16、10/8 的連線失敗，並各核對到 DROP counter 增加 |
| IPv6 | ::1 與公網 IPv6 socket 均 EAFNOSUPPORT；不把宿主未受管流量算入會話政策 |
| 真實 PTY | 中文、readline 刪改、Ctrl-C、Ctrl-Z/fg、31×97 resize、exit 及關閉 PTY master 通過 |
| 後代回收 | nohup、double-fork、忽略 HUP/TERM 程序回收；TERM、native relay KILL、explicit close 競態通過 |
| 入口 SIGKILL | unit 實際留存，限制維持、無測試流量直出；explicit close 可回收頑固後代 |
| Docker daemon restart | 三路並行探測既有 TLS socket／新 HTTPS／強制介面；實體直出 0；check/run 125；全部關閉後 init 與新 HTTPS 成功 |
| 同時存在的 A/B/C | 三個均 READY、不同 SID，依 B/A/C 關閉，其他會話持續工作 |
| 100 次短會話 | 100/100，164.507 秒，殘留 request/net_cls/unit 為零；55 條政策不變。最多三個工作執行緒，不宣稱 100 個同時存活 |

抓包使用 immediate mode、正常退出和零 kernel drop 檢查。實體介面捕獲開始及結束的 root 正向對照（source port 21000）；受管探測使用 21001–21199。三份實體介面抓包均 captured=received=2（兩個正向對照），受管直出封包為零。核心測試另捕獲 132 個指定節點外層 UDP 封包及 30 個改送 1.1.1.1 的 DNS 封包；外層無明文測試查詢名。Docker bridge 的外送檢查排除實際宿主地址與本地回應，不能把反向 NAT 的回包當外洩。`IP_UNICAST_IF` 的 connect/send 成功本身也不代表直出：TUN 可先完成本地握手，判定依據是實際封包。

獨立 reviewer 只讀 source 與本地 mock，指出並修正了 DNS wire-format、HTTP 自動重連、抓包起訖／退出／丟包、非自然退出被清理補救掩蓋、以及 Docker 新舊連線探測序列化等驗收缺口。它沒有操作遠端；實機結果由本次執行紀錄支持。

最後 source review 沒有未解決的 Critical／Important 阻塞項，見 [host-review.md](host-review.md)。

## 重現方式

僅在可丟棄、已安裝本版及相依套件的 rootful Docker 測試機使用。額外測試依賴為 Python 3、tcpdump、openssl。以下路徑與 fixture 程式的固定測試目錄一致，原節點需為不投入使用的測試配置；腳本不會替真實遠端驗證憑證。

```bash
sudo install -d -m 700 /root/dev-session-acceptance-20261009
sudo docker cp dev-network:/usr/local/bin/net-worker /root/dev-session-acceptance-20261009/net-worker
sudo chmod 700 /root/dev-session-acceptance-20261009/net-worker
sudo python3 /root/dev-session-v8/tests/host_upstream_fixture.py setup
sudo /opt/dev-session/dev-session init
sudo python3 /root/dev-session-v8/tests/host_acceptance.py
sudo python3 /root/dev-session-v8/tests/host_lifecycle.py
sudo python3 /root/dev-session-v8/tests/host_upstream_fixture.py cleanup
sudo rm -f /root/dev-session-acceptance-20261009/fixture-key.pem /root/dev-session-acceptance-20261009/fixture-cert.pem /root/dev-session-acceptance-20261009/fixture-server.json
```

實機 full suite 使用 `DEV_NETWORK_TEST_ENGINE=/root/dev-session-acceptance-20261009/net-worker python3 -m unittest discover -s tests -p 'test_*.py' -v`。DNS 契約使用 `tests/test_dns_runtime.py --engine /root/dev-session-acceptance-20261009/net-worker`；另加 `--negative-control` 應在第二次查詢發現上游次數為 2，並以非零退出。

## 證據與收尾

evidence/（原始資料僅留私人存檔） 保留原始結果 JSON、完整測試輸出、pcap、tcpdump 統計、實機版本及已安裝 runtime 雜湊；早期失敗紀錄保留作為修復證據。正式套件 runtime 與已測安裝逐檔 SHA-256 相同；驗收日誌未包含節點密碼。

cleanup.json（原始資料僅留私人存檔） 與 closure-readback.json（原始資料僅留私人存檔） 記錄收尾：臨時 service、namespace、veth、精確 /32 route、三條測試規則、測試憑證及傳輸目錄已移除，unit/request/net_cls 子目錄殘留為零。測試網關容器已停止；正式安裝、Docker 及 55 條共用保護保留。遠端操作工具原本的命令限制已恢復，控制連線仍可用。正式使用仍需配置存在的遠端節點。

## 邊界

這不是完整惡意程式沙箱，無法對受信任宿主 IPC／loopback 服務代為執行、同 UID 外部程序、root 修改防護、kernel 漏洞或硬體故障提供絕對保證。正常受管程序的測試結果也不能概括所有 kernel 或所有斷線時序。入口 SIGKILL 仍需要管理員 `close`，不是正常關閉自動回收的通過案例。

Python 僅是可移除的測試工具；日常會話仍為 Bash、setpriv、systemd-run 原生 PTY 及 Docker 網關。
