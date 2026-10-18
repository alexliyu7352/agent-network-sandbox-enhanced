> 公開版說明：以下為歷史技術／驗證紀錄，並非本次重新執行的測試。含主機資訊的原始日誌、封包擷取及測試輸出僅留在私人存檔，不隨公開版提供；代理設定已改為範例。歷史版本識別與流程描述僅供追溯，不代表公開版包含舊 Git 歷史。

# 單一目錄版本：AWS 實機驗收（2026-10-10）

透過 Remote Desktop Commander 在使用者授權的 AWS 測試 VPS 執行。正式程式基底為 GitHub commit `407b0df5998852dd23810491e50d0c98c0f3f8f3`，tree `5a4533c8736178415c7d93a564d2055edec46c0e`。本次新增簡短命令的實機驗收腳本與證據，沒有修改正式網路政策或節點設定。

## 環境與安裝

Ubuntu 20.04.6、kernel `5.15.0-1092-aws`、systemd `245.4-4ubuntu3.24+esm3`、Docker `26.1.3`、Compose `1.25.0`、iptables-legacy `1.8.4`、cgroup v1 `net_cls,net_prio`，核心 sing-box `1.14.2`。這台是 AWS Server 環境；本次沒有測試 Ubuntu Desktop 的 NetworkManager、其他 kernel 或宿主重開機。

VPS 沒有私有 GitHub 的 Git 憑證，因此使用包含上述真實 Git 歷史的 bundle 傳輸，核對 SHA-256 後 checkout，並把 origin 設回原 GitHub 倉庫。不是重新打包成另一套來源。安裝位置 `/opt/session`，`session` 捷徑指向同一份 `dev-session`。

實際執行 installer `--check`、正式安裝、Docker build、Compose 啟動與 `session init`。確認目錄 root:root `0700`，`network.json`／`policy.json` 為 `0600`；容器及映像名稱為 `worker`／`worker:1.14.2-v8`，根檔案系統唯讀，設定來源 `/opt/session/network.json` 以唯讀掛至 `/etc/worker/network.json`。已測正式檔案的 SHA-256 見 runtime-sha256.json（原始資料僅留私人存檔）。

開始時舊 V8 容器已停止、沒有受管會話。在核對舊政策完整相符且沒有 request／cgroup task 後，只撤銷它所擁有的 D8 hooks、chains 與路由，再初始化新網關。舊安裝、停止的舊容器及原始測試證據保留。沒有全域 flush，也沒有更換宿主預設網關。

## 真實網路測試拓撲

使用同一 VPS 內的獨立 network namespace 作為臨時 Hysteria2 伺服器。受管流量經宿主實際 netfilter、Docker 網關、真實 Hysteria2 client/server，再由測試伺服器訪問 Internet。精確的節點 `/32` 路由只在測試期間指向該 namespace。正式 `network.json` 位元組保持不變，包括 UDP DNS、快取容量 4096、節點資訊與原有 TLS 設定。

這驗證本機整合與故障阻斷；沒有驗證真實遠端節點的登入、身分或跨主機 WAN 品質。伺服器也在這台宿主，所以它解密後的 Internet 流量不能當成受管程序直出。封包檢查分別觀察 Docker bridge 上的外層 UDP，以及實體網卡上具指定來源埠的受管探測。

## 測試結果

| 項目 | 結果 |
|---|---|
| 完整回歸 | 79/79，零跳過，65.157 秒 |
| 核心網路驗收 | 15/15，包括 DNS 攔截、公網 HTTPS、loopback、強制指定實體介面、私有／link-local／IPv6 拒絕 |
| DNS 真實核心 | UDP／TCP 共用快取，TTL 到期重新查詢；關閉快取的負對照如預期在第二次上游查詢失敗 |
| 生命週期 | 11/11；真實 PTY、終端關閉、後代回收、三會話互不干擾與 Docker daemon restart 通過 |
| 100 次短會話 | 100/100，最多三路並行，163.443 秒；request／net_cls／unit 殘留 0，55 條政策不變 |
| 簡短指令與專用帳戶 | 9/9；真實 sudo caller、含空格的目前目錄、實體 cwd、`-u`、可選 `--cwd`、舊語法、權限拒絕與互動 PTY |

核心與生命週期測試使用本次建立的普通帳戶 `d8runner`（UID/GID 1001），沒有 sudo、docker 等附加群組。確認工作負載附加群組空、五個 capability 欄位全零、NoNewPrivs=1、Seccomp=2，且位於專屬 systemd 與 net_cls cgroup。沒有使用代理環境變數。

停止網關、SIGKILL 網關核心、移除自有策略表的可用 default（保留 unreachable）、移除網關的一條 TUN `/1` 路由時，既有／新連線均受阻；其他會話的允許 loopback 仍可用。錯誤 HTTPS probe、額外政策規則、可寫的 policy.json 均拒絕啟動 payload。每次故障測試後恢復原設定。

核心抓包取得 2 個正向對照封包、0 個受管直接外送封包、131 個指定節點外層 UDP 封包與 26 個改送至 `1.1.1.1` 的 DNS 封包，外層未出現明文測試查詢名。`IP_UNICAST_IF` 的 connect/send 成功不等於直接出站；判定依據是實際封包。pcap 與 tcpdump 的退出／丟包統計均保留於證據目錄。

生命週期的入口 SIGKILL、Docker restart 兩份實體介面抓包，也都各取得 2 個正向對照封包、0 個受管直接外送封包。完整生命週期執行 270.82 秒。簡短命令 suite 以真正的普通帳戶呼叫 sudo；互動 PTY 只執行 `sudo -n session`，沒有指定 user、run 或 cwd，確認回到呼叫者及原專案。另一個帳戶不能讀取 `/opt/session/network.json`；無權進入目前目錄時以 125 退出且不建立 payload 標記。

本次獨立審查另外修正了新增驗收腳本自身的失敗清理：timeout 仍保存 SID，PTY 等待有 TERM／KILL 期限，某個 SID 清理失敗也會繼續處理其他會話與暫存專案。這些是測試工具的修正，沒有放寬正式程式的安全檢查。

## 測試中觀察到的限制

- Remote Desktop Commander 的一般命令輸入輸出是 socket。直接用這種描述符啟動會話會被既有的 inherited-socket 檢查拒絕，退出 125；改由真正的 pipe／PTY 驗收。沒有移除或放寬這項檢查。
- Docker daemon restart 令 NAT hook 順序漂移，`check`／新會話以 125 拒絕；沒有執行 payload。測試先關閉所有會話，再明確 `init`，新 HTTPS 連線恢復。不是無縫自動復原。
- 入口被 SIGKILL 時 unit 可留存，但受限政策保持；需 `session close ID` 回收。一般 exit、TERM、終端關閉與 native relay KILL 則另外驗證自然清理。

## 重現

只在已授權、可丟棄的測試主機執行故障注入。fixture 目前沿用歷史 `/root/dev-session-acceptance-20261009` 暫存目錄；它是驗收工具，日常安裝不需要此目錄。`d8runner` 是事先建立的獨立普通測試帳戶。

```bash
sudo install -d -m 700 /root/dev-session-acceptance-20261009
sudo docker cp worker:/usr/local/bin/worker /root/dev-session-acceptance-20261009/worker
sudo chmod 700 /root/dev-session-acceptance-20261009/worker
sudo python3 /opt/session/tests/host_upstream_fixture.py setup
sudo session init
sudo python3 /opt/session/tests/host_acceptance.py --user d8runner --output /root/safe-network-test-20261010/core
sudo python3 /opt/session/tests/host_lifecycle.py --user d8runner --output /root/safe-network-test-20261010/lifecycle --repetitions 100
sudo python3 /opt/session/tests/host_cli.py --caller ubuntu --target d8runner --output /root/safe-network-test-20261010/cli
sudo python3 /opt/session/tests/host_upstream_fixture.py cleanup
```

各 suite 依序執行，避免不同故障測試互相干擾。完整 unittest 使用環境變數 `DEV_NETWORK_TEST_ENGINE=/root/dev-session-acceptance-20261009/worker`，確保真實執行檔測試沒有跳過。DNS 契約另執行 `tests/test_dns_runtime.py --engine /root/dev-session-acceptance-20261009/worker` 及 `--negative-control`。

## 證據與收尾

原始輸出、結果 JSON、pcap 與抓包統計保存在 evidence/20261010/（原始資料僅留私人存檔），歷史 2026-10-09 證據不覆蓋。匯出前逐檔檢查，未包含節點密碼。

cleanup.json（原始資料僅留私人存檔） 記錄先清除臨時 service、namespace、veth、精確 `/32` 路由、測試規則、憑證、核心副本與測試帳戶；closure-readback.json（原始資料僅留私人存檔） 接著確認傳輸目錄已移除，unit／request／net_cls 子目錄殘留皆為 0，`worker` 已停止，宿主 default route 不變。正式安裝與共用保護政策保留；VPS checkout 保持乾淨的受測 commit `407b0df`。新增 CLI 驗收腳本的原件移至 root 私有測試紀錄中，其 SHA-256 與此倉庫版本相同。

Remote Desktop Commander 的原始命令限制已恢復，另一次 `get_config` 讀回逐項相符，見 tool-restrictions.json（原始資料僅留私人存檔）。測試報告與新增驗收腳本是其後的倉庫提交；沒有宣稱 VPS 已切到這個只增加測試與文件的提交。

本工具仍有 README 所列的宿主 IPC、loopback 服務、同 UID 外部程序等信任邊界；這些通過的測試不構成完整惡意程式沙箱保證，也不能直接當作使用者桌面主機已驗收。
