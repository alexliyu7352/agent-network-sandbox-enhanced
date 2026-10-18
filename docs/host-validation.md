> 本文件供目前版本重驗；含主機資訊的歷史原始日誌與封包擷取不隨公開版提供。

# Ubuntu 20.04 實機驗收程序

單一目錄版本的執行紀錄見 [host-acceptance-20261010.md](host-acceptance-20261010.md)，前版紀錄見 [host-acceptance-20261009.md](host-acceptance-20261009.md)。下列程序亦供不同 kernel、Docker 或宿主環境重驗；已測環境不代表所有版本都通過。

在有控制台、可回復的測試主機執行。請勿以離線單元測試代替此清單。

1. 記錄 kernel、systemd、Docker、iptables backend、cgroup mount。确认是 cgroup v1 `net_cls,net_prio`；不要為本工具盲目切換全機 backend。啟動失敗須無使用者程序被執行。
2. 安裝／啟動後執行 `dev-session init`，再啟動兩個會話 A/B。檢查 A/B 的 `/proc/self/cgroup` 分別位於自己的 systemd service 及 net_cls 子目錄。`/proc/self/status` 中 UID 應為目標帳號，`CapPrm`／`CapEff`／`CapInh`／`CapAmb` 為零，`CapBnd` 與可信啟動器繼承的上限相同，NoNewPrivs=1，Seccomp=2。`id -G` 只有 primary group。
3. 在外部宿主先開 IPv4 loopback TCP/UDP 測試服務，會話內可存取不同埠、`127.0.0.1` 及 `127.0.0.2`。目的埠 53 必須被攔截。驗證開發伺服器、Ctrl-C、Ctrl-Z／fg、視窗 resize、Unicode 輸入和 readline。
4. DNS 以 localhost、8.8.8.8、內網 DNS 地址為目的地測 TCP／UDP 53；抓包確認全部經網關，不流向原 DNS。實體介面僅能看見指定節點的外層 UDP，不能出現查詢域名或明文 DNS。若宿主有背景流量，使用隔離測試帳號和唯一的目的 IP／port 對照，勿把背景流量算成會話。
5. 測公網 TCP/UDP 以及 `curl --interface <實體介面>`、Python socket 的 SO_BINDTODEVICE／IP_UNICAST_IF（能力允許時）。任何強制實體介面路徑都不得直接出站。測內網、link-local、IPv6 公網與 `::1` 全部拒絕。
6. 先建立長連線，然後停止／kill 網關核心、Docker daemon restart、刪除網關 TUN 的一條 /1 路由，以及只刪除自有 table 的 unicast default（保留 unreachable）。逐項故障時測既有及新連線，捕獲物理網卡檢查直出。容器 stop/start 與路由復原後執行 `check`；daemon restart 若改變 hook 順序，應拒絕入場，全部會話關閉後才顯式 `init`，再驗證新會話 HTTPS。只在測試機做路由故障注入；不要清空 mangle 防護。
7. 在 A 內啟動 `nohup`／double-fork／忽略 HUP/TERM 的程序，正常 `exit` 及直接關閉 A 的終端視窗。最長停止期限後 A 的 service／程序／net_cls 子目錄應消失，B 繼續工作。確認清理沒有改變 D8 規則數。
8. 對 A 的外層入口送 TERM、對 systemd-run 送 KILL；驗證 wrapper 能停止 A。再單獨測 wrapper SIGKILL：若 unit 留存，應仍受限，且 `close ID` 可終止。這是已公開的強制中止限制，不能誤記成正常關閉通過。
9. 故意使 probe URL 不可用，確認 `run -- /usr/bin/touch /tmp/should-not-exist` 不執行命令，沒有殘留 unit。測 Docker 未 ready、錯誤政策、額外/重排規則、網關重建、root 配置權限變更同樣拒絕入場。保存外層退出碼；外層 shell 自身仍是未受管的。
10. 連續 100 次短命令會話，確認沒有殘留 request／net_cls 子目錄，D8 chains 與 ip rules 數量固定。並行啟動及关闭 A/B/C，驗證無交叉清理。

验收紀錄需要：每項命令、退出碼、unit/cgroup 結果、故障前後 packet capture 與版本。不要在紀錄公開節點密碼。任何直接出站或正常終端關閉殘留的結果都應視為未通過，不要改用 unfiltered fallback。

Ubuntu Focal 官方依據（已查閱，不等於實機測試）：

- https://manpages.ubuntu.com/manpages/focal/man1/systemd-run.1.html
- https://manpages.ubuntu.com/manpages/focal/man5/systemd.kill.5.html
- https://manpages.ubuntu.com/manpages/focal/man5/systemd.exec.5.html
