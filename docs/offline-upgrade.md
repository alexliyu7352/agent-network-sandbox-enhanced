# 離線升級、修改配置與重新綁定

本程序適用於升級舊版、修改已綁定的代理配置／解析器，以及容器或 Docker 網絡身分變更後的重新綁定。**「離線」指全部受管會話停止、沒有待啟動請求，並暫停啟動新會話。** 管理員仍可使用宿主原本的網絡下載程式與建立映像；不要在維護期間從普通外層終端直接運行 Agent。

以下命令以 `/opt/session` 為安裝目錄、`worker` 為 Compose 專案及服務名稱。由有 sudo 權限的管理員執行。Compose v1 使用者將 `docker compose` 換成 `docker-compose`。本文件是維護操作說明，不是程式會自動執行的遷移，也沒有新增 CLI 開關。

## 先分清楚修復與重新綁定

| 情況 | 處理方式 |
| --- | --- |
| 原 binding 身分、原始／有效配置及解析器全部相符，只是本工具規則順序或路由需要修復 | 全部會話關閉後可用 `session init`；仍不符合時保留限制並排查。 |
| 舊版四行 binding、舊版簡單 ready marker，或損壞／缺少欄位的狀態 | 新版明確拒絕；需離線升級，不能改一個版本號或自行補寫 ready 來通過。 |
| `network.json` 任意位元組變更 | 需離線重新綁定，包括認證、TLS、log、空白／JSON 格式、協議、跳埠及引用圖變更。 |
| `gateway-policy.jq` 更新 | 主機和映像內的解析器必須一起更新，並重新綁定。 |
| container ID、Docker network ID、bridge／地址或網絡 namespace 身分變更 | 需離線重新綁定。同名容器或同一 container ID 不保證 namespace 仍相同；restart 也可能觸發。 |
| cgroup 掛載、父群組身分、模式或開機身分不符 | 拒絕新會話並保留現有規則；不能在仍有 socket／程序時換模式。 |

新版主機 `/run/dev-session-v8/binding` 是 `format:2` 的 JSON，包含 cgroup 狀態、網關身分、正規化政策及三份 SHA-256。容器 `/run/worker/policy-ready` 也是 `format:2` 的 JSON，包含政策與原始設定、有效設定、解析器三份 SHA-256。主機還會獨立讀取容器內實際檔案、規則和路由，不能只放置一個 ready 檔案代替檢查。具體判斷見 [binding 檢查](../lib/host.sh)、[網關身分及檔案核對](../lib/network.sh) 與 [容器啟動器](../entrypoint-gateway.sh)。

## 1. 維護前備份與停止會話

先儲存所有工作，安排可中斷服務的維護時段。若準備使用下文的重啟路徑，確認有主機控制台或其他復原入口；整機重啟會中斷 SSH、桌面、其他容器和本機服務。

**更新程式前，先使用目前安裝版本的入口關閉會話。** 在 Agent 內正常退出，再從外層查看剩餘會話：

```bash
session status
```

對每個尚未停止的會話，使用實際顯示的 32 位 ID：

```bash
session close 0123456789abcdef0123456789abcdef
sudo systemctl list-units --all --plain --no-legend 'dev-session-*.service'
```

不要直接照抄範例 ID，也不要用廣泛的 `systemctl stop` 模式終止其他服務。確認沒有受管 workload、殘留 session unit 或待啟動 request；v2 模式下父 `devsession.slice` 保留是正常行為，不代表還有活躍會話。若已先換新版而 legacy binding 導致 cleanup 報錯，由 root 依實際 unit 身分停止及核對；新版 `session close ID` 會先要求 systemd 停止該 unit，再驗證 cleanup 身分，錯誤碼不能代替存活程序核對。

由 root 將原始 `network.json`、`policy.json`、本機 Compose 調整及需要回復的程式版本備份到另一個 `0700` 目錄，設定檔保持 `0600`。記錄已安裝提交及映像 ID。備份只供 root 查閱，不放進公開倉庫；日誌或診斷可能包含節點資料，也不要公開原始內容。**保留使用者原本的 TLS、認證及 log，不用公開假節點範例覆蓋真實設定。**

停止網關並確認結果：

```bash
sudo docker compose -p worker -f /opt/session/docker-compose.yml stop worker
sudo docker inspect -f '{{.State.Running}} {{.HostConfig.RestartPolicy.Name}}' worker
```

隨附 Compose 使用 `unless-stopped`；手動停止的容器不會因 Docker daemon 重啟而自動復活，見 [Docker restart policy](https://docs.docker.com/engine/containers/start-containers-automatically/)。若本機另有自動化工具替你執行 `up`／`start`，須在這個維護時段暫停該項自動啟動。不要停掉與本專案無關的自動化。

## 2. 更新程式並準備新配置

使用已審閱的發佈版本或提交，更新同一個 root 專用安裝目錄。不要為了方便更新而開放 `/opt/session` 的權限，也不要以 `git reset --hard` 清掉尚未妥善備份的私有設定。這個專案直接使用原目錄，不會另行複製安裝。

對照 [協議矩陣](protocol-matrix.md) 調整原始配置。新程式仍保留相同 CLI、普通帳戶工作目錄及 GUI／語言／時區／umask 行為。自動生成的有效設定只修改受管 DNS 和真正外層葉節點的 `bind_interface`，不修改原始 `network.json`，也不替你變更 TLS、認證或 log。`LOG_LEVEL` 環境變數不再覆寫 `log.level`，所以需要的日誌等級要寫在原始配置內。

只有升級發佈檔案且尚未恢復私有設定時，才以該版本的 `MANIFEST.sha256` 核對原版檔案；恢復真實節點後的 `network.json` 與公開範例雜湊不同是預期結果。發佈清單與運行時三份配置身分核對用途不同。

更新完成後執行：

```bash
sudo /opt/session/install-dev-session.sh --check
sudo /opt/session/install-dev-session.sh
sudo docker compose -p worker -f /opt/session/docker-compose.yml build worker
```

這時先不要啟動新會話。舊網關保持停止，binding 與共用防直連規則仍留在原處。建立新映像不會替正在運行的舊容器更新檔案；重新建立容器後也不能把舊 namespace binding 當成新容器的證據。

## 3. 通用重新綁定路徑：受控整機重啟

目前沒有一鍵遷移或卸載命令。若要在不逐條拆除既有核心政策的情況下清除本次開機的 session、socket、cgroup 及 runtime 狀態，**最穩妥的通用路徑是先完成上述關閉與備份，再由管理員重啟主機。**

重啟會中斷整台主機上的服務，必須由管理員安排。它不會刪除安裝目錄、Docker 映像或私有配置，也不應被當作本專案的自動故障恢復。先核對防火牆保存服務或自行撰寫的開機腳本，沒有把本工具的 D8 規則、table 32190、policy rule 或舊 runtime binding 恢復進新一次開機；若有，先由 root 只調整本工具那一部分的持久化設定，保留其他防火牆規則。

在工作已儲存、所有受管會話已關閉、舊網關已停止且可接受整機中斷後：

```bash
sudo systemctl reboot
```

一般 systemd 主機的 `/run` 是開機時清空的 runtime 檔案系統，見 [Ubuntu Focal file-hierarchy(7)](https://manpages.ubuntu.com/manpages/focal/man7/file-hierarchy.7.html)。本工具的 binding、request 及 v2 slice 定義放在 `/run`；不要把它們從備份還原。重啟也結束上一個核心中的 socket 和 cgroup 身分，讓後續初始化能重新選擇當次可用模式。

重新登入後，先核對沒有意外自動恢復的舊狀態：

```bash
sudo systemctl list-units --all --plain --no-legend 'dev-session-*.service'
sudo test ! -e /run/dev-session-v8/binding
sudo iptables-legacy -t mangle -S
sudo iptables-legacy -t nat -S
sudo ip6tables-legacy -t mangle -S
sudo ip -4 rule show
sudo ip -4 route show table 32190
```

`test` 成功時沒有輸出；table 尚不存在時，最後一行可能回報不存在。其餘命令是 root 的讀取檢查，輸出可能包含主機資料。預期沒有舊 D8 chains／hooks、priority 1190 的本工具 lookup、mark `0x6d730001`／table 32190 的本工具狀態。其他程式的規則與路由應保留。若有人持久化並恢復了本工具的舊狀態，或名稱／table 已由其他工具使用，先確認擁有者；不要清空整張表或整台防火牆來讓 `init` 通過。

## 4. 啟動新網關並建立新 binding

在舊 runtime 政策已退出且沒有會話的狀態下，明確建立新容器：

```bash
sudo docker compose -p worker -f /opt/session/docker-compose.yml up -d --force-recreate worker
sudo docker compose -p worker -f /opt/session/docker-compose.yml logs --tail=50 worker
sudo docker exec worker /entrypoint.sh --check
session init
session check
```

`--force-recreate` 只在這個重新綁定步驟使用，不要當作活躍會話的修復捷徑。新容器先建立自身 DROP 政策、驗證原始／有效配置及核心，再發佈版本 2 ready；`ip_forward` 維持關閉，直到主機完成獨立核對才啟用。`/entrypoint.sh --check` 使用暫存有效配置，不改寫既有 runtime 或 ready，不做外網連通探測；它不能替代實際啟動和主機檢查。

首次 `init` 依實際能力優先選 v1，再嘗試 v2。它只在保留名稱和路由資源未被佔用時建立新狀態；若拒絕，保留已建立的限制並排查，不刪 binding 強迫重試。v2 的父 slice 必須由程式在受管位置建立，不能自行補一個同名持久化 unit 或不同 drop-in 來繞過檢查。

`init`／`check` 只確認本機政策，沒有替你測試代理連通性。回到普通帳戶可讀寫的專案目錄，使用原本的入口做受管測試：

```bash
session -- /usr/bin/curl -q --noproxy '*' -4 --fail --show-error --connect-timeout 5 --max-time 15 https://www.cloudflare.com/cdn-cgi/trace
```

確認 `ip=` 是預期代理出口，再依 [實機驗收清單](host-validation.md) 驗證 DNS、適用的 UDP、實體介面端點及故障阻斷。只有 TCP 的出口會自動使用 HTTPS DNS；普通 UDP 不可用時不能增加直連放行補救。只有以上核對完成後才重新開啟日常 Agent／GUI 工作。

## 不能重啟時

無重啟遷移需要 root 先證明所有受管程序、socket 與待啟動請求已結束，再依實際規則快照，按正確順序只移除本工具的 hooks、chains、policy lookup、路由和 cgroup/runtime 狀態。v2 path 匹配持有群組身分，不能先刪父群組再移除引用它的規則；父 slice 的手動停止亦被程式刻意拒絕。

本專案目前沒有可通用套用的自動 teardown／rebind 工具。不能安排重啟時，應維持會話停止，讓管理員按該主機的實際狀態審閱專用維護步驟。**不要使用全機 `iptables -F`、整份空白 `iptables-restore`、`ip rule flush`，或只刪 `/run/dev-session-v8` 的方式遷移。** 僅刪磁碟上的狀態不會移除仍在核心中的規則、socket、cgroup 或 namespace 身分。

回退版本也遵守相同程序：保持會話停止、使用 root 專用備份恢復一致的程式／配置／映像組合，清除上次開機的 runtime 身分後重新初始化，再測試實際受管連線。不要把新版或舊版的 binding 互相複製使用。
