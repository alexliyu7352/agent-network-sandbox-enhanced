# cgroup／代理自動適配：2026-10-18 驗證紀錄

本頁只記錄本次實際執行的結果。配置解析、核心配置檢查、真實代理傳輸、完整主機故障驗收是不同層次；任何一層通過都不能代替其餘層。

## 可重現的版本與環境

- 原始基準：`aac516d650a8150282b3a96633af6f5f7d7830d7`。
- 首個整合 checkpoint：`616943ce46999c17066a6b3be4db8acf8993fc0d`，Git tree `c0b50a065d421f16c44681e314bd1a68f3f5d180`。
- VPS：Ubuntu 20.04.6、Linux 5.15.0-1117-aws、systemd 245、Docker 26.1.3、legacy iptables 1.8.4；cgroup v1／v2 混合掛載。
- 核心：官方 sing-box 1.14.2，提交 `af6e64c3b69e6132ebaee0e1a3d24e93903f6709`，`linux/amd64`。映像內的實際 ELF 名稱為 `worker`；測試執行檔從已存在的映像複製，未重編譯核心。
- 原生偵測使用實際可寫 net_cls 及兩個 IP family 的獨立未掛接測試鏈，結果為 `v1`、`/sys/fs/cgroup/net_cls,net_prio`、`name=systemd`。沒有改動控制器掛載或開機參數。

測試配置使用文件保留地址與假認證。公開報告不附生產節點、密碼、主機出口 IP 或可能含私人流量的原始 pcap。

## 已執行的檢查

| 層次 | 實際結果 | 能證明的範圍 |
| --- | --- | --- |
| 原始版本 VPS 回歸 | 127 項，126 通過、1 跳過 | 建立同一主機的舊版基準。 |
| 首個整合 checkpoint VPS 完整回歸 | 198 項，197 通過、1 跳過 | 含真實 root 私有安裝測試；沒有 assertion failure。唯一跳過是未以環境變數指定核心路徑的選用二進位身分測試。 |
| 整合修正後 VPS 完整回歸 | 201／201 通過，零跳過 | 包含真實核心身分檢查、binding 單一物件、路由表別名與容器 default route 格式回歸；此輪尚未包含最後三個代理圖測試。 |
| 同 checkpoint 本機回歸 | 198 項，183 通過、13 環境錯誤、2 跳過 | 13 個錯誤全部是安裝測試無法在本機唯讀 `/root` 建立 fixture；這些項目已在 VPS 通過。 |
| 公開配置 | 24／24 | 兩個 jq 模式可編譯且有效配置冪等；全部通過 VPS 的固定核心 `worker check`。尚不能據此宣稱每種協議都已實測轉發。 |
| 真實 Hysteria2 DNS | 通過 | UDP DNS 經本機真實 Hysteria2 連線，UDP／TCP 查詢共用快取，TTL 到期會再次請求上游。 |
| 真實 HTTP CONNECT DNS | 通過 | 認證後的 CONNECT 承載經憑證驗證的 HTTPS DNS；UDP／TCP 查詢共用快取，TTL 重新查詢，普通 UDP 沒有 direct fallback。 |
| DNS 反向測試 | 按預期失敗 | 關閉快取後觀察到第二次上游請求；去除 DNS detour 後首個查詢逾時。測試可以偵測其聲稱保護的行為。 |
| 真實容器本機政策＋主機獨立核對 | 通過 | 最少 capabilities、唯讀根目錄與設定掛載下，真實 TUN、完整有序規則、節點路由及三份配置雜湊可被兩端獨立確認。此步保持容器 forwarding 關閉，尚未宣稱 workload 轉發成功。 |
| 最後代理圖修正的本機回歸 | 33／33 通過 | 包含 URLTest 的 TCP 探測能力拒絕及共享下層圖的執行時間上限回歸；50 節點共享圖實測約 0.020 秒。 |

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

## 整合時修正的問題

1. legacy iptables 回讀可能將 `ESTABLISHED,RELATED` 寫成 `RELATED,ESTABLISHED`。兩端現在只正規化該等價值，仍保留整條規則的先後次序核對。
2. `ip -j` 可能把路由表 ID 顯示成 `rt_tables` 別名。涉及表身分的讀回使用 numeric 輸出，避免誤判外部表為空閒；按數字選表的路由細節仍保留 `scope:link` 語義。
3. 多份串接 JSON binding 不得只取第一份。binding 必須恰好是一份完整物件，否則在載入 cgroup 前拒絕。
4. VPS 的映像內 iproute2 在 `route show default dev eth0` 回讀中省略 `.dev`。容器改讀完整 default 集合，再驗證只有一條且明確屬於 eth0；沒有放寬 gateway 條件。
5. URLTest 即使被當成 UDP 承載路徑，仍會對候選建立 TCP 健康探測。解析器現在明確拒絕不保證 TCP 的候選路徑，避免接受後才由封鎖規則阻止必要探測；探測候選也不能直接使用 ShadowTLS 包裝，經正常代理的 ShadowTLS detour 則保留。
6. 多層 selector 共用下層節點時，遞迴列舉可能隨路徑數急遽增加。改用拓撲排序、每節點能力快取與合併需求，保留循環、深度及相容性檢查。

上述問題均先以針對性測試重現失敗，再修正並重跑。default route 問題同時在真實 Docker 容器重現，修正後容器與主機獨立核對均通過。

## 接受範圍與後續證據

Ubuntu 26.04 純 v2、另一發行版的新 systemd，以及完整主機轉發／連續連線故障矩陣的結果仍須補入本頁。提供驗收程式或 CI 設定不等於已執行成功。

容器停止／重建／daemon restart 若改變 namespace 身分，預期行為是保留 binding 和共用封鎖、拒絕新會話，關閉既有會話後依[離線升級流程](offline-upgrade.md)處理。不能將直接刪掉 binding 後重新啟動記作故障恢復通過。

任何合併仍須由使用者審閱最終測試結果後明確同意；本次提交只位於工作分支。
