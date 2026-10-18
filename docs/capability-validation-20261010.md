> 公開版說明：以下為歷史技術／驗證紀錄，並非本次重新執行的測試。含主機資訊的原始日誌、封包擷取及測試輸出僅留在私人存檔，不隨公開版提供；代理設定已改為範例。歷史版本識別與流程描述僅供追溯，不代表公開版包含舊 Git 歷史。

# 2026-10-10：繼承能力上限相容性驗證

本次同一 VPS 上的能力驗證 11／11、核心實機驗證 15／15、CLI 實機驗證 9／9，以及 unittest 88／88（零跳過）均通過。完整安裝版 launcher 可啟動帶有 `cap_net_raw=ep` 的測試執行檔，同時維持非 root 身分、零可用能力、`NoNewPrivs=1` 與 `Seccomp=2`。

## 變更範圍與版本

- 程式基底為原倉庫提交 `6669c074e5e4bc66604044848d51c9cfe92bb2ae`；本次部署候選為本地提交 `9f6c78188f8c2cddf4af0cc7598b35ea5e503950`。
- 相對上述基底，執行期程式變更集中在 [`lib/session.sh`](../lib/session.sh)：保留原先繼承的 `CapBnd`，並將該值傳入降權後的驗證程序，要求完整、相同的 16 位小寫十六進位遮罩。
- 降權後仍要求四個 UID 欄位均等於目標非 root UID，且 `CapPrm`、`CapEff`、`CapInh`、`CapAmb` 全為零，`NoNewPrivs=1`、`Seccomp=2`；不符時拒絕啟動工作負載。
- Bash helper 現在用內建 `read` 直接讀取自己的 `/proc/self/status`，修正原先 `$(cat /proc/self/status)` 實際讀到子程序狀態的問題。
- cgroup 附掛順序、受限位址族及既有網路限制未變更。既有歷史驗收報告原樣保留。

部署紀錄（原始資料僅留私人存檔）保存候選提交、檔案雜湊及當時的安裝結果。本報告以該候選快照與其 `runtime_sha256` 識別實際受測內容。

本次受測 `lib/session.sh` 的 SHA-256：

```text
83560875958e0c46d0c7b30878111c89b1a8cc2a7bb5c7a899e617e1bb7eea2c
```

## 環境與部署

驗證沿用原 VPS 的 Ubuntu 20.04／Focal 環境，沒有更換核心或工具鏈；能力測試使用既有 `ubuntu`（UID 1000），核心與 CLI 驗證沿用既有 `ubuntu`／`nobody` 帳戶。

| 項目 | 受測環境 |
| --- | --- |
| 核心 | `5.15.0-1092-aws` |
| setpriv | util-linux `2.34` |
| systemd | `245`，套件 `245.4-4ubuntu3.24+esm3` |
| Python | `3.8.10` |
| Docker | `26.1.3` |

更新前基線（原始資料僅留私人存檔）記錄原 VPS 提交 `407b0df5998852dd23810491e50d0c98c0f3f8f3`、工具版本及設定檔雜湊。部署紀錄（原始資料僅留私人存檔）確認安裝前檢查、安裝器及 manifest 校驗均通過，部署當時工作樹乾淨；`network.json` 與 `policy.json` 的位元組內容保持不變。

## 能力驗證：11／11 通過

使用 [`tests/host_capabilities.py`](../tests/host_capabilities.py) 驗證完整安裝版 launcher。測試 fixture 為實際 `/bin/cat` ELF 的副本，設為 root 擁有、目標 GID 1000、模式 `0550`，加上 `cap_net_raw=ep`；其父目錄為 root 擁有、模式 `0710`。該副本只讀取自己的 `/proc/self/status`。

| 檢查 | 實際結果 |
| --- | --- |
| 零 bounding set 負對照 | 以 `setpriv` 降至目標 UID/GID、清除附加群組及 B/I/A、設定 NNP 後，執行同一 fixture 回傳 `126`；錯誤為 `failed to execute … Operation not permitted`。 |
| 完整 launcher | 回傳 `0`，取得唯一的 payload JSON。 |
| 工作負載 UID | 四欄均為 `1000`。 |
| 工作負載 P/E/I/A | 四組均為 `0000000000000000`。 |
| 工作負載限制 | `NoNewPrivs=1`、`Seccomp=2`。 |
| 繼承的 bounding set | `000001ffffffffff`，非零且包含 `CAP_NET_RAW`。 |
| 帶 file capability 的 cat | 執行回傳 `0`；子程序四個 UID、P/E/I/A、NNP、seccomp 與上述要求相符，`CapBnd` 完全相同。 |
| raw socket | 嘗試建立 `AF_INET / SOCK_RAW / IPPROTO_ICMP` 失敗，`errno=1`（`EPERM`）。 |
| `/bin/ping -V` | 回傳 `0`，版本為 `iputils s20190709`；實際檔案帶有 `cap_net_raw+ep`。 |
| 經 PATH 執行 sysctl | `sysctl -n kernel.ostype` 回傳 `0`，輸出 `Linux`。 |
| 清理 | 本次 fixture 與本次會話均已清理，錯誤列表為空。 |

完整欄位、檔案屬性及各項布林結果見能力驗證原始 JSON（原始資料僅留私人存檔）。`ping -V` 只驗證執行檔可啟動；raw socket 測試沒有送出封包。本報告不主張 ICMP 封包可送達。

## 自動化測試

| 執行位置 | unittest 日誌結果 | 跳過情形 |
| --- | --- | --- |
| 同一 VPS 日誌（原始資料僅留私人存檔） | `Ran 88 tests in 63.697s`，`OK` | 0 項 |
| 本地日誌（原始資料僅留私人存檔） | `Ran 88 tests in 33.393s`，`OK (skipped=2)` | 普通使用者 UID 對映、實際網路核心執行檔兩項環境相依測試 |

上述項目數與耗時依本次 unittest 執行日誌記錄。VPS 執行彙總（原始資料僅留私人存檔）另記錄程序回傳 `0`，外層計時 `63.987` 秒；外層計時與 unittest 自身計時分開列示。

## 核心與 CLI 實機驗證：已完成

| 套件 | 結果 | 外層耗時／回傳值 |
| --- | --- | --- |
| 核心主機驗證（原始資料僅留私人存檔） | 15／15 通過 | 50.655 秒／0（原始資料僅留私人存檔） |
| CLI 主機驗證（原始資料僅留私人存檔） | 9／9 通過 | 18.727 秒／0（原始資料僅留私人存檔） |

核心驗證包含雙會話身分、主機 loopback TCP／UDP、HTTPS、各指定目的地的 TCP／UDP DNS 重新導向，以及私有位址、IPv6 與提權拒絕。網關停止、網關核心程序終止、宿主自有策略表 `32190` 的可用 default 路由移除（保留 unreachable），以及網關 TUN 的一條 `/1` 路由移除時，既有與新外連均受阻，另一會話的 loopback 仍可用。probe 失敗、額外政策規則及可寫政策檔均以 `125` 阻止 payload 執行。

CLI 驗證涵蓋預設呼叫者、實際工作目錄、`-u nobody`、明確 `--cwd`、舊語法及真實 PTY 的裸 `sudo session`；不可進入的目錄、可繼承 socket 標準輸入輸出會阻止 payload，目標帳戶亦無法讀取 root 私有設定。

指定測試流量的封包觀測如下；強制介面嘗試的判定同時使用封包擷取結果，沒有將 `connect()` 成功直接視為可繞過限制。

| 觀測項目 | 結果 |
| --- | --- |
| 實體介面正對照封包 | 2 |
| 實體介面上指定的直連工作負載封包 | 0 |
| Hysteria2 外層 UDP 封包 | 127 |
| 重新導向的 DNS 封包 | 26 |

原始擷取：實體介面（原始資料僅留私人存檔）、網關外層（原始資料僅留私人存檔）、重新導向 DNS（原始資料僅留私人存檔）。外層擷取未出現本次明文 DNS 測試查詢名；共同規則快照的 55 行保持相同，詳見上述核心結果 JSON。

## 清理與復原

清理紀錄（原始資料僅留私人存檔）確認已核對本次產生的 13 個會話 ID，殘留 session units、requests 與 net_cls 群組各為 0。fixture 檔案、狀態、network namespace、veth 及臨時規則均已移除。

`worker` 與 `dev-network` 容器均回到基線的 `exited` 狀態；主機預設路由與設定檔位元組和原基線一致。

## 本輪驗證範圍

- 本次實機環境為上述 Focal／核心 `5.15.0-1092-aws` VPS；上游使用本地 Hysteria2 fixture。真實 WAN 節點與使用者桌面未在本輪重測。
- `ping -V` 僅驗證執行檔啟動，未驗證 ICMP 傳輸或送達。
- 本輪未重跑 100 輪壓力迴圈、完整生命週期矩陣或 Docker daemon 重新啟動驗證；已完成的網關與路由故障案例以上述核心證據為準。
