> 公開版說明：以下為歷史技術／驗證紀錄，並非本次重新執行的測試。含主機資訊的原始日誌、封包擷取及測試輸出僅留在私人存檔，不隨公開版提供；代理設定已改為範例。歷史版本識別與流程描述僅供追溯，不代表公開版包含舊 Git 歷史。

# 單一目錄與簡短命令驗證（2026-10-10）

這份文件保留最初離線驗證的範圍。其後已在使用者授權的 AWS VPS 執行真實安裝、Docker、cgroup、DNS 與會話驗收，見 [實機報告](host-acceptance-20261010.md)；當時跳過的兩項測試也已在 VPS 通過。

基底：GitHub `master` 的 `08d7bb495743ae5572b71802a5e05210d529e862`。本地檔案逐一比對 Git blob SHA，基底 tree 為 `950e69c19f810e641142f4c4c17802e8326de323`；保留倉庫中已上傳的修改，再進行本次調整。

## 改動

- Git checkout 原地安裝，建議 `/opt/session`；不另複製一套程式。目錄 root:root `0700`，設定 `0600`，其他檔案移除群組及其他帳戶存取權限。
- `/usr/local/bin/session` 只有符號連結，可用 `--no-link` 省略；既有不同目標拒絕覆蓋。
- `sudo session` 使用經驗證的 `SUDO_UID` 帳戶及真實目前目錄；支援 `-u`、可選 `--cwd` 和舊語法。root 工作負載拒絕。
- 控制程式檢查路徑信任；正式降權後先進入工作目錄，失敗時不執行連線測試或工作負載。
- service／container／image／容器執行檔改為 worker；核心執行檔改名放在 Docker build 階段。修正已上傳入口向唯讀 `/etc`、`/sbin` 複製檔案的啟動失敗。
- Compose 使用相對設定掛載，補回 `.dockerignore` allowlist，節點與 Git 歷史不進入映像建置內容。
- `network.json` 位元組不變：UDP DNS、cache capacity 4096、節點與 TLS 設定保留。主機網路規則不变，僅同步網關 readiness 路徑／標記名稱。

## 已執行

```bash
python3 -m unittest discover -s tests -v
```

結果：**79 項，77 通過，2 明確跳過，0 失敗**。

實際在隔離的 root 私有測試目錄執行原地安裝／重複安裝、唯讀 `--check`、權限收緊、拒絕可寫／符號連結／硬連結檔案，以及透過捷徑執行真正入口與主程式。會話啟動測試在主機操作邊界停止，未修改 Docker、systemd 或防火牆。

CLI 測試涵蓋 caller UID、指定普通帳戶、目前目錄、舊語法、字串原樣傳遞、root／缺值／衝突參數拒絕。工作目錄不存在時，先失敗再跳過網路測試與使用者命令。

網關測試執行真實 shell 入口，但以測試命令替代核心／iptables／route 邊界；其中明確模擬唯讀根檔案系統，確認啟動不再複製檔案到 `/etc` 或 `/sbin`。

另外通過逐檔 Bash／sh 語法檢查、所有 Python 測試腳本語法檢查、Compose YAML 的名稱及唯讀掛載檢查、Docker build allowlist 檢查、`git diff --check` 與 SHA-256 manifest 檢查。

獨立程式碼審查指出安裝器新增的 systemctl 查詢會繼承 D-Bus 環境設定；已加入會先失敗的邊界測試，再以乾淨環境呼叫修正，最後重跑全套。也調整實機驗收腳本為從所在倉庫推導安裝目錄，並明確指定測試工作目錄 `/`。

## 本次未驗證

- 缺少 sing-box 執行檔，真實核心程序名稱測試跳過。
- 執行環境只映射 UID/GID 0，實際切換至普通 UID 的檔案權限測試跳過；沒有把 `setpriv` 失敗算成通過。
- 此處没有 Docker daemon／目標 Ubuntu systemd 主機，未執行映像 build、真實容器啟動、cgroup 封鎖與 PTY／斷線驗收。

`tests/host_*.py` 會修改實驗主機的狀態，只能在可拋棄的 Ubuntu 測試機執行；本次只更新其路徑與名稱並檢查語法。舊版 `docs/evidence/` 保留歷史原貌，不代表本次變更已在使用者主機部署。

## 範圍決定

Docker 的全機資料目錄、OS 的 `/run` 暫存與核心 cgroup 維持原位置。集中的是本工具的程式、Git 版本、設定及 Compose；移動 Docker 全機資料會波及其他容器，並非這次要求的部署目錄整理。

`sudo -i`／`sudo -s` 若保留有效普通 `SUDO_UID`，預設帳戶仍依它判斷；沒有該資訊時必須指定 `-u`。README 已說明，工作負載仍一律拒絕 UID 0。
