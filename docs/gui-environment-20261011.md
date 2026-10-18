> 公開版說明：以下為歷史技術／驗證紀錄，並非本次重新執行的測試。含主機資訊的原始日誌、封包擷取及測試輸出僅留在私人存檔，不隨公開版提供；代理設定已改為範例。歷史版本識別與流程描述僅供追溯，不代表公開版包含舊 Git 歷史。

# GUI 與使用者執行環境修正：2026-10-11

基準版本：`63c89be9527a6ea34ec796ffdfd520195833c726`。本次處理同帳戶 GUI、locale、時區與 umask 的相容性；既有網路政策、降權、capability 上限、附加群組及 session lifecycle 沒有改動。

## 修正了什麼

基準版本在 root 入口清除環境，並在工作負載的啟動環境固定 `LANG=C.UTF-8`；systemd 的 `UMask=0077` 也一直延續到使用者命令。結果是桌面連線資料消失、原本的 locale 被替换、新建檔案權限與外層開發環境不同。

新增 `lib/context.sh`，以有限名稱清單和字面 argv 傳遞設定。入口先保存收到的設定及 mask，再立即採用管理器的乾淨環境與 `0077`。設定經原有 root 私有 NUL-delimited request 保存，作為最後工作負載 wrapper 的參數；原 request 欄位布局保持不變。

還原順序為：既有 cgroup／service 啟動、降為普通帳戶、credential check、進入工作目錄、HTTPS probe 成功、還原工作負載 context、`exec` 原命令。還原程式碼來自可信函式定義，變動值不會拼成 shell 程式碼，也不使用 `eval`。

| 設定 | 修正後行為 |
|---|---|
| Locale | 保留 `LANG`、`LANGUAGE`、`LC_ALL` 及標準 `LC_*` 類別的原值；區分不存在與空字串 |
| 時區 | 保留 `TZ`，包括不存在／空字串；不把 bootstrap 的預設 locale 留给 payload |
| Umask | 預設還原入口的 mask；新增 `--umask OCTAL` 可傳入明確值 |
| X11 | 相同 caller／target UID 才傳遞 `DISPLAY`、`XAUTHORITY` |
| Wayland／桌面 session | 相同 UID 才傳遞 `WAYLAND_DISPLAY`、`XDG_RUNTIME_DIR`、`DBUS_SESSION_BUS_ADDRESS`、`XDG_SESSION_TYPE`、`XDG_CURRENT_DESKTOP` |
| 管理器／admission helper | 固定 locale、私有 mask 與既有乾淨環境仍保留；不使用工作負載桌面地址或認證 |
| 互動 shell／直接命令 | 先按原始命令選定 PTY 或 pipe，再包 wrapper；預設仍為 `/bin/bash -i`，原 argv 及 exit status 保留 |

新的 root-side helper 加入 main 的 `trusted_path` 清單及 installer 必要檔清單。installer 仍檢查 Bash 語法及原有檔案／目錄權限。

## 為何保留兩種執行環境

使用者的 locale、時區和 umask 會影響編碼、排序、日期、數字、測試輸出和檔案建立權限。工作負載應依呼叫者選擇；管理器需要穩定的解析環境和私有設定檔權限。後者不需要連接使用者的桌面。

恢復 `0022` 或 `0002` 是恢復普通使用者的檔案建立預設。它沒有授予 capability、管理群組或 root 權限，也不改變管理器 request 的 `0600` 權限。既有會話中的普通使用者原本就可以為自己的程序執行 `umask`／`chmod`。

GUI 延續目前工具既有的宿主 IPC 信任範圍。不同 `-u` 帳戶不會自动獲得 caller 桌面環境；同一帳戶仍須具備桌面本身的存取權。沒有變更 X server 存取控制、複製 cookie 或把 GUI 資料設成 root service 的 active environment。

## sudo 的精確邊界與用法

本次快照是 **post-sudo**：即 dev-session 入口真正收到的設定。sudo 的環境過濾、PAM 設定或 mask 合併已經發生；腳本不聲稱還原此前不存在於輸入中的資訊。[Focal sudoers](https://manpages.ubuntu.com/manpages/focal/man5/sudoers.5.html) 說明其預設 mask 為 `0022`，通常與呼叫者 mask 合併，因此 `0002` 可能已變成 `0022`。

精確傳入原終端的 umask：

```bash
sudo session --umask "$(umask)"
```

在自己的圖形桌面終端中，如 sudo 過濾桌面變數，可用有限清單：

```bash
session_desktop_env=DISPLAY,XAUTHORITY,WAYLAND_DISPLAY,XDG_RUNTIME_DIR,DBUS_SESSION_BUS_ADDRESS,XDG_SESSION_TYPE,XDG_CURRENT_DESKTOP
sudo --preserve-env="$session_desktop_env" session --umask "$(umask)"
```

可重現測試可明確選擇設定：

```bash
LC_ALL=C TZ=UTC sudo --preserve-env=LC_ALL,TZ session --umask 0022 -- ./run-tests.sh
```

上述 `--preserve-env` 仍須符合主機 sudo 政策。其他環境與 `PATH`／HOME 的規則、完整 locale 清單見 [README](../README.md)。互動 shell 的 `~/.bashrc` 可以按使用者配置繼續調整 locale、mask 或開發工具。

## 驗證結果

本地最終回歸為 **112 項、110 通過、2 跳過、零失敗、零錯誤**，耗時 36.176 秒。跳過的是 executor 未映射普通測試 UID，以及未提供 pinned engine binary；不把這兩項算成通過。見 完整 log（原始資料僅留私人存檔） 與 版本／程式雜湊紀錄（原始資料僅留私人存檔）。基準版本的 88 項回歸紀錄（原始資料僅留私人存檔） 有相同兩項環境限制。

新增 **20 項 context 行為測試** 全部通過，見 context log（原始資料僅留私人存檔）。產品碼修改前，最初兩項測試明確失敗：`LANG=C` 實際仍得到 UTF-8；mask `0022` 實際仍建立 `0600／0700`，而非 `0644／0755`。修正後實際執行 `locale`、`date` 及檔案／目錄建立來驗證結果。

覆蓋内容包括 unset／empty、locale precedence、時區 offset、五種檔案建立 mask、同／不同 UID 的桌面資料、含空白／換行／等號／shell metacharacters 的字面值、固定 admission 環境、失敗 probe 不啟動 payload、request 私有權限，以及入口 prefix 與真正 parser 的銜接。CLI 另覆蓋合法／非法／重複 `--umask`。安裝測試實際走入口、main、request write/read，分別確認 PTY／pipe、context、mask，以及新的 helper 信任檢查。

所有 **9 個 Shell 檔案** 語法檢查通過，見 syntax.json（原始資料僅留私人存檔）。獨立 read-only review 未發現 blocking、P1 或 P2 問題，並另外實跑 wrapper 的 argv、exit status、PID／PTY 描述符保持；review 提出的 help 用語已補成 `after sudo`。

本地 context fixture 使用真正的 bootstrap 產生環境與 Bash helper，僅替換本 executor 無法提供的 cgroup attachment、credential check、network probe，並略過真正的 setpriv。整合 fixture 不呼叫主機的 systemd 或變更防火牆；不可把這些記錄當成完整實機網路驗收。

另在 **Ubuntu 20.04.6／Bash 5.0.17／Python 3.8.10** 的 VPS，以普通 ubuntu 帳戶執行同一 context suite：**17 通過、3 個 root-only snapshot 測試跳過，零失敗**，耗時 0.803 秒。五個複製檔案的 SHA-256 與本地一致；測試保持原有 stub 及省略 setpriv，自己的私有 fixture 已清除。見 Focal 原始 log（原始資料僅留私人存檔） 和 機器可讀結果（原始資料僅留私人存檔）。這項結果確認該版本 Bash／Python 的相容性，未涵蓋 root 入口或真實 GUI。

## GUI 實機驗收仍未完成

測試 VPS 的遠端工具禁止 `sudo`／`su`，普通 ubuntu 帳戶不能存取 root 私有 `/opt/session`；本次沒有在該安裝上部署修改，也沒有重跑完整 systemd／降權／網路鏈路。

已由普通 UID 1000 嘗試臨時 Xvfb：只在私有暫存目錄下載及解包小型 Focal 套件，沒有安裝系統套件或變更系統路徑。動態庫依賴補齊後，Xvfb 因固定 `/usr/bin/xkbcomp` 缺少而在提供 display 前退出。因此 **真正 X11 視窗、正確／錯誤 cookie 的 client 檢查都未執行**，結果記為 `not_run`，見 X11 JSON（原始資料僅留私人存檔） 和 操作摘要（原始資料僅留私人存檔）。自己的 server、cookie 及暫存目錄已清理。

已保留 [普通使用者 X11 runner](../tests/host_gui_context.py)，在具備 Xvfb／XKB 的環境可執行。它只驗證 context helper 與本地 X11 授權／視窗，不替代 rootful session 或 Wayland 驗收。Native Wayland、實際 GNOME／Qt／GTK 程式及 GPU 調試本次尚未驗證。

GUI 程式的單例轉交或 D-Bus activation 可能使用會話外既有程序；這些程序不會自動加入本會話 cgroup。實機驗收應啟動獨立實例並核對實際工作 PID，也應確認結束會話後該實例一同結束。

## 更新方式

先關閉現有會話，按 README 的原有流程在同一安裝目錄 `git pull --ff-only`，重新執行 installer 的 `--check` 和正式權限檢查，再開新會話。本次沒有改網關、Compose、網路政策或節點設定，因此這項修改本身不要求重建 Docker 映像或重新初始化網路規則。
