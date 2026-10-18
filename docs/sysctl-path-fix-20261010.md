> 公開版說明：以下為歷史技術／驗證紀錄，並非本次重新執行的測試。含主機資訊的原始日誌、封包擷取及測試輸出僅留在私人存檔，不隨公開版提供；代理設定已改為範例。歷史版本識別與流程描述僅供追溯，不代表公開版包含舊 Git 歷史。

# Ubuntu 工具路徑相容性修正（2026-10-10）

使用者桌面主機在 `sudo session init` 報錯：

```text
nsenter: failed to execute /usr/sbin/sysctl: No such file or directory
```

原因是宿主工具路徑被寫死。AWS Ubuntu 20.04 測試機的 `/sbin -> usr/sbin`、`/bin -> usr/bin` 連結掩蓋了問題；實際 `dpkg-query -L` 顯示 procps 提供 `/sbin/sysctl`，iproute2 提供 `/bin/ip` 及 `/sbin/ip`。使用者主機尚未直接檢查其目錄佈局，但這個固定路徑假設已由報錯及新增回歸測試確認不成立。

`nsenter --net` 只切換網路 namespace，工具仍取自宿主檔案系統，參考 [Ubuntu Focal nsenter 手冊](https://manpages.ubuntu.com/manpages/focal/man1/nsenter.1.html)。本次將 sysctl、ip 及 legacy iptables 呼叫統一使用入口已固定的系統 PATH：`/usr/sbin:/usr/bin:/sbin:/bin`，並在 preflight 檢查 sysctl。沒有加入使用者目錄、改動政策內容或建立系統符號連結。

驗證：

- 新增三項邊界回歸：模擬未合併 /usr 時的 IPv6／路由檢查、forwarding 開啟及讀回，以及 sysctl 寫入失敗仍拒絕放行。修改前都因固定路徑失敗，修改後全部通過。這是邊界模擬，不是把 AWS 改造成未合併 /usr 的系統。
- 本地完整測試：82 項，80 通過，2 因缺少真實核心／普通 UID 映射而跳過，0 失敗；35.353 秒。Bash 語法、diff whitespace 及 manifest 檢查通過。
- AWS 臨時部署這兩個修正檔，真實 Docker 網關的 `session init` 與 `session check` 均退出 0，沒有 stderr。僅驗證本次初始化相容性，沒有重跑先前 100 次會話或把它宣稱為本次完整網路驗收。
- 測試後停止容器、恢復原本乾淨的受測 checkout、移除臨時檔案，並恢復／讀回確認遠端工具原始命令限制。

AWS 修正檔驗證結果：

```json
{
  "init_and_check": [
    {
      "action": "init",
      "exit": 0,
      "stdout": "Local policy verified. No workload connectivity test was run.",
      "stderr": ""
    },
    {
      "action": "check",
      "exit": 0,
      "stdout": "Local policy verified. No workload connectivity test was run.",
      "stderr": ""
    }
  ],
  "libs_sha256": {
    "host.sh": "0359b9ac37076ee5753a9189570c252ad5d967c9473fe2f0d30e75dc1fa222ce",
    "network.sh": "c6f715c3f16bd6dd71bcf8e5fae324eb3bf5bfcc6e4d1c0edaa595c99d45d1e0"
  }
}
```

更新目前安裝所在的 Git checkout，重跑 installer 收緊權限，然後再次 `sudo session init`。不需要重建映像或容器。
