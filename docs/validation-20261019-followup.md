# 逐協議主機驗收與固定核心限制

本頁接續 [2026-10-18 起的驗證紀錄](validation-20261018.md)。固定核心仍是 sing-box **1.14.2**，revision `af6e64c3b69e6132ebaee0e1a3d24e93903f6709`。工作分支為 `work/cgroup-proxy-adaptation-20261018`，`main` 尚未合併；測試結果不代替使用者的合併批准。

## 第一輪逐協議原生矩陣：50／59，保留失敗

[CI 39202665481](https://github.com/alexliyu7352/agent-network-sandbox-enhanced/actions/runs/39202665481) 在提交 [`3b5767dd518c7867ef54403b4af635f9af008399`](https://github.com/alexliyu7352/agent-network-sandbox-enhanced/commit/3b5767dd518c7867ef54403b4af635f9af008399) 執行，2026-10-19 05:04:37–05:19:58 UTC，結論為 **failure**。59 個 job 的 artifacts 均逐份讀取，ZIP digest、manifest 引用檔案的 SHA-256、提交及 cgroup 模式核對一致。

| 範圍 | 通過 | 失敗 | 實際執行內容 |
| --- | --- | --- | --- |
| 既有代表性環境／故障矩陣 | 11 | 1 | Ubuntu HTTP／Hysteria2 各五種情境，Debian KVM 各一種 healthy 情境。 |
| 逐協議／封裝矩陣 | 39 | 8 | 每組獨立 Ubuntu 純 v2 VM，出口 IP、兩個受管 service 的 socket 建立身分、17 項核心故障與封包驗收、fixture 身分及故障後核對。 |
| 合計 | **50** | **9** | 未將缺少核心測試、失敗的健康基線或擷取證據記為通過。 |

每個 job 的離線 discover 為 295 項：292 通過、3 跳過；inline helper 25／25 通過。離線階段尚無指定的實際核心及 SSH 依賴；SSH job 後續在 CPython 3.13.16 的私有環境安裝固定依賴，另跑 18／18 項 SSH fixture 測試且零跳過。VPS 對同一公開提交使用實際 ELF、Python 3.8.10 與私有 SSH 環境，完整 discover **295／295、零跳過**，另有 inline **25／25**；這不能抵銷原生 CI 的九件失敗。

### 九件失敗的判定與處理

| 失敗類別 | 件數 | 已取得的證據與處理 |
| --- | --- | --- |
| Legacy Hysteria2 fixture setup | 1 | 在變更範圍內失敗並成功執行自有 cleanup；舊 artifact 沒有足夠的命令定位資訊。新增只含 repository function／line、白名單命令類別、exit status 的安全診斷，後續實跑仍須確認。沒有猜測並修改 readiness。 |
| VLESS、VLESS HTTP、VLESS gRPC、SOCKS5 UoT 的 qname 斷言 | 4 | 這些設定的未加密代理流可能包含明文應用資料。修正測試的內容可見性假設，仍要求所有外層封包符合完整的允許端點、實體介面直連為零、DNS 被攔截到指定 resolver。 |
| VMess HTTPUpgrade 的起始 canary 缺失 | 1 | 實體 PCAP 只有本次末端 canary，collector 沒有 kernel drop；起始固定 sleep 並未證明 collector 已開始。改成有期限地等待本次唯一 canary 實際入檔，再開始 workload；末端證據仍獨立必要。 |
| AnyTLS 在注入前的 HTTPS 基線失敗 | 1 | 精確發生在故障 DROP 規則建立前；固定核心的 cancelled-dial 重用問題已由四組隔離對照重現，見下節。 |
| Trojan／VLESS HTTPUpgrade 的健康入場或出口 IP 失敗 | 2 | Trojan 的 session B 在 curl TLS EOF 後拒絕啟動 workload。後續固定核心的重複配對測試也在三種 HTTPUpgrade 封裝重現間歇失敗；本版明確拒絕此封裝。 |

VLESS 的 [artifact 12164588536](https://github.com/alexliyu7352/agent-network-sandbox-enhanced/actions/runs/39202665481/artifacts/12164588536) 已獨立逐包解析：170 個外層封包全部到 `192.0.2.1` 的 TCP 443，八個隨機 DNS qname 與普通 UDP token 只出現在這條允許的代理流；沒有目的埠 53 的外層直連封包。ZIP SHA-256 為 `198513e09f7b5438fbbf994e7877085b3faf79c766bb8742b296741cbb314135`。

`payload_marker_policy=encapsulated` 僅由明確的未加密 fixture 選用。擷取仍先收集廣泛的 gateway 對外流量，再逐包比對完整 outer policy；不能在擷取時預先濾掉非法端點。`plaintext_dns_on_outer`、`plaintext_udp_on_outer` 記錄實際找到 marker 與否。沒有找到特定 byte sequence 不構成加密證明；WebSocket masking 也不是加密。管理的 DoH 及不支援的 UDP，即使此選項開啟仍不允許其 marker 出現在外層。

## AnyTLS：保留固定核心的有限可用性限制

以同一個未修改的核心 client／server、驗證憑證的本機 TLS echo、隔離的遠端 dial 等待控制，完成四組對照。沒有 TUN、主機防火牆、全局路由、WAN 或生產設定變更。

| 控制條件 | 第一條新的 TLS 連線 | 緊接著的新連線 | 另一條既有 TLS stream |
| --- | --- | --- | --- |
| 沒有負向連線 | 成功，0.051467 秒 | 成功 | 保持正常 |
| Dial 仍在等待，未送 payload 就關閉 | 成功，0.056883 秒 | 成功 | 保持正常 |
| Dial 立即拒絕，曾送 payload | 成功，0.047686 秒 | 成功 | 保持正常 |
| Dial 仍在等待，已送 payload 後關閉 | `SSLEOFError`，3.001975 秒 | 成功，0.052670 秒 | 保持正常 |

這與固定 [`sing-anytls v0.0.11` 的 session 實作](https://github.com/anytls/sing-anytls/blob/v0.0.11/session/session.go) 中的重用及三秒 SYNACK watchdog 相符：等待遠端 dial 的 stream 尚未消耗資料時，同一 session 的後續處理可能受阻；核心關閉該 session 後，新的連線可以另建 session。這次結果限於單個已取消的等待中 dial，不能推論任意數目的受影響 idle sessions 都只需要一次重試。

本版保留 AnyTLS 的政策適配，並公開這項可用性限制。健康入場探測可能因此拒絕一次啟動；程式不改走直連、不替換協議、不重啟核心或重設 pool。產品探測和一般故障測試沒有新增重試。

原生 AnyTLS job 額外要求 `anytls_cancelled_dial_recovery`：在負向連線測試後、獨立故障測試前記錄第一條新連線的完整結果。只有指定 EOF／reset 類型且符合 2.5–4 秒窗口，才允許再建立一次新連線，而且必須成功；其他錯誤或第二次失敗立即失敗。另一條 TLS socket 的 object、fd、inode、peer 必須保持相同，HTTP body 必須完整，前後 policy／binding 不變。這增加為 **18 項核心驗收**；其他逐協議 job 保留 17 項。故障期間既有／新連線阻斷、實體介面零直連與 namespace 拒絕的條件都保留。

## HTTPUpgrade：本版拒絕，歷史單次通過保留

在固定核心的 client／server 配對中，使用相同的驗證 TLS 應用流量，每組 100 次、並行 4，未注入故障、未更改核心參數，結果如下：

| 協議 | 原生封裝 | HTTPUpgrade |
| --- | --- | --- |
| Trojan | 100／100 | 82／100；18 次 TLS EOF，上游記錄 bad request／fallback disabled |
| VMess | 100／100 | 98／100；2 次 TLS EOF，上游記錄 bad request |
| VLESS | 100／100 | 98／100；2 次 TLS EOF，上游記錄 unknown protobuf message header |

三個配對在失敗時核心程序都仍存活。這證明目前固定核心配對的 HTTPUpgrade 未達可靠驗收，**不代表所有遠端服務或出站 client 都存在相同缺陷**。本版在 policy／effective 編譯時明確拒絕 `transport.type="httpupgrade"`，不產生部分政策、不啟動 workload，也不偷偷改寫 transport、TLS 或認證。可依服務端能力選擇省略 transport 的原生 TCP，或已列入矩陣的 HTTP、WebSocket、gRPC、QUIC。

初輪 47 組 loopback 曾各至少一次通過的紀錄仍保留；它們無法抵銷後來的可靠性反例。現行可接受的預設案例為 **44 組**，三個 HTTPUpgrade 案例列入明確的 blocked inventory，不會作為 experimental case 自動回到原生矩陣。

## 後續完整關卡

修正後的工作分支須通過 **44 組逐協議原生 job＋12 組代表性環境／故障 job，共 56 組**。本節目前記錄必要關卡，尚未把等待重跑的修正記成通過；最終結果需要與正在審閱的提交及 artifact 對應。

兩種 hopping 在首輪原生 CI 已額外證明健康期間同一條 TLS socket 的連續交換：各 12 次交換，窗口為 20.295680884／20.305655949 秒，各觀察到五個允許目的埠的正增量。故障後的 fixture 核對保留同一份窗口證據；不能把故障造成的重連當成持續跳埠證據。SSH 的原生 17 項核心、出口 IP、socket 建立身分與 PCAP 也已在首輪通過。

代表性 12 組保留 100 個短會話、concurrency 3、退出回收與 namespace 故障；逐協議 jobs 不重複宣稱執行該壓力套件。VPS 原有容器維持原 ID 與名稱並持續運行，生產配置與 launcher 雜湊保持不變；原生故障測試的自有資源已回收，後續兩種核心診斷也只使用本機隔離 fixture。沒有重啟 VPS Docker daemon 或主機。
