> 公開版說明：以下為歷史技術／驗證紀錄，並非本次重新執行的測試。含主機資訊的原始日誌、封包擷取及測試輸出僅留在私人存檔，不隨公開版提供；代理設定已改為範例。歷史版本識別與流程描述僅供追溯，不代表公開版包含舊 Git 歷史。

# Independent acceptance review

The reviewer had read-only access to the working tree and ran local behavioral tests and failure-path mocks. It did not operate the AWS host; remote results are separately recorded in `host-acceptance-20261009.md` and `evidence/`.

Confirmed runtime findings from real-host testing were independently assessed:

- Focal mawk hexadecimal conversion, newer-kernel capability enumeration and portable stat PTY identity were retained without weakening readback or credentials.
- systemd 245 can invoke ExecStopPost before its final kill of stubborn descendants. Cleanup now also runs after the synchronous stop job, uses only the exact SID's empty cgroup, tolerates concurrent removal and retains real errors.
- A completed stop job can briefly precede kernel task release. Only the busy result is retried, at 50ms intervals for at most 40 attempts. No PID scanning/killing or shared policy removal was added. The reviewer independently ran the final 13 session tests successfully, plus shell syntax and diff checks.

Review also found false-positive risks in the acceptance harness. These were corrected before final acceptance: DNS wire-format matching, HTTPConnection's automatic reconnect hiding an old-socket test, a fallback close masking failure to exit naturally, readiness of descendants' ignore handlers, tcpdump premature exit/loss/incomplete tail handling, explicit positive controls, and serialization allowing new HTTPS attempts to miss the Docker restart interval. Existing/new/forced flows now run independently in three ready sessions.

Docker daemon restart changed NAT hook order. The reviewer agreed that strict rejection followed by closing every session and explicit `init` is correct; weakening hook validation or repairing live policy would contradict the approved design. Container stop/start remains a separate recovery scenario.

Final assessment: no remaining Critical or Important blocker in the reviewed changes. This is source and local behavioral review, not an independent replication of remote tests or a proof against every possible bypass. One minor wording suggestion was adopted: the busy wait is approximately two seconds, subject to scheduling, rather than a hard wall-clock guarantee.
