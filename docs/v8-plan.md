> 公開版說明：以下為歷史技術／驗證紀錄，並非本次重新執行的測試。含主機資訊的原始日誌、封包擷取及測試輸出僅留在私人存檔，不隨公開版提供；代理設定已改為範例。歷史版本識別與流程描述僅供追溯，不代表公開版包含舊 Git 歷史。

# Shared network policy and native session management

Update 2026-10-09: this file preserves the original approved plan and its pre-host progress. The later AWS Ubuntu 20.04 acceptance, including actual findings and changes, is recorded in `host-acceptance-20261009.md`; the original pending-integration statements below are historical.

> Execution: superpowers:executing-plans; implementation in this branch, one fresh independent review after implementation. User explicitly approved starting on 2026-10-09 after the architecture comparison.

## Agreed design

Ubuntu 20.04 / Linux 5.4 / cgroup v1 / iptables-legacy. Administrator starts a normal-user interactive shell in each terminal. Keep host network and filesystem, all trusted IPv4 loopback services (DNS port 53 remains intercepted), deny managed IPv6 including ::1. No Python terminal relay or custom supervisor/guardian. Keep the v7 sing-box/Hysteria2 single outbound and cached UDP DNS configuration, with unchanged node credentials and TLS settings.

Use one root systemd transient service per shell. A small root bootstrap enters a root-owned net_cls child, prepares its private PTY, then uses native setpriv and exec to drop capabilities, groups and privilege escalation before running probes and the shell. systemd supervises the main shell and kills its service cgroup on stop. The service cleanup hook removes only its empty net_cls directory. Startup probes have bounded timeouts and run after restriction and privilege drop, before user shell startup files.

All sessions have IDENTICAL network policy: one fixed net_cls classid/packet/connection mark, one routing table and a fixed set of shared host chains. No per-session chain, counter, ID reservation, connmark, or persistent session JSON. Networking enforcement is independent of successful cleanup or state-file writes. Existing sockets remain restricted by the same shared policy even after their original shell exits. Shared rules and the default unreachable route stay installed while this tool is installed. They do not grow with session count. This deliberately does not promise per-session immediate network revocation for sockets handed to trusted outside services; that promise was not required by the user's clarified network-only trust boundary.

On shell exit the entire systemd service is stopped; surviving processes remain proxy-only until terminated. Closing a terminal and client crashes require explicit PTY/service integration verification. No claim that systemd magically removes firewall rules, prevents all IPC delegation, or fixes terminal restoration after every crash. Host services and local same-exit proxies are trusted by user decision. IPC command delegation and same-UID external tasks remain explicitly outside complete sandbox guarantees.

Network defaults: CLASSID/MARK 0x6d730001, table 32190, rule priority 1190, root /sys/fs/cgroup/net_cls,net_prio/dev-session-v8; namespaced D8* chains. Common policy applies to socket class, packet mark and connmark. Mark classification precedes filtering. IPv6 has permanent OUTPUT/POSTROUTING DROP guards. IPv4 final egress allows only IPv4 loopback TCP/UDP or the verified dedicated Docker bridge; destination policy blocks private/link-local/multicast addresses. DNS TCP/UDP 53 is DNATed to 1.1.1.1. Container forwarding starts disabled, then the host verifies native gateway policy before enabling it. Keep the existing pre-forwarding host bridge guard.

## Implementation tasks

- [x] 1. `lib/network.sh`: emit constant firewall policy, install and verify only owned chains/hooks, discover and pin the gateway namespace, verify routes/defaults, install unreachable fallback and shared routing. Tests execute the real Bash emitter and model actual emitted rule semantics: all three selectors, IPv6 loopback, physical interface binding, stale marks, gateway down, private destination rejection, constant rule count, foreign hooks.
- [x] 2. `dev-session` and `lib/session.sh`: root trust checks, safe argv/env, native systemd service + bootstrap, reduced UID/groups/caps, private PTY handling, constrained startup probes, exact unit stop/status, idempotent empty-group cleanup. Tests cover malformed identifiers, failed probes never reaching the shell, foreign cgroups not removed, nonempty cleanup retaining guards, argv injection, native unit options and bootstrap sequencing.
- [x] 3. Installer, Compose/root paths and documentation: keep immutable gateway implementation/configuration, remove old Python controller/install/runtime artifacts from v8 package, provide explicit host acceptance commands. Preserve old releases and all credentials. Test native configuration with available official binary and existing gateway regression tests. No live host modifications or node traffic in this executor.
- [x] 4. Whole-branch fresh review, fix confirmed important issues with reproductions, run retained and new tests once, package and persist the replacement release with explicit privileged-integration limitations.

## Review focus

- Cleanup cannot delete shared policy or touch another terminal's service/cgroup.
- Reading or writing bookkeeping cannot be a prerequisite for eventual process termination.
- No transient service may execute user-controlled content with root privileges.
- Old socket/conntrack state must never acquire an unrestricted host default route.
- systemd 245 compatibility and PTY loss handling must not be inferred solely from model tests.

## Progress / rulings

Baseline: v7 4dedcbf, fresh independent review: 173 passed, 1 process-name race failure, 1 capability skip. The isolated executor has CapEff=0, no PID1 systemd, no NET_ADMIN, and no Docker. Real Ubuntu packet/systemd integration cannot run here.

Ruling: Shared permanent policy replaces per-session revoke gates — all sessions use the same permitted exit, so leaving that restriction in force while systemd terminates descendants satisfies no-direct-egress and avoids historical tombstones. Cost: this is not instant per-session revocation of a socket delegated outside the service, which is explicitly outside the clarified trust boundary. Do not claim zero packets after the shell exits.

Ruling: User's 'start according to the proposal' authorizes implementation and reversible worktree creation without another approval round. Written plan records the approved architecture and concrete choices; it is not used to interrupt the task.

Pre-flight: network functions expose fixed constants plus GATEWAY_IP, BRIDGE, NODE_IP, NODE_PORT; launcher/cleanup must never change those shared rules per session. Gateway retains v7 readiness protocol and config validation; controller implementation changes only the host consumer.

Task 1 complete: shared policy emitter/install/readback, pinned gateway checks and routing implemented in 260f9ba. Rule serialization normalization now verifies ordering, not just membership. Task-specific tests passed (26 at that point).
Task 2 complete: native system service, request argv passed through root-private NUL data to avoid systemd variable expansion, net_cls attach then setpriv, bounded probe, PTY ownership and exact cleanup implemented in 260f9ba. New suite 28 passed before review.
Task 3 complete: root-only Bash installer, retained gateway implementation/config, removed obsolete v7 controller/tests, README and real-host acceptance checklist. Official local sing-box configs pass check; DNS runtime attempt blocked by netlink EPERM, documented rather than counted as passing.
Ruling: Kernel/systemd integration cannot run with executor capabilities — deliver a reviewed candidate plus an explicit host acceptance list, not a claimed production-safe release. Cost: the user must still run target-host verification before relying on the isolation.
Ruling: Keep the completed v8 branch and package it without merging into the preserved v7 baseline or pushing — this task requests a deliverable, not repository integration. Cost: no automatic deployment; intended for review and host acceptance.

Final review: one fresh independent reviewer found three Important defects at 1977e7a; all accepted after reproductions. No Critical/Minor finding was established.
Final fixed: private-PTY caller fd inspection — native PTY test RED→GREEN.
Final fixed: failed/hung request cancellation must not gate unit stop — actual teardown body regression RED→GREEN; bookkeeping cancellation bounded to 2 seconds.
Final fixed: inherited system bus environment can execute a root helper — clean environment loader added before all main orchestration, boundary regression RED→GREEN. New Bash/model suite 32 passed before final full run.
Final Ruling: reviewer declined native systemd/PTY lifecycle, real packet enforcement and DNS runtime judgment because executor cannot run them — leave these explicit target-host acceptance gates, not passing claims. Cost: runtime integration defects may remain until Ubuntu acceptance.
Final Ruling: reviewer excluded hostile host IPC and deliberate root policy mutation — retain the user's trusted-host-services boundary. Cost: this is not a complete adversarial process sandbox.

Task 4 complete: one independent whole-branch review, three Important findings fixed in one pass with RED→GREEN regressions. Final complete retained suite: 62/62 passed, zero skipped, 45.523 seconds. Separate DNS runtime blocked by netlink EPERM remains unverified. Native gateway config check, Bash/sh syntax, git diff --check and unchanged-gateway/config comparison passed. No Minor findings deferred. Package as candidate; keep target-host integration unaccepted.
