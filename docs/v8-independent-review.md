> 公開版說明：以下為歷史技術／驗證紀錄，並非本次重新執行的測試。含主機資訊的原始日誌、封包擷取及測試輸出僅留在私人存檔，不隨公開版提供；代理設定已改為範例。歷史版本識別與流程描述僅供追溯，不代表公開版包含舊 Git 歷史。

# Independent whole-branch review — v8

Reviewed baseline `4dedcbf` through HEAD `1977e7a4f32505f1ff4d16f771642e27cc0a45eb`, on 2026-10-09. This is one independent review of that snapshot, including the complete Bash launcher/helpers, installer, retained gateway, Compose/Dockerfile, README, plan/rulings, verification ledger and test/host-acceptance coverage. No runtime implementation was changed by this review.

The agreed boundary was applied: arbitrary trusted host IPv4 loopback services and host IPC remain available; managed IPv6 is denied; the shared policy is permanent. A full malicious-code sandbox, loopback allowlist, instant delegated-socket revocation and host administrator tampering are not requirements of this review.

## Findings

### Important — valid interactive sessions always fail the private-PTY check

**Location:** `lib/session.sh:58–59` at reviewed HEAD.

`private_tty` checks descriptor 1 using `$(stat ... /proc/self/fd/1)`. The `stat` process's stdout is the command-substitution pipe, so `/proc/self/fd/1` identifies that pipe rather than the bootstrap's terminal. Its identity cannot match the PTY recorded from fd 0. Therefore every normal `run` without an explicit command exits during bootstrap and never reaches the probe or interactive shell.

**Evidence:** a real, harmless PTY reproduction allocates two distinct PTYs, passes the second slave as all three child standard descriptors, and supplies the first slave's identity as `outer`. The reviewed function returns failure despite valid terminal descriptors. This independently agrees with the author's newly added failing PTY test. The defect is in Bash/proc descriptor handling and does not require a real systemd manager to demonstrate.

**Correction direction:** inspect the bootstrap process's descriptors through a stable caller PID, rather than each command-substitution child's `/proc/self`; retain the distinct-outer-terminal check.

### Important — request-file deletion failure aborts teardown before stopping the service

**Location:** `dev-session:98–105`, especially line 103, at reviewed HEAD.

`finish` removes the request before invoking `systemctl stop`, under the launcher's active `set -e`. That removal is unguarded, and the function has already disabled its EXIT/signal traps. If it fails, Bash terminates immediately: neither the service stop nor the relay termination is attempted. Request cancellation is useful for the registration race, but its success cannot be a prerequisite for terminating an already-started unit. A hung bookkeeping operation likewise delays the subsequent stop.

**Evidence:** the reproduction extracts the actual reviewed `finish` body and substitutes only a failing `rm` plus a recording `systemctl`. Output is `request-delete-attempt`, exit status is 1, and there is no `UNIT_STOP_ATTEMPT`. This is a concrete violation of the explicit bookkeeping-independent termination requirement; it is not a claim that `/run` routinely fails.

**Correction direction:** make bookkeeping best-effort and ensure the exact unit-stop request is still attempted on its failure. Preserve the stop-before-registration protection.

### Important — inherited bus environment can select a helper executed as root

**Location:** `dev-session:3–4,115`; `lib/session.sh:25`, at reviewed HEAD.

The launcher fixes `PATH` and removes a few shell variables but retains `DBUS_SYSTEM_BUS_ADDRESS`. It then runs root `systemd-run --wait`. In upstream systemd v245, this path deliberately connects through the system bus, which reads `DBUS_SYSTEM_BUS_ADDRESS`; the supported `unixexec:` address scheme executes the named helper with the caller's credentials. Thus a preserved or contaminated caller environment can select arbitrary root executable content before the service's `setpriv` boundary. A normal sudo environment policy may remove this variable, but the launcher itself does not enforce that assumption. The final workload's `env -i` occurs too late to protect this root-side operation.

**Evidence:** read the versioned upstream sources: [`run.c`](https://github.com/systemd/systemd/blob/v245/src/run/run.c), lines 1710–1714; [`bus-util.c`](https://github.com/systemd/systemd/blob/v245/src/shared/bus-util.c), `bus_connect_transport`; and [`sd-bus.c`](https://github.com/systemd/systemd/blob/v245/src/libsystemd/sd-bus/sd-bus.c), `bus_set_address_system`, `parse_exec_address` and `bus_start_address`. An offline call to the executor's real `libsystemd.sd_bus_open_system`, using `unixexec:path=/usr/bin/touch,argv1=<temporary-marker>`, created that marker with caller EUID 0. No daemon connection, transient service or privileged host mutation was involved. This native-library reproduction is not represented as execution of a systemd 245 service.

**Correction direction:** establish a minimal root-side environment before invoking external helpers, preserving only deliberately required terminal data. Do not limit the fix to the eventual workload environment. Other inherited Docker/systemd/pager configuration variables should be covered by that same boundary; they were not separately asserted as proven exploits here.

## Review evidence and limits

The harmless reproduction script is a private temporary script (not distributed with the public version); it obtains the reviewed source with `git show 1977e7a:<path>` so later working-tree fixes do not silently change its inputs. It demonstrates the three findings above. The author notified the reviewer of in-progress fixes for the first two while this review was completing; those fixes are outside this snapshot's judgment.

No concrete shared-policy deletion or cross-session cgroup deletion defect was established: the reviewed cleanup helper addresses only its validated ID, uses `rmdir` after checking membership, and contains no firewall/route deletion. The fixed POSTROUTING guard and unreachable fallback are present in the inspected source, and per-session teardown does not remove them. These observations are source review, not proof of real packet enforcement.

The retained gateway implementation, Dockerfile, Compose and `network.json` have no diff between the specified base and reviewed HEAD. Credentials were not printed. Test-suite totals supplied by the author were not treated as native systemd/netfilter acceptance evidence.

## Declined to judge

- **Real systemd 245 lifecycle, terminal hangup, resize/job-control and descendant termination:** this executor has no systemd PID 1 or target cgroup v1 hierarchy. The Focal [`systemd-run` manual](https://manpages.ubuntu.com/manpages/focal/man1/systemd-run.1.html) and v245 source establish availability and describe behavior, but cannot prove the full wrapper/PTY/service interaction. In particular, v245's successful PTY-forwarding completion can continue waiting for unit inactivity; wrapper HUP/stop behavior needs the target-host acceptance scenarios. No additional terminal-loss defect is asserted solely from that observation.
- **Actual Linux 5.4 hook order, routing/SNAT/DNAT, cgroup socket classification, old socket/conntrack behavior, gateway failure/restart and IPv6 packets:** no NET_ADMIN, iptables mutation, Docker or target kernel integration is available. The rule model/readback tests do not establish these properties. Execute the documented packet-capture and fault-injection checklist on the intended host.
- **Native Hysteria2 DNS runtime and remote node reachability:** the existing runtime attempt is blocked by netlink EPERM. Configuration checking and a renamed official binary do not prove runtime DNS/cache behavior. No real node traffic was sent during this review.
- **A full sandbox against trusted loopback/IPC services, external same-UID tasks or deliberate root policy changes:** excluded by the approved boundary. No additional restrictions are requested on that basis.

The reviewed snapshot has three Important findings and no separately established Critical or Minor findings. Target-host acceptance remains pending even after these code defects are fixed.
