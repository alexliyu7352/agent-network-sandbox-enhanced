> 公開版說明：以下為歷史技術／驗證紀錄，並非本次重新執行的測試。含主機資訊的原始日誌、封包擷取及測試輸出僅留在私人存檔，不隨公開版提供；代理設定已改為範例。歷史版本識別與流程描述僅供追溯，不代表公開版包含舊 Git 歷史。

# Single-directory V8 installation

> **For agentic workers:** Use superpowers:executing-plans to implement these tasks inline.

**Goal:** Keep the Git checkout, launcher, settings and Compose deployment in one root-private directory, with a short session command.

**Architecture:** Install in place (recommended `/opt/session`); `/usr/local/bin/session` is only a symlink. Derive the trusted installation root from the executable, preserving the caller's working directory. Keep OS-owned volatile state in `/run` and Docker layers in Docker's existing data root.

**Tech Stack:** Bash, systemd 245, Compose v1/v2, Python unittest fixtures.

**Spec:** User requests in this conversation: GitHub as source of truth; neutral container/image names; dedicated ordinary user support; implicit current working directory; unified directory with strict permissions.

## Global Constraints

- Preserve Ubuntu 20.04, cgroup v1, existing V8 network policy and UDP DNS cache.
- Preserve `network.json` exactly; no credentials in build context or test output.
- No host deployment or modification of the user's running Docker gateway.
- Keep the legacy `--user ACCOUNT run --cwd DIR` syntax.

## Review Focus

- Root startup environment and user-controlled/symlinked installation paths.
- Incorrect account inference when invoked directly as root.
- Separate user's inability to traverse the project path after dropping groups.
- Installer collisions, repeated installation, and writable or linked files.
- Read-only container startup after binary/container renaming.

## Task 1: Installation and invocation

Files: `dev-session`, `install-dev-session.sh`, `lib/main.sh`, new `lib/cli.sh`, `lib/session.sh`, `tests/test_installation.py`, `tests/test_cli.py`.

Interfaces: `parse_cli` produces command, user, workdir, workload; `resolve_account` produces uid, gid, home. Launcher retains only validated caller UID and TERM in its clean environment.

- [x] Write and run failing behavioral tests for in-place permissions, cwd/default-user parsing, legacy syntax, invalid input and inaccessible cwd.
- [x] Implement trusted-root discovery, in-place installation, optional shortcut and parsing.
- [x] Run targeted tests; expected all pass without changing host network state.

## Task 2: Container names and documentation

Files: Compose, Dockerfile, entrypoint, policy, network readiness checks, existing test fixtures, `.dockerignore`, README and verification note.

Interfaces: container/image/binary `worker`; container runtime `/run/worker`; policy readiness marker `worker-policy-v8`.

- [x] Run the existing entrypoint fixture to demonstrate the uploaded runtime-copy failure.
- [x] Rename the executable at build time, preserve read-only runtime, use a relative configuration mount; restore build-context allowlist.
- [x] Document one-directory setup, ordinary account permissions, short commands and existing security limits.
- [x] Run unittest discovery, shell syntax and manifest checks; record any unavailable real-host tests separately.
- [x] Review changes and prepare an atomic commit based on the authorized GitHub HEAD, with a branch-head lease.

Verification: 79 tests, 77 passed, 2 explicit environment skips. Independent review addressed installer bus environment; updated host-test paths and root-shell documentation. No host deployment. See `docs/install-cli-verification.md`.
