# Go rewrite implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Replace script backends with a maintainable Go client for Windows/Linux.

**Architecture:** Go owns configuration, SSH verification, a background supervisor and application launch. A bundled sing-box owns HTTP/SOCKS forwarding through SSH. OS-specific Go files implement file permissions, locks and child process lifecycle.

**Tech Stack:** Go 1.25.8+, existing huh v2, golang.org/x/crypto/ssh, golang.org/x/sys, sing-box 1.14.3.

**Spec:** `docs/superpowers/specs/2026-10-11-go-rewrite-design.md`, approved by user.

## Global Constraints

- Windows/Linux amd64/arm64; no script runtime or administrator rights for normal operation.
- No system proxy, TUN, firewall or DNS changes; external destinations use SSH with no direct fallback.
- SSH key and passphrase never copied in decrypted form to disk; ephemeral configuration goes through stdin.
- Existing keys and Firefox profile survive migration; only owned old service/task may be disabled.
- Keep huh, use focused packages, do not introduce a generic framework.

## Review Focus

1. IPv6, user@host and paths containing spaces must survive parsing and process launch (tasks 1, 5).
2. Corrupt/symlinked state and unknown future config versions must fail without overwriting user data (tasks 1, 4).
3. Concurrent starts and an unrelated occupied port must not kill or attach to a foreign process (task 4).
4. Encrypted keys, revoked host keys and a failed migration must preserve trust and old state (tasks 2, 6).
5. Existing lowercase proxy variables, OAuth callback and nonzero Claude exit codes must retain intended routing and behavior (task 5).

## Task 1: Settings and private files

**Files:** `internal/config/config.go`, `config_test.go`; `internal/platform/files_linux.go`, `files_windows.go`.

**Interfaces:** `config.Settings` holds version, server/user/key, SSH/proxy ports, host pin, domains, engine path and optional expected IPs. `Defaults() Settings`, `Normalize(home string) error`, `Load(path string) (Settings,error)`, `Save(path string, Settings) error`. Platform exports `PrivateDir(path string) error`, `WritePrivate(path string, []byte) error`.

- [x] Add normalization and persistence tests: IPv6/user@host, ports, public-suffix exclusions, malformed JSON, unsupported version, overwrite rejection for symlink, secret-free round trip.
- [x] Run `go test ./internal/config` and observe missing API failure.
- [x] Implement versioned config, private directory/file permissions, atomic same-directory replacement; native Windows ACL.
- [x] Run `go test ./internal/config`; expected success.

## Task 2: SSH authentication and trust

**Files:** `internal/sshconn/ssh.go`, `ssh_test.go`; update `go.mod`, `go.sum`.

**Interfaces:** consumes Settings; `Signer(path string, passphrase []byte) (ssh.Signer,error)`, `Probe(ctx context.Context, Settings, passphrase []byte) (hostKey string,error)`. Unknown hosts return typed `UnknownHostError{Key,Fingerprint}`; known mismatch/revocation never become TOFU.

- [x] Add local SSH-server tests for valid/encrypted keys, bad passphrase, unknown key, correct pin, changed pin, hashed known_hosts and revoked keys.
- [x] Run `go test ./internal/sshconn`; observe missing API failure.
- [x] Implement x/crypto/ssh parsing, context/deadline-bounded handshake and strict callback; no command line OpenSSH dependency.
- [x] Run `go test ./internal/sshconn`; expected success.

## Task 3: sing-box configuration and probes

**Files:** `internal/engine/config.go`, `engine.go`, `engine_test.go`.

**Interfaces:** consumes Settings; `Config(Settings, []byte) ([]byte,error)`, `Find(Settings) (string,error)`, `Check(ctx, binary string, data []byte) error`, `Egress(ctx, port int) (string,error)`, `Serve(ctx, binary string, data []byte, io.Writer) error`.

- [x] Add tests rejecting missing pin, forcing protected domains before direct rules, exact loopback binding, stdin-only secret transport and explicit HTTP proxy with hostile ambient environment.
- [x] Run `go test ./internal/engine`; observe missing API failure.
- [x] Implement typed JSON, bundled/PATH engine discovery, bounded version/check execution, HTTP IP probe and one-child supervision with cancellable restart backoff and bounded log output.
- [x] Run `go test ./internal/engine`; expected success.

## Task 4: Background session

**Files:** `internal/session/session.go`, `control.go`, `session_test.go`; `internal/platform/process_linux.go`, `process_windows.go`.

**Interfaces:** `session.Manager{Dir,Executable}`; `Start(ctx, Settings, []byte) error`, `Stop(ctx) error`, `Status(ctx) (Status,error)`, `Run(ctx, bootstrap io.Reader) error`. Bootstrap contains Settings and passphrase only in stdin. State contains control address/token and connection identity, no passphrase. Platform exports OS file lock and detached/owned-child operations.

- [x] Add authenticated control tests: wrong token/Origin/method rejected; stop terminates own session; stopped proxy probe fails; simultaneous starts share one session; occupied port rejected; bounded bootstrap and corrupt state.
- [x] Run `go test ./internal/session`; observe missing API failure.
- [x] Implement singleton OS lock, random loopback control listener, private state, bounded startup, own-session status/stop and detached executable bootstrap. Linux parent-death signal and Windows Job Object prevent orphan sing-box.
- [x] Run `go test ./internal/session`; expected success.

## Task 5: Launch and terminal UI

**Files:** `internal/launch/launch.go`, `launch_test.go`; replace `internal/app/settings.go`, `runtime.go`, `ui.go`, `settings_test.go` with `app.go`, `ui.go`, `app_test.go`; retain `cmd/cproxy/main.go`.

**Interfaces:** `launch.Environment(base []string, port int) []string`, `Browser(Settings, profile, url string) error`, `Claude(ctx, Settings, args []string) error`. App calls the APIs above through concrete types; no script dispatch.

- [x] Add tests for environment isolation, lowercase proxies/NO_PROXY override, profile generation, arguments/working-directory/exit preservation and CLI help/error codes.
- [x] Run launch/app tests to observe absent new behavior.
- [x] Implement native Firefox/Claude discovery, managed prefs, Windows .cmd handling and portable stdin/out forwarding. Replace menu/wizard; masked passphrase, explicit host fingerprint confirmation, diagnostics, save only after validated connection, stop and exit distinction.
- [x] Run `go test ./...` and terminal smoke check; expected success.

## Task 6: Legacy migration

**Files:** `internal/legacy/legacy.go`, `legacy_linux.go`, `legacy_windows.go`, `legacy_test.go`; connect setup UI.

**Interfaces:** `Detect() (*Installation,error)`, `Installation.Settings() (config.Settings,error)`, `Pause(ctx) (restore func() error,error)`. Disable only owned service/task; no recursive deletion of old data. Reuse the preserved owned profile by explicit path instead of copying possibly active databases.

- [x] Add tests importing session original key, route exclusions and host pin; reject unsafe/missing markers; confirm failed transition restores old state and original files.
- [x] Run `go test ./internal/legacy`; observe missing API failure.
- [x] Implement Go JSON import, Linux systemctl arguments and Windows schtasks XML/ownership checks, rollback and profile preservation. Explain migration in UI.
- [x] Run `go test ./...`; expected success.

## Task 7: Remove obsolete paths, package and verify

**Files:** README/docs, `.github/workflows/test.yml`, `build.yml`; remove `linux/`, `windows/`, `config/`, root script launchers, old script/Python tests and superseded docs/plans.

- [x] Add Go integration test using temporary local SSH server and real sing-box: HTTP, SOCKS remote DNS, private direct exclusion, wrong host key, SSH outage/recovery and supervisor shutdown. Engine path supplied with `CPROXY_TEST_SING_BOX`; local CI supplies it, no user VPS needed.
- [x] Observe integration failure before fixes if a new gap appears; fix through RED→GREEN.
- [x] Package cproxy plus pinned official sing-box and licenses for four targets; verify release checksums. CI runs native Windows/Linux tests and integration; archive generation uses CI shell only.
- [x] Replace stale docs with concise setup, routing limits, encrypted key behavior, migration and verification guidance. Remove old implementation via apply_patch after replacement works.
- [x] Run `go test -race ./...`, `go vet ./...`, local integration, four cross-builds and `git diff --check`. Review whole diff independently before final report. Record checks not run on actual user environment.

## Execution notes

User approved the rewrite and architecture; implementation proceeds inline under that authorization. Git metadata is read-only in this harness: worktree creation failed, so work stays in the supplied checkout without commits, merges or pushes. Task completion and rulings are recorded in a private progress ledger. These environment limits do not change the product design.
