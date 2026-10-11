# cproxy terminal interface implementation plan

Goal: a single friendly terminal application, with three connection fields, editable review, cancellation, and a persistent action menu; remove the false failure when direct and proxied exits coincide.

Architecture: Go Huh forms render the interface; existing Bash/PowerShell continue to own configuration policy, sing-box, services, rollback, key pinning and wrappers. No new networking implementation. CLI executes backend scripts with argument arrays, never shell interpolation. Installer delegates interactive entry to the UI and accepts a private wizard file from it.

Constraints: loopback only; final SSH, no fallback; retain optional explicit expected_ips validation; no required outgoing-IP input; encrypted keys use session mode, never save passphrases; old config retained on apply failure; Windows needs no globally changed PATH/profile.

Tasks:
- [x] Add regression tests for equal direct/proxy IP and readiness errors; fix both backends and suppress repeated diagnostic errors while waiting for readiness.
- [x] Add tested wizard data validation, default-key detection, secure temporary files, argument-safe backend dispatch; implement Go Huh forms and main menu with previous/edit/cancel/retry.
- [x] Wire Linux/Windows entrypoints, installed UI and uninstall ownership, source builds and release artifacts. Keep automation via --params / -ParamsFile.
- [x] Run backend suite, Go tests, syntax/lint, Linux interactive smoke/cancel, Windows cross-compile; rewrite quickstart and record remaining native Windows/VPS checks.

Review focus: equal IP with an existing VPN; cancellation before and during apply; spaces in key/project paths; encrypted key selection; retry after a failed transaction; installed binary finding its own backends.
