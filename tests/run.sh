#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
python3 -m unittest discover -s tests -v
bash -n cproxy linux/*.sh linux/proxyctl tests/*.sh
if command -v fish >/dev/null; then fish -n linux/claude-vpn.fish; else echo 'SKIP: fish syntax (fish missing)'; fi
if command -v shellcheck >/dev/null; then shellcheck cproxy linux/*.sh linux/proxyctl tests/*.sh; else echo 'SKIP: shellcheck missing'; fi
if command -v pwsh >/dev/null; then
    pwsh -NoProfile -File tests/syntax.ps1
    pwsh -NoProfile -File tests/windows-tests.ps1
    pwsh -NoProfile -File tests/windows-host-key-tests.ps1
else echo 'SKIP: PowerShell tests (pwsh missing)'; fi

if command -v go >/dev/null; then go test ./...; else echo 'SKIP: Go UI tests (Go missing)'; fi
