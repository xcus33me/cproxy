#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# Symlink launchers are resolved by their small installed scripts.
# shellcheck source=linux/common.sh
source "$HERE/common.sh"
load_config
verify_egress >/dev/null
need claude
for argument in "$@"; do
    [[ "$argument" != --bg && "$argument" != --bg=* ]] || { fail 'Для фоновых агентов нужны отдельные настройки: docs/claude-code.md'; exit 1; }
done
[[ ${1:-} != agents ]] || { fail 'Фоновый supervisor не наследует wrapper надёжно: docs/claude-code.md'; exit 1; }
# Explicit values in both cases override inherited settings; no broad NO_PROXY exception.
exec env -u ALL_PROXY -u all_proxy HTTP_PROXY="$SP_PROXY" HTTPS_PROXY="$SP_PROXY" \
    http_proxy="$SP_PROXY" https_proxy="$SP_PROXY" NO_PROXY=localhost,127.0.0.1,::1 \
    no_proxy=localhost,127.0.0.1,::1 claude "$@"
