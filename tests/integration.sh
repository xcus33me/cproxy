#!/usr/bin/env bash
# Explicitly requested tests against an installed real VPS configuration.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=linux/common.sh
source "$HERE/linux/common.sh"
load_config
case ${1:-} in
    '') exec "$HERE/linux/proxyctl" test ;;
    --outage) ;;
    *) echo 'integration.sh [--outage]' >&2; exit 2 ;;
esac
owned || { fail 'Нужна установленная конфигурация.'; exit 1; }
systemctl --user is-active --quiet "$SP_UNIT" || { fail 'Сначала запустите прокси.'; exit 1; }
verify_egress
# This mode intentionally interrupts cproxy only; restore even when assertion fails.
trap 'systemctl --user start "$SP_UNIT"' EXIT
systemctl --user stop "$SP_UNIT"
for proxy in "$SP_PROXY" "socks5h://127.0.0.1:$SP_PORT"; do
    if fetch "$proxy" https://api4.ipify.org >/dev/null 2>&1; then
        fail 'Прокси-запрос успешен при остановленном сервисе: проверка fail-closed провалена.'; exit 1
    fi
done
if "$HERE/linux/claude-vpn.sh" --help >/dev/null 2>&1; then fail 'Wrapper запустил Claude без proxy.'; exit 1; fi
echo 'PASS: остановленный proxy даёт ошибку; wrapper блокирует запуск. Сервис восстанавливается.'
