#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=linux/common.sh
source "$HERE/common.sh"
owned || { fail 'Нет управляемой установки; ничего не удалено.'; exit 1; }
exec 9>"$(dirname -- "$SP_DIR")/.selective-proxy-install.lock"
flock -n 9 || { fail 'Установка уже выполняется.'; exit 1; }
unit_file="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/$SP_UNIT"
if [[ -f "$unit_file" ]]; then
    grep -q '^# Managed by cproxy' "$unit_file" || { fail 'Unit не принадлежит cproxy.'; exit 1; }
    systemctl --user disable --now "$SP_UNIT"
    rm -f -- "$unit_file"
    systemctl --user daemon-reload
fi
# Only the dedicated runtime copy, never the original SSH key.
if [[ -f "$SP_SETTINGS" && $(jq -r '.key_mode' "$SP_SETTINGS") == session && -n "${XDG_RUNTIME_DIR:-}" ]]; then
    rm -f -- "$XDG_RUNTIME_DIR/selective-proxy/session.key"
    rmdir -- "$XDG_RUNTIME_DIR/selective-proxy" 2>/dev/null || true
fi
for name in proxyctl claude-vpn cproxy; do
    file="$HOME/.local/bin/$name"
    if [[ -f "$file" ]] && grep -qx '# Managed by cproxy' "$file"; then rm -f -- "$file"; fi
done
file="${XDG_CONFIG_HOME:-$HOME/.config}/fish/functions/claude-vpn.fish"
if [[ -f "$file" ]] && grep -qx '# Managed by cproxy' "$file"; then rm -f -- "$file"; fi
for name in config.json settings.json common.sh proxyctl claude-vpn.sh claude-vpn.fish uninstall.sh install.sh selective-proxy.service cproxy-ui sing-box.json.tpl validate-params.jq; do
    rm -f -- "$SP_DIR/$name"
done
if [[ $(find "$SP_DIR" -mindepth 1 -maxdepth 1 ! -name .cproxy-owner | wc -l) == 0 ]]; then
    rm -f -- "$SP_DIR/.cproxy-owner"; rmdir -- "$SP_DIR"
fi
echo 'Удалены только файлы cproxy. Firefox-профиль и оригинальные SSH-ключи сохранены. sing-box оставлен установленным.'
