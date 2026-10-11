#!/usr/bin/env bash
set -euo pipefail
umask 077
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=linux/common.sh
source "$HERE/common.sh"
# Import an existing pin, otherwise use default OpenSSH trust, otherwise TOFU.
# The selected key is saved in config.json; never change global known_hosts.
automatic_host_key() {
    local server=$1 port=$2 scan=$3 offered lookup known='' found file candidate status
    offered=$(awk '!/^#/ && NF>=3 {print $2" "$3}' <<< "$scan")
    if [[ -f "$SP_CONFIG" ]]; then
        validate_config || return 1
        if jq -e --arg server "$server" --argjson port "$port" '.outbounds[0] | .server==$server and .server_port==$port' "$SP_CONFIG" >/dev/null; then
            candidate=$(jq -r '.outbounds[0].host_key[0]' "$SP_CONFIG")
            grep -Fxq -- "$candidate" <<< "$offered" || { fail 'Ключ VPS изменился. Сохранённый ключ не будет заменён автоматически.'; return 1; }
            printf '%s\n' "$candidate"; return 0
        fi
    fi
    lookup=$server; [[ "$port" == 22 ]] || lookup="[$server]:$port"
    for file in "$HOME/.ssh/known_hosts" /etc/ssh/ssh_known_hosts; do
        [[ -e "$file" ]] || continue
        [[ -r "$file" ]] || { fail "Не удалось прочитать $file."; return 1; }
        status=0
        found=$(ssh-keygen -F "$lookup" -f "$file") || status=$?
        ((status <= 1)) || { fail "Не удалось проверить $file."; return 1; }
        known+="$found"$'\n'
    done
    if awk '$1 ~ /^@/ {found=1} END {exit !found}' <<< "$known"; then
        fail 'Для VPS найден отозванный ключ или SSH CA. Автоматическая настройка такого доступа не поддерживается.'; return 1
    fi
    known=$(awk '!/^#/ && NF>=3 {print $2" "$3}' <<< "$known")
    if [[ -n "$known" ]]; then
        while IFS= read -r candidate; do
            if grep -Fxq -- "$candidate" <<< "$offered"; then
                echo 'Используется сохранённый ключ SSH-сервера.' >&2
                printf '%s\n' "$candidate"; return 0
            fi
        done <<< "$known"
        fail 'Ключ VPS не совпадает с сохранённым в SSH. Проверьте адрес сервера; установка отменена.'; return 1
    fi
    candidate=$(awk '!/^#/ && NF>=3 {if (!first) first=$2" "$3; if ($2=="ssh-ed25519") ed=$2" "$3} END {print ed ? ed : first}' <<< "$scan")
    [[ -n "$candidate" ]] || { fail 'Не получен ключ SSH-сервера.'; return 1; }
    echo 'Первое подключение: ключ SSH-сервера будет сохранён автоматически.' >&2
    printf '%s\n' "$candidate"
}
params_file=''; wizard_file=''; reconfigure=0
while (($#)); do
    case "$1" in
        --params) [[ $# -ge 2 ]] || exit 2; params_file=$2; shift 2 ;;
        --wizard-file) [[ $# -ge 2 ]] || exit 2; wizard_file=$2; reconfigure=1; shift 2 ;;
        --reconfigure) reconfigure=1; shift ;;
        --help|-h) echo 'install.sh [--reconfigure | --params FILE]'; exit 0 ;;
        *) fail "Неизвестный аргумент: $1"; exit 2 ;;
    esac
done
if [[ -z "$params_file" && -z "$wizard_file" && -t 0 ]]; then
    launcher="$HERE/../cproxy"
    if [[ -x "$HERE/cproxy-ui" ]]; then exec "$HERE/cproxy-ui" setup; fi
    exec "$launcher" setup
fi
[[ $(uname -s) == Linux ]] || { fail 'Требуется Linux.'; exit 1; }
[[ "$UID" != 0 ]] || { fail 'Запускайте от обычного пользователя, без sudo.'; exit 1; }
# shellcheck source=/dev/null
source /etc/os-release
arch_like=0
if [[ "${ID:-} ${ID_LIKE:-}" == *arch* || "${ID:-}" == cachyos ]]; then arch_like=1; fi
if ((!arch_like)); then echo 'ОС вне Arch/CachyOS: зависимости должны быть установлены заранее; автоматическая установка пакетов недоступна.' >&2; fi
case $(uname -m) in x86_64|aarch64) ;; *) fail 'Неподдерживаемая архитектура.'; exit 1;; esac
for dependency in jq curl openssh; do
    case "$dependency" in openssh) binary=ssh-keyscan;; *) binary=$dependency;; esac
    if ! command -v "$binary" >/dev/null; then
        ((arch_like)) || { fail "Установите зависимость $dependency самостоятельно."; exit 1; }
        [[ -t 0 ]] || { fail "Установите $dependency через pacman."; exit 1; }
        read -r -p "Установить $dependency через sudo pacman -S? [y/N] " answer
        [[ "$answer" == y ]] || exit 1
        sudo pacman -S --needed "$dependency"
        need "$binary"
    fi
done
if ! command -v sing-box >/dev/null; then
    ((arch_like)) || { fail 'Установите sing-box самостоятельно; автоматическая установка поддерживается на Arch.'; exit 1; }
    [[ -t 0 ]] || { fail 'Установите sing-box: sudo pacman -S sing-box'; exit 1; }
    read -r -p 'Установить sing-box через sudo pacman -S? [y/N] ' answer
    [[ "$answer" == y ]] || exit 1
    sudo pacman -S --needed sing-box
    need sing-box
fi
for binary in ssh-keygen timeout systemctl flock; do need "$binary"; done
version=$(sing-box version | awk 'NR==1 {print $3}')
[[ $(printf '%s\n' 1.12.0 "$version" | sort -V | head -1) == 1.12.0 ]] || { fail 'Нужен sing-box >= 1.12.0.'; exit 1; }
systemctl --user show-environment >/dev/null || { fail 'Недоступен systemd --user. Запустите из пользовательского сеанса.'; exit 1; }
mkdir -p -- "$(dirname -- "$SP_DIR")"
exec 9>"$(dirname -- "$SP_DIR")/.selective-proxy-install.lock"
flock -n 9 || { fail 'Другой установщик уже работает.'; exit 1; }
existing=0
if [[ -e "$SP_DIR" ]]; then
    if [[ -L "$SP_DIR" ]] || ! owned; then fail 'Каталог selective-proxy не принадлежит cproxy.'; exit 1; fi
    existing=1
fi
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
unit_file="$unit_dir/$SP_UNIT"
if [[ -e "$unit_file" ]] && ! grep -qx '# Managed by cproxy. Installer writes absolute quoted paths from this template.' "$unit_file"; then
    fail 'Существующий unit не принадлежит cproxy.'; exit 1
fi
bin_dir="$HOME/.local/bin"
for name in proxyctl claude-vpn cproxy; do
    if [[ -e "$bin_dir/$name" || -L "$bin_dir/$name" ]]; then
        grep -qx '# Managed by cproxy' "$bin_dir/$name" || { fail "Команда $name уже существует и не принадлежит cproxy."; exit 1; }
    fi
done
fish_file="${XDG_CONFIG_HOME:-$HOME/.config}/fish/functions/claude-vpn.fish"
if [[ -e "$fish_file" ]] && ! grep -qx '# Managed by cproxy' "$fish_file"; then
    fail 'Fish function claude-vpn уже существует.'; exit 1
fi
stage=$(mktemp -d "$(dirname -- "$SP_DIR")/.selective-proxy-stage.XXXXXX")
backup=''; applied=0; committed=0; was_active=0; was_enabled=0
session_candidate=''; session_backup=''; session_replaced=0; session_had_key=0
systemctl --user is-active --quiet "$SP_UNIT" && was_active=1
systemctl --user is-enabled --quiet "$SP_UNIT" && was_enabled=1
cleanup() {
    local result=$?
    trap - EXIT
    if ((applied && !committed)); then
        echo 'Установка не завершена; восстанавливаю предыдущую версию.' >&2
        systemctl --user stop "$SP_UNIT" || true
        if [[ -n "$backup" && -d "$backup" ]]; then
            rm -rf -- "$SP_DIR"; mv -- "$backup" "$SP_DIR"
        elif ((!existing)); then rm -rf -- "$SP_DIR"; fi
        if ((session_replaced)); then
            if ((session_had_key)); then mv -f -- "$session_backup" "$key"; else rm -f -- "$key"; fi
        fi
        if [[ -f "$stage/previous-unit" ]]; then cp -- "$stage/previous-unit" "$unit_file"; else rm -f -- "$unit_file"; fi
        if ((!existing)); then
            for name in proxyctl claude-vpn cproxy; do
                if [[ -f "$bin_dir/$name" ]] && grep -qx '# Managed by cproxy' "$bin_dir/$name"; then rm -f -- "$bin_dir/$name"; fi
            done
            if [[ -f "$fish_file" ]] && grep -qx '# Managed by cproxy' "$fish_file"; then rm -f -- "$fish_file"; fi
        fi
        systemctl --user daemon-reload || true
        if ((was_enabled)); then systemctl --user enable "$SP_UNIT" || true; else systemctl --user disable "$SP_UNIT" || true; fi
        if ((was_active)); then systemctl --user start "$SP_UNIT" || true; fi
    fi
    rm -rf -- "$stage"
    [[ -z "$session_candidate" ]] || rm -f -- "$session_candidate"
    [[ -z "$session_backup" ]] || rm -f -- "$session_backup"
    if ((committed)) && [[ -n "$backup" && -e "$backup" ]]; then rm -rf -- "$backup"; fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$stage/app"
if ((existing)); then cp -a -- "$SP_DIR/." "$stage/app/"; fi
if [[ -n "$params_file" ]]; then
    params=$(jq -ce . "$params_file")
elif ((existing && !reconfigure)) && [[ -f "$SP_CONFIG" ]]; then
    validate_config
    params=$(jq -c '{server:.outbounds[0].server,ssh_port:.outbounds[0].server_port,user:.outbounds[0].user,
      key:.outbounds[0].private_key_path,host_key:.outbounds[0].host_key[0],proxy_port:.inbounds[0].listen_port,
      domains:[.route.rules[]|select(.outbound=="direct")|.domain_suffix[]?],
      cidrs:[.route.rules[]|select(.outbound=="direct")|.ip_cidr[]?]}' "$SP_CONFIG")
elif [[ -n "$wizard_file" ]]; then
    params=$(jq -ce . "$wizard_file")
    server=$(jq -r '.server' <<< "$params"); ssh_port=$(jq -r '.ssh_port' <<< "$params")
    [[ "$ssh_port" =~ ^[0-9]+$ && "$server" =~ ^[a-zA-Z0-9][a-zA-Z0-9.:-]*$ ]] || { fail 'Некорректный адрес или порт.'; exit 1; }
    scan=$(ssh-keyscan -T 5 -p "$ssh_port" -t ed25519,ecdsa,rsa "$server" 2>/dev/null) || { fail 'SSH-сервер не отвечает.'; exit 1; }
    host_key=$(automatic_host_key "$server" "$ssh_port" "$scan")
    key=$(jq -r '.key' <<< "$params"); case "$key" in \~/*) key="$HOME/${key:2}" ;; esac
    params=$(jq -c --arg key "$key" --arg host_key "$host_key" '.key=$key | .host_key=$host_key | .domains=["local"] |
      .cidrs=["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","::1/128","fc00::/7","fe80::/10"]' <<< "$params")
    if ((existing)) && [[ -f "$SP_CONFIG" ]] && ! jq -e --arg server "$server" --argjson port "$ssh_port" '.outbounds[0] | .server==$server and .server_port==$port' "$SP_CONFIG" >/dev/null; then
        params=$(jq -c '.expected_ips=[]' <<< "$params")
    fi
else
    fail 'Для настройки запустите ./cproxy setup в терминале; для автоматизации используйте --params FILE.'; exit 1

fi
if ((existing && reconfigure)) && [[ -z "$params_file" && -f "$SP_CONFIG" ]]; then
    domains=$(jq -c '[.route.rules[]|select(.outbound=="direct")|.domain_suffix[]?]' "$SP_CONFIG")
    cidrs=$(jq -c '[.route.rules[]|select(.outbound=="direct")|.ip_cidr[]?]' "$SP_CONFIG")
    params=$(jq -c --argjson domains "$domains" --argjson cidrs "$cidrs" '.domains=$domains|.cidrs=$cidrs' <<< "$params")
fi
key_mode=$(jq -r '.key_mode // empty' <<< "$params")
if [[ -z "$key_mode" && -f "$SP_SETTINGS" ]]; then key_mode=$(jq -r '.key_mode' "$SP_SETTINGS"); fi
key_mode=${key_mode:-unattended}
key=$(jq -r '.key' <<< "$params")
[[ "$key" == /* ]] || { fail 'Путь к ключу должен быть абсолютным.'; exit 1; }
if [[ "$key_mode" == session ]]; then
    [[ -n "${XDG_RUNTIME_DIR:-}" && -d "$XDG_RUNTIME_DIR" && $(stat -c %u "$XDG_RUNTIME_DIR") == "$UID" ]] || { fail 'Для session нужен принадлежащий пользователю XDG_RUNTIME_DIR.'; exit 1; }
    if [[ -z "$params_file" ]] && ((existing && !reconfigure)); then
        encrypted_key=$(jq -r '.encrypted_key_path' "$SP_SETTINGS")
    else
        encrypted_key=$key
        key="$XDG_RUNTIME_DIR/selective-proxy/session.key"
        mkdir -p -- "$(dirname -- "$key")"; chmod 700 "$(dirname -- "$key")"
        session_candidate=$(mktemp "$XDG_RUNTIME_DIR/selective-proxy/session.new.XXXXXX")
        unlock_key "$encrypted_key" "$session_candidate"
    fi
    check_key "${session_candidate:-$key}" || { fail 'Ключ заблокирован. proxyctl unlock, затем повторите обновление.'; exit 1; }
    params=$(jq -c --arg key "$key" '.key=$key' <<< "$params")
elif [[ "$key_mode" == unattended ]]; then
    check_key "$key" || { fail 'Ключ повреждён или защищён passphrase. Используйте session либо отдельный ключ без passphrase.'; exit 1; }
else fail 'key_mode: unattended или session.'; exit 1; fi
if ((existing && !reconfigure)) && [[ -z "$params_file" && -f "$SP_CONFIG" ]]; then
    cp -- "$SP_CONFIG" "$stage/app/config.json"
else render_config "$params" > "$stage/app/config.json"; fi
validate_config "$stage/app/config.json"
check_file="$stage/app/config.json"
if [[ -n "$session_candidate" ]]; then
    jq --arg key "$session_candidate" '.outbounds[0].private_key_path=$key' "$check_file" > "$stage/check.json"
    check_file="$stage/check.json"
fi
sing-box check -c "$check_file"
# Verify the offered live host key matches an explicitly pinned key. Never write global known_hosts.
server=$(jq -r '.server' <<< "$params"); ssh_port=$(jq -r '.ssh_port' <<< "$params")
host_key=$(jq -r '.host_key' <<< "$params")
scan=$(ssh-keyscan -T 5 -p "$ssh_port" "$server" 2>/dev/null) || { fail 'VPS SSH недоступен.'; exit 1; }
awk '{print $2" "$3}' <<< "$scan" | grep -Fxq -- "$host_key" || { fail 'VPS host key изменился или не совпадает.'; exit 1; }
SP_PORT=$(jq -r '.proxy_port' <<< "$params")
if tcp_ready 127.0.0.1 "$SP_PORT" && ! ((existing && was_active)); then fail "Порт $SP_PORT занят."; exit 1; fi
if [[ ! -f "$stage/app/settings.json" ]]; then echo '{"expected_ips":[],"local_tests":[]}' > "$stage/app/settings.json"; fi
jq --argjson p "$params" --arg mode "$key_mode" --arg encrypted "${encrypted_key:-}" \
  '.key_mode=$mode | .encrypted_key_path=$encrypted |
   if $p|has("expected_ips") then .expected_ips=$p.expected_ips else . end |
   if $p|has("local_tests") then .local_tests=$p.local_tests else . end' \
  "$stage/app/settings.json" > "$stage/settings.json"
mv -- "$stage/settings.json" "$stage/app/settings.json"
cp -- "$HERE/common.sh" "$HERE/proxyctl" "$HERE/claude-vpn.sh" "$HERE/claude-vpn.fish" "$HERE/uninstall.sh" "$HERE/install.sh" "$HERE/selective-proxy.service" "$stage/app/"
if [[ -n "${CPROXY_UI_BINARY:-}" ]]; then cp -- "$CPROXY_UI_BINARY" "$stage/app/cproxy-ui"; chmod 755 "$stage/app/cproxy-ui"; fi
cp -- "$SP_TEMPLATE" "$SP_VALIDATOR" "$stage/app/"
echo cproxy-v1 > "$stage/app/.cproxy-owner"
chmod 700 "$stage/app"; chmod 600 "$stage/app/config.json" "$stage/app/settings.json"
# systemd quoted arguments: escape its own dollar/specifier parsing as well as quotes.
systemd_quote() {
    local value=$1
    [[ "$value" != *$'\n'* ]] || return 1
    value=${value//\\/\\\\}; value=${value//\"/\\\"}; value=${value//\$/\$\$}; value=${value//%/%%}
    printf '"%s"' "$value"
}
executable=$(command -v sing-box)
exec_line="$(systemd_quote "$executable") run -c $(systemd_quote "$SP_CONFIG")"
unit=$(cat "$HERE/selective-proxy.service"); unit=${unit//@EXEC@/$exec_line}
[[ ! -f "$unit_file" ]] || cp -- "$unit_file" "$stage/previous-unit"
applied=1
if ((existing)); then
    backup=$(mktemp -d "$(dirname -- "$SP_DIR")/.selective-proxy-backup.XXXXXX"); rmdir "$backup"
    mv -- "$SP_DIR" "$backup"
fi
if [[ -n "$session_candidate" ]]; then
    if [[ -f "$key" ]]; then
        session_had_key=1
        session_backup=$(mktemp "$XDG_RUNTIME_DIR/selective-proxy/session.previous.XXXXXX")
        cp -- "$key" "$session_backup"
    fi
    session_replaced=1
    mv -f -- "$session_candidate" "$key"
fi
mv -- "$stage/app" "$SP_DIR"
mkdir -p -- "$unit_dir"
printf '%s\n' "$unit" > "$unit_file"
systemctl --user daemon-reload
if [[ "$key_mode" == unattended ]]; then systemctl --user enable "$SP_UNIT"; else systemctl --user disable "$SP_UNIT"; fi
systemctl --user restart "$SP_UNIT"
load_config
wait_ready
# Publish shell launchers only after the service is ready.
mkdir -p -- "$bin_dir" "$(dirname -- "$fish_file")"
for name in proxyctl claude-vpn cproxy; do
    [[ "$name" != cproxy || -x "$SP_DIR/cproxy-ui" ]] || continue
    target="$SP_DIR/proxyctl"; [[ "$name" != claude-vpn ]] || target="$SP_DIR/claude-vpn.sh"
    [[ "$name" != cproxy ]] || target="$SP_DIR/cproxy-ui"
    { printf '#!/usr/bin/env bash\n# Managed by cproxy\nexec '; [[ "$name" == cproxy ]] || printf 'bash '; printf '%q' "$target"; printf ' "$@"\n'; } > "$bin_dir/$name"
    chmod 755 "$bin_dir/$name"
done
{ echo '# Managed by cproxy'; cat "$HERE/claude-vpn.fish"; } > "$fish_file"
committed=1
printf 'Готово. Меню: ~/.local/bin/cproxy. PATH должен содержать ~/.local/bin.\nПроверка: %s/proxyctl test\nFirefox: %s/proxyctl browser\nClaude Code: %s/claude-vpn --help\n' "$bin_dir" "$bin_dir" "$bin_dir"
[[ "$key_mode" != session ]] || echo 'После нового входа: proxyctl unlock. Автозапуск отключён для защищённого ключа.'
