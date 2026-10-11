#!/usr/bin/env bash
# Shared by installed CLI/wrappers and repository installer. No global environment edits.
SP_LIB_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SP_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/selective-proxy"
SP_CONFIG="$SP_DIR/config.json"
SP_SETTINGS="$SP_DIR/settings.json"
SP_UNIT=selective-proxy.service
SP_TEMPLATE="$SP_LIB_DIR/../config/sing-box.json.tpl"
[[ -f "$SP_TEMPLATE" ]] || SP_TEMPLATE="$SP_DIR/sing-box.json.tpl"
SP_VALIDATOR="$SP_LIB_DIR/../config/validate-params.jq"
[[ -f "$SP_VALIDATOR" ]] || SP_VALIDATOR="$SP_DIR/validate-params.jq"
fail() { printf 'Ошибка: %s\n' "$*" >&2; return 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Нужна команда $1."; }
render_config() {
    local params=$1 template=${2:-$SP_TEMPLATE}
    jq -e -f "$SP_VALIDATOR" <<< "$params" >/dev/null || { fail 'Некорректные параметры: host key, порты или исключения.'; return 1; }
    jq --argjson p "$params" '
      .inbounds[0].listen_port=$p.proxy_port |
      .outbounds[0].server=$p.server | .outbounds[0].server_port=$p.ssh_port |
      .outbounds[0].user=$p.user | .outbounds[0].private_key_path=$p.key |
      .outbounds[0].host_key=[$p.host_key] |
      .outbounds[0].host_key_algorithms=(($p.host_key|split(" ")[0]) as $alg |
        if $alg=="ssh-rsa" then ["rsa-sha2-512","rsa-sha2-256"] else [$alg] end) |
      .route.rules[2].ip_cidr=$p.cidrs | .route.rules[3].domain_suffix=$p.domains |
      .route.rules |= map(select((has("ip_cidr")|not) or (.ip_cidr|length)>0)) |
      .route.rules |= map(select((has("domain_suffix")|not) or (.domain_suffix|length)>0))
    ' "$template"
}
validate_config() {
    local file=${1:-$SP_CONFIG} params expected
    [[ -r "$file" ]] || { fail "Нет конфигурации: $file. Запустите install.sh."; return 1; }
    params=$(jq -e '{server:.outbounds[0].server,ssh_port:.outbounds[0].server_port,
      user:.outbounds[0].user,key:.outbounds[0].private_key_path,host_key:.outbounds[0].host_key[0],
      proxy_port:.inbounds[0].listen_port,
      domains:[.route.rules[]|select(.outbound=="direct")|.domain_suffix[]?],
      cidrs:[.route.rules[]|select(.outbound=="direct")|.ip_cidr[]?]}' "$file") || return 1
    expected=$(render_config "$params") || return 1
    # Allow log tuning only. All network-relevant fields must match the audited template.
    jq -e --argjson expected "$expected" 'del(.log) == ($expected|del(.log))' "$file" >/dev/null || {
      fail 'Конфигурация нарушает политику loopback / pinned SSH / fail-closed. Изменяйте параметры установщиком.'; return 1;
    }
}
validate_settings() {
    [[ -f "$SP_SETTINGS" ]] || return 0
    jq -e '(.key_mode=="unattended" or .key_mode=="session") and
      ((.expected_ips // []) | type=="array" and all(.[]; type=="string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))) and
      ((.local_tests // []) | type=="array" and all(.[]; type=="string" and test("^https?://")))' "$SP_SETTINGS" >/dev/null || {
        fail 'Некорректный settings.json.'; return 1;
    }
    if [[ $(jq -r '.key_mode' "$SP_SETTINGS") == session ]]; then
        [[ -n "${XDG_RUNTIME_DIR:-}" && $(jq -r '.outbounds[0].private_key_path' "$SP_CONFIG") == "$XDG_RUNTIME_DIR/selective-proxy/session.key" ]] || {
            fail 'Runtime key path не соответствует выделенному файлу сеанса.'; return 1;
        }
    fi
}
load_config() {
    need jq && need curl && need timeout || return 1
    validate_config && validate_settings || return 1
    SP_PORT=$(jq -r '.inbounds[0].listen_port' "$SP_CONFIG")
    SP_PROXY="http://127.0.0.1:$SP_PORT"
    # Used by sourced CLI.
    # shellcheck disable=SC2034
    SP_SERVER=$(jq -r '.outbounds[0].server' "$SP_CONFIG")
    # shellcheck disable=SC2034
    SP_SSH_PORT=$(jq -r '.outbounds[0].server_port' "$SP_CONFIG")
}
# bash -c expands the positional parameters in its own shell.
# shellcheck disable=SC2016
tcp_ready() { timeout 3 bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "$1" "$2" 2>/dev/null; }
fetch() {
    local proxy=$1 url=$2; shift 2
    # -q must be first: ignore ~/.curlrc; never allow NO_PROXY to defeat explicit proxy.
    curl -q --silent --show-error --fail --connect-timeout 5 --max-time 15 \
      --proto '=http,https' --noproxy '' --proxy "$proxy" "$@" "$url"
}
valid_ip() {
    jq -en --arg ip "$1" '$ip | if contains(":") then test("^[0-9a-fA-F:]+$")
      else split(".") | length==4 and all(.[]; test("^[0-9]+$") and (tonumber<=255)) end' >/dev/null
}
verify_egress() {
    local ip pins='[]'
    if ! owned || ! grep -q '^# Managed by cproxy' "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/$SP_UNIT" 2>/dev/null ||
       ! systemctl --user is-active --quiet "$SP_UNIT"; then
        fail 'Прокси cproxy выключен. Включите его через меню или proxyctl start.'; return 1
    fi
    ip=$(fetch "$SP_PROXY" https://api4.ipify.org) || { fail 'HTTP-прокси не выходит в интернет. Проверьте SSH, ключ и proxyctl logs.'; return 1; }
    valid_ip "$ip" || { fail 'IP-сервис вернул некорректный ответ.'; return 1; }
    [[ ! -f "$SP_SETTINGS" ]] || pins=$(jq -ce '.expected_ips // []' "$SP_SETTINGS") || return 1
    if [[ "$pins" != '[]' ]]; then
        jq -en --arg ip "$ip" --argjson pins "$pins" '$pins|index($ip)!=null' >/dev/null || {
            fail "Неожиданный выходной IP ($ip). Сверьте expected_ips с VPS; Claude не запущен."; return 1;
        }
    fi
    printf '%s\n' "$ip"
}
wait_ready() {
    local i
    for ((i=0; i<15; i++)); do
        if systemctl --user is-active --quiet "$SP_UNIT" && tcp_ready 127.0.0.1 "$SP_PORT"; then
            verify_egress; return $?
        fi
        sleep 1
    done
    fail 'Сервис не готов. proxyctl logs'
}
owned() { [[ -d "$SP_DIR" && ! -L "$SP_DIR" && -f "$SP_DIR/.cproxy-owner" ]] && [[ $(cat "$SP_DIR/.cproxy-owner") == cproxy-v1 ]]; }
check_key() {
    [[ -f "$1" && -r "$1" && ! -L "$1" ]] || { fail 'SSH-ключ должен быть обычным читаемым файлом.'; return 1; }
    [[ $(stat -c %u "$1") == "$UID" ]] || { fail 'SSH-ключ должен принадлежать текущему пользователю.'; return 1; }
    local mode; mode=$(stat -c %a "$1")
    (( (8#$mode & 077) == 0 )) || { fail 'Ограничьте SSH-ключ: chmod 600 /путь/к/ключу'; return 1; }
    ssh-keygen -y -P '' -f "$1" >/dev/null 2>&1
}
unlock_key() {
    local source=$1 destination=$2
    [[ -f "$source" && ! -L "$source" && $(stat -c %u "$source") == "$UID" ]] || { fail 'Оригинальный ключ должен принадлежать пользователю.'; return 1; }
    local mode; mode=$(stat -c %a "$source")
    (( (8#$mode & 077) == 0 )) || { fail 'Для оригинального ключа нужен chmod 600.'; return 1; }
    [[ -t 0 ]] || { fail 'Для разблокирования ключа нужен интерактивный терминал.'; return 1; }
    mkdir -p -- "$(dirname -- "$destination")"; chmod 700 "$(dirname -- "$destination")"
    [[ ! -L "$destination" ]] || { fail 'Runtime key является symlink.'; return 1; }
    cp -- "$source" "$destination"; chmod 600 "$destination"
    printf 'Введите старую passphrase; новая будет пустой. Она не записывается в конфиг.\n'
    ssh-keygen -p -N '' -f "$destination" || { rm -f -- "$destination"; return 1; }
    check_key "$destination" || { rm -f -- "$destination"; fail 'Не удалось прочитать разблокированный ключ.'; return 1; }
}
