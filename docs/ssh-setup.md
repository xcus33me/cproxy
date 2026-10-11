# SSH на VPS

cproxy не устанавливает sing-box на VPS и не меняет SSHD/AmneziaWG. Требуется TCP forwarding в существующем OpenSSH. Не используйте root для повседневного подключения.

## Пользовательский ключ

На Linux создайте **отдельный** ключ:

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
ssh-keygen -t ed25519 -f ~/.ssh/cproxy_ed25519 -C cproxy
chmod 600 ~/.ssh/cproxy_ed25519
```

Укажите passphrase для `session` либо сознательно оставьте пустой для `unattended`. Не снимайте passphrase с основного рабочего ключа. На Windows используйте `ssh-keygen.exe -t ed25519 -f "$HOME\.ssh\cproxy_ed25519" -C cproxy` и ограничьте ACL по инструкции Windows.

Добавьте `.pub` в `~/.ssh/authorized_keys` выделенного непривилегированного пользователя VPS через уже доверенный SSH-доступ/консоль. Создание пользователя выполняется вручную штатными средствами дистрибутива. Не выдавайте ему sudo. У некоторых дистрибутивов полностью locked account не допускает даже public-key SSH: проверьте политику SSHD, не включайте парольный доступ ради forwarding.

Рекомендуемые опции **для строки этого ключа** перед `ssh-ed25519 ...`:

```text
restrict,port-forwarding,command="/usr/bin/false"
```

`restrict` отключает PTY, X11 и agent forwarding; `port-forwarding` возвращает необходимый forwarding. Forced command запрещает обычную shell-сессию при использовании ключа, но не `ssh -N` и direct-tcpip каналы. Убедитесь, что `/usr/bin/false` существует на VPS. Если нужны только веб-запросы, дополнительно рассмотрите `permitopen="*:443",permitopen="*:80"`; тогда другие TCP-порты через proxy работать не будут.

Опциональный ручной SSHD Match для **имени выделенного пользователя**, а не всего сервера:

```text
Match User proxy
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AllowTcpForwarding local
    AllowStreamLocalForwarding no
    GatewayPorts no
    PermitListen none
    PermitTTY no
    AllowAgentForwarding no
    X11Forwarding no
```

Замените `proxy` своим выделенным пользователем. Сохраните уже открытый административный сеанс, проверьте `sudo sshd -t` до ручного reload вашей SSH-службы. Возможности опций зависят от версии OpenSSH. Не вставляйте Match в конфигурацию автоматически: он может взаимодействовать с существующими блоками. cproxy сам этого не делает.

## Подлинность сервера

Установщик больше не запрашивает fingerprint. Ключ выбирается автоматически:

1. Для уже настроенного адреса и SSH-порта сохраняется ключ из конфигурации cproxy. Даже `--reconfigure` / `-Reconfigure` не заменяет его автоматически.
2. При первой настройке используется совпадающий ключ из стандартного OpenSSH `known_hosts`. Поддерживаются хешированные адреса и нестандартные порты. На Linux читаются `~/.ssh/known_hosts` и `/etc/ssh/ssh_known_hosts`; на Windows — `$HOME\.ssh\known_hosts` и `%PROGRAMDATA%\ssh\ssh_known_hosts`. Эти файлы не изменяются. Пользовательские `UserKnownHostsFile`, `HostKeyAlias` и сертификаты SSH CA автоматически не импортируются; записи `@revoked` / `@cert-authority` останавливают автоматическую настройку.
3. Если сохранённого ключа нет, установщик получает его при первом подключении и закрепляет в `config.json` (trust on first use). Предпочитается Ed25519. Это доверие первому подключению, **без независимой проверки подлинности**: подмена сервера именно при первой настройке не исключается. При следующих запусках sing-box проверяет закреплённый ключ, а установщик отказывается молча принимать изменённый ключ.

Для независимой проверки при желании получите ключ через консоль провайдера:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
sudo cat /etc/ssh/ssh_host_ed25519_key.pub
```

Первое — fingerprint для ручной сверки, второе — полный public host key для поля `host_key` в JSON-параметрах. `ssh-keyscan` сам по себе не доказывает подлинность. Если ключ не совпал, остановитесь и выясните причину. После намеренной переустановки VPS проверенный новый ключ можно явно передать через `--params` / `-ParamsFile` по [инструкции о параметрах](architecture.md). Установщик не очищает `known_hosts` и не отключает проверку ключей.

Проверьте forwarding привычным `ssh -N -D 127.0.0.1:1080` с вашим пользователем/хостом. Разные SSH listening IP и egress IP — нормально. IP выхода узнавайте на самом VPS, а не предполагайте равенство. После проверки закройте временный SSH-туннель, чтобы не путать порты.

Официальные источники: [sing-box SSH](https://sing-box.sagernet.org/configuration/outbound/ssh/), [OpenSSH поиск known_hosts](https://man.openbsd.org/ssh-keygen#F), [OpenSSH authorized_keys](https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT), [sshd_config](https://man.openbsd.org/sshd_config).
