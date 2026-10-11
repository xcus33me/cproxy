# Выделенный Firefox Claude

`proxyctl browser` создаёт только каталог `firefox-Claude` внутри каталога cproxy и managed `user.js`. Запускается Firefox с явным `--profile` и `--no-remote --new-instance`. `profiles.ini`, основной профиль, bookmarks и существующие расширения основного профиля не изменяются. Имя «Claude» здесь означает выделенный профиль по пути. Для `-P Claude` можно вручную зарегистрировать отдельный профиль, но cproxy всегда использует свой явный путь.

На Linux/niri Firefox обычно автоматически выбирает Wayland. При необходимости запустите из fish `env MOZ_ENABLE_WAYLAND=1 proxyctl browser`; это переменная только данного процесса.

Настройки:

- Manual proxy (`network.proxy.type=1`). Отдельные HTTP/SSL proxy fields очищены, shared settings отключены.
- SOCKS5 `127.0.0.1`, порт из конфига. Remote DNS включён для SOCKS (`socks_remote_dns` и `socks5_remote_dns`). Список «без прокси» пуст.
- Direct failover и proxy bypass отключены; встроенный DoH отключён (`network.trr.mode=5`). Предварительные DNS, prefetch и speculative connections отключены.
- WebRTC (`media.peerconnection.enabled=false`) и HTTP/3 отключены. Поэтому voice/video/WebRTC-функции могут не работать; SSH поддерживает TCP, не UDP.

В актуальных версиях часть этих prefs зависит от сборки Firefox; отсутствие direct fallback проверяется поведением, не наличием строки в `about:config`. Firefox может особым образом обрабатывать loopback/system requests. Прокси не является sandbox для расширений, native messaging helpers, updater или внешних приложений. Основной сценарий — HTTP/HTTPS страниц в этом профиле.

Не изменяйте proxy-настройки этого профиля во время работы. `user.js` снова применится при следующем полном запуске Firefox; если окно уже открыто, Firefox может отказаться от второго запуска с тем же профилем. Закройте Claude Firefox перед обновлением настроек. Managed `user.js` перезаписывается; если файл не принадлежит cproxy, команда откажется его трогать.

## Проверка перед логином

Откройте в обычном профиле и выделенном профиле `https://api4.ipify.org`. Выделенный должен показывать проверенный IP выхода VPS. В `about:support` проверьте путь профиля; в `about:config` — перечисленные proxy/DNS prefs.

Проверьте доступный IPv6 через `https://api6.ipify.org`: исходящий IPv6 VPS может отличаться от его IPv4. Проверьте WebRTC тестом и DNS leak test, например BrowserLeaks/DNSLeakTest, либо захватом трафика, если эти сервисы недоступны. Отсутствие WebRTC и отсутствие локальных DNS-запросов для новых внешних сайтов важнее геолокации показанного resolver: VPS может пользоваться публичным resolver в другой стране. DNS для адреса самого VPS на локальной машине допустим.

Остановите cproxy (`proxyctl stop`), оставив окно Firefox открытым. Загрузите новую некэшированную HTTPS-страницу. Должна появиться ошибка proxy, а не обычный IP. Для исключения cache используйте URL с уникальным query и отключите cache в Developer Tools. Запустите `proxyctl start` и повторите запрос.

OAuth: Claude Code может открыть системный default browser. Скопируйте адрес авторизации в выделенный профиль; не меняйте default browser всей системы автоматически. Cookies и токены из обычного профиля не копируются.

## Ручная настройка

Если Firefox не найден, установите его отдельно. Если нужна ручная настройка, откройте `about:profiles`, создайте **новый** профиль Claude, запустите его в отдельном окне. В Settings → Network Settings выберите Manual, оставьте HTTP/HTTPS поля пустыми, задайте SOCKS Host `127.0.0.1`, порт cproxy, SOCKS v5 и Proxy DNS when using SOCKS v5. Очистите bypass list. Затем примените hardening выше только в новом профиле и выполните проверку отказа. Автоматическая команда cproxy продолжит использовать собственный каталог, не ручной профиль.

Источники prefs: [Mozilla StaticPrefList](https://github.com/mozilla-firefox/firefox/blob/main/modules/libpref/init/StaticPrefList.yaml), [Mozilla all.js](https://github.com/mozilla-firefox/firefox/blob/main/modules/libpref/init/all.js).
