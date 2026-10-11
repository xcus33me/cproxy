# Диагностика

Начните с `proxyctl status`, затем `proxyctl test`, затем `proxyctl logs`. Windows: те же аргументы `proxyctl.ps1`. Логи warn могут содержать hostnames/IP; не публикуйте конфиг, путь к ключу, адреса внутренних серверов или debug-логи без просмотра. Пароли/Claude tokens скрипты не запрашивают и не выводят.

| Симптом | Действие |
|---|---|
| Нет user systemd | Запустите из обычного desktop-сеанса; не через sudo. Проверьте `systemctl --user show-environment` |
| Порт занят | Linux: `ss -ltnp 'sport = :2080'`; Windows: `Get-NetTCPConnection -LocalPort 2080`. Выберите другой порт через reconfigure, затем перезапустите Claude Firefox |
| Ключ VPS изменился / Host key mismatch | Установщик автоматически использует сохранённый ключ. Проверьте адрес; при намеренной переустановке VPS получите новый ключ через консоль провайдера и явно передайте его в параметрах по docs/ssh-setup.md. `--reconfigure` сам по себе не сбрасывает старый ключ |
| Key encrypted/invalid | Используйте session или отдельный ограниченный unattended key. Проверяйте формат OpenSSH и permissions/ACL |
| Runtime key missing | В session выполните unlock из интерактивного терминала. В Linux нужен нормальный `$XDG_RUNTIME_DIR` |
| SSH TCP доступен, proxy нет | Это может быть неверный user/key, запрет TCP forwarding или VPS DNS. Смотрите sing-box/SSHD логи; локальный порт не доказывает forwarding |
| Direct и proxy IP одинаковы | Это само по себе не ошибка, например при включённой Amnezia. Сравнение больше не блокирует запуск. HTTP и SOCKS5 должны работать; при желании можно дополнительно закрепить независимо проверенный исходящий IPv4 в expected_ips |
| Unexpected egress IP | Возможно, сменился выход VPS. Проверьте через консоль, обновите только проверенный pin; не удаляйте pin ради прохождения теста |
| IPv6 unavailable | Отсутствие IPv6 у сети/VPS нормально. Внешний IPv4 через HTTP и SOCKS5 должен работать |
| Firefox already running/profile in use | Закройте все окна выделенного профиля. Основной Firefox может оставаться открыт. Не удаляйте lock-файлы живого профиля |
| Локальный сервис по IP работает, по имени нет | Добавьте конкретный внутренний suffix в параметры. Внешние домены не разрешаются локально ради угадывания private IP |
| sing-box после обновления не стартует | Проверьте `sing-box check -c` и версию. Установщик откатывает cproxy-файлы, не обновлённый binary |
| Windows task не запускается | Проверьте LastTaskResult, права текущего пользователя, RemoteSigned/Zone.Identifier, абсолютный binary путь. Новый PATH иногда требует нового PowerShell |
| После uninstall install просит параметры | Конфиг удалён намеренно; сохранён только Firefox-профиль. Пройдите мастер снова |

## Проверка AmneziaVPN

cproxy не меняет Amnezia, default routes, DNS или firewall. При выключенном Amnezia выполните status/test и запишите egress. Повторите после его включения. Linux status показывает `ip route get` для разрешённого IPv4 VPS; Windows — `Find-NetRoute`. Это снимок маршрута, не доказательство независимости туннелей.

При активном VPN SSH TCP может использовать VPN-интерфейс; kill switch может запретить VPS или локальный proxy. Сначала проверяйте доступность VPS. Если меняете состояние Amnezia, открытые SSH/TCP streams могут прерваться. Выполните `proxyctl restart`, если следующая попытка не восстанавливается. Не отключайте корпоративный firewall для диагностики и не обещайте независимость без проверки.

## Ручное восстановление

Остановить управляемый proxy можно даже при повреждённом JSON (`proxyctl stop`). В Linux при полном повреждении файлов остаётся `systemctl --user stop selective-proxy.service`. Windows используйте принадлежащую вам задачу и inspect PID перед ручным завершением процесса; не выполняйте `taskkill /IM sing-box.exe` для всех процессов.

Если процесс установки был прерван питанием, проверьте скрытые stage/backup-каталоги в родительском config/LOCALAPPDATA. Они могут содержать чувствительные connection details или Windows runtime key. Остановите cproxy, сохраните текущие файлы отдельно и восстановите известную предыдущую папку; затем повторите installer. Не удаляйте backup вслепую. За пределами штатных обработанных ошибок полного journaling не реализовано.
