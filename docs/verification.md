# Проверка реализации — 2026-10-11

## Выполнено в рабочей Linux-среде

- 33 Python unittest-теста, включая настоящий `sing-box check`, прошли. Установочные тесты используют отдельный HOME с пробелами и подставные systemctl/network-команды: рабочий сервис пользователя не устанавливался. Проверены автоматическое закрепление ключа без вопроса о fingerprint, импорт хешированного known_hosts на нестандартном порту, отказ при изменённом или отозванном ключе, сохранение ключа при повторной настройке, публикация меню и повторная настройка из установленной копии.
- Четыре из этих тестов запускают настоящий Go UI в PTY: экран настройки, отмена без создания конфига, Shift+Tab назад, возврат с экрана подтверждения и исправление данных, выход из меню. Эти проверки не вызывают реальную установку или подключение к VPS.
- 9 Go-тестов прошли: валидация полей, автоматическое определение режима обычного/зашифрованного OpenSSH-ключа, приватный временный JSON и очистка после ошибки/отмены, сохранение аргументов и exit codes. `go vet ./...` и `go test -race ./...` без ошибок. Проверено `./cproxy --help`. Отдельно установлен настоящий Go-бинарник в тестовый HOME и успешно выполнен `status` через установленный launcher с установленными backend-скриптами; systemd/network в этой проверке подставные.
- UI успешно собран для Linux amd64/arm64 и Windows amd64/arm64. Это проверка сборки, не запуска на Windows/ARM64. Готовые архивы настроены в workflow `build.yml`; сам workflow в GitHub ещё не запускался.
- Совпадающие direct/proxy IP без явного IP-pin больше не блокируют запуск; явно заданный pin по-прежнему проверяется. Ошибка сетевой готовности выводится один раз. Остановленный управляемый сервис блокирует wrapper, даже если подставной другой proxy отвечает успешно.
- Bash syntax (`bash -n`), fish syntax (`fish -n`) и ShellCheck 0.11.0: без ошибок.
- PowerShell Parser проверил все Windows/test ps1. PowerShell 7.6.6 **на Linux** выполнил тесты генерации JSON, сетевой политики, quoting/путей и изоляции child environment, включая реальный round trip пустого аргумента через дочерний PowerShell.
- PowerShell на Linux также выполнил тесты автоматического выбора ключа: мастер без fingerprint, хешированный known_hosts, отказ при изменении или отзыве ключа. Чтение known_hosts проверяется настоящим `ssh-keygen`; сетевой ответ SSH-сервера подставной. Это не подтверждает реальную Windows-установку.
- Официальный sing-box **1.14.3**, скачанный во временный каталог: реальный check с временным SSH-ключом, без сети и установки пакета/сервиса.
- Реальный локальный интеграционный тест: временные OpenSSH (несколько host keys) и HTTP server только на loopback, временные ключи, настоящий sing-box. Проверены HTTP и SOCKS5h forwarding, выбор закреплённого Ed25519, отказ при неверном host key и остановленном proxy. Интернет/VPS пользователя в этом тесте не участвовали.
- Отдельная ревизия кода выявила проблемы empty native args PowerShell 5.1, host-key negotiation, session rollback, удаления/повторной установки, stop с повреждённым JSON, ownership задачи и Firefox prefs. Исправлены; покрытие воспроизводящих тестов указано в tests.

## Не выполнено здесь

- Установка/autostart/выход-вход и native Task Scheduler, ACL/interactive key unlock на **настоящей Windows 10/11**. Windows installer fixture tests подготовлены, но здесь требуют Windows и не запускались. PowerShell 5.1 недоступен на Linux: его тесты подготовлены в GitHub Actions, запуск CI ещё не выполнялся.
- Настоящий `systemd --user` autostart после перезагрузки/входа и установка пакета pacman/winget. Установщик не применялся к текущему HOME.
- Подключение к зарубежному VPS пользователя, аутентификация его ключом, IP/geolocation, IPv6, внешний DNS, outage/recovery настоящего SSH и взаимодействие с AmneziaVPN.
- Реальный Firefox, WebRTC/DNS leak и OAuth; реальный Claude Code с auth/child commands, IDE/background supervisors.
- Запуск на ARM64 и sing-box 1.12.x: версия 1.12 — минимальная по использованным официальным полям, фактическая локальная проверка выполнена на 1.14.3.

Эти проверки требуют окружения пользователя; следуйте [acceptance.md](acceptance.md). Наличие теста/CI-файла не означает успешный запуск на платформе.

## Повторение

```bash
./tests/run.sh
python3 tests/local_ssh.py --sing-box "$(command -v sing-box)"
./tests/integration.sh
./tests/integration.sh --outage
```

Последние две команды требуют установленной конфигурации и настоящего VPS. Outage-команда временно останавливает только сервис cproxy и восстанавливает его; она не отключает SSH на VPS.

```powershell
.\tests\syntax.ps1
.\tests\windows-tests.ps1
.\tests\windows-host-key-tests.ps1
.\tests\windows-install-tests.ps1
```

Windows installer tests моделируют Scheduler/network и не создают настоящих задач. На GitHub они запускаются в Windows PowerShell 5.1; тесты общей логики также выполняются в PowerShell 7.

Дополнительно для UI:

```bash
go test -race ./...
go vet ./...
python3 -m unittest discover -s tests -p test_ui.py -v
```
