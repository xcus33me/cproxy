# Проверка Go-версии

```console
go test ./...
go vet ./...
go test -race ./...
go run ./cmd/bundle -engine-only -out .build/engine
```

Для реального интеграционного теста задайте `CPROXY_TEST_SING_BOX` абсолютным
путём к загруженному sing-box и выполните `go test ./... -count=1`.
Для проверки готового архива также задайте `CPROXY_TEST_BINARY` абсолютным
путём к его cproxy: тест использует этот бинарник вместо сборки из исходников.

Интеграционный тест работает только на loopback: временный SSH-сервер,
HTTP/TLS endpoints, временные ключи и собственный Go supervisor. Проверяет
HTTP/SOCKS с серверным DNS, encrypted key, private direct исключение,
занятый порт, конкурентный start, outage/recovery, неверный host pin,
остановку и отсутствие оставшегося слушающего sing-box после смерти supervisor.
Регрессионные тесты покрывают отмену конкурирующего запуска с другими настройками,
отзыв сохранённого ключа во всех entrypoints сессии, CRLF старого Windows-профиля,
нативную блокировку Firefox и отказ читать symlink вместо session state.

Windows использует собственное хранилище доверенных сертификатов; тест не
добавляет в него временный CA. Поэтому synthetic HTTPS readiness и CLI start
проверяются в Linux, а Windows проверяет native detach/job lifecycle и
HTTP/SOCKS forwarding через `--serve`. Go PTY smoke-тест мастера выполняется
на Linux. Native CI настроен для обеих ОС; наличие workflow не означает,
что он уже прошёл на GitHub.

Отдельной проверки на компьютере пользователя требуют VPS, рабочие домены,
реальный Firefox, OAuth и установленный Claude Code. Cross-build не заменяет
запуск приложения на Windows/ARM64. Доступность Claude и решения об аккаунте
не являются свойствами, которые подтверждают эти тесты.

Локально 2026-10-11: весь набор с `-race -count=1` и настоящим sing-box 1.14.3
прошёл на Linux amd64; `go vet` и cross-build Windows/Linux amd64/arm64 прошли.
Архивы Linux amd64 и Windows amd64 собраны с проверкой SHA256 движка.
Linux-архив распакован, и оба его бинарника прошли реальный loopback integration;
Windows ZIP прошёл проверку CRC. Реальный Windows runtime здесь не запускался.
