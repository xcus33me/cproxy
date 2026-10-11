# Windows

Цель: Windows 10/11, x64/ARM64, 64-битный Windows PowerShell 5.1 или PowerShell 7. Sing-box ≥ 1.12. Запуск в обычной учётной записи; задача использует текущий SID, Limited/Interactive и без сохранения пароля Windows. После выхода из учётной записи работа не обещается; автозапуск — после входа.

## Зависимости и политика скриптов

Проверьте:

```powershell
Get-Command ssh-keygen.exe, ssh-keyscan.exe, curl.exe, winget.exe
```

Если OpenSSH Client отсутствует, включите его в Settings → Apps → Optional Features → OpenSSH Client. Это ручная системная установка компонента Windows и может потребовать администратора. cproxy не включает SSH Server. winget предоставляется App Installer; наличие winget не гарантируется на старых Windows 10. Поддержанный пакет: `SagerNet.sing-box`.

Если `.ps1` скачаны из интернета, после просмотра кода снимите Zone.Identifier только с скриптов репозитория:

```powershell
Get-ChildItem .\windows\*.ps1 | Unblock-File
Get-Item .\cproxy.ps1 | Unblock-File
Set-ExecutionPolicy -Scope Process RemoteSigned
.\cproxy.ps1
```

Process policy действует в текущем PowerShell. Системная policy не меняется; корпоративную policy нельзя обойти этими командами. Задача отдельно запускает reviewed локальные скрипты с RemoteSigned. Если организация запрещает scheduler/скрипты, требуется согласованный с администратором способ запуска, установщик не изменяет правила машины.

## SSH-ключ и ACL

```powershell
New-Item -ItemType Directory "$HOME\.ssh" -Force | Out-Null
ssh-keygen.exe -t ed25519 -f "$HOME\.ssh\cproxy_ed25519" -C cproxy
```

Выберите passphrase для session или отдельный ключ без неё для unattended. Установщик не меняет ACL оригинального ключа молча: он отвергает широкие права. Для **вашего отдельного** ключа, после проверки пути:

```powershell
$key = Join-Path $HOME '.ssh\cproxy_ed25519'
$who = [Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls.exe $key /inheritance:r
icacls.exe $key /grant:r "${who}:(F)"
icacls.exe $key
```

`/inheritance:r` убирает наследуемые ACE, но не произвольные explicit ACE. Если остались Users/Everyone/другие пользователи с доступом, удалите их через Properties → Security → Advanced **только для этого ключа**. Владельцу, SYSTEM и Administrators доступ допустим; администратор машины всё равно имеет возможность доступа. Установочный каталог получает private ACL для текущего SID и SYSTEM.

## Работа

```powershell
$proxy = Join-Path $env:LOCALAPPDATA 'SelectiveProxy'
& "$proxy\proxyctl.ps1" test
& "$proxy\proxyctl.ps1" browser
& "$proxy\claude-vpn.ps1" --help
```

Опциональные функции только для текущего терминала:

```powershell
function proxyctl { & "$env:LOCALAPPDATA\SelectiveProxy\proxyctl.ps1" @args }
function claude-vpn { & "$env:LOCALAPPDATA\SelectiveProxy\claude-vpn.ps1" @args }
proxyctl status
claude-vpn --help
```

cproxy не правит `$PROFILE`, PATH или proxy env системы. Функции можно самостоятельно добавить в свой profile после просмотра. Wrapper не правит env родительского PowerShell.

Task Scheduler запускает `run-proxy.ps1` скрыто; supervisor держит один процесс sing-box. У задачи имя `SelectiveProxy-<SID>`, description `Managed by cproxy`. При stop проверяются principal/action, PID, время запуска и командная строка ребёнка. Другие процессы sing-box не завершаются. Повторный start не создаёт второй экземпляр задачи.

```powershell
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Get-ScheduledTask -TaskName "SelectiveProxy-$sid"
Get-ScheduledTaskInfo -TaskName "SelectiveProxy-$sid"
Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 2080 -State Listen
```

## Session и ограничения хранения

```powershell
& "$proxy\proxyctl.ps1" unlock
& "$proxy\proxyctl.ps1" lock
```

Оригинальный зашифрованный ключ сохраняется. `ssh-keygen -p` запрашивает passphrase непосредственно в терминале и снимает её только с отдельной копии. Пароль не записывается в JSON/лог/argv. Расшифрованная копия — `%LOCALAPPDATA%\SelectiveProxy\runtime\session.key`, ACL restricted. В этом режиме нет logon trigger; после входа нужен unlock.

Windows-копия хранится на диске. Выполняйте lock перед выходом/завершением работы и используйте шифрование диска. Не обещаются secure erase, очистка после аварийного отключения питания или защита от процесса того же пользователя. После аварии вручную выполните lock и снова unlock. Uninstall удаляет только runtime-копию, не оригинальный ключ.

## Обновление и удаление

```powershell
.\windows\install.ps1
.\windows\install.ps1 -Reconfigure
.\windows\uninstall.ps1
```

Проверка кандидата выполняется до изменения рабочей задачи. При ошибке запуска восстанавливается старый конфиг и XML задачи, а ранее запущенная задача запускается снова. Для исходного sing-box binary нужен отдельный откат через менеджер пакетов. Locked/stopped состояние сохраняется при откате; успешная установка запускает proxy для проверки.

Если удаление оставило Firefox-профиль/посторонние файлы, marker остаётся для повторной установки. Закройте Firefox перед удалением его профиля вручную. cproxy не удаляет sing-box через winget.

Для проверки fail-closed оставьте Claude Firefox открытым, выполните stop, загрузите новую HTTPS-страницу и убедитесь в ошибке. `claude-vpn --help` также должен отказать. Затем start. При реальном SSH-отказе (безопасно воспроизведённом отдельно) запросы должны ошибаться даже пока локальный порт слушает. Не выключайте firewall/SSH на VPS без запасного административного доступа.

## Меню cproxy

Первый запуск из проекта: `.\cproxy.ps1`. Установщик `.\windows\install.ps1` без параметров также открывает мастер. Из исходников потребуется Go 1.25.8+, его можно установить по предложению приложения через winget. Готовые архивы CI содержат бинарник. После установки: `& "$env:LOCALAPPDATA\SelectiveProxy\cproxy.ps1"`. Этот launcher запускает защищённую временную копию UI, удаляет её при завершении и не изменяет PATH / PowerShell profile. Shift+Tab — назад, Esc — отмена; сначала показываются три поля и экран подтверждения.
