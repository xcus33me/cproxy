package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"charm.land/huh/v2"
	"cproxy/internal/config"
)

func form(groups ...*huh.Group) *huh.Form {
	keys := huh.NewDefaultKeyMap()
	keys.Quit.SetKeys("ctrl+c", "esc")
	keys.Quit.SetHelp("esc", "отмена")
	keys.Input.Next.SetHelp("enter / tab", "далее")
	keys.Input.Prev.SetHelp("shift+tab", "назад")
	f := huh.NewForm(groups...).WithTheme(huh.ThemeFunc(huh.ThemeCatppuccin)).WithKeyMap(keys)
	if os.Getenv("CPROXY_ACCESSIBLE") == "1" {
		f.WithAccessible(true)
	}
	return f
}
func runForm(f *huh.Form) error {
	if e := f.Run(); e != nil {
		if errors.Is(e, huh.ErrUserAborted) {
			return ErrCancelled
		}
		return e
	}
	return nil
}
func notice(title, body string) error {
	return runForm(form(huh.NewGroup(huh.NewNote().Title(title).Description(body).Next(true).NextLabel("Вернуться"))))
}
func confirm(title, body string, value *bool) error {
	return runForm(form(huh.NewGroup(huh.NewConfirm().Title(title).Description(body).Value(value).Affirmative("Да").Negative("Нет"))))
}
func readPassword() (string, error) {
	value := ""
	e := runForm(form(huh.NewGroup(huh.NewInput().Title("Пароль SSH-ключа").Description("Не сохраняется. Esc — отмена.").EchoMode(huh.EchoModePassword).Value(&value))))
	return value, e
}
func port(value string) error {
	n, e := strconv.Atoi(value)
	if e != nil || n < 1 || n > 65535 {
		return errors.New("Число от 1 до 65535")
	}
	return nil
}
func domains(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' })
}
func advanced(s *config.Settings) error {
	sshPort, proxyPort := strconv.Itoa(s.SSHPort), strconv.Itoa(s.ProxyPort)
	direct := strings.Join(s.Domains, ", ")
	networks := strings.Join(s.CIDRs, ", ")
	e := runForm(form(huh.NewGroup(
		huh.NewInput().Title("SSH-порт").Value(&sshPort).Validate(port),
		huh.NewInput().Title("Локальный порт").Value(&proxyPort).Validate(port),
		huh.NewInput().Title("Домены рабочей сети").Description("Через запятую, например corp.example, local. Разрешаются локальным DNS.").Value(&direct),
		huh.NewInput().Title("Прямые частные подсети").Description("Через запятую; стандартные LAN-подсети уже заполнены").Value(&networks),
		huh.NewInput().Title("Путь к sing-box (необязательно)").Description("По умолчанию — из готового архива или PATH").Value(&s.Engine),
	).Title("Дополнительные настройки")))
	if e != nil {
		return e
	}
	s.SSHPort, _ = strconv.Atoi(sshPort)
	s.ProxyPort, _ = strconv.Atoi(proxyPort)
	s.Domains = domains(direct)
	s.CIDRs = domains(networks)
	return nil
}
func wizard(s config.Settings, home string) (config.Settings, error) {
	for {
		next := "review"
		e := runForm(form(huh.NewGroup(huh.NewInput().Title("Адрес вашего сервера").Description("IP, имя или user@host:port").Value(&s.Server), huh.NewInput().Title("Пользователь на сервере").Value(&s.User), huh.NewInput().Title("Ваш SSH-ключ").Description("Приватный файл, без .pub; можно ~/.ssh/id_ed25519").Value(&s.Key), huh.NewSelect[string]().Title("Дальше").Options(huh.NewOption("Проверить подключение", "review"), huh.NewOption("Дополнительные настройки", "advanced"), huh.NewOption("Отмена", "cancel")).Value(&next)).Title("Настройка cproxy")))
		if e != nil {
			return s, e
		}
		if next == "cancel" {
			return s, ErrCancelled
		}
		if next == "advanced" {
			if e = advanced(&s); e != nil {
				return s, e
			}
			continue
		}
		if e = s.Normalize(home); e != nil {
			if e = notice("Проверьте данные", e.Error()); e != nil {
				return s, e
			}
			continue
		}
		choice := "connect"
		e = runForm(form(huh.NewGroup(huh.NewNote().Title("Всё верно?").Description(fmt.Sprintf("Сервер: %s:%d\nПользователь: %s\nКлюч: %s\n\nОбычная сеть сохранится. Прокси работает только для запущенных через cproxy приложений.", s.Server, s.SSHPort, s.User, s.Key)), huh.NewSelect[string]().Options(huh.NewOption("Подключиться и сохранить", "connect"), huh.NewOption("Назад — исправить", "edit"), huh.NewOption("Отмена", "cancel")).Value(&choice))))
		if e != nil {
			return s, e
		}
		if choice == "connect" {
			return s, nil
		}
		if choice == "cancel" {
			return s, ErrCancelled
		}
	}
}
func (a application) menu(ctx context.Context) error {
	for {
		state := "Прокси остановлен"
		if s, e := a.manager.Status(ctx); e == nil {
			state = "Сессия: " + s.Server + " · выход через VPS проверяется при запуске"
		}
		action := "browser"
		e := runForm(form(huh.NewGroup(huh.NewSelect[string]().Title("Что хотите сделать?").Description(state).Options(huh.NewOption("Открыть Claude в Firefox", "browser"), huh.NewOption("Запустить Claude Code", "claude"), huh.NewOption("Проверить подключение и IP", "doctor"), huh.NewOption("Настройки", "setup"), huh.NewOption("Остановить прокси", "stop"), huh.NewOption("Посмотреть ошибки", "logs"), huh.NewOption("Выйти (прокси продолжит работать)", "quit")).Value(&action))))
		if e != nil {
			return e
		}
		if action == "quit" {
			return nil
		}
		if action == "setup" {
			e = a.setup(ctx)
		} else {
			e = a.execute(ctx, action, nil)
		}
		if errors.Is(e, ErrCancelled) {
			continue
		}
		if e != nil {
			if e = notice("Не получилось", e.Error()+"\nНастройки сохранены; можно исправить их и повторить."); e != nil {
				return e
			}
		} else if action != "browser" && action != "setup" {
			if e = notice("Готово", "Результат операции показан выше."); e != nil {
				return e
			}
		}
	}
}
