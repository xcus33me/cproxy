package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"charm.land/huh/v2"
	"charm.land/huh/v2/spinner"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/term"
)

var ErrCancelled = errors.New("отменено")
var heading = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#cba6f7"))

func processExitCode(exit *exec.ExitError) int {
	if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	// Native Windows console cancellation status.
	if uint32(exit.ExitCode()) == 0xc000013a {
		return 130
	}
	return exit.ExitCode()
}

func form(groups ...*huh.Group) *huh.Form {
	keys := huh.NewDefaultKeyMap()
	keys.Quit.SetKeys("ctrl+c", "esc")
	keys.Quit.SetHelp("esc / ctrl+c", "отмена")
	keys.Input.Prev.SetHelp("shift+tab", "назад")
	keys.Input.Next.SetHelp("enter / tab", "далее")
	f := huh.NewForm(groups...).WithTheme(huh.ThemeFunc(huh.ThemeCatppuccin)).WithKeyMap(keys)
	if os.Getenv("CPROXY_ACCESSIBLE") == "1" {
		f.WithAccessible(true)
	}
	return f
}
func runForm(f *huh.Form) error {
	if err := f.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return ErrCancelled
		}
		return err
	}
	return nil
}
func notice(title, body string) error {
	return runForm(form(huh.NewGroup(huh.NewNote().Title(title).Description(body).Next(true).NextLabel("Вернуться"))))
}
func validatePort(v string) error {
	p, e := strconv.Atoi(v)
	if e != nil || p < 1 || p > 65535 {
		return errors.New("Число от 1 до 65535")
	}
	return nil
}
func advanced(s *Settings) error {
	sshPort, proxyPort := strconv.Itoa(s.SSHPort), strconv.Itoa(s.ProxyPort)
	err := runForm(form(huh.NewGroup(
		huh.NewInput().Title("SSH-порт сервера").Value(&sshPort).Validate(validatePort),
		huh.NewInput().Title("Локальный порт").Value(&proxyPort).Validate(validatePort),
		huh.NewSelect[string]().Title("Работа с ключом").Options(huh.NewOption("Определить автоматически", "auto"), huh.NewOption("Без пароля — запускать после входа", "unattended"), huh.NewOption("С паролем — разблокировать после входа", "session")).Value(&s.Mode),
	).Title("Дополнительные настройки")))
	if err != nil {
		return err
	}
	s.SSHPort, _ = strconv.Atoi(sshPort)
	s.ProxyPort, _ = strconv.Atoi(proxyPort)
	return nil
}
func Wizard(s Settings, home string) (Settings, error) {
	for {
		action := "review"
		err := runForm(form(huh.NewGroup(
			huh.NewInput().Title("Адрес вашего сервера").Description("IP или имя зарубежного VPS").Value(&s.Server).Validate(ValidateServer),
			huh.NewInput().Title("Пользователь на сервере").Description("Тот же, что при подключении по SSH").Value(&s.User).Validate(ValidateUser),
			huh.NewInput().Title("Ваш SSH-ключ").Description("Приватный файл, без .pub; можно ~/.ssh/id_ed25519").Value(&s.Key).Validate(func(v string) error { return ValidateKey(v, home) }),
			huh.NewSelect[string]().Title("Дальше").Options(huh.NewOption("Проверить и установить", "review"), huh.NewOption("Дополнительные настройки", "advanced"), huh.NewOption("Отмена", "cancel")).Value(&action),
		).Title("Настройка подключения").Description("Tab — далее · Shift+Tab — назад · Esc — отмена")))
		if err != nil {
			return s, err
		}
		if action == "cancel" {
			return s, ErrCancelled
		}
		if action == "advanced" {
			if err = advanced(&s); err != nil {
				return s, err
			}
			continue
		}
		if err = s.Normalize(home); err != nil {
			if e := notice("Проверьте данные", err.Error()); e != nil {
				return s, e
			}
			continue
		}
		mode := s.Mode
		if mode == "auto" {
			mode, err = DetectMode(s.Key)
			if err != nil {
				if e := notice("Не удалось прочитать ключ", err.Error()); e != nil {
					return s, e
				}
				continue
			}
		}
		modeLabel := "Автоматически после входа в компьютер"
		if mode == "session" {
			modeLabel = "Ключ с паролем: разблокирование после каждого входа"
		}
		action = "apply"
		summary := fmt.Sprintf("Сервер: %s:%d\nПользователь: %s\nКлюч: %s\n\n%s\nОбычные приложения сохранят своё соединение.", s.Server, s.SSHPort, s.User, s.Key, modeLabel)
		err = runForm(form(huh.NewGroup(huh.NewNote().Title("Всё верно?").Description(summary),
			huh.NewSelect[string]().Options(huh.NewOption("Установить / сохранить", "apply"), huh.NewOption("Назад — исправить данные", "edit"), huh.NewOption("Порты и режим ключа", "advanced"), huh.NewOption("Отмена", "cancel")).Value(&action))))
		if err != nil {
			return s, err
		}
		switch action {
		case "cancel":
			return s, ErrCancelled
		case "advanced":
			if err = advanced(&s); err != nil {
				return s, err
			}
		case "apply":
			s.Mode = mode
			return s, nil
		}
	}
}

// Foreground installation keeps a normal terminal for package-manager and key prompts.
// On Unix the child receives Ctrl+C in the same process group and runs its rollback trap.
func foreground(cmd *exec.Cmd) error {
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	return cmd.Run()
}
func (r Runtime) Apply(s Settings) error {
	path, cleanup, err := WriteWizard(s)
	if err != nil {
		return err
	}
	defer cleanup()
	cmd, err := r.Command("setup", []string{path})
	if err != nil {
		return err
	}
	cmd.Env = append(os.Environ(), "CPROXY_UI_BINARY="+r.UIPath)
	fmt.Println(heading.Render("Подключаем сервер и настраиваем фоновый запуск…"))
	err = foreground(cmd)
	var interrupted *exec.ExitError
	if errors.As(err, &interrupted) && processExitCode(interrupted) == 130 {
		return ErrCancelled
	}
	return err
}
func (r Runtime) Setup() error {
	home, _ := os.UserHomeDir()
	s, err := LoadSettings(r.AppDir, home)
	if err != nil {
		return err
	}
	for {
		s, err = Wizard(s, home)
		if err != nil {
			return err
		}
		err = r.Apply(s)
		if errors.Is(err, ErrCancelled) {
			return err
		}
		if err == nil {
			return nil
		}
		choice := "edit"
		message := "Установка не завершена. Предыдущая конфигурация сохранена.\nИсправьте данные или повторите попытку. Подробная ошибка показана выше."
		if e := runForm(form(huh.NewGroup(huh.NewNote().Title("Не получилось подключиться").Description(message), huh.NewSelect[string]().Options(huh.NewOption("Исправить данные", "edit"), huh.NewOption("Повторить установку", "retry"), huh.NewOption("Вернуться без изменений", "cancel")).Value(&choice)))); e != nil {
			return e
		}
		if choice == "cancel" {
			return ErrCancelled
		}
		if choice == "retry" {
			if err = r.Apply(s); err == nil {
				return nil
			}
			if errors.Is(err, ErrCancelled) {
				return err
			}
		}
	}
}
func (r Runtime) statusLine() string {
	if !exists(filepath.Join(r.AppDir, "config.json")) {
		return "Подключение ещё не настроено"
	}
	home, _ := os.UserHomeDir()
	s, err := LoadSettings(r.AppDir, home)
	if err != nil {
		return "Не удалось прочитать настройки"
	}
	status := "Прокси остановлен"
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.ProxyPort)), 300*time.Millisecond)
	if err == nil {
		conn.Close()
		status = "Локальный порт доступен"
	}
	return status + " · " + s.Server + "\nПроверить соединение с сервером можно в меню ниже."
}
func (r Runtime) report(action string) error {
	cmd, err := r.Command(action, nil)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// Construct a cancellable command from the already validated argument array.
	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	var operationErr error
	done := make(chan struct{})
	go func() { operationErr = cmd.Run(); close(done) }()
	err = spinner.New().Title("Выполняем…").ActionWithErr(func(ctxSpinner context.Context) error {
		stop := context.AfterFunc(ctxSpinner, cancel)
		defer stop()
		select {
		case <-done:
			return nil
		case <-ctxSpinner.Done():
			cancel()
			<-done
			return ctxSpinner.Err()
		}
	}).Run()
	cancel()
	<-done
	if err != nil {
		return ErrCancelled
	}
	title := "Готово"
	if operationErr != nil {
		title = "Есть проблема"
	}
	body := strings.TrimSpace(output.String())
	if body == "" {
		if operationErr != nil {
			body = operationErr.Error()
		} else {
			body = "Команда выполнена"
		}
	}
	return notice(title, body)
}
func (r Runtime) controls() (string, error) {
	action := "back"
	options := []huh.Option[string]{huh.NewOption("Изменить подключение", "setup"), huh.NewOption("Включить прокси", "start"), huh.NewOption("Выключить прокси", "stop"), huh.NewOption("Перезапустить", "restart"), huh.NewOption("Состояние и маршрут", "status"), huh.NewOption("Сообщения об ошибках", "logs")}
	home, _ := os.UserHomeDir()
	settings, _ := LoadSettings(r.AppDir, home)
	if settings.Mode == "session" {
		options = append(options, huh.NewOption("Разблокировать ключ", "unlock"), huh.NewOption("Заблокировать ключ", "lock"))
	}
	options = append(options, huh.NewOption("Назад", "back"))
	err := runForm(form(huh.NewGroup(huh.NewSelect[string]().Title("Настройки и управление").Options(options...).Value(&action))))
	return action, err
}
func (r Runtime) Menu() error {
	for {
		action := "browser"
		opts := []huh.Option[string]{huh.NewOption("Открыть Claude в Firefox", "browser"), huh.NewOption("Запустить Claude Code", "claude"), huh.NewOption("Проверить соединение и IP", "test"), huh.NewOption("Настройки и управление", "controls"), huh.NewOption("Выйти", "quit")}
		err := runForm(form(huh.NewGroup(huh.NewSelect[string]().Title("Что хотите сделать?").Description(r.statusLine()).Options(opts...).Value(&action))))
		if err != nil {
			return err
		}
		if action == "quit" {
			return nil
		}
		if action == "controls" {
			action, err = r.controls()
			if errors.Is(err, ErrCancelled) {
				continue
			}
			if err != nil {
				return err
			}
			if action == "back" {
				continue
			}
		}
		if action == "setup" {
			err = r.Setup()
		} else if action == "claude" || action == "unlock" {
			var cmd *exec.Cmd
			cmd, err = r.Command(action, nil)
			if err == nil {
				err = foreground(cmd)
			}
		} else {
			err = r.report(action)
		}
		if errors.Is(err, ErrCancelled) {
			continue
		}
		if err != nil {
			if e := notice("Не удалось выполнить", err.Error()); e != nil {
				return e
			}
		}
	}
}
func Run(args []string) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "help" || args[0] == "-h") {
		fmt.Println("cproxy — Claude через ваш сервер\n\nБез аргументов: открыть меню\ncproxy setup: настроить подключение\ncproxy browser: открыть Firefox для Claude\ncproxy claude [аргументы]: запустить Claude Code\ncproxy status|start|stop|restart|test|logs|unlock|lock\n\nВ мастере: Tab — далее, Shift+Tab — назад, Esc / Ctrl+C — отмена")
		return 0
	}
	r, err := Discover()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	action := "menu"
	if len(args) > 0 {
		action = args[0]
	}
	if action == "menu" || action == "setup" {
		if len(args) > 1 {
			fmt.Fprintln(os.Stderr, "У команды меню нет дополнительных аргументов")
			return 2
		}
		if !term.IsTerminal(os.Stdin.Fd()) {
			fmt.Fprintln(os.Stderr, "Для меню нужен терминал. Для автоматизации используйте --params / -ParamsFile установщика.")
			return 2
		}
		fmt.Println(heading.Render("  CPROXY  ") + "  Claude через ваш сервер\n")
		if action == "setup" {
			err = r.Setup()
			if err == nil {
				err = r.Menu()
			}
		} else {
			if !exists(filepath.Join(r.AppDir, "config.json")) {
				err = r.Setup()
			}
			if err == nil {
				err = r.Menu()
			}
		}
	} else {
		var cmd *exec.Cmd
		cmd, err = r.Command(action, args[1:])
		if err == nil {
			err = foreground(cmd)
		}
	}
	if errors.Is(err, ErrCancelled) {
		fmt.Println("Отменено.")
		return 130
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return processExitCode(exit)
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
