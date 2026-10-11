// Package app connects the terminal UI to the native Go backend.
package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"cproxy/internal/config"
	"cproxy/internal/launch"
	"cproxy/internal/session"
	"cproxy/internal/sshconn"
	"github.com/charmbracelet/x/term"
	"golang.org/x/crypto/ssh"
)

var ErrCancelled = errors.New("отменено")

const help = `cproxy — браузер и Claude Code через ваш VPS

Без аргументов: мастер настройки и меню
  setup              настроить или изменить подключение
  start / stop       включить / выключить фоновый прокси
  status             состояние собственной сессии
  doctor             проверить SSH, прокси и исходящий IP
  browser [URL]      открыть отдельный Firefox (также для OAuth-ссылки)
  claude [аргументы] запустить Claude Code в текущей папке
  logs               последние сообщения прокси
  run                прокси в переднем плане до Ctrl+C

В формах: Tab / Enter — далее, Shift+Tab — назад, Esc — отмена.
Рабочая сеть и системные настройки не изменяются.
`

type application struct {
	dir, path string
	manager   session.Manager
}

func newApplication() (application, error) {
	dir, e := config.Dir()
	if e != nil {
		return application{}, e
	}
	state, e := config.StateDir()
	if e != nil {
		return application{}, e
	}
	executable, e := os.Executable()
	return application{dir, filepath.Join(dir, "settings.json"), session.Manager{Dir: state, Executable: executable}}, e
}
func (a application) load() (config.Settings, error) {
	s, e := config.Load(a.path)
	if e != nil {
		if os.IsNotExist(e) {
			return s, errors.New("Подключение ещё не настроено. Выполните cproxy setup")
		}
		return s, e
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return s, e
	}
	return s, s.Normalize(home)
}
func passphrase(s config.Settings) ([]byte, error) {
	_, e := sshconn.Signer(s.Key, nil)
	var missing *ssh.PassphraseMissingError
	if !errors.As(e, &missing) {
		return nil, e
	}
	if !term.IsTerminal(os.Stdin.Fd()) {
		return nil, errors.New("SSH-ключ защищён паролем; запустите cproxy из терминала")
	}
	for {
		value, e := readPassword()
		if e != nil {
			return nil, e
		}
		pass := []byte(value)
		value = ""
		if _, e = sshconn.Signer(s.Key, pass); e == nil {
			return pass, nil
		}
		clear(pass)
		if e = notice("Пароль не подошёл", "Проверьте пароль SSH-ключа и повторите ввод."); e != nil {
			return nil, e
		}
	}
}
func (a application) ensure(ctx context.Context, s config.Settings) error {
	if _, e := a.manager.Status(ctx); e == nil {
		_, e = a.manager.Ready(ctx, s)
		return e
	}
	pass, e := passphrase(s)
	if e != nil {
		return e
	}
	defer clear(pass)
	return a.manager.Start(ctx, s, pass)
}
func (a application) execute(ctx context.Context, action string, args []string) error {
	if action == "stop" {
		return a.manager.Stop(ctx)
	}
	if action == "logs" {
		b, e := os.ReadFile(filepath.Join(a.manager.Dir, "cproxy.log"))
		if e != nil {
			return e
		}
		if len(b) > 16384 {
			b = b[len(b)-16384:]
		}
		fmt.Print(string(b))
		return nil
	}
	if action == "status" {
		s, e := a.manager.Status(ctx)
		if os.IsNotExist(e) {
			fmt.Println("Прокси остановлен")
			return nil
		}
		if e != nil {
			return fmt.Errorf("Прокси остановлен или недоступен: %w", e)
		}
		fmt.Printf("Сессия: %s · порт %d · с %s\n", s.Server, s.ProxyPort, s.Started.Local().Format("15:04"))
		fmt.Println("Проверка выхода в интернет: cproxy doctor")
		return nil
	}
	s, e := a.load()
	if e != nil {
		return e
	}
	if action == "run" {
		pass, e := passphrase(s)
		if e != nil {
			return e
		}
		defer clear(pass)
		return a.manager.Foreground(ctx, s, pass)
	}
	if e = a.ensure(ctx, s); e != nil {
		return e
	}
	switch action {
	case "start":
		fmt.Println("Прокси готов. Терминал можно закрыть.")
	case "doctor":
		pass, e := passphrase(s)
		if e != nil {
			return e
		}
		defer clear(pass)
		if _, e = sshconn.Probe(ctx, s, pass); e != nil {
			return e
		}
		ip, e := a.manager.Ready(ctx, s)
		if e != nil {
			return e
		}
		fmt.Printf("SSH: ключ проверен\nПрокси: работает\nИсходящий IPv4: %s\nСистемная сеть: настройки не изменены\n", ip)
	case "browser":
		url := "https://claude.ai"
		if len(args) > 0 {
			url = args[0]
		}
		profile := s.Profile
		if profile == "" {
			profile = filepath.Join(a.dir, "firefox")
		}
		return launch.Browser(s, profile, url)
	case "claude":
		return launch.Claude(ctx, s, args)
	}
	return nil
}

func Run(args []string) int {
	action := "menu"
	if len(args) > 0 {
		action = args[0]
	}
	if action == "--help" || action == "-h" || action == "help" {
		fmt.Print(help)
		return 0
	}
	allowed := map[string]bool{"menu": true, "setup": true, "start": true, "stop": true, "status": true, "doctor": true, "browser": true, "claude": true, "logs": true, "run": true, "--serve": true}
	if !allowed[action] {
		fmt.Fprintln(os.Stderr, "Неизвестная команда:", action)
		return 2
	}
	if action == "--serve" && len(args) != 2 {
		fmt.Fprintln(os.Stderr, "Не передан каталог состояния")
		return 2
	}
	if action != "claude" && action != "browser" && action != "--serve" && len(args) > 1 || action == "browser" && len(args) > 2 {
		fmt.Fprintln(os.Stderr, "Лишние аргументы команды")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	a, e := newApplication()
	if e == nil {
		switch action {
		case "--serve":
			a.manager.Dir = args[1]
			e = a.manager.Run(ctx, os.Stdin)
		case "setup", "menu":
			if !term.IsTerminal(os.Stdin.Fd()) && os.Getenv("CPROXY_ACCESSIBLE") != "1" {
				fmt.Fprintln(os.Stderr, "Для настройки и меню нужен терминал")
				return 2
			}
			if action == "setup" {
				e = a.setup(ctx)
			} else {
				if _, err := os.Stat(a.path); os.IsNotExist(err) {
					e = a.setup(ctx)
				}
				if e == nil {
					e = a.menu(ctx)
				}
			}
		default:
			var rest []string
			if len(args) > 1 {
				rest = args[1:]
			}
			e = a.execute(ctx, action, rest)
		}
	}
	if e == nil {
		return 0
	}
	if errors.Is(e, ErrCancelled) || errors.Is(e, context.Canceled) {
		fmt.Fprintln(os.Stderr, "Отменено.")
		return 130
	}
	var exit *exec.ExitError
	if errors.As(e, &exit) {
		if uint32(exit.ExitCode()) == 0xc000013a {
			return 130
		}
		if exit.ExitCode() < 0 {
			return 130
		}
		return exit.ExitCode()
	}
	fmt.Fprintln(os.Stderr, strings.TrimSpace(e.Error()))
	return 1
}
