package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"cproxy/internal/config"
	"cproxy/internal/engine"
	"cproxy/internal/legacy"
	"cproxy/internal/platform"
	"cproxy/internal/sshconn"
)

func (a application) setup(ctx context.Context) error {
	if e := platform.PrivateDir(a.dir); e != nil {
		return e
	}
	lock, e := platform.Lock(filepath.Join(a.dir, "setup.lock"))
	if e != nil {
		return errors.New("Другой мастер настройки уже открыт")
	}
	defer lock.Close()
	previous, e := config.Load(a.path)
	var old *legacy.Installation
	if os.IsNotExist(e) {
		previous = config.Defaults()
		old, e = legacy.Detect()
		if e != nil {
			return e
		}
		if old != nil {
			accept := true
			if e = confirm("Найдена прежняя установка", "Перенести подключение, SSH-ключ и профиль Firefox? Старый прокси будет отключён после проверки новых данных.", &accept); e != nil {
				return e
			}
			if accept {
				previous, e = old.Settings()
				if e != nil {
					return e
				}
			} else {
				old = nil
			}
		}
	} else if e != nil {
		return e
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return e
	}
	if previous.Key == "" {
		for _, name := range []string{"id_ed25519", "cproxy_ed25519", "id_rsa"} {
			p := filepath.Join(home, ".ssh", name)
			if i, e := os.Stat(p); e == nil && i.Mode().IsRegular() {
				previous.Key = p
				break
			}
		}
	}
	candidate := previous
	for {
		before := candidate
		candidate, e = wizard(candidate, home)
		if e != nil {
			return e
		}
		if candidate.Server != before.Server || candidate.SSHPort != before.SSHPort {
			candidate.HostKey = ""
			candidate.ExpectedIPs = nil
		}
		e = a.connect(ctx, previous, &candidate, old)
		if e == nil || errors.Is(e, ErrCancelled) || ctx.Err() != nil {
			return e
		}
		if e = notice("Не получилось подключиться", e.Error()+"\nДанные оставлены в мастере. Исправьте их или нажмите Esc."); e != nil {
			return e
		}
	}
}

func (a application) connect(ctx context.Context, previous config.Settings, candidate *config.Settings, old *legacy.Installation) error {
	pass, e := passphrase(*candidate)
	if e != nil {
		return e
	}
	defer clear(pass)
	fmt.Println("Проверяем SSH-подключение…")
	key, e := sshconn.Probe(ctx, *candidate, pass)
	var unknown *sshconn.UnknownHostError
	if errors.As(e, &unknown) {
		accept := false
		if e = confirm("Первое подключение к VPS", "Отпечаток: "+unknown.Fingerprint+"\nСверьте его с консолью VPS. Сохранить этот ключ сервера?", &accept); e != nil {
			return e
		}
		if !accept {
			return ErrCancelled
		}
		candidate.HostKey = unknown.Key
		key, e = sshconn.Probe(ctx, *candidate, pass)
	}
	if e != nil {
		return e
	}
	candidate.HostKey = key
	binary, e := engine.Find(*candidate)
	if e != nil {
		return e
	}
	data, e := engine.Config(*candidate, pass)
	if e != nil {
		return e
	}
	defer clear(data)
	if e = engine.Check(ctx, binary, data); e != nil {
		return e
	}
	wasRunning := false
	previousPass := pass
	if _, e = a.manager.Status(ctx); e == nil {
		wasRunning = true
		if previous.Key != candidate.Key {
			previousPass, e = passphrase(previous)
			if e != nil {
				return e
			}
			defer clear(previousPass)
		}
		if e = a.manager.Stop(ctx); e != nil {
			return e
		}
	}
	restore := func() error { return nil }
	if old != nil {
		restore, e = old.Pause(ctx)
		if e != nil {
			if wasRunning {
				return errors.Join(e, a.manager.Start(ctx, previous, previousPass))
			}
			return e
		}
	}
	candidateStarted := false
	rollback := func(cause error) error {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if candidateStarted {
			a.manager.Stop(stopCtx)
		}
		result := errors.Join(cause, restore())
		if wasRunning {
			result = errors.Join(result, a.manager.Start(stopCtx, previous, previousPass))
		}
		return result
	}
	if e = a.manager.Start(ctx, *candidate, pass); e != nil {
		return rollback(e)
	}
	candidateStarted = true
	if e = config.Save(a.path, *candidate); e != nil {
		return rollback(e)
	}
	fmt.Println("Подключение сохранено. Прокси работает в фоне.")
	return nil
}
