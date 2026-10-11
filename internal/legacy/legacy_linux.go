package legacy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func (i Installation) pause(ctx context.Context) (func() error, error) {
	root := filepath.Dir(i.Dir)
	unit := filepath.Join(root, "systemd", "user", "selective-proxy.service")
	b, e := os.ReadFile(unit)
	if os.IsNotExist(e) {
		return func() error { return nil }, nil
	}
	if e != nil {
		return nil, e
	}
	escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", "$$", "%", "%%").Replace(filepath.Join(i.Dir, "config.json"))
	if !strings.HasPrefix(string(b), "# Managed by cproxy") || !strings.Contains(string(b), escaped) {
		return nil, errors.New("Старый systemd unit не принадлежит этой установке cproxy")
	}
	active := exec.CommandContext(ctx, "systemctl", "--user", "is-active", "--quiet", "selective-proxy.service").Run() == nil
	enabled := exec.CommandContext(ctx, "systemctl", "--user", "is-enabled", "--quiet", "selective-proxy.service").Run() == nil
	restore := func() error {
		rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var result error
		if enabled {
			result = exec.CommandContext(rctx, "systemctl", "--user", "enable", "selective-proxy.service").Run()
		}
		if active {
			result = errors.Join(result, exec.CommandContext(rctx, "systemctl", "--user", "start", "selective-proxy.service").Run())
		}
		return result
	}
	if out, e := exec.CommandContext(ctx, "systemctl", "--user", "disable", "--now", "selective-proxy.service").CombinedOutput(); e != nil {
		r := restore()
		return nil, errors.Join(fmt.Errorf("Не удалось остановить старый прокси: %s: %w", strings.TrimSpace(string(out)), e), r)
	}
	return restore, nil
}
