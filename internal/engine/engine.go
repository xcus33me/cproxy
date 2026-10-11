package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"cproxy/internal/config"
	"cproxy/internal/platform"
)

func Find(s config.Settings) (string, error) {
	name := "sing-box"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if s.Engine != "" {
		p, e := exec.LookPath(s.Engine)
		if e != nil {
			return "", fmt.Errorf("sing-box: %w", e)
		}
		return filepath.Abs(p)
	}
	executable, _ := os.Executable()
	for _, p := range []string{filepath.Join(filepath.Dir(executable), name), filepath.Join(filepath.Dir(executable), "bin", name)} {
		if i, e := os.Stat(p); e == nil && i.Mode().IsRegular() {
			return p, nil
		}
	}
	if p, e := exec.LookPath(name); e == nil {
		return filepath.Abs(p)
	}
	return "", errors.New("sing-box не найден. Скачайте готовый архив cproxy или укажите путь к sing-box в настройках")
}
func Check(ctx context.Context, binary string, data []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	version := exec.CommandContext(ctx, binary, "version")
	platform.Hide(version)
	out, e := version.CombinedOutput()
	if e != nil {
		return fmt.Errorf("Не удалось запустить sing-box: %w", e)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 3 {
		return errors.New("Не удалось определить версию sing-box")
	}
	v := strings.TrimPrefix(fields[2], "v")
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return errors.New("Некорректная версия sing-box")
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	if major != 1 || minor < 14 {
		return errors.New("Нужен sing-box 1.14 или новее в ветке 1.x")
	}
	cmd := exec.CommandContext(ctx, binary, "check", "-c", "stdin")
	cmd.Stdin = bytes.NewReader(data)
	platform.Hide(cmd)
	if out, e = cmd.CombinedOutput(); e != nil {
		return fmt.Errorf("Проверка sing-box не пройдена: %w", e)
	}
	return nil
}
func Egress(ctx context.Context, port int) (string, error) {
	proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSHandshakeTimeout: 8 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api4.ipify.org", nil)
	resp, e := client.Do(req)
	if e != nil {
		return "", fmt.Errorf("Нет выхода через VPS: %w", e)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("IP-проверка вернула HTTP %d", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, 128))
	if e != nil {
		return "", e
	}
	ip := strings.TrimSpace(string(b))
	if _, e = netip.ParseAddr(ip); e != nil {
		return "", errors.New("Сервис проверки вернул некорректный IP")
	}
	return ip, nil
}
func VerifyIP(s config.Settings, ip string) error {
	if len(s.ExpectedIPs) == 0 {
		return nil
	}
	for _, allowed := range s.ExpectedIPs {
		if ip == allowed {
			return nil
		}
	}
	return fmt.Errorf("Неожиданный исходящий IP %s; запуск заблокирован", ip)
}
func Serve(ctx context.Context, binary string, data []byte, output io.Writer) error {
	// Linux parent-death signals follow the spawning OS thread. Keep it alive.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for {
		if ctx.Err() != nil {
			return nil
		}
		cmd := exec.CommandContext(ctx, binary, "run", "-c", "stdin")
		cmd.Stdin = bytes.NewReader(data)
		cmd.Stdout = output
		cmd.Stderr = output
		cmd.WaitDelay = 3 * time.Second
		cleanup, e := platform.StartChild(cmd)
		if e != nil {
			return fmt.Errorf("Запуск sing-box: %w", e)
		}
		e = cmd.Wait()
		cleanup()
		if ctx.Err() != nil {
			return nil
		}
		fmt.Fprintf(output, "sing-box завершился (%v); повторный запуск через 2 секунды\n", e)
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
