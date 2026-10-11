// Package launch scopes proxy settings to the applications cproxy starts.
package launch

import (
	"context"
	"errors"
	"fmt"
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

func Environment(base []string, port int) []string {
	result := make([]string, 0, len(base)+6)
	for _, entry := range base {
		name, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(name) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
			continue
		}
		result = append(result, entry)
	}
	proxy := "http://127.0.0.1:" + strconv.Itoa(port)
	return append(result, "HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy, "http_proxy="+proxy, "https_proxy="+proxy, "NO_PROXY=localhost,127.0.0.1,::1", "no_proxy=localhost,127.0.0.1,::1")
}

func WriteProfile(dir string, port int) error {
	if e := platform.PrivateDir(dir); e != nil {
		return e
	}
	path := filepath.Join(dir, "user.js")
	if b, e := os.ReadFile(path); e == nil {
		line, _, _ := strings.Cut(string(b), "\n")
		if strings.TrimSuffix(line, "\r") != "// Managed by cproxy" {
			return errors.New("user.js в этом профиле создан не cproxy; выберите другой профиль")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	prefs := fmt.Sprintf(`// Managed by cproxy
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "");
user_pref("network.proxy.http_port", 0);
user_pref("network.proxy.ssl", "");
user_pref("network.proxy.ssl_port", 0);
user_pref("network.proxy.share_proxy_settings", false);
user_pref("network.proxy.socks", "127.0.0.1");
user_pref("network.proxy.socks_port", %d);
user_pref("network.proxy.socks_version", 5);
user_pref("network.proxy.socks_remote_dns", true);
user_pref("network.proxy.socks5_remote_dns", true);
user_pref("network.proxy.no_proxies_on", "");
user_pref("network.proxy.failover_direct", false);
user_pref("network.proxy.allow_bypass", false);
user_pref("network.trr.mode", 5);
user_pref("media.peerconnection.enabled", false);
user_pref("network.http.http3.enable", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.prefetch-next", false);
user_pref("browser.urlbar.speculativeConnect.enabled", false);
user_pref("network.predictor.enabled", false);
`, port)
	return platform.WritePrivate(path, []byte(prefs))
}

func executable(name string, candidates []string) (string, error) {
	if p, e := exec.LookPath(name); e == nil {
		return p, nil
	}
	for _, p := range candidates {
		if i, e := os.Stat(p); e == nil && i.Mode().IsRegular() {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s не найден. Установите приложение и повторите запуск", name)
}
func Firefox() (string, error) {
	name := "firefox"
	var candidates []string
	if runtime.GOOS == "windows" {
		name += ".exe"
		for _, root := range []string{os.Getenv("PROGRAMFILES"), os.Getenv("PROGRAMFILES(X86)"), os.Getenv("LOCALAPPDATA")} {
			if root != "" {
				candidates = append(candidates, filepath.Join(root, "Mozilla Firefox", "firefox.exe"))
			}
		}
	}
	return executable(name, candidates)
}
func Browser(s config.Settings, profile, address string) error {
	u, e := url.Parse(address)
	if e != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return errors.New("Ссылка должна начинаться с https:// или http://")
	}
	if busy, e := platform.ProfileInUse(profile); e != nil {
		return e
	} else if busy {
		return fmt.Errorf("Выделенный Firefox уже открыт. Перейдите в его окно и вставьте ссылку:\n%s\nДля применения изменённых настроек закройте это окно и откройте снова", address)
	}
	binary, e := Firefox()
	if e != nil {
		return e
	}
	if e = WriteProfile(profile, s.ProxyPort); e != nil {
		return e
	}
	cmd := exec.Command(binary, "--no-remote", "--new-instance", "--profile", profile, address)
	cmd.Stderr = os.Stderr
	if e = cmd.Start(); e != nil {
		return e
	}
	finished := make(chan error, 1)
	go func() { finished <- cmd.Wait() }()
	select {
	case e := <-finished:
		if e != nil {
			return fmt.Errorf("Firefox не открыл профиль: %w. Откройте ссылку в уже выделенном окне: %s", e, address)
		}
		return nil
	case <-time.After(500 * time.Millisecond):
		return nil
	}
}

func FindClaude() (string, error) {
	home, _ := os.UserHomeDir()
	name := "claude"
	if runtime.GOOS == "windows" {
		name = "claude.exe"
	}
	if p, e := executable(name, []string{filepath.Join(home, ".local", "bin", name)}); e == nil {
		return p, nil
	}
	if runtime.GOOS == "windows" {
		if p, e := exec.LookPath("claude.cmd"); e == nil {
			return p, nil
		}
	}
	return "", errors.New("Claude Code не найден. Установите официальный native-клиент Claude Code и повторите запуск")
}
func Command(binary string, args []string, port int) (*exec.Cmd, error) {
	// Npm's Windows wrapper is launched through Node, avoiding cmd.exe quoting.
	if strings.EqualFold(filepath.Ext(binary), ".cmd") || strings.EqualFold(filepath.Ext(binary), ".bat") {
		entry := filepath.Join(filepath.Dir(binary), "node_modules", "@anthropic-ai", "claude-code", "cli.js")
		if i, e := os.Stat(entry); e != nil || !i.Mode().IsRegular() {
			return nil, errors.New("Неизвестный wrapper Claude Code. Установите native-клиент или стандартный npm-пакет")
		}
		node := filepath.Join(filepath.Dir(binary), "node.exe")
		if _, e := os.Stat(node); e != nil {
			node, e = exec.LookPath("node.exe")
			if e != nil {
				return nil, errors.New("Для npm-версии Claude Code нужен node.exe")
			}
		}
		binary = node
		args = append([]string{entry}, args...)
	}
	cmd := exec.Command(binary, args...)
	cmd.Env = Environment(os.Environ(), port)
	return cmd, nil
}
func Claude(ctx context.Context, s config.Settings, args []string) error {
	binary, e := FindClaude()
	if e != nil {
		return e
	}
	cmd, e := Command(binary, args, s.ProxyPort)
	if e != nil {
		return e
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// The child shares the terminal and receives Ctrl+C itself. Do not swallow its exit code.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return cmd.Run()
}
