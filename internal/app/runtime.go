package app

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

type Runtime struct{ Root, AppDir, UIPath, OS string }

func exists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
func Discover() (Runtime, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Runtime{}, err
	}
	r := Runtime{OS: runtime.GOOS}
	r.UIPath, err = os.Executable()
	if err != nil {
		return r, err
	}
	if r.OS == "windows" {
		r.AppDir = filepath.Join(os.Getenv("LOCALAPPDATA"), "SelectiveProxy")
	} else {
		dir := os.Getenv("XDG_CONFIG_HOME")
		if dir == "" {
			dir = filepath.Join(home, ".config")
		}
		r.AppDir = filepath.Join(dir, "selective-proxy")
	}
	candidates := []string{os.Getenv("CPROXY_SOURCE_DIR"), filepath.Dir(r.UIPath), filepath.Dir(filepath.Dir(r.UIPath)), r.AppDir}
	for _, dir := range candidates {
		if dir != "" && (exists(filepath.Join(dir, "linux", "install.sh")) || exists(filepath.Join(dir, "install.sh")) || exists(filepath.Join(dir, "windows", "install.ps1")) || exists(filepath.Join(dir, "install.ps1"))) {
			r.Root = dir
			return r, nil
		}
	}
	return r, errors.New("Не найдены скрипты cproxy. Запустите приложение из скачанного проекта")
}
func (r Runtime) backend(name string) string {
	platform := "linux"
	if r.OS == "windows" {
		platform = "windows"
	}
	if exists(filepath.Join(r.Root, platform, name)) {
		return filepath.Join(r.Root, platform, name)
	}
	return filepath.Join(r.Root, name)
}
func (r Runtime) Command(action string, args []string) (*exec.Cmd, error) {
	if action == "setup" {
		if len(args) != 1 {
			return nil, errors.New("Не передан файл настройки")
		}
		if r.OS == "windows" {
			return exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-File", r.backend("install.ps1"), "-WizardFile", args[0]), nil
		}
		return exec.Command("bash", r.backend("install.sh"), "--wizard-file", args[0]), nil
	}
	if action == "claude" {
		if r.OS == "windows" {
			return exec.Command("powershell.exe", append([]string{"-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-File", r.backend("claude-vpn.ps1")}, args...)...), nil
		}
		return exec.Command("bash", append([]string{r.backend("claude-vpn.sh")}, args...)...), nil
	}
	switch action {
	case "status", "start", "stop", "restart", "test", "logs", "browser", "unlock", "lock", "config":
	default:
		return nil, errors.New("Неизвестная команда: " + action)
	}
	if len(args) != 0 {
		return nil, errors.New("Эта команда не принимает аргументы")
	}
	if r.OS == "windows" {
		params := []string{"-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-File", r.backend("proxyctl.ps1"), action}
		if action == "logs" {
			params = append(params, "-Once")
		}
		return exec.Command("powershell.exe", params...), nil
	}
	params := []string{r.backend("proxyctl"), action}
	if action == "logs" {
		params = append(params, "--once")
	}
	return exec.Command("bash", params...), nil
}
