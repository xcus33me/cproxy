package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type Settings struct {
	Server    string `json:"server"`
	User      string `json:"user"`
	Key       string `json:"key"`
	SSHPort   int    `json:"ssh_port"`
	ProxyPort int    `json:"proxy_port"`
	Mode      string `json:"key_mode"`
}

var serverPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.:-]*$`)

func Defaults(home string) Settings {
	s := Settings{SSHPort: 22, ProxyPort: 2080, Mode: "auto"}
	for _, name := range []string{"id_ed25519", "cproxy_ed25519", "id_rsa"} {
		path := filepath.Join(home, ".ssh", name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			s.Key = path
			break
		}
	}
	return s
}
func ExpandHome(path, home string) string {
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		return filepath.Join(home, path[2:])
	}
	return path
}
func ValidateServer(value string) error {
	if !serverPattern.MatchString(strings.TrimSpace(value)) {
		return errors.New("Укажите адрес сервера: IP или имя, без ssh://")
	}
	return nil
}
func ValidateUser(value string) error {
	if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n\x00") {
		return errors.New("Укажите пользователя на сервере")
	}
	return nil
}
func ValidateKey(value, home string) error {
	path := ExpandHome(strings.TrimSpace(value), home)
	if !filepath.IsAbs(path) {
		return errors.New("Укажите полный путь или ~/.ssh/имя_ключа")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("Файл ключа не найден; нужен приватный ключ без .pub")
	}
	if strings.HasSuffix(path, ".pub") {
		return errors.New("Выберите приватный ключ — файл без .pub")
	}
	return nil
}
func (s *Settings) Normalize(home string) error {
	s.Server = strings.TrimSpace(s.Server)
	s.User = strings.TrimSpace(s.User)
	s.Key = ExpandHome(strings.TrimSpace(s.Key), home)
	if err := ValidateServer(s.Server); err != nil {
		return err
	}
	if err := ValidateUser(s.User); err != nil {
		return err
	}
	if err := ValidateKey(s.Key, home); err != nil {
		return err
	}
	if s.SSHPort < 1 || s.SSHPort > 65535 || s.ProxyPort < 1 || s.ProxyPort > 65535 {
		return errors.New("Порт должен быть от 1 до 65535")
	}
	if s.Mode != "auto" && s.Mode != "unattended" && s.Mode != "session" {
		return errors.New("Неизвестный режим ключа")
	}
	return nil
}
func LoadSettings(dir, home string) (Settings, error) {
	s := Defaults(home)
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	var c struct {
		Outbounds []struct {
			Server string `json:"server"`
			Port   int    `json:"server_port"`
			User   string `json:"user"`
			Key    string `json:"private_key_path"`
		}
		Inbounds []struct {
			Port int `json:"listen_port"`
		}
	}
	if err = json.Unmarshal(data, &c); err != nil {
		return s, fmt.Errorf("Не удалось прочитать сохранённые настройки: %w", err)
	}
	if len(c.Outbounds) == 0 || len(c.Inbounds) == 0 {
		return s, errors.New("Сохранённая конфигурация неполна")
	}
	s.Server = c.Outbounds[0].Server
	s.User = c.Outbounds[0].User
	s.Key = c.Outbounds[0].Key
	s.SSHPort = c.Outbounds[0].Port
	s.ProxyPort = c.Inbounds[0].Port
	if data, err = os.ReadFile(filepath.Join(dir, "settings.json")); err == nil {
		var state struct {
			Mode      string `json:"key_mode"`
			Encrypted string `json:"encrypted_key_path"`
		}
		if err = json.Unmarshal(data, &state); err != nil {
			return s, err
		}
		s.Mode = state.Mode
		if state.Mode == "session" {
			s.Key = state.Encrypted
		}
	}
	return s, nil
}
func DetectMode(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	binary := "ssh-keygen"
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	cmd := exec.CommandContext(ctx, binary, "-y", "-P", "", "-f", path)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	output, err := cmd.CombinedOutput()
	if err == nil {
		return "unattended", nil
	}
	if strings.Contains(strings.ToLower(string(output)), "incorrect passphrase") {
		return "session", nil
	}
	return "", errors.New("Не удалось прочитать SSH-ключ. Проверьте файл и права доступа; OpenSSH Client должен быть установлен")
}
func WriteWizard(s Settings) (string, func(), error) {
	dir, err := os.MkdirTemp("", "cproxy-wizard-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	if runtime.GOOS == "windows" {
		// No user input is interpolated into PowerShell code.
		script := `$ErrorActionPreference='Stop'; $acl=New-Object Security.AccessControl.DirectorySecurity; $acl.SetOwner([Security.Principal.WindowsIdentity]::GetCurrent().User); $acl.SetAccessRuleProtection($true,$false); foreach($id in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18')) {$r=New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit, ObjectInherit','None','Allow'); $acl.AddAccessRule($r)}; Set-Acl -LiteralPath $env:CPROXY_PRIVATE_DIR -AclObject $acl`
		cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
		cmd.Env = append(os.Environ(), "CPROXY_PRIVATE_DIR="+dir)
		if out, e := cmd.CombinedOutput(); e != nil {
			cleanup()
			return "", nil, fmt.Errorf("Защита временного файла: %s", out)
		}
	}
	data, err := json.Marshal(s)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	path := filepath.Join(dir, "wizard.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}
