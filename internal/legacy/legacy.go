// Package legacy imports the previous script-based installation without deleting it.
package legacy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"cproxy/internal/config"
)

type Installation struct{ Dir string }

func Detect() (*Installation, error) {
	home, e := os.UserHomeDir()
	if e != nil {
		return nil, e
	}
	var dir string
	if runtime.GOOS == "windows" {
		dir = filepath.Join(os.Getenv("LOCALAPPDATA"), "SelectiveProxy")
	} else {
		root := os.Getenv("XDG_CONFIG_HOME")
		if root == "" {
			root = filepath.Join(home, ".config")
		}
		dir = filepath.Join(root, "selective-proxy")
	}
	if _, e = os.Stat(filepath.Join(dir, "config.json")); os.IsNotExist(e) {
		return nil, nil
	} else if e != nil {
		return nil, e
	}
	i := &Installation{Dir: dir}
	if e = i.owned(); e != nil {
		return nil, e
	}
	return i, nil
}
func (i Installation) owned() error {
	info, e := os.Lstat(i.Dir)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Старый каталог cproxy не является обычным каталогом")
	}
	b, e := os.ReadFile(filepath.Join(i.Dir, ".cproxy-owner"))
	if e != nil || strings.TrimSpace(string(b)) != "cproxy-v1" {
		return errors.New("Старая установка не принадлежит cproxy; автоматический перенос отменён")
	}
	return nil
}
func (i Installation) Settings() (config.Settings, error) {
	s := config.Defaults()
	if e := i.owned(); e != nil {
		return s, e
	}
	b, e := os.ReadFile(filepath.Join(i.Dir, "config.json"))
	if e != nil {
		return s, e
	}
	var old struct {
		Inbounds []struct {
			Port int `json:"listen_port"`
		}
		Outbounds []struct {
			Type, Server, User string
			Port               int      `json:"server_port"`
			Key                string   `json:"private_key_path"`
			Pins               []string `json:"host_key"`
		}
		Route struct {
			Rules []struct {
				Outbound string
				Domains  []string `json:"domain_suffix"`
				CIDRs    []string `json:"ip_cidr"`
			}
		}
	}
	if e = json.Unmarshal(b, &old); e != nil {
		return s, e
	}
	if len(old.Inbounds) != 1 || len(old.Outbounds) < 1 || old.Outbounds[0].Type != "ssh" || len(old.Outbounds[0].Pins) != 1 {
		return s, errors.New("Старая конфигурация не распознана")
	}
	o := old.Outbounds[0]
	s.Server = o.Server
	s.User = o.User
	s.Key = o.Key
	s.SSHPort = o.Port
	s.ProxyPort = old.Inbounds[0].Port
	s.HostKey = o.Pins[0]
	s.Domains = nil
	s.CIDRs = nil
	for _, r := range old.Route.Rules {
		if r.Outbound == "direct" {
			s.Domains = append(s.Domains, r.Domains...)
			s.CIDRs = append(s.CIDRs, r.CIDRs...)
		}
	}
	b, e = os.ReadFile(filepath.Join(i.Dir, "settings.json"))
	if e != nil {
		return s, e
	}
	var state struct {
		Mode     string   `json:"key_mode"`
		Original string   `json:"encrypted_key_path"`
		IPs      []string `json:"expected_ips"`
		Binary   string   `json:"binary"`
	}
	if e = json.Unmarshal(b, &state); e != nil {
		return s, e
	}
	if state.Mode == "session" {
		if state.Original == "" {
			return s, errors.New("В старой установке отсутствует путь исходного зашифрованного ключа")
		}
		s.Key = state.Original
	}
	s.ExpectedIPs = state.IPs
	s.Engine = state.Binary
	s.Profile = filepath.Join(i.Dir, "firefox-Claude")
	return s, nil
}
func (i Installation) Pause(ctx context.Context) (func() error, error) {
	if e := i.owned(); e != nil {
		return nil, e
	}
	return i.pause(ctx)
}
