// Package config stores user choices, never key material or passwords.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"cproxy/internal/platform"
)

var ProtectedDomains = []string{"anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com", "claudemcpcontent.com"}
var PrivateNetworks = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}

type Settings struct {
	Version     int      `json:"version"`
	Server      string   `json:"server"`
	User        string   `json:"user"`
	Key         string   `json:"key"`
	SSHPort     int      `json:"ssh_port"`
	ProxyPort   int      `json:"proxy_port"`
	HostKey     string   `json:"host_key,omitempty"`
	Domains     []string `json:"direct_domains"`
	CIDRs       []string `json:"direct_cidrs"`
	Engine      string   `json:"sing_box,omitempty"`
	ExpectedIPs []string `json:"expected_ips,omitempty"`
	Profile     string   `json:"firefox_profile,omitempty"`
}

func Defaults() Settings {
	return Settings{Version: 1, SSHPort: 22, ProxyPort: 2080, Domains: []string{"local"}, CIDRs: append([]string(nil), PrivateNetworks...)}
}
func Dir() (string, error)      { d, e := os.UserConfigDir(); return filepath.Join(d, "cproxy"), e }
func StateDir() (string, error) { d, e := os.UserCacheDir(); return filepath.Join(d, "cproxy"), e }
func ExpandHome(p, home string) string {
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Join(home, p[2:])
	}
	return p
}
func validName(s string) bool {
	if s == "" || len(s) > 253 || strings.Contains(s, "..") {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func ValidateDomain(d string) error {
	if !validName(d) || (!strings.Contains(d, ".") && d != "local") {
		return fmt.Errorf("Укажите конкретный внутренний домен, например corp.example или local: %q", d)
	}
	for _, p := range ProtectedDomains {
		if d == p || strings.HasSuffix(d, "."+p) || strings.HasSuffix(p, "."+d) {
			return errors.New("Домен Claude нельзя добавить в прямые исключения")
		}
	}
	return nil
}
func ValidateCIDR(value string) error {
	prefix, e := netip.ParsePrefix(value)
	if e != nil {
		return fmt.Errorf("Некорректная подсеть: %q", value)
	}
	for _, v := range PrivateNetworks {
		allowed := netip.MustParsePrefix(v)
		if allowed.Addr().BitLen() == prefix.Addr().BitLen() && allowed.Contains(prefix.Addr()) && prefix.Bits() >= allowed.Bits() {
			return nil
		}
	}
	return fmt.Errorf("Прямые исключения допустимы только для частных подсетей: %s", value)
}
func (s *Settings) Normalize(home string) error {
	if s.Version != 1 {
		return fmt.Errorf("Неподдерживаемая версия настроек: %d", s.Version)
	}
	s.Server = strings.TrimSpace(s.Server)
	s.User = strings.TrimSpace(s.User)
	if i := strings.LastIndexByte(s.Server, '@'); i >= 0 {
		s.User = s.Server[:i]
		s.Server = s.Server[i+1:]
	}
	if host, p, e := net.SplitHostPort(s.Server); e == nil {
		n, e := strconv.Atoi(p)
		if e != nil {
			return errors.New("Некорректный SSH-порт")
		}
		s.Server = host
		s.SSHPort = n
	} else {
		s.Server = strings.TrimPrefix(strings.TrimSuffix(s.Server, "]"), "[")
	}
	if _, e := netip.ParseAddr(s.Server); e != nil && !validName(s.Server) {
		return errors.New("Укажите IP или имя VPS, без ssh://")
	}
	if s.User == "" || strings.ContainsAny(s.User, "\x00\r\n\t @") {
		return errors.New("Укажите SSH-пользователя без пробелов")
	}
	if s.SSHPort < 1 || s.SSHPort > 65535 || s.ProxyPort < 1 || s.ProxyPort > 65535 {
		return errors.New("Порт должен быть от 1 до 65535")
	}
	s.Key = ExpandHome(strings.TrimSpace(s.Key), home)
	info, e := os.Stat(s.Key)
	if e != nil || !info.Mode().IsRegular() || strings.HasSuffix(s.Key, ".pub") {
		return errors.New("Выберите существующий приватный SSH-ключ, без .pub")
	}
	if !filepath.IsAbs(s.Key) {
		s.Key, e = filepath.Abs(s.Key)
		if e != nil {
			return e
		}
	}
	for i, d := range s.Domains {
		d = strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
		if e = ValidateDomain(d); e != nil {
			return e
		}
		s.Domains[i] = d
	}
	for _, ip := range s.ExpectedIPs {
		if _, e = netip.ParseAddr(ip); e != nil {
			return fmt.Errorf("Некорректный ожидаемый IP: %q", ip)
		}
	}
	for _, cidr := range s.CIDRs {
		if e = ValidateCIDR(cidr); e != nil {
			return e
		}
	}
	if s.Profile != "" && !filepath.IsAbs(s.Profile) {
		return errors.New("Путь профиля Firefox должен быть абсолютным")
	}
	return nil
}
func Load(path string) (Settings, error) {
	s := Defaults()
	b, e := os.ReadFile(path)
	if e != nil {
		return s, e
	}
	if e = json.Unmarshal(b, &s); e != nil {
		return s, fmt.Errorf("Повреждены настройки: %w", e)
	}
	if s.Version != 1 {
		return s, fmt.Errorf("Неподдерживаемая версия настроек: %d", s.Version)
	}
	return s, nil
}
func Save(path string, s Settings) error {
	b, e := json.MarshalIndent(s, "", "  ")
	if e != nil {
		return e
	}
	return platform.WritePrivate(path, append(b, '\n'))
}
