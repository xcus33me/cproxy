package config

import (
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T) Settings {
	t.Helper()
	key := filepath.Join(t.TempDir(), "key with spaces")
	if err := os.WriteFile(key, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	s := Defaults()
	s.Server = "proxy@[2001:db8::1]:2222"
	s.Key = key
	return s
}
func TestNormalizeAddress(t *testing.T) {
	s := fixture(t)
	if err := s.Normalize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if s.Server != "2001:db8::1" || s.User != "proxy" || s.SSHPort != 2222 {
		t.Fatalf("address lost: %+v", s)
	}
}
func TestUnsafeExclusions(t *testing.T) {
	for _, domain := range []string{"com", "ai", "claude.ai", "x.anthropic.com", "bad..company", "*"} {
		t.Run(domain, func(t *testing.T) {
			s := fixture(t)
			s.Domains = []string{domain}
			if s.Normalize(t.TempDir()) == nil {
				t.Fatal("accepted unsafe exclusion")
			}
		})
	}
}

func TestOnlyPrivateCIDRsCanBypassProxy(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0", "8.8.8.8/32", "10.0.0.0/7"} {
		s := fixture(t)
		s.CIDRs = []string{cidr}
		if s.Normalize(t.TempDir()) == nil {
			t.Fatalf("accepted public range %s", cidr)
		}
	}
	s := fixture(t)
	s.CIDRs = []string{"10.2.0.0/16", "fc00::/8"}
	if e := s.Normalize(t.TempDir()); e != nil {
		t.Fatal(e)
	}
}
func TestPersistenceRejectsFutureAndCorruptConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	for _, data := range []string{`{"version":99}`, `{broken`} {
		os.WriteFile(p, []byte(data), 0600)
		if _, err := Load(p); err == nil {
			t.Fatal("accepted bad config")
		}
	}
}
func TestPrivateRoundTrip(t *testing.T) {
	s := fixture(t)
	if err := s.Normalize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "app", "settings.json")
	if err := Save(p, s); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != s.Key || got.Server != s.Server {
		t.Fatal("settings lost")
	}
}
func TestRefuseSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "unrelated")
	os.WriteFile(target, []byte("original"), 0600)
	p := filepath.Join(dir, "settings.json")
	if err := os.Symlink(target, p); err != nil {
		t.Skip(err)
	}
	if Save(p, fixture(t)) == nil {
		t.Fatal("accepted symlink")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "original" {
		t.Fatal("overwrote unrelated file")
	}
}
