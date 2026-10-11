package app

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWizardDefaultsAndHomePath(t *testing.T) {
	home := t.TempDir()
	key := filepath.Join(home, ".ssh", "id_ed25519")
	os.MkdirAll(filepath.Dir(key), 0700)
	os.WriteFile(key, []byte("key"), 0600)
	s := Defaults(home)
	if s.Key != key || s.SSHPort != 22 || s.ProxyPort != 2080 || s.Mode != "auto" {
		t.Fatalf("wrong defaults: %+v", s)
	}
	s.Server = "vps.example.org"
	s.User = "root"
	s.Key = "~/.ssh/id_ed25519"
	if err := s.Normalize(home); err != nil {
		t.Fatal(err)
	}
	if s.Key != key {
		t.Fatalf("home path not resolved: %q", s.Key)
	}
}
func TestRejectInvalidFieldsBeforeApply(t *testing.T) {
	home := t.TempDir()
	key := filepath.Join(home, "key with spaces")
	os.WriteFile(key, []byte("fixture"), 0600)
	good := Settings{Server: "vps.example.org", User: "proxy", Key: key, SSHPort: 22, ProxyPort: 2080, Mode: "unattended"}
	for _, change := range []func(*Settings){func(s *Settings) { s.Server = "-bad" }, func(s *Settings) { s.User = "" }, func(s *Settings) { s.SSHPort = 0 }, func(s *Settings) { s.ProxyPort = 65536 }, func(s *Settings) { s.Key = home }, func(s *Settings) { s.Mode = "unknown" }} {
		s := good
		change(&s)
		if s.Normalize(home) == nil {
			t.Fatalf("accepted invalid fields: %+v", s)
		}
	}
}
func TestPrivateWizardFileDoesNotContainPasswordsOrHostKey(t *testing.T) {
	s := Settings{Server: "vps.example.org", User: "proxy", Key: "/key with spaces", SSHPort: 22, ProxyPort: 2080, Mode: "unattended"}
	path, cleanup, err := WriteWizard(s)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if json.Unmarshal(data, &p) != nil {
		t.Fatal("invalid JSON")
	}
	if p["server"] != "vps.example.org" || p["key"] != "/key with spaces" || p["key_mode"] != "unattended" {
		t.Fatalf("incorrect payload: %s", data)
	}
	if strings.Contains(string(data), "host_key") || strings.Contains(string(data), "password") || strings.Contains(string(data), "expected_ips") {
		t.Fatalf("unnecessary wizard fields: %s", data)
	}
	if info, _ := os.Stat(path); runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("wizard file is not private")
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("wizard file not cleaned up")
	}
}
func TestBackendArgumentsKeepSpacesAndLiteralShellCharacters(t *testing.T) {
	root := filepath.Join(t.TempDir(), "project with spaces")
	os.MkdirAll(filepath.Join(root, "linux"), 0700)
	os.WriteFile(filepath.Join(root, "linux", "claude-vpn.sh"), nil, 0600)
	r := Runtime{Root: root, OS: "linux"}
	cmd, err := r.Command("claude", []string{"a b", "$(touch nope)", ""})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Path == "" || len(cmd.Args) != 5 || cmd.Args[1] != filepath.Join(root, "linux", "claude-vpn.sh") || cmd.Args[3] != "$(touch nope)" || cmd.Args[4] != "" {
		t.Fatalf("arguments changed: %#v", cmd.Args)
	}
	if _, err := r.Command("arbitrary-command", nil); err == nil {
		t.Fatal("unexpected backend operation allowed")
	}
}
func TestLoadExistingSessionUsesOriginalEncryptedKey(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"outbounds":[{"server":"vps.example.org","server_port":2222,"user":"proxy","private_key_path":"/runtime/session.key"}],"inbounds":[{"listen_port":2081}]}`), 0600)
	os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"key_mode":"session","encrypted_key_path":"/original/key"}`), 0600)
	s, err := LoadSettings(dir, "/home/person")
	if err != nil {
		t.Fatal(err)
	}
	if s.Key != "/original/key" || s.SSHPort != 2222 || s.ProxyPort != 2081 || s.Mode != "session" {
		t.Fatalf("settings lost: %+v", s)
	}
}

func TestDetectModeForPlainAndEncryptedKeys(t *testing.T) {
	binary, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("OpenSSH missing")
	}
	for _, pass := range []string{"", "example passphrase"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "key")
		cmd := exec.Command(binary, "-q", "-t", "ed25519", "-N", pass, "-f", path)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture key: %s %v", out, err)
		}
		mode, err := DetectMode(path)
		if err != nil {
			t.Fatal(err)
		}
		want := "unattended"
		if pass != "" {
			want = "session"
		}
		if mode != want {
			t.Fatalf("wanted %s got %s", want, mode)
		}
	}
}
func TestApplyFailureCleansUpWizardFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Bash backend fixture")
	}
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "linux"), 0700)
	pathRecord := filepath.Join(root, "wizard-path")
	script := `#!/bin/bash
printf '%s' "$2" > "$CPROXY_TEST_RECORD"
test -r "$2" || exit 9
exit 37
`
	os.WriteFile(filepath.Join(root, "linux", "install.sh"), []byte(script), 0700)
	t.Setenv("CPROXY_TEST_RECORD", pathRecord)
	r := Runtime{Root: root, OS: "linux", UIPath: "/binary with spaces"}
	err := r.Apply(Settings{Server: "vps.example.org", User: "proxy", Key: "/a key", SSHPort: 22, ProxyPort: 2080, Mode: "unattended"})
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 37 {
		t.Fatalf("exit lost: %v", err)
	}
	path, err := os.ReadFile(pathRecord)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(string(path)); !os.IsNotExist(err) {
		t.Fatal("wizard file remains after failed installation")
	}
}

func TestApplyCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Bash backend fixture")
	}
	root := t.TempDir()
	t.Setenv("TMPDIR", root)
	os.Mkdir(filepath.Join(root, "linux"), 0700)
	os.WriteFile(filepath.Join(root, "linux", "install.sh"), []byte("#!/bin/bash\nexit 130\n"), 0700)
	r := Runtime{Root: root, OS: "linux"}
	if err := r.Apply(Settings{}); !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if paths, _ := filepath.Glob(filepath.Join(root, "cproxy-wizard-*")); len(paths) != 0 {
		t.Fatal("cancelled wizard remains")
	}
}

func TestChildSignalExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix process signals")
	}
	for _, tc := range []struct {
		signal string
		code   int
	}{{"INT", 130}, {"TERM", 143}} {
		err := exec.Command("bash", "-c", "kill -"+tc.signal+" $$").Run()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || processExitCode(exit) != tc.code {
			t.Fatalf("signal %s exit lost: %v", tc.signal, err)
		}
	}
}
