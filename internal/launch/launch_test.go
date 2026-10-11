package launch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvironmentCannotBypassOrMutateParent(t *testing.T) {
	base := []string{"PATH=original", "https_proxy=http://wrong", "NO_PROXY=*", "all_proxy=socks5://wrong", "Token=keep"}
	got := strings.Join(Environment(base, 2080), "\n")
	for _, bad := range []string{"http://wrong", "NO_PROXY=*", "socks5://wrong"} {
		if strings.Contains(got, bad) {
			t.Fatalf("inherited bypass: %s", got)
		}
	}
	if !strings.Contains(got, "https_proxy=http://127.0.0.1:2080") || !strings.Contains(got, "Token=keep") || base[1] != "https_proxy=http://wrong" {
		t.Fatal("bad child environment")
	}
}
func TestProfilePreservesUserDataAndRejectsUnmanagedPrefs(t *testing.T) {
	d := t.TempDir()
	cookies := filepath.Join(d, "cookies.sqlite")
	os.WriteFile(cookies, []byte("saved session"), 0600)
	if e := WriteProfile(d, 2080); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(cookies)
	if string(b) != "saved session" {
		t.Fatal("profile data lost")
	}
	prefs, _ := os.ReadFile(filepath.Join(d, "user.js"))
	if !strings.Contains(string(prefs), `user_pref("network.proxy.failover_direct", false)`) {
		t.Fatal("browser can fall back")
	}
	os.WriteFile(filepath.Join(d, "user.js"), []byte("// my configuration"), 0600)
	if WriteProfile(d, 2080) == nil {
		t.Fatal("overwrote unmanaged prefs")
	}
}
func TestProfileAcceptsManagedWindowsLineEndings(t *testing.T) {
	for _, ending := range []string{"\n", "\r\n"} {
		d := t.TempDir()
		os.WriteFile(filepath.Join(d, "user.js"), []byte("// Managed by cproxy"+ending+"old prefs"), 0600)
		if e := WriteProfile(d, 2080); e != nil {
			t.Fatalf("managed marker %q rejected: %v", ending, e)
		}
	}
}
func TestCommandPreservesArgumentsAndWorkingDirectory(t *testing.T) {
	exe, _ := os.Executable()
	args := []string{"-test.run=TestLaunchHelper", "--", "a b", `$(touch nope)`, "", `x&y%PATH%`}
	cmd, e := Command(exe, args, 2080)
	if e != nil {
		t.Fatal(e)
	}
	cmd.Env = append(cmd.Env, "CPROXY_LAUNCH_HELPER=1")
	cmd.Dir = t.TempDir()
	out, e := cmd.Output()
	if e != nil {
		t.Fatalf("helper failed: %v %s", e, out)
	}
	var got struct {
		Args       []string
		Dir, Proxy string
	}
	if e = json.Unmarshal(out, &got); e != nil {
		t.Fatal(e)
	}
	if len(got.Args) != 4 || got.Args[1] != `$(touch nope)` || got.Args[2] != "" || got.Proxy != "http://127.0.0.1:2080" {
		t.Fatalf("arguments or environment lost: %s", out)
	}
	a, _ := filepath.EvalSymlinks(got.Dir)
	b, _ := filepath.EvalSymlinks(cmd.Dir)
	if a != b {
		t.Fatal("working directory lost")
	}
}
func TestLaunchHelper(t *testing.T) {
	if os.Getenv("CPROXY_LAUNCH_HELPER") != "1" {
		return
	}
	index := 0
	for i, a := range os.Args {
		if a == "--" {
			index = i + 1
			break
		}
	}
	dir, _ := os.Getwd()
	json.NewEncoder(os.Stdout).Encode(struct {
		Args       []string
		Dir, Proxy string
	}{os.Args[index:], dir, os.Getenv("HTTPS_PROXY")})
	os.Exit(0)
}
