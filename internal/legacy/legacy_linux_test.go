package legacy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func init() {
	if os.Getenv("CPROXY_SYSTEMCTL_HELPER") != "1" {
		return
	}
	path := os.Getenv("CPROXY_SYSTEMCTL_STATE")
	b, _ := os.ReadFile(path)
	state := string(b)
	if len(os.Args) < 4 || os.Args[1] != "--user" || os.Args[len(os.Args)-1] != "selective-proxy.service" {
		os.Exit(9)
	}
	switch os.Args[2] {
	case "is-active":
		if state[0] != '1' {
			os.Exit(3)
		}
	case "is-enabled":
		if state[1] != '1' {
			os.Exit(1)
		}
	case "disable":
		os.WriteFile(path, []byte("00"), 0600)
		if os.Getenv("CPROXY_FAIL_DISABLE") == "1" {
			os.Exit(1)
		}
	case "enable":
		os.WriteFile(path, []byte(state[:1]+"1"), 0600)
	case "start":
		os.WriteFile(path, []byte("1"+state[1:]), 0600)
	default:
		os.Exit(9)
	}
	os.Exit(0)
}

func TestMigrationRestoresServiceState(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failed-disable"}[fail], func(t *testing.T) {
			root := t.TempDir()
			i := Installation{Dir: filepath.Join(root, "selective-proxy")}
			os.Mkdir(i.Dir, 0700)
			os.WriteFile(filepath.Join(i.Dir, ".cproxy-owner"), []byte("cproxy-v1"), 0600)
			unit := filepath.Join(root, "systemd", "user", "selective-proxy.service")
			os.MkdirAll(filepath.Dir(unit), 0700)
			os.WriteFile(unit, []byte("# Managed by cproxy\nExecStart=sing-box run -c \""+filepath.Join(i.Dir, "config.json")+"\"\n"), 0600)
			bin := filepath.Join(root, "bin")
			os.Mkdir(bin, 0700)
			exe, _ := os.Executable()
			os.Symlink(exe, filepath.Join(bin, "systemctl"))
			state := filepath.Join(root, "state")
			os.WriteFile(state, []byte("11"), 0600)
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("CPROXY_SYSTEMCTL_HELPER", "1")
			t.Setenv("CPROXY_SYSTEMCTL_STATE", state)
			if fail {
				t.Setenv("CPROXY_FAIL_DISABLE", "1")
			}
			restore, e := i.Pause(context.Background())
			if fail {
				if e == nil {
					t.Fatal("disable failure ignored")
				}
			} else {
				if e != nil {
					t.Fatal(e)
				}
				b, _ := os.ReadFile(state)
				if string(b) != "00" {
					t.Fatal("old service not paused")
				}
				if e = restore(); e != nil {
					t.Fatal(e)
				}
			}
			b, _ := os.ReadFile(state)
			if strings.TrimSpace(string(b)) != "11" {
				t.Fatal("old service state not restored")
			}
		})
	}
}
