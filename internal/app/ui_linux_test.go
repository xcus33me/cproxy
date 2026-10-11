package app

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/creack/pty"
)

func TestTerminalCancellationLeavesNoConfig(t *testing.T) {
	exe, _ := os.Executable()
	home := t.TempDir()
	cmd := exec.Command(exe, "-test.run=TestTerminalHelper")
	cmd.Env = append(os.Environ(), "CPROXY_TERMINAL_HELPER=1", "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, "config"), "XDG_CACHE_HOME="+filepath.Join(home, "cache"), "TERM=xterm-256color", "CPROXY_ACCESSIBLE=0")
	terminal, e := pty.StartWithSize(cmd, &pty.Winsize{Rows: 35, Cols: 100})
	if e != nil {
		t.Fatal(e)
	}
	defer terminal.Close()
	defer cmd.Process.Kill()
	chunks := make(chan []byte, 64)
	go func() {
		for {
			b := make([]byte, 4096)
			n, e := terminal.Read(b)
			if n > 0 {
				chunks <- b[:n]
			}
			if e != nil {
				close(chunks)
				return
			}
		}
	}()
	deadline := time.After(5 * time.Second)
	var output []byte
	ready := false
	for !ready {
		select {
		case b, ok := <-chunks:
			if !ok {
				t.Fatalf("terminal closed: %s", output)
			}
			output = append(output, b...)
			if bytes.Contains(b, []byte("\x1b[6n")) {
				io.WriteString(terminal, "\x1b[1;1R")
			}
			ready = bytes.Contains(output, []byte("Адрес вашего сервера"))
		case <-deadline:
			t.Fatalf("wizard missing: %s", output)
		}
	}
	io.WriteString(terminal, "\x1b")
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case e := <-done:
		var code int
		if exit, ok := e.(*exec.ExitError); ok {
			code = exit.ExitCode()
		}
		if code != 130 {
			t.Fatalf("cancel exit %d, error %v", code, e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Esc did not cancel")
	}
	if _, e := os.Stat(filepath.Join(home, "config", "cproxy", "settings.json")); !os.IsNotExist(e) {
		t.Fatal("cancelled wizard wrote settings")
	}
}
func TestTerminalHelper(t *testing.T) {
	if os.Getenv("CPROXY_TERMINAL_HELPER") == "1" {
		os.Exit(Run([]string{"setup"}))
	}
}
