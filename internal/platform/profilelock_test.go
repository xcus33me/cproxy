package platform

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestFirefoxProfileLock(t *testing.T) {
	dir := t.TempDir()
	if busy, e := ProfileInUse(dir); e != nil || busy {
		t.Fatalf("new profile: %v %v", busy, e)
	}
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "-test.run=TestFirefoxLockHelper")
	cmd.Env = append(os.Environ(), "CPROXY_FIREFOX_LOCK="+dir)
	input, _ := cmd.StdinPipe()
	output, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { input.Close(); cmd.Process.Kill(); cmd.Wait() }()
	scan := bufio.NewScanner(output)
	if !scan.Scan() || scan.Text() != "locked" {
		t.Fatal("helper failed to acquire Firefox-style lock")
	}
	if busy, e := ProfileInUse(dir); e != nil || !busy {
		t.Fatalf("running profile not detected: %v %v", busy, e)
	}
	input.Close()
	if e := cmd.Wait(); e != nil {
		t.Fatal(e)
	}
	if busy, e := ProfileInUse(dir); e != nil || busy {
		t.Fatalf("stale lock file incorrectly considered busy: %v %v", busy, e)
	}
}

func TestFirefoxLockHelper(t *testing.T) {
	dir := os.Getenv("CPROXY_FIREFOX_LOCK")
	if dir == "" {
		return
	}
	lock, e := acquireFirefoxLock(filepath.Join(dir, firefoxLockFile))
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	fmt.Println("locked")
	io.Copy(io.Discard, os.Stdin)
}
