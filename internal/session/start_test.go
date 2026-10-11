package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cproxy/internal/config"
	"cproxy/internal/platform"
	"golang.org/x/crypto/ssh"
)

func init() {
	if os.Getenv("CPROXY_START_HELPER") != "" && len(os.Args) > 1 && os.Args[1] == "--serve" {
		io.Copy(io.Discard, os.Stdin)
		os.WriteFile(os.Getenv("CPROXY_START_HELPER"), []byte(strconv.Itoa(os.Getpid())), 0600)
		for {
			time.Sleep(time.Minute)
		}
	}
}

// A different supervisor wins after our initial status check, then our caller
// is cancelled. Cleanup must kill only our own launcher, not the winner.
func TestCancelledConcurrentStartCannotStopWinner(t *testing.T) {
	engine := os.Getenv("CPROXY_TEST_SING_BOX")
	if engine == "" {
		t.Skip("set CPROXY_TEST_SING_BOX")
	}
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	marker := filepath.Join(root, "child-started")
	t.Setenv("CPROXY_START_HELPER", marker)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "test")
	key := filepath.Join(root, "key")
	os.WriteFile(key, pem.EncodeToMemory(block), 0600)
	signer, _ := ssh.NewSignerFromKey(priv)
	s := config.Defaults()
	s.Server, s.User, s.Key, s.Engine = "127.0.0.1", "proxy", key, engine
	s.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	exe, _ := os.Executable()
	m := Manager{Dir: filepath.Join(root, "state"), Executable: exe}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- m.Start(ctx, s, nil) }()
	waitFor(t, func() bool { _, e := os.Stat(marker); return e == nil })
	b, _ := os.ReadFile(marker)
	pid, _ := strconv.Atoi(string(b))
	child, _ := os.FindProcess(pid)
	defer child.Kill()
	var stopped atomic.Bool
	winner := httptest.NewServer(controlHandler(strings.Repeat("a", 64), Status{Identity: "different-settings"}, func() { stopped.Store(true) }))
	defer winner.Close()
	platform.WritePrivate(filepath.Join(m.Dir, "session.json"), mustJSON(t, state{strings.TrimPrefix(winner.URL, "http://"), strings.Repeat("a", 64)}))
	cancel()
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("cancelled start succeeded")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("cancelled start did not return")
	}
	if stopped.Load() {
		t.Fatal("losing caller stopped a different winning supervisor")
	}
}

func TestRevokedSavedPinRejectedByEverySessionEntry(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "test")
	key := filepath.Join(root, "key")
	os.WriteFile(key, pem.EncodeToMemory(block), 0600)
	signer, _ := ssh.NewSignerFromKey(priv)
	s := config.Defaults()
	s.Server, s.User, s.Key = "revoked.example", "proxy", key
	s.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	os.Mkdir(filepath.Join(root, ".ssh"), 0700)
	os.WriteFile(filepath.Join(root, ".ssh", "known_hosts"), []byte("@revoked revoked.example "+s.HostKey+"\n"), 0600)
	m := Manager{Dir: filepath.Join(root, "state")}
	for _, entry := range []struct {
		name string
		run  func() error
	}{
		{"Start", func() error { return m.Start(context.Background(), s, nil) }},
		{"Ready", func() error { _, e := m.Ready(context.Background(), s); return e }},
		{"Foreground", func() error { return m.Foreground(context.Background(), s, nil) }},
	} {
		t.Run(entry.name, func(t *testing.T) {
			if e := entry.run(); e == nil || !strings.Contains(e.Error(), "known_hosts") {
				t.Fatalf("revoked pin bypassed shared trust validation: %v", e)
			}
		})
	}
}
