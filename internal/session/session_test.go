package session

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cproxy/internal/config"
	"cproxy/internal/platform"
)

func TestControlRejectsUnauthorizedAndBrowserRequests(t *testing.T) {
	stopped := false
	h := controlHandler("secret", Status{Server: "vps"}, func() { stopped = true })
	for _, tc := range []struct {
		method, token, origin string
		want                  int
	}{{"POST", "bad", "", 401}, {"POST", "secret", "https://evil.example", 403}, {"GET", "secret", "", 405}, {"POST", "secret", "", 200}} {
		r := httptest.NewRequest(tc.method, "http://127.0.0.1/stop", nil)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("got %d want %d", w.Code, tc.want)
		}
	}
	if !stopped {
		t.Fatal("authorized stop ignored")
	}
}
func TestStateCannotPointToRemoteHost(t *testing.T) {
	m := Manager{Dir: t.TempDir()}
	os.WriteFile(filepath.Join(m.Dir, "session.json"), []byte(`{"address":"evil.example:1234","token":"secret"}`), 0600)
	if _, e := m.Status(context.Background()); e == nil {
		t.Fatal("accepted remote control endpoint")
	}
}
func TestStateCannotBeSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "another-session.json")
	os.WriteFile(target, mustJSON(t, state{"127.0.0.1:1234", strings.Repeat("a", 64)}), 0600)
	if e := os.Symlink(target, filepath.Join(dir, "session.json")); e != nil {
		t.Skipf("symlink unavailable: %v", e)
	}
	if _, e := (Manager{Dir: dir}).readState(); e == nil {
		t.Fatal("accepted symlinked session state")
	}
}
func TestSingletonLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lock")
	first, e := platform.Lock(p)
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	if second, e := platform.Lock(p); e == nil {
		second.Close()
		t.Fatal("second lock accepted")
	}
}
func TestOversizedBootstrapRejected(t *testing.T) {
	m := Manager{Dir: t.TempDir()}
	if e := m.Run(context.Background(), &oversized{}); e == nil {
		t.Fatal("unbounded bootstrap accepted")
	}
}

type oversized struct{}

func (*oversized) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
func TestSettingsIdentityChangesWithRoute(t *testing.T) {
	s := config.Defaults()
	a := identity(s)
	s.Domains = []string{"corp.example"}
	if a == identity(s) {
		t.Fatal("session reused after route change")
	}
}

func TestLogRedactsAcrossWritesAndBoundsDisk(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log")
	log, e := newLog(p, "session-secret")
	if e != nil {
		t.Fatal(e)
	}
	log.Write([]byte("session-"))
	log.Write([]byte("secret\n"))
	huge := make([]byte, 2*1024*1024)
	for i := range huge {
		huge[i] = 'x'
	}
	huge[len(huge)-1] = '\n'
	log.Write(huge)
	log.Close()
	b, _ := os.ReadFile(p)
	if bytes.Contains(b, []byte("session-secret")) || len(b) > 1024*1024 {
		t.Fatalf("unbounded or secret log: %d bytes", len(b))
	}
}
