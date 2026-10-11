package launch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cproxy/internal/config"
)

func TestOpenBrowserRefusesBusyProfileAndOffersURL(t *testing.T) {
	dir := t.TempDir()
	prefs := filepath.Join(dir, "user.js")
	os.WriteFile(prefs, []byte("// Managed by cproxy\nkeep while running"), 0600)
	if e := os.Symlink("127.0.0.1:+1234", filepath.Join(dir, "lock")); e != nil {
		t.Fatal(e)
	}
	address := "https://claude.ai/oauth/example"
	e := Browser(config.Defaults(), dir, address)
	if e == nil || !strings.Contains(e.Error(), "уже открыт") || !strings.Contains(e.Error(), address) {
		t.Fatalf("busy browser did not offer safe URL handoff: %v", e)
	}
	b, _ := os.ReadFile(prefs)
	if string(b) != "// Managed by cproxy\nkeep while running" {
		t.Fatal("modified a running profile")
	}
}
