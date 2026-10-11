package legacy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestImportPreservesEncryptedOriginalAndProfile(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, ".cproxy-owner"), []byte("cproxy-v1\n"), 0600)
	os.WriteFile(filepath.Join(d, "config.json"), []byte(`{"inbounds":[{"listen_port":2080}],"outbounds":[{"type":"ssh","server":"vps.example.org","server_port":2222,"user":"proxy","private_key_path":"/runtime/session.key","host_key":["ssh-ed25519 fixture"]}],"route":{"rules":[{"outbound":"direct","domain_suffix":["corp.example"]}]}}`), 0600)
	os.WriteFile(filepath.Join(d, "settings.json"), []byte(`{"key_mode":"session","encrypted_key_path":"/original/key","expected_ips":["203.0.113.7"]}`), 0600)
	i := Installation{Dir: d}
	s, e := i.Settings()
	if e != nil {
		t.Fatal(e)
	}
	if s.Key != "/original/key" || s.SSHPort != 2222 || s.Domains[0] != "corp.example" || s.HostKey != "ssh-ed25519 fixture" || s.Profile != filepath.Join(d, "firefox-Claude") {
		t.Fatalf("lost migration data: %+v", s)
	}
}
func TestUnownedDirectoryCannotMigrate(t *testing.T) {
	i := Installation{Dir: t.TempDir()}
	if _, e := i.Settings(); e == nil {
		t.Fatal("accepted foreign directory")
	}
}
