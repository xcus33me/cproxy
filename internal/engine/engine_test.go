package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"cproxy/internal/config"
	"golang.org/x/crypto/ssh"
)

func settings(t *testing.T) config.Settings {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	s := config.Defaults()
	s.Server = "vps.example.org"
	s.User = "proxy"
	s.Key = "/key with spaces"
	s.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	s.Domains = []string{"corp.example"}
	return s
}
func TestConfigFailsWithoutPin(t *testing.T) {
	s := settings(t)
	s.HostKey = ""
	if _, e := Config(s, nil); e == nil {
		t.Fatal("unpinned SSH accepted")
	}
}
func TestRoutingAndEphemeralPassphrase(t *testing.T) {
	data, e := Config(settings(t), []byte("private secret"))
	if e != nil {
		t.Fatal(e)
	}
	var c struct {
		Inbounds []struct {
			Listen string `json:"listen"`
			System bool   `json:"set_system_proxy"`
		}
		Outbounds []struct {
			Pass string `json:"private_key_passphrase"`
		}
		Route struct {
			Final string
			Rules []struct {
				Domains  []string `json:"domain_suffix"`
				Outbound string
			}
		}
	}
	if e = json.Unmarshal(data, &c); e != nil {
		t.Fatal(e)
	}
	if c.Inbounds[0].Listen != "127.0.0.1" || c.Inbounds[0].System || c.Route.Final != "ssh-out" || c.Route.Rules[1].Outbound != "ssh-out" || c.Outbounds[0].Pass != "private secret" {
		t.Fatalf("unsafe config: %s", data)
	}
	if c.Route.Rules[len(c.Route.Rules)-1].Domains[0] != "corp.example" {
		t.Fatal("lost internal domain")
	}
}
func TestEgressUsesExplicitProxyDespiteEnvironment(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	t.Setenv("https_proxy", "http://wrong:1")
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		if r.Method != "CONNECT" {
			t.Errorf("expected CONNECT, got %s", r.Method)
		}
		w.WriteHeader(502)
	}))
	defer srv.Close()
	p, _ := strconv.Atoi(strings.Split(srv.Listener.Addr().String(), ":")[1])
	if _, e := Egress(context.Background(), p); e == nil {
		t.Fatal("bad proxy reported healthy")
	}
	if !hit {
		t.Fatal("explicit proxy bypassed")
	}
}
