package sshconn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"cproxy/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func key(t *testing.T) (string, ssh.Signer) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	b, _ := x509.MarshalPKCS8PrivateKey(priv)
	p := filepath.Join(t.TempDir(), "key")
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), 0600)
	s, _ := ssh.NewSignerFromKey(priv)
	return p, s
}
func server(t *testing.T) (config.Settings, string) {
	t.Helper()
	path, client := key(t)
	_, host := key(t)
	c := &ssh.ServerConfig{PublicKeyCallback: func(m ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) != string(client.PublicKey().Marshal()) {
			return nil, errors.New("wrong key")
		}
		return nil, nil
	}}
	c.AddHostKey(host)
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				s, ch, r, e := ssh.NewServerConn(conn, c)
				if e != nil {
					conn.Close()
					return
				}
				defer s.Close()
				go ssh.DiscardRequests(r)
				for c := range ch {
					c.Reject(ssh.UnknownChannelType, "unused")
				}
			}()
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(p)
	s := config.Defaults()
	s.Server = h
	s.SSHPort = port
	s.User = "proxy"
	s.Key = path
	return s, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(host.PublicKey())))
}
func TestUnknownHostNeedsConfirmation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	s, k := server(t)
	_, e := Probe(context.Background(), s, nil)
	var u *UnknownHostError
	if !errors.As(e, &u) || u.Key != k || !strings.HasPrefix(u.Fingerprint, "SHA256:") {
		t.Fatalf("expected unknown host, got %v", e)
	}
}
func TestPinnedHostCannotChange(t *testing.T) {
	s, k := server(t)
	s.HostKey = k
	if got, e := Probe(context.Background(), s, nil); e != nil || got != k {
		t.Fatalf("valid pin: %v", e)
	}
	_, wrong := key(t)
	s.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(wrong.PublicKey())))
	if _, e := Probe(context.Background(), s, nil); e == nil {
		t.Fatal("accepted wrong pin")
	}
}
func TestHashedKnownHostAndRevoked(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	s, k := server(t)
	os.Mkdir(filepath.Join(home, ".ssh"), 0700)
	p := filepath.Join(home, ".ssh", "known_hosts")
	host := knownhosts.Normalize(net.JoinHostPort(s.Server, strconv.Itoa(s.SSHPort)))
	os.WriteFile(p, []byte(knownhosts.HashHostname(host)+" "+k+"\n"), 0600)
	s.HostKey = k
	if e := ValidateTrust(s); e != nil {
		t.Fatalf("saved trusted pin: %v", e)
	}
	if got, e := Probe(context.Background(), s, nil); e != nil || got != k {
		t.Fatalf("hashed host: %v", e)
	}
	os.WriteFile(p, []byte("@revoked "+host+" "+k+"\n"), 0600)
	if e := ValidateTrust(s); e == nil {
		t.Fatal("saved pin bypassed revocation")
	}
	_, e := Probe(context.Background(), s, nil)
	var u *UnknownHostError
	if e == nil || errors.As(e, &u) {
		t.Fatalf("revoked key must not offer TOFU: %v", e)
	}
}
func TestEncryptedKeyRequiresCorrectPassphrase(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, e := ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte("secret"))
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(t.TempDir(), "encrypted")
	b := pem.EncodeToMemory(block)
	os.WriteFile(p, b, 0600)
	if _, e = Signer(p, nil); e == nil {
		t.Fatal("encrypted key accepted without password")
	}
	if _, e = Signer(p, []byte("wrong")); e == nil {
		t.Fatal("wrong password accepted")
	}
	if _, e = Signer(p, []byte("secret")); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(p)
	if string(after) != string(b) {
		t.Fatal("key file modified")
	}
}
