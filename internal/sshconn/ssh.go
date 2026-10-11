// Package sshconn verifies credentials and server identity before starting a proxy.
package sshconn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"cproxy/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type UnknownHostError struct{ Key, Fingerprint string }

func (e *UnknownHostError) Error() string {
	return "Неизвестный SSH-сервер: " + e.Fingerprint
}
func Signer(path string, passphrase []byte) (ssh.Signer, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	defer clear(b)
	if len(passphrase) > 0 {
		return ssh.ParsePrivateKeyWithPassphrase(b, passphrase)
	}
	return ssh.ParsePrivateKey(b)
}
func Algorithms(key ssh.PublicKey) []string {
	if key.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{key.Type()}
}
func PublicKey(s string) (ssh.PublicKey, error) {
	key, _, _, rest, e := ssh.ParseAuthorizedKey([]byte(s))
	if e != nil || len(strings.TrimSpace(string(rest))) > 0 {
		return nil, errors.New("Некорректный сохранённый SSH host key")
	}
	if _, ok := key.(*ssh.Certificate); ok {
		return nil, errors.New("SSH-сертификаты пока не поддерживаются")
	}
	return key, nil
}

func knownHosts() (ssh.HostKeyCallback, error) {
	home, e := os.UserHomeDir()
	if e != nil {
		return nil, e
	}
	paths := []string{filepath.Join(home, ".ssh", "known_hosts")}
	if runtime.GOOS == "windows" {
		if p := os.Getenv("PROGRAMDATA"); p != "" {
			paths = append(paths, filepath.Join(p, "ssh", "ssh_known_hosts"))
		}
	} else {
		paths = append(paths, "/etc/ssh/ssh_known_hosts")
	}
	var existing []string
	for _, p := range paths {
		if _, e := os.Stat(p); e == nil {
			existing = append(existing, p)
		} else if !os.IsNotExist(e) {
			return nil, e
		}
	}
	if len(existing) > 0 {
		known, e := knownhosts.New(existing...)
		if e != nil {
			return nil, fmt.Errorf("known_hosts: %w", e)
		}
		return known, nil
	}
	return nil, nil
}

func checkKnown(known ssh.HostKeyCallback, host string, remote net.Addr, key ssh.PublicKey, pinned bool) error {
	if known != nil {
		if e := known(host, remote, key); e != nil {
			var ke *knownhosts.KeyError
			if !errors.As(e, &ke) || len(ke.Want) > 0 {
				return fmt.Errorf("Проверка known_hosts: %w", e)
			}
			if !pinned {
				return &UnknownHostError{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), ssh.FingerprintSHA256(key)}
			}
		}
	} else if !pinned {
		return &UnknownHostError{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), ssh.FingerprintSHA256(key)}
	}
	return nil
}

// ValidateTrust rechecks a saved pin against local revocations/mismatches without
// needing the private-key passphrase or connecting to the VPS. The SSH engine
// still verifies this pin on every actual connection.
func ValidateTrust(s config.Settings) error {
	key, e := PublicKey(s.HostKey)
	if e != nil {
		return e
	}
	known, e := knownHosts()
	if e != nil {
		return e
	}
	host := net.JoinHostPort(s.Server, strconv.Itoa(s.SSHPort))
	return checkKnown(known, host, &net.TCPAddr{IP: net.ParseIP(s.Server), Port: s.SSHPort}, key, true)
}

func Probe(ctx context.Context, s config.Settings, passphrase []byte) (string, error) {
	signer, e := Signer(s.Key, passphrase)
	if e != nil {
		return "", fmt.Errorf("SSH-ключ: %w", e)
	}
	var pinned ssh.PublicKey
	if s.HostKey != "" {
		pinned, e = PublicKey(s.HostKey)
		if e != nil {
			return "", e
		}
	}
	known, e := knownHosts()
	if e != nil {
		return "", e
	}
	var verified string
	callback := func(host string, remote net.Addr, k ssh.PublicKey) error {
		if _, ok := k.(*ssh.Certificate); ok {
			return errors.New("SSH-сертификаты пока не поддерживаются")
		}
		if pinned != nil && string(pinned.Marshal()) != string(k.Marshal()) {
			return errors.New("Ключ VPS изменился; сохранённый ключ не заменён")
		}
		if e := checkKnown(known, host, remote, k, pinned != nil); e != nil {
			return e
		}
		verified = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
		return nil
	}
	cfg := &ssh.ClientConfig{User: s.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: callback, Timeout: 12 * time.Second}
	if pinned != nil {
		cfg.HostKeyAlgorithms = Algorithms(pinned)
	}
	addr := net.JoinHostPort(s.Server, strconv.Itoa(s.SSHPort))
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	conn, e := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if e != nil {
		return "", fmt.Errorf("Соединение с VPS: %w", e)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	client, ch, r, e := ssh.NewClientConn(conn, addr, cfg)
	if e != nil {
		return "", fmt.Errorf("SSH: %w", e)
	}
	ssh.NewClient(client, ch, r).Close()
	return verified, nil
}
