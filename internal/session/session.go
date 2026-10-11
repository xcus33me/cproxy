// Package session owns one background cproxy process and its sing-box child.
package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"cproxy/internal/config"
	"cproxy/internal/engine"
	"cproxy/internal/platform"
	"cproxy/internal/sshconn"
)

type Manager struct{ Dir, Executable string }
type bootstrap struct {
	Settings   config.Settings `json:"settings"`
	Passphrase []byte          `json:"passphrase,omitempty"`
}

func (m Manager) Foreground(ctx context.Context, s config.Settings, pass []byte) error {
	packet, e := json.Marshal(bootstrap{s, pass})
	if e != nil {
		return e
	}
	defer clear(packet)
	return m.Run(ctx, bytes.NewReader(packet))
}

func identity(s config.Settings) string {
	b, _ := json.Marshal(s)
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}
func (m Manager) Ready(ctx context.Context, s config.Settings) (string, error) {
	if e := sshconn.ValidateTrust(s); e != nil {
		return "", e
	}
	st, e := m.Status(ctx)
	if e != nil {
		return "", e
	}
	if st.Identity != identity(s) {
		return "", errors.New("Прокси запущен с другими настройками; остановите его и запустите снова")
	}
	ip, e := engine.Egress(ctx, s.ProxyPort)
	if e != nil {
		return "", e
	}
	return ip, engine.VerifyIP(s, ip)
}
func (m Manager) Start(ctx context.Context, s config.Settings, pass []byte) error {
	if e := sshconn.ValidateTrust(s); e != nil {
		return e
	}
	if e := platform.PrivateDir(m.Dir); e != nil {
		return e
	}
	if _, e := m.readState(); e != nil && !os.IsNotExist(e) {
		return e
	}
	if running, e := m.Status(ctx); e == nil {
		if running.Identity != identity(s) {
			return errors.New("Уже запущена сессия с другими настройками; сначала остановите её")
		}
		_, e = m.Ready(ctx, s)
		return e
	}
	binary, e := engine.Find(s)
	if e != nil {
		return e
	}
	data, e := engine.Config(s, pass)
	if e != nil {
		return e
	}
	defer clear(data)
	if e = engine.Check(ctx, binary, data); e != nil {
		return e
	}
	packet, e := json.Marshal(bootstrap{s, pass})
	if e != nil {
		return e
	}
	defer clear(packet)
	executable := m.Executable
	if executable == "" {
		executable, e = os.Executable()
		if e != nil {
			return e
		}
	}
	cmd := exec.Command(executable, "--serve", m.Dir)
	reader, writer, e := os.Pipe()
	if e != nil {
		return e
	}
	defer reader.Close()
	defer writer.Close()
	cmd.Stdin = reader
	platform.Detach(cmd)
	if e = cmd.Start(); e != nil {
		return e
	}
	reader.Close()
	go cmd.Wait() // reap failed/duplicate launchers while the menu remains open
	writeCtx, writeCancel := context.WithTimeout(ctx, 10*time.Second)
	defer writeCancel()
	stopWrite := context.AfterFunc(writeCtx, func() { writer.Close() })
	_, e = writer.Write(packet)
	writer.Close()
	stopWrite()
	if e != nil {
		cmd.Process.Kill()
		return fmt.Errorf("Не удалось передать настройки сессии: %w", e)
	}
	deadline, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	for {
		if _, e = m.Ready(deadline, s); e == nil {
			return nil
		}
		select {
		case <-deadline.Done():
			// Only terminate the process this invocation started. A concurrent
			// launcher may have won the singleton lock with different settings.
			cmd.Process.Kill()
			return fmt.Errorf("Прокси не готов: %w. Подробности: cproxy logs", e)
		case <-time.After(150 * time.Millisecond):
		}
	}
}

func (m Manager) Run(ctx context.Context, input io.Reader) error {
	raw, e := io.ReadAll(io.LimitReader(input, 65537))
	if e != nil {
		return e
	}
	defer clear(raw)
	if len(raw) > 65536 {
		return errors.New("Слишком большой bootstrap")
	}
	var b bootstrap
	if e = json.Unmarshal(raw, &b); e != nil {
		return errors.New("Некорректный bootstrap сессии")
	}
	defer clear(b.Passphrase)
	home, e := os.UserHomeDir()
	if e != nil {
		return e
	}
	if e = b.Settings.Normalize(home); e != nil {
		return e
	}
	if e = sshconn.ValidateTrust(b.Settings); e != nil {
		return e
	}
	if e = platform.PrivateDir(m.Dir); e != nil {
		return e
	}
	lock, e := platform.Lock(filepath.Join(m.Dir, "session.lock"))
	if e != nil {
		return errors.New("Сессия cproxy уже запускается")
	}
	defer lock.Close()
	probe, e := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(b.Settings.ProxyPort)))
	if e != nil {
		return errors.New("Локальный порт занят другим процессом")
	}
	probe.Close()
	binary, e := engine.Find(b.Settings)
	if e != nil {
		return e
	}
	data, e := engine.Config(b.Settings, b.Passphrase)
	if e != nil {
		return e
	}
	defer clear(data)
	if e = engine.Check(ctx, binary, data); e != nil {
		return e
	}
	log, e := newLog(filepath.Join(m.Dir, "cproxy.log"), string(b.Passphrase))
	if e != nil {
		return e
	}
	defer log.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	defer listener.Close()
	secret := make([]byte, 32)
	if _, e = rand.Read(secret); e != nil {
		return e
	}
	st := state{listener.Addr().String(), hex.EncodeToString(secret)}
	status := Status{b.Settings.Server, b.Settings.ProxyPort, time.Now().UTC(), identity(b.Settings)}
	srv := &http.Server{Handler: controlHandler(st.Token, status, cancel), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	stateData, _ := json.Marshal(st)
	statePath := filepath.Join(m.Dir, "session.json")
	if e = platform.WritePrivate(statePath, stateData); e != nil {
		return e
	}
	defer os.Remove(statePath)
	controlDone := make(chan error, 1)
	go func() { controlDone <- srv.Serve(listener) }()
	defer func() {
		shutdown, done := context.WithTimeout(context.Background(), time.Second)
		defer done()
		srv.Shutdown(shutdown)
		<-controlDone
	}()
	return engine.Serve(ctx, binary, data, log)
}
