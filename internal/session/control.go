package session

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Status struct {
	Server    string    `json:"server"`
	ProxyPort int       `json:"proxy_port"`
	Started   time.Time `json:"started"`
	Identity  string    `json:"identity"`
}
type state struct {
	Address string `json:"address"`
	Token   string `json:"token"`
}

func controlHandler(token string, status Status, stop func()) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Header.Get("Origin") != "" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/status":
			if r.Method != "GET" {
				http.Error(w, "Method not allowed", 405)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(status)
		case "/stop":
			if r.Method != "POST" {
				http.Error(w, "Method not allowed", 405)
				return
			}
			w.WriteHeader(200)
			stop()
		default:
			http.NotFound(w, r)
		}
	})
}
func (m Manager) readState() (state, error) {
	var s state
	path := filepath.Join(m.Dir, "session.json")
	info, e := os.Lstat(path)
	if e != nil {
		return s, e
	}
	if !info.Mode().IsRegular() {
		return s, errors.New("Файл состояния cproxy должен быть обычным файлом, не ссылкой")
	}
	f, e := os.Open(path)
	if e != nil {
		return s, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 8193))
	if e != nil {
		return s, e
	}
	if len(b) > 8192 {
		return s, errors.New("Слишком большой файл состояния")
	}
	if e = json.Unmarshal(b, &s); e != nil {
		return s, errors.New("Повреждён файл состояния cproxy")
	}
	host, port, e := net.SplitHostPort(s.Address)
	if e != nil || host != "127.0.0.1" || port == "" || len(s.Token) != 64 || strings.ContainsAny(s.Token, "\r\n") {
		return s, errors.New("Некорректный адрес управления cproxy")
	}
	return s, nil
}
func (m Manager) request(ctx context.Context, method, path string) ([]byte, error) {
	s, e := m.readState()
	if e != nil {
		return nil, e
	}
	tr := &http.Transport{Proxy: nil}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, e := http.NewRequestWithContext(ctx, method, "http://"+s.Address+path, nil)
	if e != nil {
		return nil, e
	}
	r.Header.Set("Authorization", "Bearer "+s.Token)
	resp, e := client.Do(r)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("Управляющий процесс cproxy отклонил запрос")
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8192))
}
func (m Manager) Status(ctx context.Context) (Status, error) {
	var s Status
	b, e := m.request(ctx, "GET", "/status")
	if e != nil {
		return s, e
	}
	e = json.Unmarshal(b, &s)
	return s, e
}
func (m Manager) Stop(ctx context.Context) error {
	if _, e := m.readState(); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	_, e := m.request(ctx, "POST", "/stop")
	if e != nil {
		return e
	}
	for {
		if _, e := m.Status(ctx); e != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
