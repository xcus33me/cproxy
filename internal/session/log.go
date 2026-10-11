package session

import (
	"bytes"
	"os"
	"strings"
	"sync"

	"cproxy/internal/platform"
)

// Logs are line-buffered so a secret spanning Write calls is still redacted.
type logWriter struct {
	mu      sync.Mutex
	f       *os.File
	pending []byte
	secret  string
	size    int64
}

func newLog(path, secret string) (*logWriter, error) {
	old, _ := os.ReadFile(path)
	if len(old) > 512*1024 {
		old = old[len(old)-512*1024:]
	}
	if e := platform.WritePrivate(path, old); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	return &logWriter{f: f, secret: secret, size: int64(len(old))}, nil
}
func (l *logWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pending = append(l.pending, p...)
	for {
		end := bytes.IndexByte(l.pending, '\n')
		if end < 0 {
			if len(l.pending) > 8192 {
				l.pending = nil
			}
			break
		}
		line := string(l.pending[:end+1])
		if end > 8192 {
			line = "[слишком длинная строка журнала]\n"
		}
		l.pending = l.pending[end+1:]
		if l.secret != "" {
			line = strings.ReplaceAll(line, l.secret, "[скрыто]")
		}
		if l.size+int64(len(line)) > 1024*1024 {
			if e := l.f.Truncate(0); e != nil {
				return 0, e
			}
			l.f.Seek(0, 0)
			l.size = 0
		}
		n, e := l.f.WriteString(line)
		l.size += int64(n)
		if e != nil {
			return 0, e
		}
	}
	return len(p), nil
}
func (l *logWriter) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	clear(l.pending)
	l.secret = ""
	return l.f.Close()
}
