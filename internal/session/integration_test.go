package session

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cproxy/internal/config"
	"cproxy/internal/platform"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

// TestRealSession exercises real sing-box, SSH channels and the detached Go daemon.
// It uses only loopback. The synthetic ipify certificate is trusted only by the test child.
func TestRealSession(t *testing.T) {
	binary := os.Getenv("CPROXY_TEST_SING_BOX")
	if binary == "" {
		t.Skip("set CPROXY_TEST_SING_BOX to run real loopback integration")
	}
	root := t.TempDir()
	name := "cproxy"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	app := os.Getenv("CPROXY_TEST_BINARY")
	if app == "" {
		app = filepath.Join(root, name)
		build := exec.Command("go", "build", "-o", app, "../../cmd/cproxy")
		if out, e := build.CombinedOutput(); e != nil {
			t.Fatalf("build: %v %s", e, out)
		}
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "through-ssh") }))
	defer target.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, e := ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte("session-secret"))
	if e != nil {
		t.Fatal(e)
	}
	key := filepath.Join(root, "encrypted key")
	os.WriteFile(key, pem.EncodeToMemory(block), 0600)
	_, host, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(host)
	pub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cproxy loopback test"}, DNSNames: []string{"api4.ipify.org"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, certificate, certificate, pub, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca := filepath.Join(root, "test-ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	ipify := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "203.0.113.9") }))
	ipify.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: caKey}}}
	ipify.StartTLS()
	defer ipify.Close()
	targetURL, _ := url.Parse(target.URL)
	ipURL, _ := url.Parse(ipify.URL)
	var forwarded atomic.Int64
	sshServer := newLoopbackSSH(t, hostSigner, priv.Public().(ed25519.PublicKey), func(host string, port uint32) (string, bool) {
		switch host {
		case "public.test":
			forwarded.Add(1)
			return targetURL.Host, true
		case "api4.ipify.org":
			return ipURL.Host, true
		}
		return "", false
	})
	defer sshServer.close()
	s := config.Defaults()
	s.Server = "127.0.0.1"
	s.SSHPort = sshServer.port
	s.User = "proxy"
	s.Key = key
	s.Engine = binary
	s.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey())))
	s.ProxyPort = freePort(t)
	settingsDir := filepath.Join(root, "config", "cproxy")
	if runtime.GOOS == "windows" {
		settingsDir = filepath.Join(root, "roaming", "cproxy")
	}
	if e = config.Save(filepath.Join(settingsDir, "settings.json"), s); e != nil {
		t.Fatal(e)
	}
	env := os.Environ()
	env = append(env, "HOME="+root, "USERPROFILE="+root, "XDG_CONFIG_HOME="+filepath.Join(root, "config"), "XDG_CACHE_HOME="+filepath.Join(root, "cache"), "APPDATA="+filepath.Join(root, "roaming"), "LOCALAPPDATA="+filepath.Join(root, "local"), "SSL_CERT_FILE="+ca)
	stateDir := filepath.Join(root, "cache", "cproxy")
	if runtime.GOOS == "windows" {
		stateDir = filepath.Join(root, "local", "cproxy")
	}
	m := Manager{Dir: stateDir}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.Stop(ctx)
	})
	packet := bootstrap{s, []byte("session-secret")}
	data := mustJSON(t, packet)
	occupied, e := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.ProxyPort)))
	if e != nil {
		t.Fatal(e)
	}
	blocked := exec.Command(app, "--serve", stateDir)
	blocked.Env = env
	blocked.Stdin = bytes.NewReader(data)
	if out, e := blocked.CombinedOutput(); e == nil || !strings.Contains(string(out), "порт занят") {
		occupied.Close()
		t.Fatalf("occupied port not rejected: %v %s", e, out)
	}
	occupied.Close()
	cmd := exec.Command(app, "--serve", stateDir)
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	waitFor(t, func() bool { _, e := m.Status(context.Background()); return e == nil })
	request := func(socks bool, target string) (string, error) {
		tr := &http.Transport{}
		if socks {
			d, _ := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.ProxyPort)), nil, &net.Dialer{Timeout: time.Second})
			tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				return d.(proxy.ContextDialer).DialContext(ctx, network, address)
			}
		} else {
			u, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(s.ProxyPort))
			tr.Proxy = http.ProxyURL(u)
		}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
		resp, e := client.Get(target)
		if e != nil {
			return "", e
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return "", io.ErrUnexpectedEOF
		}
		b, e := io.ReadAll(resp.Body)
		return string(b), e
	}
	waitFor(t, func() bool { b, e := request(false, "http://public.test/"); return e == nil && b == "through-ssh" })
	for _, socks := range []bool{false, true} {
		b, e := request(socks, "http://public.test/")
		if e != nil || b != "through-ssh" {
			t.Fatalf("forwarding socks=%v: %v %q; %s", socks, e, b, stderr.String())
		}
	}
	before := forwarded.Load()
	if b, e := request(false, target.URL); e != nil || b != "through-ssh" || forwarded.Load() != before {
		t.Fatalf("private exclusion did not stay local: %v", e)
	}
	// Refuse a second supervisor, without touching the existing proxy.
	duplicate := exec.Command(app, "--serve", stateDir)
	duplicate.Env = env
	duplicate.Stdin = bytes.NewReader(data)
	if duplicate.Run() == nil {
		t.Fatal("two supervisors accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if e = m.Stop(ctx); e != nil {
		t.Fatal(e)
	}
	cancel()
	waitFor(t, func() bool { _, e := request(false, "http://public.test/"); return e != nil })
	if e = cmd.Wait(); e != nil {
		t.Fatalf("supervisor stop: %v %s", e, stderr.String())
	}
	// Start through the real manager entrypoint, with an unencrypted test key.
	plain, _ := ssh.MarshalPrivateKey(priv, "test")
	os.WriteFile(key, pem.EncodeToMemory(plain), 0600)
	if runtime.GOOS == "windows" {
		// Windows uses the native certificate store, not SSL_CERT_FILE. Check native
		// detach/job lifecycle without adding this synthetic CA to the host store.
		restarted := exec.Command(app, "--serve", stateDir)
		restarted.Env = env
		restarted.Stdin = bytes.NewReader(mustJSON(t, bootstrap{s, nil}))
		platform.Detach(restarted)
		if e = restarted.Start(); e != nil {
			t.Fatal(e)
		}
		defer func() { restarted.Process.Kill(); restarted.Wait() }()
		waitFor(t, func() bool { _, e := m.Status(context.Background()); return e == nil })
		waitFor(t, func() bool { b, e := request(false, "http://public.test/"); return e == nil && b == "through-ssh" })
	} else {
		var wg sync.WaitGroup
		for n := 0; n < 2; n++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				start := exec.Command(app, "start")
				start.Env = env
				if out, e := start.CombinedOutput(); e != nil {
					t.Errorf("concurrent detached start failed: %v %s", e, out)
				}
			}()
		}
		wg.Wait()
	}
	status, e := m.Status(context.Background())
	if e != nil || status.Server != "127.0.0.1" {
		t.Fatalf("daemon did not survive launcher: %v", e)
	}
	// Drop actual SSH connections; requests must fail while the listener is down.
	sshServer.close()
	if _, e = request(false, "http://public.test/"); e == nil {
		t.Fatal("outage fell back to direct")
	}
	sshServer.restart(t)
	waitFor(t, func() bool { b, e := request(false, "http://public.test/"); return e == nil && b == "through-ssh" })
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	if e = m.Stop(ctx); e != nil {
		t.Fatal(e)
	}
	cancel()
	// A wrong pin must never open a forwarding channel.
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	wrongSigner, _ := ssh.NewSignerFromKey(wrong)
	s.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(wrongSigner.PublicKey())))
	bad := exec.Command(app, "--serve", stateDir)
	bad.Env = env
	bad.Stdin = bytes.NewReader(mustJSON(t, bootstrap{s, nil}))
	if e = bad.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { bad.Process.Kill(); bad.Wait() }()
	waitFor(t, func() bool { _, e := m.Status(context.Background()); return e == nil })
	before = forwarded.Load()
	waitFor(t, func() bool {
		conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.ProxyPort)), time.Second)
		if e == nil {
			conn.Close()
			return true
		}
		return false
	})
	if _, e = request(false, "http://public.test/"); e == nil || forwarded.Load() != before {
		t.Fatal("wrong pin forwarded request")
	}
	bad.Process.Kill()
	bad.Wait()
	waitFor(t, func() bool {
		conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.ProxyPort)), time.Second)
		if e == nil {
			conn.Close()
			return false
		}
		return true
	})
	log, _ := os.ReadFile(filepath.Join(stateDir, "cproxy.log"))
	state, _ := os.ReadFile(filepath.Join(stateDir, "session.json"))
	if bytes.Contains(log, []byte("session-secret")) || bytes.Contains(state, []byte("session-secret")) {
		t.Fatal("passphrase leaked to disk")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func waitFor(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for local session")
}
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

type loopbackSSH struct {
	mu          sync.Mutex
	ln          net.Listener
	port        int
	cfg         *ssh.ServerConfig
	connections []net.Conn
	route       func(string, uint32) (string, bool)
}

func newLoopbackSSH(t *testing.T, host ssh.Signer, client ed25519.PublicKey, route func(string, uint32) (string, bool)) *loopbackSSH {
	t.Helper()
	pub, _ := ssh.NewPublicKey(client)
	s := &loopbackSSH{route: route}
	s.cfg = &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(pub.Marshal(), k.Marshal()) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, nil
	}}
	s.cfg.AddHostKey(host)
	s.restart(t)
	return s
}
func (s *loopbackSSH) restart(t *testing.T) {
	t.Helper()
	l, e := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.port)))
	if e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	s.ln = l
	s.port = l.Addr().(*net.TCPAddr).Port
	s.mu.Unlock()
	go func() {
		for {
			conn, e := l.Accept()
			if e != nil {
				return
			}
			s.mu.Lock()
			s.connections = append(s.connections, conn)
			s.mu.Unlock()
			go s.serve(conn)
		}
	}()
}
func (s *loopbackSSH) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		s.ln.Close()
	}
	for _, c := range s.connections {
		c.Close()
	}
	s.connections = nil
}
func (s *loopbackSSH) serve(conn net.Conn) {
	defer conn.Close()
	server, channels, requests, e := ssh.NewServerConn(conn, s.cfg)
	if e != nil {
		return
	}
	defer server.Close()
	go ssh.DiscardRequests(requests)
	for ch := range channels {
		if ch.ChannelType() != "direct-tcpip" {
			ch.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		var dest struct {
			Host       string
			Port       uint32
			Origin     string
			OriginPort uint32
		}
		if ssh.Unmarshal(ch.ExtraData(), &dest) != nil {
			ch.Reject(ssh.ConnectionFailed, "invalid")
			continue
		}
		addr, ok := s.route(dest.Host, dest.Port)
		if !ok {
			ch.Reject(ssh.Prohibited, "unmapped test destination")
			continue
		}
		remote, e := net.DialTimeout("tcp", addr, time.Second)
		if e != nil {
			ch.Reject(ssh.ConnectionFailed, "offline")
			continue
		}
		channel, r, e := ch.Accept()
		if e != nil {
			remote.Close()
			continue
		}
		go ssh.DiscardRequests(r)
		go func() {
			defer channel.Close()
			defer remote.Close()
			done := make(chan struct{})
			go func() { io.Copy(remote, channel); remote.(*net.TCPConn).CloseWrite(); close(done) }()
			io.Copy(channel, remote)
			channel.CloseWrite()
			<-done
		}()
	}
}
