package sshd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	writeTestPAM(t, dir, currentTestUsername())
	return Config{TCPAddr: "127.0.0.1:0", HTTPAddr: "127.0.0.1:0", HostKeyFile: filepath.Join(dir, "host_key"), PAMService: "webssh-test", PAMConfigDir: dir, MaxConnections: 8, AllowedOrigins: []string{"http://127.0.0.1:9000", "null"}}
}

func newTestServer(t *testing.T, cfg Config) (*Server, net.Listener, *httptest.Server) {
	t.Helper()
	srv, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTCP(listener)
	web := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { listener.Close(); web.Close(); srv.Close() })
	return srv, listener, web
}

func clientConfig(srv *Server) *ssh.ClientConfig {
	return &ssh.ClientConfig{User: currentTestUsername(), Auth: []ssh.AuthMethod{ssh.Password(testPassword)}, HostKeyCallback: ssh.FixedHostKey(srv.signer.PublicKey()), Timeout: 5 * time.Second}
}

func sshDialForTest(srv *Server, listener net.Listener, username string) (*ssh.Client, error) {
	config := clientConfig(srv)
	config.User = username
	return ssh.Dial("tcp", listener.Addr().String(), config)
}

func tcpClient(t *testing.T, srv *Server, listener net.Listener) *ssh.Client {
	t.Helper()
	client, err := ssh.Dial("tcp", listener.Addr().String(), clientConfig(srv))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func TestTCPExecStdinAndExitStatus(t *testing.T) {
	srv, listener, _ := newTestServer(t, testConfig(t))
	client := tcpClient(t, srv, listener)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	session.Stdin = strings.NewReader("stdin 中文\n")
	var out, stderr strings.Builder
	session.Stdout, session.Stderr = &out, &stderr
	err = session.Run("cat; printf 'stderr' >&2; exit 7")
	var exit *ssh.ExitError
	if !errors.As(err, &exit) || exit.ExitStatus() != 7 {
		t.Fatalf("expected exit status 7, got %v", err)
	}
	if out.String() != "stdin 中文\n" || stderr.String() != "stderr" {
		t.Fatalf("unexpected stdout/stderr: %q / %q", out.String(), stderr.String())
	}
}

func TestWebSocketCarriesActualSSH(t *testing.T) {
	cfg := testConfig(t)
	cfg.RekeyBytes = 1024
	srv, _, web := newTestServer(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(web.URL, "http")+"/ssh", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	raw := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	config := clientConfig(srv)
	// The same algorithm suite implemented by the independent browser client.
	config.Config = ssh.Config{KeyExchanges: []string{"ecdh-sha2-nistp256"}, Ciphers: []string{"aes128-ctr"}, MACs: []string{"hmac-sha2-256"}}
	conn, channels, requests, err := ssh.NewClientConn(raw, "websocket", config)
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(conn, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	input := strings.Repeat("SSH over WebSocket 中文\n", 5000)
	session.Stdin = strings.NewReader(input)
	output, err := session.Output("cat")
	if err != nil || string(output) != input {
		t.Fatalf("encrypted SSH roundtrip/rekey failed: %v (received %d of %d bytes)", err, len(output), len(input))
	}
}

func TestPTYResizeAndUTF8(t *testing.T) {
	srv, listener, _ := newTestServer(t, testConfig(t))
	client := tcpClient(t, srv, listener)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	if err := session.WindowChange(42, 101); err != nil {
		t.Fatal(err)
	}
	output, err := session.Output("stty size; printf '中文终端\\n'")
	if err != nil || string(output) != "42 101\r\n中文终端\r\n" {
		t.Fatalf("PTY output: %q, error: %v", output, err)
	}
}

func TestPTYZeroDimensions(t *testing.T) {
	srv, listener, _ := newTestServer(t, testConfig(t))
	client := tcpClient(t, srv, listener)
	for _, resize := range []bool{false, true} {
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if err := session.RequestPty("xterm", 0, 0, ssh.TerminalModes{}); err != nil {
			t.Fatal(err)
		}
		expected := "24 80\r\n"
		if resize {
			if err := session.WindowChange(0, 120); err != nil {
				t.Fatal(err)
			}
			expected = "24 120\r\n"
		}
		output, err := session.Output("stty size")
		session.Close()
		if err != nil || string(output) != expected {
			t.Fatalf("zero dimensions should use/keep defaults: %q, %v", output, err)
		}
	}
}

func TestPasswordAndUsernameRejected(t *testing.T) {
	srv, listener, _ := newTestServer(t, testConfig(t))
	for _, wrongUser := range []bool{false, true} {
		config := clientConfig(srv)
		if wrongUser {
			config.User = "wrong-user"
		} else {
			config.Auth = []ssh.AuthMethod{ssh.Password("wrong-password")}
		}
		client, err := ssh.Dial("tcp", listener.Addr().String(), config)
		if err == nil {
			client.Close()
			t.Fatal("invalid credentials were accepted")
		}
	}
}

func TestSystemAuthorizedKeysAndHostKeyPersistence(t *testing.T) {
	cfg := testConfig(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	account, err := lookupAccount(currentTestUsername())
	if err != nil {
		t.Fatal(err)
	}
	account.Home = t.TempDir()
	if err := os.Chmod(account.Home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(account.Home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(account.Home, ".ssh", "authorized_keys")
	if err := os.WriteFile(path, append(ssh.MarshalAuthorizedKey(key.PublicKey()), []byte("\n# trailing comment\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if !systemKeyAllowed(account, key.PublicKey()) {
		t.Fatal("valid system authorized_keys rejected")
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if systemKeyAllowed(account, key.PublicKey()) {
		t.Fatal("world-writable authorized_keys accepted")
	}
	os.Chmod(path, 0600)
	os.WriteFile(path, append([]byte("command=\"false\" "), ssh.MarshalAuthorizedKey(key.PublicKey())...), 0600)
	if systemKeyAllowed(account, key.PublicKey()) {
		t.Fatal("key restrictions were ignored")
	}
	os.Rename(path, path+".real")
	os.Symlink(path+".real", path)
	if systemKeyAllowed(account, key.PublicKey()) {
		t.Fatal("authorized_keys symlink accepted")
	}
	srv, _, _ := newTestServer(t, cfg)
	loaded, err := hostKey(cfg.HostKeyFile)
	if err != nil || string(loaded.PublicKey().Marshal()) != string(srv.signer.PublicKey().Marshal()) {
		t.Fatal("host identity changed between loads")
	}
	info, err := os.Stat(cfg.HostKeyFile)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("host private key must be mode 0600")
	}
}

func TestBrowserOriginsAndHTTPRoutes(t *testing.T) {
	srv, _, web := newTestServer(t, testConfig(t))
	for _, tc := range []struct {
		origin  string
		allowed bool
	}{
		{"http://127.0.0.1:9000", true}, {"null", true}, {web.URL, true},
		{"https://evil.example", false}, {"http://127.0.0.1:9000.evil.example", false}, {web.URL + "/path", false},
	} {
		request := httptest.NewRequest("GET", web.URL+"/ssh", nil)
		request.Header.Set("Origin", tc.origin)
		if srv.originAllowed(request) != tc.allowed {
			t.Errorf("origin check for %q", tc.origin)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, response, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(web.URL, "http")+"/ssh", &websocket.DialOptions{HTTPHeader: http.Header{"Origin": []string{"https://evil.example"}}})
	if err == nil || response.StatusCode != http.StatusForbidden {
		t.Fatal("cross-origin WebSocket should be rejected before upgrade")
	}
	for _, tc := range []struct {
		path   string
		status int
	}{{"/healthz", 200}, {"/", 404}, {"/client/index.html", 404}} {
		resp, err := http.Get(web.URL + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Errorf("GET %s: got %d, want %d", tc.path, resp.StatusCode, tc.status)
		}
	}
}

func TestRejectUnsafeConfigurationAndKeyOptions(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.PAMService = "../login" },
		func(c *Config) { c.AllowedOrigins = []string{"*"} },
		func(c *Config) { c.TLSCertFile = "without-key" },
		func(c *Config) { c.MaxConnections = 0 },
		func(c *Config) { c.TCPAddr, c.HTTPAddr = "", "" },
		func(c *Config) { c.TCPAddr, c.TCPFallbackAddr = "", "127.0.0.1:22223" },
	} {
		cfg := testConfig(t)
		change(&cfg)
		if _, err := New(cfg, nil); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewSignerFromKey(private)
	path := filepath.Join(t.TempDir(), "authorized_keys")
	os.WriteFile(path, append([]byte("command=\"false\" "), ssh.MarshalAuthorizedKey(key.PublicKey())...), 0600)
	if _, err := authorizedKeys(path); err == nil {
		t.Fatal("authorized_keys restrictions must not be silently ignored")
	}
}

func TestForwardingRejectedAndSecretsNotInherited(t *testing.T) {
	t.Setenv("SSH_PASSWORD", "must-not-leak-to-shell")
	srv, listener, _ := newTestServer(t, testConfig(t))
	client := tcpClient(t, srv, listener)
	if channel, _, err := client.OpenChannel("direct-tcpip", nil); err == nil {
		channel.Close()
		t.Fatal("port forwarding unexpectedly accepted")
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if output, err := session.Output("printf '%s' \"$SSH_PASSWORD\""); err != nil || len(output) != 0 {
		t.Fatal("service credentials were inherited by the shell")
	}
}

func TestShutdownClosesRunningShell(t *testing.T) {
	srv, listener, _ := newTestServer(t, testConfig(t))
	client := tcpClient(t, srv, listener)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.Start("sleep 120"); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { srv.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server shutdown did not release an active shell")
	}
}
