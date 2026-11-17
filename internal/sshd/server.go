package sshd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
)

const (
	DefaultTCPAddr         = "127.0.0.1:22"
	DefaultHTTPAddr        = "127.0.0.1:22222"
	DefaultTCPFallbackAddr = "127.0.0.1:22223"
)

type Config struct {
	TCPAddr, HTTPAddr, HostKeyFile string
	TCPFallbackAddr                string `json:",omitempty"`
	PAMService                     string
	AllowedOrigins                 []string
	TLSCertFile, TLSKeyFile        string
	MaxConnections                 int
	RekeyBytes                     uint64
	// Used by isolated PAM integration tests, never populated by network input.
	PAMConfigDir string `json:",omitempty"`
}

type Server struct {
	cfg     Config
	log     *slog.Logger
	signer  ssh.Signer
	slots   chan struct{}
	mu      sync.Mutex
	closing bool
	conns   map[net.Conn]struct{}
	wg      sync.WaitGroup
}

func New(cfg Config, logger *slog.Logger) (*Server, error) {
	if cfg.HostKeyFile == "" {
		return nil, errors.New("host-key must be set")
	}
	if cfg.PAMService == "" {
		cfg.PAMService = "sshd"
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(cfg.PAMService) {
		return nil, errors.New("pam-service must be a policy name, not a path")
	}
	pamDirectory := cfg.PAMConfigDir
	if pamDirectory == "" {
		pamDirectory = "/etc/pam.d"
	}
	policy := filepath.Join(pamDirectory, cfg.PAMService)
	if info, err := os.Stat(policy); err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("PAM policy %q is missing; select an installed policy with -pam-service", policy)
	}
	if cfg.MaxConnections < 1 {
		return nil, errors.New("max-connections must be positive")
	}
	if cfg.RekeyBytes != 0 && cfg.RekeyBytes < 256 {
		return nil, errors.New("rekey-bytes must be at least 256")
	}
	if cfg.TCPAddr == "" && cfg.HTTPAddr == "" {
		return nil, errors.New("enable at least one listener")
	}
	if cfg.TCPFallbackAddr != "" && cfg.TCPAddr == "" {
		return nil, errors.New("TCP fallback requires a TCP listener")
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return nil, errors.New("tls-cert and tls-key must be provided together")
	}
	for _, origin := range cfg.AllowedOrigins {
		if origin == "null" {
			continue
		}
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return nil, fmt.Errorf("invalid browser origin %q; use an exact origin such as http://127.0.0.1:9000", origin)
		}
	}
	signer, err := hostKey(cfg.HostKeyFile)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, log: logger, signer: signer, slots: make(chan struct{}, cfg.MaxConnections), conns: make(map[net.Conn]struct{})}, nil
}

func (s *Server) Run(ctx context.Context) error {
	var tcp, httpListener net.Listener
	var err error
	if s.cfg.TCPAddr != "" {
		tcp, err = s.listenTCP()
		if err != nil {
			return err
		}
		defer tcp.Close()
	}
	if s.cfg.HTTPAddr != "" {
		httpListener, err = net.Listen("tcp", s.cfg.HTTPAddr)
		if err != nil {
			return err
		}
		defer httpListener.Close()
	}
	httpServer := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	errCh := make(chan error, 2)
	if tcp != nil {
		s.log.Info("SSH TCP listening", "address", tcp.Addr())
		go func() { errCh <- s.ServeTCP(tcp) }()
	}
	if httpListener != nil {
		s.log.Info("SSH WebSocket listening", "address", httpListener.Addr(), "path", "/ssh", "tls", s.cfg.TLSCertFile != "")
		go func() {
			if s.cfg.TLSCertFile != "" {
				errCh <- httpServer.ServeTLS(httpListener, s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
			} else {
				errCh <- httpServer.Serve(httpListener)
			}
		}()
	}
	s.log.Info("SSH host identity", "fingerprint", ssh.FingerprintSHA256(s.signer.PublicKey()), "authentication", "system PAM", "pam-service", s.cfg.PAMService)
	select {
	case <-ctx.Done():
		err = nil
	case err = <-errCh:
	}
	// Hijacked WebSockets are not closed by http.Server.Shutdown.
	if tcp != nil {
		tcp.Close()
	}
	httpServer.Close()
	s.Close()
	return err
}

func (s *Server) listenTCP() (net.Listener, error) {
	listener, err := net.Listen("tcp", s.cfg.TCPAddr)
	if err == nil || s.cfg.TCPFallbackAddr == "" || !errors.Is(err, syscall.EADDRINUSE) {
		return listener, err
	}
	listener, err = net.Listen("tcp", s.cfg.TCPFallbackAddr)
	if err != nil {
		return nil, fmt.Errorf("TCP address %s is already in use; fallback %s failed: %w", s.cfg.TCPAddr, s.cfg.TCPFallbackAddr, err)
	}
	s.log.Warn("SSH TCP address is busy; using fallback", "requested", s.cfg.TCPAddr, "address", listener.Addr())
	return listener, nil
}

func (s *Server) ServeTCP(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		if !s.acquire() {
			conn.Close()
			continue
		}
		go s.serveConn(conn)
	}
}

func (s *Server) acquire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	select {
	case s.slots <- struct{}{}:
		s.wg.Add(1)
		return true
	default:
		return false
	}
}

func (s *Server) release() {
	<-s.slots
	s.wg.Done()
}

func (s *Server) Close() {
	s.mu.Lock()
	s.closing = true
	connections := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		connections = append(connections, conn)
	}
	s.mu.Unlock()
	var closing sync.WaitGroup
	for _, conn := range connections {
		closing.Add(1)
		go func() { defer closing.Done(); conn.Close() }()
	}
	closing.Wait()
	s.wg.Wait()
}

func (s *Server) serveConn(raw net.Conn) {
	defer s.release()
	defer raw.Close()
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	s.conns[raw] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.conns, raw)
		s.mu.Unlock()
	}()
	if err := s.runConnectionProcess(raw); err != nil {
		s.log.Debug("SSH worker ended", "remote", raw.RemoteAddr(), "error", err)
	}
}

// This runs in a dedicated process on a locked OS thread, one per SSH connection.
func (s *Server) serveAuthenticatedConn(raw net.Conn, remoteHost string) error {
	auth := &systemAuth{cfg: s.cfg, remoteHost: remoteHost}
	defer auth.close()
	config := auth.config(s.signer)
	raw.SetDeadline(time.Now().Add(60 * time.Second))
	conn, channels, requests, err := ssh.NewServerConn(raw, config)
	if err != nil {
		return err
	}
	defer conn.Close()
	raw.SetDeadline(time.Time{})
	if auth.account == nil || conn.Permissions == nil || conn.Permissions.Extensions["system-user"] != auth.account.Name {
		return errors.New("authenticated connection has no system identity")
	}
	if err := auth.openSession(); err != nil {
		return fmt.Errorf("PAM session: %w", err)
	}
	account := auth.account
	s.log.Info("SSH connected", "remote", remoteHost, "user", account.Name, "uid", account.UID, "gid", account.GID)
	defer s.log.Info("SSH disconnected", "remote", remoteHost, "user", account.Name)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for request := range requests {
			request.Reply(request.Type == "keepalive@openssh.com", nil)
		}
	}()
	var sessions sync.WaitGroup
	sessionSlots := make(chan struct{}, 16)
	type startRequest struct {
		run    func() error
		result chan error
	}
	starts := make(chan startRequest)
	start := func(run func() error) error {
		request := startRequest{run: run, result: make(chan error, 1)}
		select {
		case starts <- request:
			// Once accepted, always wait for Start to finish before the
			// session reads or cleans up the command and its descriptors.
			return <-request.result
		case <-ctx.Done():
			return ctx.Err()
		}
	}
acceptChannels:
	for {
		var newChannel ssh.NewChannel
		select {
		case request := <-starts:
			// Fork the shell from the PAM thread so it inherits thread-local
			// audit identity, keyrings and other session attributes.
			request.result <- request.run()
			continue
		case value, ok := <-channels:
			if !ok {
				break acceptChannels
			}
			newChannel = value
		}
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		select {
		case sessionSlots <- struct{}{}:
		default:
			newChannel.Reject(ssh.ResourceShortage, "too many session channels")
			continue
		}
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			<-sessionSlots
			continue
		}
		sessions.Add(1)
		go func() {
			defer sessions.Done()
			defer func() { <-sessionSlots }()
			s.serveSession(ctx, channel, channelRequests, account, auth.environ, start)
		}()
	}
	cancel()
	sessions.Wait()
	return nil
}

func (s *Server) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // Native WebSocket clients have no browser Origin.
	}
	for _, allowed := range s.cfg.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	u, err := url.Parse(origin)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && strings.EqualFold(u.Host, r.Host) && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /ssh", func(w http.ResponseWriter, r *http.Request) {
		if !s.originAllowed(r) {
			http.Error(w, "WebSocket origin is not allowed", http.StatusForbidden)
			return
		}
		if !s.acquire() {
			http.Error(w, "SSH connection limit reached", http.StatusServiceUnavailable)
			return
		}
		// Origin was checked against exact allowed values above.
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			s.release()
			return
		}
		defer ws.CloseNow()
		// Binary frames carry the SSH byte stream, with no JSON/base64 wrapper.
		conn := &remoteConn{Conn: websocket.NetConn(context.Background(), ws, websocket.MessageBinary), remote: socketAddr(r.RemoteAddr)}
		s.serveConn(conn)
	})
	return mux
}
