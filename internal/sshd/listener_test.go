package sshd

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"syscall"
	"testing"
)

func occupiedTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener.Addr().String()
}

func TestTCPPortFallbackAcceptsSSH(t *testing.T) {
	cfg := testConfig(t)
	cfg.TCPAddr = occupiedTCPAddress(t)
	cfg.TCPFallbackAddr = "127.0.0.1:0"
	srv, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	listener, err := srv.listenTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	if listener.Addr().String() == cfg.TCPAddr {
		t.Fatal("fallback reused the occupied primary address")
	}
	go srv.ServeTCP(listener)
	client := tcpClient(t, srv, listener)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	output, err := session.Output("printf FALLBACK_OK")
	if err != nil || string(output) != "FALLBACK_OK" {
		t.Fatalf("SSH over the fallback listener failed: %q, %v", output, err)
	}
}

func TestTCPPortFallbackConditions(t *testing.T) {
	primaryBusy := occupiedTCPAddress(t)
	fallbackBusy := occupiedTCPAddress(t)
	for _, test := range []struct {
		name, primary, fallback string
		wantError, wantBusy     bool
	}{
		{"free primary", "127.0.0.1:0", fallbackBusy, false, false},
		{"explicit occupied address", primaryBusy, "", true, true},
		{"both ports occupied", primaryBusy, fallbackBusy, true, true},
		{"other listen errors", "127.0.0.1:-1", "127.0.0.1:0", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.TCPAddr, cfg.TCPFallbackAddr = test.primary, test.fallback
			srv, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			listener, err := srv.listenTCP()
			if listener != nil {
				defer listener.Close()
			}
			if (err != nil) != test.wantError {
				t.Fatalf("listen error = %v; want error: %v", err, test.wantError)
			}
			if test.wantBusy && !errors.Is(err, syscall.EADDRINUSE) {
				t.Fatalf("expected an address-in-use error, got %v", err)
			}
			if test.name == "both ports occupied" && !strings.Contains(err.Error(), fallbackBusy) {
				t.Fatalf("error omitted the failed fallback address: %v", err)
			}
		})
	}
}
