package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"websshserver/internal/sshd"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--connection-worker" {
		if err := sshd.RunConnectionWorker(); err != nil {
			slog.Debug("SSH connection ended", "error", err)
		}
		return
	}
	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		os.Exit(2)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if os.Geteuid() != 0 {
		logger.Error("system account authentication and UID/GID switching require root; start with sudo ./bin/sshserver")
		os.Exit(1)
	}
	srv, err := sshd.New(cfg, logger)
	if err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Run(ctx); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func parseConfig(args []string) (sshd.Config, error) {
	var cfg sshd.Config
	var origins string
	flags := flag.NewFlagSet("sshserver", flag.ContinueOnError)
	flags.StringVar(&cfg.TCPAddr, "tcp", sshd.DefaultTCPAddr, "TCP SSH listen address; empty disables TCP; default port 22 falls back to 22223 if busy (explicit -tcp disables fallback)")
	flags.StringVar(&cfg.HTTPAddr, "http", sshd.DefaultHTTPAddr, "WebSocket HTTP listen address; empty disables HTTP")
	flags.StringVar(&cfg.HostKeyFile, "host-key", "data/ssh_host_ecdsa_key", "persistent SSH host private key")
	flags.StringVar(&cfg.PAMService, "pam-service", "sshd", "system PAM policy in /etc/pam.d; no application username/password")
	flags.StringVar(&origins, "origin", os.Getenv("SSH_WS_ORIGINS"), "comma-separated browser origins; use null for file:// pages")
	flags.StringVar(&cfg.TLSCertFile, "tls-cert", "", "TLS certificate for WSS")
	flags.StringVar(&cfg.TLSKeyFile, "tls-key", "", "TLS private key for WSS")
	flags.IntVar(&cfg.MaxConnections, "max-connections", 64, "maximum concurrent SSH connections across both transports")
	flags.Uint64Var(&cfg.RekeyBytes, "rekey-bytes", 64<<20, "SSH rekey threshold in bytes per direction (minimum 256)")
	if err := flags.Parse(args); err != nil {
		return cfg, err
	}
	tcpSpecified := false
	flags.Visit(func(value *flag.Flag) {
		if value.Name == "tcp" {
			tcpSpecified = true
		}
	})
	if !tcpSpecified {
		cfg.TCPFallbackAddr = sshd.DefaultTCPFallbackAddr
	}
	for _, origin := range strings.Split(origins, ",") {
		if origin = strings.TrimSpace(origin); origin != "" {
			cfg.AllowedOrigins = append(cfg.AllowedOrigins, origin)
		}
	}
	return cfg, nil
}
