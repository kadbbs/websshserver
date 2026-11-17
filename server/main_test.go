package main

import "testing"

func TestDefaultPortsAndExplicitOverrides(t *testing.T) {
	t.Setenv("SSH_WS_ORIGINS", "")
	for _, test := range []struct {
		name                string
		args                []string
		tcp, http, fallback string
	}{
		{"defaults", nil, "127.0.0.1:22", "127.0.0.1:22222", "127.0.0.1:22223"},
		{"custom TCP", []string{"-tcp", ":32022"}, ":32022", "127.0.0.1:22222", ""},
		{"explicit port 22", []string{"-tcp=127.0.0.1:22"}, "127.0.0.1:22", "127.0.0.1:22222", ""},
		{"TCP disabled", []string{"-tcp="}, "", "127.0.0.1:22222", ""},
		{"custom WebSocket", []string{"-http", ":8443"}, "127.0.0.1:22", ":8443", "127.0.0.1:22223"},
		{"WebSocket disabled", []string{"-http="}, "127.0.0.1:22", "", "127.0.0.1:22223"},
		{"custom listeners", []string{"-tcp", "[::1]:32022", "-http", "[::1]:32023"}, "[::1]:32022", "[::1]:32023", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := parseConfig(test.args)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.TCPAddr != test.tcp || cfg.HTTPAddr != test.http || cfg.TCPFallbackAddr != test.fallback {
				t.Fatalf("listeners = TCP %q, WebSocket %q, fallback %q; want %q, %q, %q", cfg.TCPAddr, cfg.HTTPAddr, cfg.TCPFallbackAddr, test.tcp, test.http, test.fallback)
			}
		})
	}
}
