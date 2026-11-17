package sshd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const testPassword = "pam-test-password"

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--connection-worker" {
		if err := RunConnectionWorker(); err != nil {
			fmt.Fprintln(os.Stderr, "test worker:", err)
		}
		os.Exit(0)
	}
	// This entry point exists only in the test executable. The production
	// command has no custom PAM directory or non-root serving option.
	if len(os.Args) == 3 && os.Args[1] == "--test-server" {
		file, err := os.Open(os.Args[2])
		if err != nil {
			panic(err)
		}
		var cfg Config
		if err := json.NewDecoder(file).Decode(&cfg); err != nil {
			panic(err)
		}
		file.Close()
		srv, err := New(cfg, nil)
		if err != nil {
			panic(err)
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
		defer stop()
		if err := srv.Run(ctx); err != nil {
			panic(err)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func currentTestUsername() string {
	u, err := user.Current()
	if err != nil {
		panic(err)
	}
	return u.Username
}

// Native PAM uses an isolated policy. Host accounts, passwords, authorized_keys
// and /etc/pam.d are never modified by these tests.
func writeTestPAM(t *testing.T, dir, username string) {
	t.Helper()
	script := filepath.Join(dir, "check.py")
	source := `import glob, json, os, sys
parent = os.getppid()
thread = next((int(path.split("/")[-2]) for path in glob.glob("/proc/%d/task/*/children" % parent) if str(os.getpid()) in open(path).read().split()), None)
with open(` + strconv.Quote(filepath.Join(dir, "events.jsonl")) + `, "a") as log:
    log.write(json.dumps({"type": os.getenv("PAM_TYPE"), "user": os.getenv("PAM_USER"), "remote": os.getenv("PAM_RHOST"), "pid": parent, "thread": thread}) + "\n")
if os.environ.get("PAM_USER") != ` + strconv.Quote(username) + `:
    sys.exit(1)
if os.environ.get("PAM_TYPE") == "auth":
    sys.exit(0 if sys.stdin.buffer.read().rstrip(b"\0") == ` + strconv.Quote(testPassword) + `.encode() else 1)
`
	if err := os.WriteFile(script, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	policy := "auth required pam_exec.so expose_authtok /usr/bin/python3 " + script + "\nauth required pam_permit.so\naccount required pam_exec.so /usr/bin/python3 " + script + "\nsession required pam_exec.so /usr/bin/python3 " + script + "\n"
	if err := os.WriteFile(filepath.Join(dir, "webssh-test"), []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPAMAndShellUseProcessMainThread(t *testing.T) {
	cfg := testConfig(t)
	srv, listener, _ := newTestServer(t, cfg)
	client := tcpClient(t, srv, listener)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	// /proc records which parent thread forked a child. Use exec so this
	// Python process is the shell child itself, with no intermediate parent.
	probe := `import glob, os
parent = os.getppid()
for path in glob.glob("/proc/%d/task/*/children" % parent):
    if str(os.getpid()) in open(path).read().split():
        print(parent, path.split("/")[-2])
        break
`
	output, err := session.Output("exec /usr/bin/python3 -c '" + probe + "'")
	session.Close()
	client.Close()
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(output))
	if len(fields) != 2 || fields[0] != fields[1] {
		t.Fatalf("shell did not fork from the PAM process leader: %q", output)
	}
	srv.Close()
	data, err := os.ReadFile(filepath.Join(cfg.PAMConfigDir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var event struct {
			Type        string
			PID, Thread int
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event.PID == 0 || event.PID != event.Thread || strconv.Itoa(event.PID) != fields[0] {
			t.Errorf("PAM %s did not use the shell's process leader: %s", event.Type, line)
		}
	}
}

func TestActualSystemIdentityAndPAMLifecycle(t *testing.T) {
	cfg := testConfig(t)
	srv, listener, _ := newTestServer(t, cfg)
	client := tcpClient(t, srv, listener)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	output, err := session.Output("id -u; id -g; printf '%s\\n' \"$USER\" \"$LOGNAME\" \"$HOME\" \"$SHELL\"; pwd")
	session.Close()
	client.Close()
	if err != nil {
		t.Fatal(err)
	}
	account, err := lookupAccount(currentTestUsername())
	if err != nil {
		t.Fatal(err)
	}
	expected := fmt.Sprintf("%d\n%d\n%s\n%s\n%s\n%s\n%s\n", account.UID, account.GID, account.Name, account.Name, account.Home, account.Shell, account.Home)
	if string(output) != expected {
		t.Fatalf("system identity mismatch: %q; expected %q", output, expected)
	}
	srv.Close()
	data, err := os.ReadFile(filepath.Join(cfg.PAMConfigDir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"auth", "account", "open_session", "close_session"} {
		if !strings.Contains(string(data), `"type": "`+stage+`"`) {
			t.Fatalf("missing PAM %s: %s", stage, data)
		}
	}
	if !strings.Contains(string(data), `"remote": "127.0.0.1"`) {
		t.Fatalf("missing PAM remote: %s", data)
	}
}

func TestPAMAccountPolicyCanDenyValidPassword(t *testing.T) {
	cfg := testConfig(t)
	path := filepath.Join(cfg.PAMConfigDir, cfg.PAMService)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.WriteString("account required pam_deny.so\n")
	file.Close()
	srv, listener, _ := newTestServer(t, cfg)
	client, err := sshDialForTest(srv, listener, currentTestUsername())
	if err == nil {
		client.Close()
		t.Fatal("PAM account denial ignored")
	}
}

func TestPrivilegedUIDGIDAndSupplementaryGroups(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to verify root-to-user UID/GID transition")
	}
	u, err := user.LookupId("1000")
	if err != nil {
		t.Skip("no UID 1000 system account available")
	}
	cfg := testConfig(t)
	writeTestPAM(t, cfg.PAMConfigDir, u.Username)
	srv, listener, _ := newTestServer(t, cfg)
	client, err := sshDialForTest(srv, listener, u.Username)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	output, err := session.Output("id -u; id -g; id -G")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(output))
	if len(lines) < 3 || lines[0] != u.Uid || lines[1] != u.Gid {
		t.Fatalf("UID/GID were not switched: %s", output)
	}
	groups, err := u.GroupIds()
	if err != nil {
		t.Fatal(err)
	}
	actual := map[string]bool{}
	for _, group := range lines[2:] {
		actual[group] = true
	}
	for _, group := range groups {
		if !actual[group] {
			t.Errorf("missing group %s: %s", group, output)
		}
	}
	if actual["0"] {
		t.Errorf("root group leaked to system user: %s", output)
	}
}
