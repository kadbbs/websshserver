//go:build linux && cgo

package sshd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

type ptyRequest struct {
	Term          string
	Columns, Rows uint32
	Width, Height uint32
	Modes         string
}

type windowChange struct{ Columns, Rows, Width, Height uint32 }

func validSize(cols, rows uint32) bool { return cols > 0 && rows > 0 && cols <= 1000 && rows <= 500 }

func (s *Server) serveSession(parent context.Context, channel ssh.Channel, requests <-chan *ssh.Request, account *systemAccount, pamEnv map[string]string, start func(func() error) error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer channel.Close()
	var terminal *os.File
	var command *exec.Cmd
	var done chan uint32
	var term *ptyRequest
	environ := map[string]string{}
	defer func() {
		cancel()
		channel.Close()
		if terminal != nil {
			terminal.Close()
		}
		if command != nil && command.Process != nil {
			syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			// Reap the process and its copying goroutines before the session ends.
			if done != nil {
				<-done
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case status := <-done:
			done = nil
			channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
			channel.CloseWrite()
			return
		case request, ok := <-requests:
			if !ok {
				return
			}
			accepted := false
			switch request.Type {
			case "pty-req":
				var value ptyRequest
				if ssh.Unmarshal(request.Payload, &value) != nil {
					break
				}
				// RFC 4254: zero dimensions are ignored. OpenSSH uses them
				// when forcing a PTY without having a local terminal.
				if value.Columns == 0 {
					value.Columns = 80
				}
				if value.Rows == 0 {
					value.Rows = 24
				}
				if command == nil && term == nil && validSize(value.Columns, value.Rows) && len(value.Term) <= 128 && !strings.ContainsAny(value.Term, "\x00\r\n") {
					term = &value
					accepted = true
				}
			case "window-change":
				var value windowChange
				if term == nil || ssh.Unmarshal(request.Payload, &value) != nil {
					break
				}
				if value.Columns == 0 {
					value.Columns = term.Columns
				}
				if value.Rows == 0 {
					value.Rows = term.Rows
				}
				if validSize(value.Columns, value.Rows) {
					term.Columns, term.Rows = value.Columns, value.Rows
					accepted = terminal == nil || pty.Setsize(terminal, &pty.Winsize{Cols: uint16(value.Columns), Rows: uint16(value.Rows)}) == nil
				}
			case "env":
				var value struct{ Name, Value string }
				if command == nil && ssh.Unmarshal(request.Payload, &value) == nil && (value.Name == "LANG" || strings.HasPrefix(value.Name, "LC_")) && len(value.Name) <= 64 && len(value.Value) <= 256 && !strings.ContainsAny(value.Name+value.Value, "\x00\r\n=") && len(environ) < 32 {
					environ[value.Name] = value.Value
					accepted = true
				}
			case "shell", "exec":
				if command != nil {
					break
				}
				args := []string{}
				if request.Type == "exec" {
					var value struct{ Command string }
					if ssh.Unmarshal(request.Payload, &value) != nil || len(value.Command) > 65536 {
						break
					}
					args = []string{"-c", value.Command}
				} else if len(request.Payload) != 0 {
					break
				}
				credential, err := account.credential()
				if err != nil {
					request.Reply(false, nil)
					return
				}
				cmd := exec.CommandContext(ctx, account.Shell, args...)
				if request.Type == "shell" {
					cmd.Args[0] = "-" + filepath.Base(account.Shell)
				}
				cmd.Dir = account.Home
				cmd.Env = shellEnvironment(account, term, pamEnv, environ)
				cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credential}
				cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
				cmd.WaitDelay = time.Second
				var outputDone chan struct{}
				if term != nil {
					err = start(func() error {
						var startErr error
						terminal, startErr = startPTY(cmd, term, account)
						return startErr
					})
					if err == nil {
						outputDone = make(chan struct{})
						go func() { io.Copy(terminal, channel) }()
						go func() { io.Copy(channel, terminal); close(outputDone) }()
					}
				} else {
					cmd.SysProcAttr.Setpgid = true
					// An explicit stdin pipe lets us interrupt a client that never sends EOF.
					var input io.WriteCloser
					input, err = cmd.StdinPipe()
					if err == nil {
						cmd.Stdout, cmd.Stderr = channel, channel.Stderr()
						err = start(cmd.Start)
						if err == nil {
							go func() { io.Copy(input, channel); input.Close() }()
						} else {
							input.Close()
						}
					}
				}
				if err != nil {
					fmt.Fprintln(channel.Stderr(), "cannot start system account shell")
					s.log.Error("start system shell", "user", account.Name, "error", err)
					request.Reply(false, nil)
					return
				}
				command, done = cmd, make(chan uint32, 1)
				result := done
				go func() {
					err := cmd.Wait()
					syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					if outputDone != nil {
						<-outputDone
					}
					status := uint32(0)
					if err != nil {
						status = 1
						var exit *exec.ExitError
						if errors.As(err, &exit) {
							code := exit.ExitCode()
							if wait, ok := exit.Sys().(syscall.WaitStatus); ok && wait.Signaled() {
								code = 128 + int(wait.Signal())
							}
							status = uint32(code)
						}
					}
					result <- status
				}()
				accepted = true
			case "signal":
				var value struct{ Signal string }
				if command != nil && ssh.Unmarshal(request.Payload, &value) == nil {
					signals := map[string]syscall.Signal{"HUP": syscall.SIGHUP, "INT": syscall.SIGINT, "QUIT": syscall.SIGQUIT, "TERM": syscall.SIGTERM, "KILL": syscall.SIGKILL}
					if sig, ok := signals[value.Signal]; ok {
						accepted = syscall.Kill(-command.Process.Pid, sig) == nil
					}
				}
			}
			request.Reply(accepted, nil)
		}
	}
}

func shellEnvironment(account *systemAccount, term *ptyRequest, pamEnv, extra map[string]string) []string {
	values := map[string]string{"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
	for name, value := range pamEnv {
		values[name] = value
	}
	for name, value := range extra {
		values[name] = value
	}
	values["HOME"], values["USER"], values["LOGNAME"], values["SHELL"] = account.Home, account.Name, account.Name, account.Shell
	if term != nil {
		values["TERM"] = term.Term
		values["COLUMNS"] = strconv.FormatUint(uint64(term.Columns), 10)
		values["LINES"] = strconv.FormatUint(uint64(term.Rows), 10)
	}
	result := make([]string, 0, len(values))
	for name, value := range values {
		result = append(result, name+"="+value)
	}
	return result
}

func startPTY(cmd *exec.Cmd, term *ptyRequest, account *systemAccount) (*os.File, error) {
	master, slave, err := pty.Open()
	if err != nil {
		return nil, err
	}
	defer slave.Close()
	if err = slave.Chown(int(account.UID), int(account.GID)); err == nil {
		err = slave.Chmod(0600)
	}
	if err == nil {
		err = pty.Setsize(master, &pty.Winsize{Cols: uint16(term.Columns), Rows: uint16(term.Rows)})
	}
	if err == nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		cmd.SysProcAttr.Setsid = true
		cmd.SysProcAttr.Setctty = true
		cmd.SysProcAttr.Ctty = 0
		err = cmd.Start()
	}
	if err != nil {
		master.Close()
		return nil, err
	}
	return master, nil
}
