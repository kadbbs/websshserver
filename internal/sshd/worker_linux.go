//go:build linux && cgo

package sshd

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type workerConfig struct {
	Config     Config
	RemoteHost string
}

func init() {
	if len(os.Args) == 2 && os.Args[1] == "--connection-worker" {
		// PAM modules such as pam_loginuid address the process leader through
		// /proc/self. init runs on that thread; keep main on it as well.
		runtime.LockOSThread()
	}
}

type socketAddr string

func (a socketAddr) Network() string { return "tcp" }
func (a socketAddr) String() string  { return string(a) }

type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteConn) RemoteAddr() net.Addr { return c.remote }

func (s *Server) runConnectionProcess(raw net.Conn) error {
	// Linux ties Pdeathsig to the creator thread, not just the process.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	parentFile := os.NewFile(uintptr(pair[0]), "ssh-parent")
	childFile := os.NewFile(uintptr(pair[1]), "ssh-child")
	defer childFile.Close()
	bridge, err := net.FileConn(parentFile)
	parentFile.Close()
	if err != nil {
		return err
	}
	defer bridge.Close()
	configRead, configWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer configRead.Close()
	defer configWrite.Close()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(executable, "--connection-worker")
	cmd.ExtraFiles = []*os.File{childFile, configRead}
	cmd.Stderr = os.Stderr
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return err
	}
	childFile.Close()
	configRead.Close()
	host, _, _ := net.SplitHostPort(raw.RemoteAddr().String())
	if err := json.NewEncoder(configWrite).Encode(workerConfig{Config: s.cfg, RemoteHost: host}); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return err
	}
	configWrite.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	copied := make(chan struct{}, 2)
	var copying sync.WaitGroup
	copying.Add(2)
	go func() { defer copying.Done(); io.Copy(bridge, raw); copied <- struct{}{} }()
	go func() { defer copying.Done(); io.Copy(raw, bridge); copied <- struct{}{} }()
	select {
	case err = <-done:
		bridge.Close()
		raw.Close()
		copying.Wait()
		return err
	case <-copied:
		bridge.Close()
		raw.Close()
	}
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		err = <-done
	}
	copying.Wait()
	return err
}

// RunConnectionWorker is invoked only through inherited private descriptors.
// It implements SSH directly; no system sshd process or SSH upstream is used.
func RunConnectionWorker() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	stream := os.NewFile(3, "ssh-stream")
	configFile := os.NewFile(4, "ssh-config")
	if stream == nil || configFile == nil {
		return errors.New("missing worker descriptors")
	}
	defer stream.Close()
	defer configFile.Close()
	var config workerConfig
	if err := json.NewDecoder(io.LimitReader(configFile, 1<<20)).Decode(&config); err != nil {
		return err
	}
	configFile.Close()
	conn, err := net.FileConn(stream)
	if err != nil {
		return err
	}
	stream.Close()
	defer conn.Close()
	srv, err := New(config.Config, slog.Default())
	if err != nil {
		return err
	}
	return srv.serveAuthenticatedConn(conn, config.RemoteHost)
}
