//go:build linux && cgo

package sshd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/msteinert/pam/v2"
	"golang.org/x/crypto/ssh"
)

var errAuthentication = errors.New("system account authentication failed")

// All methods run on the worker's locked OS thread. A transaction lives until
// that SSH connection and all of its child sessions have ended.
type systemAuth struct {
	cfg                  Config
	remoteHost           string
	txn                  *pam.Transaction
	account              *systemAccount
	credentials, session bool
	environ              map[string]string
}

func (a *systemAuth) begin(username string, conversation pam.ConversationHandler) error {
	a.close()
	if username == "" || len(username) > 256 || strings.ContainsAny(username, "\x00\r\n:") {
		return errAuthentication
	}
	var err error
	if a.cfg.PAMConfigDir != "" {
		a.txn, err = pam.StartConfDir(a.cfg.PAMService, username, conversation, a.cfg.PAMConfigDir)
	} else {
		a.txn, err = pam.Start(a.cfg.PAMService, username, conversation)
	}
	if err != nil {
		return err
	}
	if err := a.txn.SetItem(pam.Rhost, a.remoteHost); err != nil {
		return err
	}
	return a.txn.SetItem(pam.Tty, "ssh")
}

func (a *systemAuth) acceptAccount() (*ssh.Permissions, error) {
	if err := a.txn.AcctMgmt(pam.DisallowNullAuthtok); err != nil {
		return nil, errAuthentication
	}
	name, err := a.txn.GetItem(pam.User)
	if err != nil {
		return nil, errAuthentication
	}
	account, err := lookupAccount(name)
	if err != nil {
		return nil, errAuthentication
	}
	if _, err := account.credential(); err != nil {
		return nil, errAuthentication
	}
	a.account = account
	return &ssh.Permissions{Extensions: map[string]string{"system-user": account.Name}}, nil
}

func (a *systemAuth) password(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if len(password) == 0 || len(password) > 4096 || strings.ContainsRune(string(password), 0) {
		return nil, errAuthentication
	}
	secret := string(password)
	defer func() { secret = "" }()
	prompts := 0
	conversation := pam.ConversationFunc(func(style pam.Style, _ string) (string, error) {
		switch style {
		case pam.PromptEchoOff:
			prompts++
			if prompts != 1 || secret == "" {
				return "", errors.New("additional PAM prompts require interactive authentication")
			}
			return secret, nil
		case pam.PromptEchoOn:
			return meta.User(), nil
		case pam.ErrorMsg, pam.TextInfo:
			return "", nil
		default:
			return "", errors.New("unsupported PAM conversation")
		}
	})
	if err := a.begin(meta.User(), conversation); err != nil {
		return nil, errAuthentication
	}
	if err := a.txn.Authenticate(pam.DisallowNullAuthtok); err != nil {
		a.close()
		return nil, errAuthentication
	}
	permissions, err := a.acceptAccount()
	if err != nil {
		a.close()
	}
	return permissions, err
}

func (a *systemAuth) publicKey(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	account, err := lookupAccount(meta.User())
	if err != nil || !systemKeyAllowed(account, key) {
		return nil, errAuthentication
	}
	conversation := pam.ConversationFunc(func(style pam.Style, _ string) (string, error) {
		if style == pam.TextInfo || style == pam.ErrorMsg {
			return "", nil
		}
		return "", errors.New("PAM password prompt during public key authentication")
	})
	if err := a.begin(meta.User(), conversation); err != nil {
		return nil, errAuthentication
	}
	permissions, err := a.acceptAccount()
	if err != nil {
		a.close()
	}
	return permissions, err
}

func (a *systemAuth) config(signer ssh.Signer) *ssh.ServerConfig {
	config := &ssh.ServerConfig{Config: ssh.Config{RekeyThreshold: a.cfg.RekeyBytes}, MaxAuthTries: 3, ServerVersion: "SSH-2.0-WebSSHServer", PasswordCallback: a.password, PublicKeyCallback: a.publicKey}
	config.AddHostKey(signer)
	return config
}

func (a *systemAuth) openSession() error {
	if a.txn == nil || a.account == nil {
		return errAuthentication
	}
	if err := a.account.initializeGroups(); err != nil {
		return err
	}
	if err := a.txn.SetCred(pam.EstablishCred); err != nil {
		return fmt.Errorf("establish credentials: %w", err)
	}
	a.credentials = true
	if err := a.txn.OpenSession(0); err != nil {
		return fmt.Errorf("open: %w", err)
	}
	a.session = true
	groups, err := os.Getgroups()
	if err != nil {
		return err
	}
	a.account.Groups = nil
	for _, group := range groups {
		a.account.Groups = append(a.account.Groups, uint32(group))
	}
	environ, err := a.txn.GetEnvList()
	if err != nil {
		return err
	}
	a.environ = environ
	return nil
}

func (a *systemAuth) close() {
	if a.txn != nil {
		if a.session {
			a.txn.CloseSession(0)
		}
		if a.credentials {
			a.txn.SetCred(pam.DeleteCred)
		}
		a.txn.End()
	}
	a.txn = nil
	a.account = nil
	a.session = false
	a.credentials = false
	a.environ = nil
}

func systemKeyAllowed(account *systemAccount, key ssh.PublicKey) bool {
	if isCertificate(key) {
		return false
	}
	for _, path := range []string{account.Home, filepath.Join(account.Home, ".ssh")} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || !secureOwner(info, account.UID) {
			return false
		}
	}
	path := filepath.Join(account.Home, ".ssh", "authorized_keys")
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !secureOwner(info, account.UID) || info.Size() > 1<<20 {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		candidate, _, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err == nil && len(options) == 0 && !isCertificate(candidate) && string(candidate.Marshal()) == string(key.Marshal()) {
			return true
		}
	}
	return false
}

func secureOwner(info os.FileInfo, uid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || stat.Uid == uid) && info.Mode().Perm()&0022 == 0
}
