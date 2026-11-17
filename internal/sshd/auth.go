package sshd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

func hostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(key, "websshserver host key")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	// O_EXCL prevents accidentally replacing another instance's host identity.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		return ssh.ParsePrivateKey(data)
	}
	if err != nil {
		return nil, err
	}
	if err = pem.Encode(f, block); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

func authorizedKeys(path string) (map[string]bool, error) {
	keys := make(map[string]bool)
	if path == "" {
		return keys, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		key, _, options, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			return nil, fmt.Errorf("parse authorized_keys: %w", err)
		}
		// Refuse restrictions rather than silently discarding their meaning.
		if len(options) != 0 || isCertificate(key) {
			return nil, errors.New("authorized_keys must contain plain public keys without options or certificates")
		}
		keys[string(key.Marshal())] = true
	}
	if len(keys) == 0 {
		return nil, errors.New("authorized_keys contains no public keys")
	}
	return keys, nil
}

func isCertificate(key ssh.PublicKey) bool {
	_, ok := key.(*ssh.Certificate)
	return ok
}
