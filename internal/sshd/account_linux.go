//go:build linux && cgo

package sshd

/*
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <errno.h>

static int account_lookup(const char *name, struct passwd *entry, char **buffer) {
    for (size_t size = 16384; size <= 1048576; size *= 2) {
        char *data = malloc(size);
        if (!data) return ENOMEM;
        struct passwd *result = NULL;
        int rc = getpwnam_r(name, entry, data, size, &result);
        if (rc == ERANGE) { free(data); continue; }
        if (rc != 0 || result == NULL) { free(data); return rc ? rc : ENOENT; }
        *buffer = data;
        return 0;
    }
    return ERANGE;
}

static int account_initgroups(const char *name, gid_t gid) {
    return initgroups(name, gid) == 0 ? 0 : errno;
}
*/
import "C"

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

type systemAccount struct {
	Name, Home, Shell string
	UID, GID          uint32
	Groups            []uint32
}

func lookupAccount(name string) (*systemAccount, error) {
	if name == "" || len(name) > 256 || strings.ContainsAny(name, "\x00\r\n:") {
		return nil, fmt.Errorf("invalid system username")
	}
	value := C.CString(name)
	defer C.free(unsafe.Pointer(value))
	var entry C.struct_passwd
	var buffer *C.char
	if code := C.account_lookup(value, &entry, &buffer); code != 0 {
		return nil, fmt.Errorf("system account lookup failed: %w", syscall.Errno(code))
	}
	defer C.free(unsafe.Pointer(buffer))
	account := &systemAccount{Name: C.GoString(entry.pw_name), Home: C.GoString(entry.pw_dir), Shell: C.GoString(entry.pw_shell), UID: uint32(entry.pw_uid), GID: uint32(entry.pw_gid)}
	if account.Shell == "" {
		account.Shell = "/bin/sh"
	}
	if !filepath.IsAbs(account.Home) || !filepath.IsAbs(account.Shell) {
		return nil, fmt.Errorf("system account has a non-absolute home or shell")
	}
	info, err := os.Stat(account.Shell)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return nil, fmt.Errorf("system account shell is not executable")
	}
	u, err := user.Lookup(account.Name)
	if err != nil {
		return nil, err
	}
	groups, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	for _, group := range groups {
		id, err := strconv.ParseUint(group, 10, 32)
		if err != nil {
			return nil, err
		}
		account.Groups = append(account.Groups, uint32(id))
	}
	return account, nil
}

func (a *systemAccount) credential() (*syscall.Credential, error) {
	credential := &syscall.Credential{Uid: a.UID, Gid: a.GID, Groups: a.Groups}
	if os.Geteuid() != 0 {
		// Allows unprivileged embedding/tests for the current system user only.
		// The public server command requires root to support other accounts.
		if uint32(os.Geteuid()) != a.UID || uint32(os.Getegid()) != a.GID {
			return nil, fmt.Errorf("root is required to switch to the authenticated system user")
		}
		credential.NoSetGroups = true
	}
	return credential, nil
}

func (a *systemAccount) initializeGroups() error {
	if os.Geteuid() != 0 {
		return nil
	}
	name := C.CString(a.Name)
	defer C.free(unsafe.Pointer(name))
	if code := C.account_initgroups(name, C.gid_t(a.GID)); code != 0 {
		return syscall.Errno(code)
	}
	return nil
}
