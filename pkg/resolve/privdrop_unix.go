//go:build unix

package resolve

import (
	"fmt"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

// DropPrivileges drops root after sockets are opened (massdns --drop-user /
// --drop-group). No-op when not running as root. When keepRoot is true (massdns
// --root), privileges are left unchanged.
func DropPrivileges(username, groupname string, keepRoot bool) error {
	if unix.Geteuid() != 0 {
		return nil
	}
	if keepRoot {
		return nil
	}
	if username == "" {
		username = "nobody"
	}
	if groupname == "" {
		groupname = "nobody"
	}

	uid, err := lookupUID(username)
	if err != nil {
		return err
	}
	gid, err := lookupGID(groupname)
	if err != nil {
		return err
	}
	if err := unix.Setgid(gid); err != nil {
		return fmt.Errorf("setgid(%s): %w", groupname, err)
	}
	if err := unix.Setuid(uid); err != nil {
		return fmt.Errorf("setuid(%s): %w", username, err)
	}
	return nil
}

func lookupUID(name string) (int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		// massdns falls back to 65534 when the default nobody user is missing,
		// but errors when an explicit --drop-user is unknown.
		if name == "nobody" {
			return 65534, nil
		}
		return 0, fmt.Errorf("user %q does not exist", name)
	}
	id, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func lookupGID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		if name == "nobody" || name == "nogroup" {
			return 65534, nil
		}
		return 0, fmt.Errorf("group %q does not exist", name)
	}
	id, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, err
	}
	return id, nil
}
