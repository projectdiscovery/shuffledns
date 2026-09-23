//go:build windows

package resolve

import "fmt"

// DropPrivileges is not supported on Windows.
func DropPrivileges(username, groupname string, keepRoot bool) error {
	if keepRoot {
		return nil
	}
	if username != "" || groupname != "" {
		return fmt.Errorf("privilege drop is not supported on Windows")
	}
	return nil
}
