package resolve

import (
	"os"
	"runtime"
	"testing"
)

func TestDropPrivilegesNonRootNoop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows privilege model differs")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root; noop path not exercised")
	}
	if err := DropPrivileges("", "", false); err != nil {
		t.Fatal(err)
	}
	if err := DropPrivileges("nobody", "nobody", false); err != nil {
		t.Fatal(err)
	}
}

func TestDropPrivilegesKeepRoot(t *testing.T) {
	if err := DropPrivileges("does-not-exist", "does-not-exist", true); err != nil {
		t.Fatal(err)
	}
}
