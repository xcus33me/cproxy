package platform

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
)

// Firefox holds parent.lock open with no sharing. Use OPEN_EXISTING so a
// read-only check never creates/truncates it. See Mozilla nsProfileLock.cpp.
func ProfileInUse(dir string) (bool, error) {
	path := filepath.Join(dir, "parent.lock")
	if e := regularTarget(path); e != nil {
		return false, e
	}
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return false, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if errors.Is(e, windows.ERROR_SHARING_VIOLATION) {
		return true, nil
	}
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	windows.CloseHandle(h)
	return false, nil
}
