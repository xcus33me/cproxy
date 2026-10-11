package platform

import (
	"golang.org/x/sys/windows"
	"os"
)

const firefoxLockFile = "parent.lock"

func acquireFirefoxLock(path string) (*os.File, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.CREATE_ALWAYS, 0, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(h), path), nil
}
