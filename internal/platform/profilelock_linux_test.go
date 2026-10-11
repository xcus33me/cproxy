package platform

import (
	"os"
	"syscall"
)

const firefoxLockFile = ".parentlock"

func acquireFirefoxLock(path string) (*os.File, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Len: 0}
	if e = syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lock); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
