package platform

import (
	"os"
	"path/filepath"
	"syscall"
)

// Firefox uses an fcntl write lock, not flock. Never delete its lock files.
// See Mozilla toolkit/profile/nsProfileLock.cpp.
func ProfileInUse(dir string) (bool, error) {
	path := filepath.Join(dir, ".parentlock")
	if e := regularTarget(path); e != nil {
		return false, e
	}
	f, e := os.OpenFile(path, os.O_RDWR, 0)
	if os.IsNotExist(e) {
		// Conservatively refuse a legacy/symlink-only lock. A network profile
		// is not safe to open from an unrelated instance either.
		_, e = os.Lstat(filepath.Join(dir, "lock"))
		if os.IsNotExist(e) {
			return false, nil
		}
		return e == nil, e
	}
	if e != nil {
		return false, e
	}
	defer f.Close()
	lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Len: 0}
	if e = syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lock); e != nil {
		return false, e
	}
	return lock.Type != syscall.F_UNLCK, nil
}
