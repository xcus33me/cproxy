package platform

import (
	"fmt"
	"os"
	"path/filepath"
)

func regularTarget(path string) error {
	i, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if !i.Mode().IsRegular() {
		return fmt.Errorf("Небезопасный путь файла: %s", path)
	}
	return nil
}
func PrivateDir(path string) error {
	if i, e := os.Lstat(path); e == nil && (!i.IsDir() || i.Mode()&os.ModeSymlink != 0) {
		return fmt.Errorf("Небезопасный каталог: %s", path)
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	return protect(path, true)
}
func WritePrivate(path string, data []byte) error {
	if e := PrivateDir(filepath.Dir(path)); e != nil {
		return e
	}
	if e := regularTarget(path); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".cproxy-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = protect(tmp, false); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
