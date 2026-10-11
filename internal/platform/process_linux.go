package platform

import (
	"os"
	"os/exec"
	"syscall"
)

func Hide(cmd *exec.Cmd)   {}
func Detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
func StartChild(cmd *exec.Cmd) (func(), error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if e := cmd.Start(); e != nil {
		return nil, e
	}
	return func() {}, nil
}
func Lock(path string) (*os.File, error) {
	if e := regularTarget(path); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
