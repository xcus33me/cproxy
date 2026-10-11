package legacy

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"cproxy/internal/platform"
	"golang.org/x/sys/windows"
)

func taskCommand(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "schtasks.exe", args...)
	platform.Hide(cmd)
	return cmd.CombinedOutput()
}
func xmlText(b []byte) []byte {
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		v := make([]uint16, (len(b)-2)/2)
		for n := range v {
			v[n] = binary.LittleEndian.Uint16(b[2+n*2:])
		}
		return []byte(string(utf16.Decode(v)))
	}
	return b
}

func (i Installation) pause(ctx context.Context) (func() error, error) {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, e
	}
	sid := user.User.Sid.String()
	name := "SelectiveProxy-" + sid
	raw, e := taskCommand(ctx, "/Query", "/TN", name, "/XML")
	if e != nil {
		return nil, fmt.Errorf("Не удалось прочитать старую задачу %s: %w", name, e)
	}
	var task struct {
		RegistrationInfo struct{ Description string }
		Principals       struct {
			Principal []struct {
				UserID string `xml:"UserId"`
			}
		}
		Settings struct{ Enabled bool }
		Actions  struct {
			Exec []struct{ Command, Arguments string }
		}
	}
	// schtasks may label a UTF-16 document even when stdout has been decoded.
	data := strings.ReplaceAll(string(xmlText(raw)), `encoding="UTF-16"`, `encoding="UTF-8"`)
	if e = xml.Unmarshal([]byte(data), &task); e != nil {
		return nil, e
	}
	expected := `-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File "` + filepath.Join(i.Dir, "run-proxy.ps1") + `"`
	if task.RegistrationInfo.Description != "Managed by cproxy" || len(task.Principals.Principal) != 1 || len(task.Actions.Exec) != 1 || task.Actions.Exec[0].Arguments != expected {
		return nil, errors.New("Старая задача не принадлежит этой установке cproxy")
	}
	owner := task.Principals.Principal[0].UserID
	if owner != sid {
		resolved, _, _, err := windows.LookupSID("", owner)
		if err != nil || resolved.String() != sid {
			return nil, errors.New("Старая задача принадлежит другому пользователю")
		}
	}
	handle, active, e := i.oldProcess()
	if e != nil {
		return nil, e
	}
	if handle != 0 {
		defer windows.CloseHandle(handle)
	}
	restore := func() error {
		rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var result error
		if task.Settings.Enabled {
			_, result = taskCommand(rctx, "/Change", "/TN", name, "/ENABLE")
		}
		if active {
			_, err := taskCommand(rctx, "/Run", "/TN", name)
			result = errors.Join(result, err)
		}
		return result
	}
	if _, e = taskCommand(ctx, "/Change", "/TN", name, "/DISABLE"); e != nil {
		return nil, e
	}
	if active {
		if _, e = taskCommand(ctx, "/End", "/TN", name); e != nil {
			return nil, errors.Join(e, restore())
		}
		if e = windows.TerminateProcess(handle, 0); e != nil {
			return nil, errors.Join(e, restore())
		}
		windows.WaitForSingleObject(handle, 5000)
	}
	return restore, nil
}

func (i Installation) oldProcess() (windows.Handle, bool, error) {
	b, e := os.ReadFile(filepath.Join(i.Dir, "process.json"))
	if os.IsNotExist(e) {
		return 0, false, nil
	}
	if e != nil {
		return 0, false, e
	}
	var s struct {
		PID    uint32 `json:"pid"`
		Ticks  string `json:"ticks"`
		Binary string `json:"binary"`
	}
	if e = json.Unmarshal(b, &s); e != nil {
		return 0, false, e
	}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, s.PID)
	if errors.Is(e, windows.ERROR_INVALID_PARAMETER) {
		return 0, false, nil
	}
	if e != nil {
		return 0, false, e
	}
	fail := func(err error) (windows.Handle, bool, error) { windows.CloseHandle(h); return 0, false, err }
	var created, exited, kernel, user windows.Filetime
	if e = windows.GetProcessTimes(h, &created, &exited, &kernel, &user); e != nil {
		return fail(e)
	}
	if exited.HighDateTime != 0 || exited.LowDateTime != 0 {
		windows.CloseHandle(h)
		return 0, false, nil
	}
	ticks, e := strconv.ParseUint(s.Ticks, 10, 64)
	actual := (uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)) + 504911232000000000
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if e != nil || actual != ticks {
		return fail(errors.New("PID старого прокси уже принадлежит другому процессу"))
	}
	if e = windows.QueryFullProcessImageName(h, 0, &buf[0], &n); e != nil {
		return fail(e)
	}
	if !strings.EqualFold(windows.UTF16ToString(buf[:n]), s.Binary) || !strings.EqualFold(filepath.Base(s.Binary), "sing-box.exe") {
		return fail(errors.New("Процесс старого прокси не распознан; он не будет завершён"))
	}
	return h, true, nil
}
