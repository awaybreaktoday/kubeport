//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// elevateBootstrap re-launches the current executable with the "runas"
// verb (triggering a UAC prompt) to run the __bootstrap subcommand with
// the given args. Returns the child's exit code. A non-zero exit code
// means the admin op failed or the user denied the UAC prompt.
func elevateBootstrap(bootstrapArgs []string) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return -1, fmt.Errorf("locate self: %w", err)
	}

	full := append([]string{"__bootstrap"}, bootstrapArgs...)
	params := strings.Join(quoteArgs(full), " ")

	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	paramsPtr, _ := syscall.UTF16PtrFromString(params)

	info := shellExecuteInfoW{
		cbSize:       uint32(unsafe.Sizeof(shellExecuteInfoW{})),
		fMask:        seeMaskNoCloseProcess,
		lpVerb:       verbPtr,
		lpFile:       exePtr,
		lpParameters: paramsPtr,
		nShow:        swShowNormal,
	}

	ret, _, lastErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		return -1, fmt.Errorf("ShellExecuteExW: %w", lastErr)
	}
	if info.hProcess == 0 {
		return -1, fmt.Errorf("ShellExecuteExW returned no process handle (SEE_MASK_NOCLOSEPROCESS missing?)")
	}

	handle := windows.Handle(info.hProcess)
	defer windows.CloseHandle(handle)

	if _, err := windows.WaitForSingleObject(handle, windows.INFINITE); err != nil {
		return -1, fmt.Errorf("WaitForSingleObject: %w", err)
	}

	var exitCode uint32
	if err := windows.GetExitCodeProcess(handle, &exitCode); err != nil {
		return -1, fmt.Errorf("GetExitCodeProcess: %w", err)
	}
	return int(exitCode), nil
}

// quoteArgs wraps each arg in double quotes if it contains whitespace,
// and escapes embedded quotes per the Windows CommandLineToArgvW rules.
func quoteArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" {
			out[i] = `""`
			continue
		}
		if !strings.ContainsAny(a, " \"\t") {
			out[i] = a
			continue
		}
		escaped := strings.ReplaceAll(a, `"`, `\"`)
		out[i] = `"` + escaped + `"`
	}
	return out
}

// ShellExecuteExW plumbing — x/sys/windows only exposes the simpler
// ShellExecute which gives us no process handle. We need
// SEE_MASK_NOCLOSEPROCESS so we can wait on the child.
var (
	shell32            = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteExW = shell32.NewProc("ShellExecuteExW")
)

const (
	seeMaskNoCloseProcess = 0x00000040
	swShowNormal          = 1
)

type shellExecuteInfoW struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	dummyUnion   uintptr
	hProcess     uintptr
}
