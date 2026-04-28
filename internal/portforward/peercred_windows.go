//go:build windows

package portforward

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                        = syscall.NewLazyDLL("kernel32.dll")
	procGetNamedPipeClientProcessId = kernel32.NewProc("GetNamedPipeClientProcessId")
)

// fdConn is implemented by go-winio's pipe connection types. It exposes the
// underlying server-side pipe handle so we can call
// GetNamedPipeClientProcessId on it.
type fdConn interface {
	Fd() uintptr
}

// wrapPeerVerify wraps a named-pipe listener so Accept() returns only
// connections whose client PID matches this process. Implemented via
// GetNamedPipeClientProcessId on the server-side handle exposed by
// go-winio's *win32File.Fd(). Blocks same-user different-process attackers
// on top of the SDDL ACL's cross-user block.
//
// If the accepted connection does not expose Fd() (unexpected winio API
// change) the connection is rejected fail-closed: we can't verify the
// peer, so we don't trust it. A runtime breakage here is preferable to
// silently downgrading security on a library upgrade.
func wrapPeerVerify(l net.Listener) net.Listener {
	return &peerVerifiedListener{Listener: l, expectedPID: uint32(os.Getpid())}
}

type peerVerifiedListener struct {
	net.Listener
	expectedPID uint32
}

func (l *peerVerifiedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		pid, verr := clientPID(c)
		if verr != nil {
			fmt.Fprintf(os.Stderr, "kubeport: rejected IPC connection: %v\n", verr)
			_ = c.Close()
			continue
		}
		if pid != l.expectedPID {
			fmt.Fprintf(os.Stderr, "kubeport: rejected IPC connection from PID %d (expected %d)\n", pid, l.expectedPID)
			_ = c.Close()
			continue
		}
		return c, nil
	}
}

func clientPID(c net.Conn) (uint32, error) {
	fd, ok := c.(fdConn)
	if !ok {
		return 0, fmt.Errorf("conn %T does not expose Fd()", c)
	}
	h := windows.Handle(fd.Fd())
	if h == 0 || h == windows.InvalidHandle {
		return 0, fmt.Errorf("invalid pipe handle")
	}
	var pid uint32
	ret, _, callErr := procGetNamedPipeClientProcessId.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&pid)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("GetNamedPipeClientProcessId: %w", callErr)
	}
	return pid, nil
}
