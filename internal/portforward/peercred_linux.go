//go:build linux

package portforward

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// wrapPeerVerify wraps a Unix-domain listener so that Accept() returns only
// connections whose peer PID matches this process. Implemented via
// SO_PEERCRED on Linux. Blocks same-user different-process attackers
// (e.g., malware running under the user's UID).
func wrapPeerVerify(l net.Listener) net.Listener {
	return &peerVerifiedListener{Listener: l, expectedPID: os.Getpid()}
}

type peerVerifiedListener struct {
	net.Listener
	expectedPID int
}

func (l *peerVerifiedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if verr := verifyPeerPID(c, l.expectedPID); verr != nil {
			_ = c.Close()
			fmt.Fprintf(os.Stderr, "kubeport: rejected IPC connection: %v\n", verr)
			continue
		}
		return c, nil
	}
}

func verifyPeerPID(c net.Conn, expectedPID int) error {
	pid, err := peerPID(c)
	if err != nil {
		return err
	}
	if pid != expectedPID {
		return fmt.Errorf("peer PID %d does not match kubeport PID %d", pid, expectedPID)
	}
	return nil
}

// verifyIPCServer is the client-side mirror of the server-side peer check.
// After DialIPC connects, the proxy calls this to confirm the socket it
// reached is served by this same kubeport process. If a local attacker
// has swapped our listener for theirs at the same path, their PID will
// not match and we refuse to use the connection.
func verifyIPCServer(c net.Conn) error {
	pid, err := peerPID(c)
	if err != nil {
		return err
	}
	if pid != os.Getpid() {
		return fmt.Errorf("IPC server PID %d does not match kubeport PID %d", pid, os.Getpid())
	}
	return nil
}

func peerPID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("conn is not a unix socket (%T)", c)
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("syscall conn: %w", err)
	}
	var ucred *unix.Ucred
	var inner error
	err = rc.Control(func(fd uintptr) {
		// #nosec G115 -- unix.GetsockoptUcred's signature takes int; file
		// descriptors from syscall.RawConn.Control are always small positive
		// integers that fit in int on every Go-supported platform.
		ucred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return 0, fmt.Errorf("control fd: %w", err)
	}
	if inner != nil {
		return 0, fmt.Errorf("getsockopt SO_PEERCRED: %w", inner)
	}
	return int(ucred.Pid), nil
}
