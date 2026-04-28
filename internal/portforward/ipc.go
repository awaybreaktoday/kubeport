package portforward

import (
	"context"
	"net"
)

// ListenIPC opens a platform-appropriate local IPC endpoint that only the
// current OS user can connect to. On POSIX it's a Unix domain socket at
// endpoint (a filesystem path) with mode 0600; on Windows it's a named pipe
// at endpoint (e.g., `\\.\pipe\kubeport-<pid>`) with a security descriptor
// granting GENERIC_ALL only to the current user's SID.
//
// On Linux the returned listener additionally filters accepted connections
// by peer PID (via SO_PEERCRED), rejecting any connection whose peer PID
// does not match the kubeport process — blocking same-user different-process
// attackers (e.g., malware running as the user).
//
// On other POSIX platforms (darwin, freebsd) the file-mode check is the
// only enforcement; same-user different-process access is possible.
//
// On Windows the SDDL ACL blocks cross-user access, and Accept() further
// filters by client PID via GetNamedPipeClientProcessId, blocking
// same-user different-process attackers.
func ListenIPC(endpoint string) (net.Listener, error) {
	return listenIPC(endpoint)
}

// DialIPC connects to an IPC endpoint created by ListenIPC.
func DialIPC(ctx context.Context, endpoint string) (net.Conn, error) {
	return dialIPC(ctx, endpoint)
}

// DefaultIPCEndpoint returns a platform-appropriate endpoint path/name for
// this process. It ensures any containing directory exists with restrictive
// permissions; the returned string is safe to pass to ListenIPC.
func DefaultIPCEndpoint() (string, error) {
	return defaultIPCEndpoint()
}
