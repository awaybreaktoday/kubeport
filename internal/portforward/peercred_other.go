//go:build !linux && !windows

package portforward

import "net"

// wrapPeerVerify is a no-op on non-Linux POSIX platforms. The socket's 0600
// file mode restricts connections to the same UID, but same-user
// different-process attacks are not blocked here.
func wrapPeerVerify(l net.Listener) net.Listener { return l }

// verifyIPCServer is a no-op on non-Linux POSIX platforms. Same-user
// socket-swap attacks rely on a shared parent directory, which
// ensureOwnedDir already rejects; client-side peer verification would be
// belt-and-braces here and is deferred.
func verifyIPCServer(net.Conn) error { return nil }
