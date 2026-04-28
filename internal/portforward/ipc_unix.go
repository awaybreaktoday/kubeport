//go:build !windows

package portforward

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

func listenIPC(path string) (net.Listener, error) {
	// Clean up any stale socket from a previous crashed run. Only remove
	// if it's actually a socket we own — never unlink something unexpected.
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	if err := ensureOwnedDir(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("prepare socket dir: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen unix %s: %w", path, err)
	}
	// Be defensive about perms in case the umask permitted wider access.
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod %s: %w", path, err)
	}
	return wrapPeerVerify(ln), nil
}

func dialIPC(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	// Verify the server side of the connection is this kubeport process.
	// Defends against an attacker who has unlinked our listener and
	// substituted their own socket at the same path.
	if err := verifyIPCServer(c); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("ipc server verification failed: %w", err)
	}
	return c, nil
}

func defaultIPCEndpoint() (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = os.TempDir()
	}
	// Per-UID subdirectory so /tmp-style shared parents don't let another
	// local user influence our socket path. The uid suffix makes
	// pre-creation by any other user distinguishable, and
	// ensureOwnedDir rejects any dir we don't own with exact mode.
	kpDir := filepath.Join(base, fmt.Sprintf("kubeport-%d", os.Getuid()))
	if err := ensureOwnedDir(kpDir, 0o700); err != nil {
		return "", fmt.Errorf("prepare ipc dir: %w", err)
	}
	return filepath.Join(kpDir, strconv.Itoa(os.Getpid())+".sock"), nil
}

// ensureOwnedDir creates dir with the given mode, or if it already exists,
// verifies it is a real directory (not a symlink), owned by the current
// UID, with exactly the given mode. Rejects the call otherwise. Defends
// against a local attacker who has pre-created the dir with weak
// permissions under a world-writable parent like /tmp, and against
// symlink-swap attacks where the path has been replaced.
func ensureOwnedDir(dir string, mode os.FileMode) error {
	// #nosec G703 -- ensureOwnedDir is the validator: dir comes from
	// defaultIPCEndpoint (OS-constant $XDG_RUNTIME_DIR or os.TempDir()
	// with a static "kubeport-<uid>" suffix), and the follow-up Lstat
	// rejects anything not owned by us with the exact mode requested.
	if err := os.Mkdir(dir, mode); err == nil {
		// We created it; Chmod explicitly in case umask widened the mode.
		// #nosec G703 -- see above; dir just returned success from os.Mkdir.
		return os.Chmod(dir, mode)
	} else if !os.IsExist(err) {
		return err
	}

	// Use Lstat so a symlinked path is detected and rejected rather than
	// being silently followed to somewhere else on disk.
	// #nosec G703 -- see above; Lstat is the ownership/mode validator.
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	if !info.Mode().IsDir() {
		return fmt.Errorf("%s exists but is not a directory (mode=%s)", dir, info.Mode())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("unsupported fileinfo type for %s", dir)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by uid %d, expected %d", dir, st.Uid, os.Getuid())
	}
	if info.Mode().Perm() != mode {
		return fmt.Errorf("%s has mode %#o, expected %#o", dir, info.Mode().Perm(), mode)
	}
	return nil
}

// removeStaleSocket unlinks a leftover socket file at path, but only if
// it is an actual socket owned by the current UID. Refuses to unlink
// regular files, directories, or anything owned by another user.
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket (mode=%s)", path, info.Mode())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("unsupported fileinfo type for %s", path)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("stale socket at %s owned by uid %d, refusing to remove", path, st.Uid)
	}
	return os.Remove(path)
}
