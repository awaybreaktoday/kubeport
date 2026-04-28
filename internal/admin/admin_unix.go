//go:build !windows

package admin

import "os"

// IsElevated reports whether the current process is effectively root.
func IsElevated() bool {
	return os.Geteuid() == 0
}
