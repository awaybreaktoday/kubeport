//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
)

// elevateBootstrap re-invokes self under sudo with the __bootstrap
// subcommand. sudo will prompt for a password if needed.
func elevateBootstrap(bootstrapArgs []string) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return -1, fmt.Errorf("locate self: %w", err)
	}
	full := append([]string{"-E", exe, "__bootstrap"}, bootstrapArgs...)
	// #nosec G204 -- sudo self-elevation is the documented feature on POSIX;
	// `exe` is our own os.Executable() path and bootstrapArgs are constructed
	// internally (hostname / IP validated upstream), not user-controlled input.
	cmd := exec.Command("sudo", full...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return -1, err
	}
	return 0, nil
}
