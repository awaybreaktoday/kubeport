//go:build windows

package truststore

import (
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// Install adds the CA certificate to the current user's "Trusted Root
// Certification Authorities" store. Chrome and Edge both read the
// CurrentUser\Root store, so a per-user install is sufficient for
// everyday browsing — and crucially requires no administrator
// privileges. It is a no-op if a certificate with the same SHA-1
// thumbprint is already installed for this user.
func Install(cert *x509.Certificate, certPath string) error {
	if IsInstalled(cert) {
		return nil
	}

	cmd := exec.Command("certutil.exe", "-user", "-addstore", "-f", "Root", certPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil -user -addstore: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// IsInstalled reports whether the CA certificate is already present in
// the current user's Root store (matched by SHA-1 thumbprint).
func IsInstalled(cert *x509.Certificate) bool {
	thumb := fmt.Sprintf("%x", sha1.Sum(cert.Raw))
	cmd := exec.Command("certutil.exe", "-user", "-store", "Root", thumb)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run() == nil
}

// Uninstall removes the CA certificate from the current user's Root store
// by SHA-1 thumbprint. Not called automatically — the CA is designed to
// persist across runs so subsequent launches do not reinstall trust.
func Uninstall(cert *x509.Certificate) error {
	thumb := fmt.Sprintf("%x", sha1.Sum(cert.Raw))
	cmd := exec.Command("certutil.exe", "-user", "-delstore", "Root", thumb)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil -user -delstore: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
