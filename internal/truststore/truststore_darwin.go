//go:build darwin

package truststore

import (
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Install adds the CA certificate to the current user's login keychain as a
// trusted root. macOS may prompt for the user's password or Touch ID when the
// trust setting is changed.
func Install(cert *x509.Certificate, certPath string) error {
	if IsInstalled(cert) {
		return nil
	}

	cmd := exec.Command(
		"security",
		"add-trusted-cert",
		"-r", "trustRoot",
		"-k", loginKeychainPath(),
		certPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("security add-trusted-cert: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// IsInstalled reports whether the CA certificate is already present in the
// current user's login keychain, matched by SHA-1 thumbprint.
func IsInstalled(cert *x509.Certificate) bool {
	thumb := strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(cert.Raw)))
	cmd := exec.Command("security", "find-certificate", "-Z", "-c", cert.Subject.CommonName, loginKeychainPath())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToUpper(string(out)), thumb)
}

// Uninstall removes the CA certificate from the current user's login keychain
// by SHA-1 thumbprint. Not called automatically; the CA is designed to persist
// across runs so subsequent launches do not reinstall trust.
func Uninstall(cert *x509.Certificate) error {
	thumb := strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(cert.Raw)))
	cmd := exec.Command("security", "delete-certificate", "-Z", thumb, loginKeychainPath())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("security delete-certificate: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func loginKeychainPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "login.keychain-db"
	}
	return filepath.Join(home, "Library", "Keychains", "login.keychain-db")
}
