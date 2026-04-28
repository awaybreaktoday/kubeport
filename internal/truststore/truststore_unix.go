//go:build !windows && !darwin

package truststore

import (
	"crypto/x509"
	"fmt"
)

// Install is a no-op on Unix platforms without a native implementation. The
// caller should import the printed CA cert path into the OS / browser trust
// store manually.
func Install(cert *x509.Certificate, certPath string) error {
	fmt.Printf("[truststore] non-Windows platform: import %s into your OS trust store manually\n", certPath)
	return nil
}

func IsInstalled(cert *x509.Certificate) bool { return false }

func Uninstall(cert *x509.Certificate) error { return nil }
