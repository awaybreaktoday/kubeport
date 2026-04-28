// Package ca manages a per-user local certificate authority used to issue
// short-lived leaf certificates for the local HTTPS reverse proxy.
//
// The CA is created on first run and persisted under the user's config
// directory (e.g. %LOCALAPPDATA%\kubeport on Windows). Installing the CA
// into the OS trust store is handled by the truststore package.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"crypto/tls"
)

const (
	caCertFile = "kubeport-ca.crt"
	caKeyFile  = "kubeport-ca.key"

	caValidity   = 10 * 365 * 24 * time.Hour
	leafValidity = 30 * 24 * time.Hour
)

// CA is a loaded local certificate authority.
type CA struct {
	Cert     *x509.Certificate
	CertPEM  []byte
	Key      *ecdsa.PrivateKey
	CertPath string
	KeyPath  string
}

// Dir returns the directory where the local CA material is stored.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config dir: %w", err)
	}
	return filepath.Join(base, "kubeport"), nil
}

// LoadOrCreate loads an existing CA from disk or generates a new one.
func LoadOrCreate() (*CA, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ca dir: %w", err)
	}

	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return load(certPath, keyPath)
		}
	}

	return create(certPath, keyPath)
}

func load(certPath, keyPath string) (*CA, error) {
	// #nosec G304 -- certPath / keyPath come from ca.Dir() which is rooted
	// at os.UserConfigDir() with a static "kubeport" suffix; not user input.
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("invalid ca cert pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}

	// #nosec G304 -- see certPath note above.
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ca key: %w", err)
	}
	kblock, _ := pem.Decode(keyPEM)
	if kblock == nil {
		return nil, errors.New("invalid ca key pem")
	}
	key, err := x509.ParseECPrivateKey(kblock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}

	return &CA{
		Cert:     cert,
		CertPEM:  certPEM,
		Key:      key,
		CertPath: certPath,
		KeyPath:  keyPath,
	}, nil
}

func create(certPath, keyPath string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "kubeport local CA",
			Organization: []string{"kubeport"},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("sign ca cert: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse new ca cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal ca key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// The CA cert is public data, but only kubeport (same user) needs to
	// read it from this location — certutil reads it as a subprocess, the
	// OS trust store owns its own copy after install. 0600 is sufficient
	// and avoids a gosec G306 finding.
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write ca cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write ca key: %w", err)
	}

	return &CA{
		Cert:     cert,
		CertPEM:  certPEM,
		Key:      key,
		CertPath: certPath,
		KeyPath:  keyPath,
	}, nil
}

// IssueLeaf signs a short-lived leaf certificate for the given hostnames.
// Any entries that parse as IP addresses are added as IP SANs; everything
// else is added as a DNS SAN.
func (c *CA) IssueLeaf(hostnames []string) (tls.Certificate, error) {
	var empty tls.Certificate

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return empty, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return empty, fmt.Errorf("generate serial: %w", err)
	}

	var dnsNames []string
	var ipSANs []net.IP
	for _, h := range hostnames {
		if ip := net.ParseIP(h); ip != nil {
			ipSANs = append(ipSANs, ip)
			continue
		}
		dnsNames = append(dnsNames, h)
	}

	commonName := "localhost"
	if len(dnsNames) > 0 {
		commonName = dnsNames[0]
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"kubeport"},
		},
		NotBefore:   time.Now().Add(-5 * time.Minute),
		NotAfter:    time.Now().Add(leafValidity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: ipSANs,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &leafKey.PublicKey, c.Key)
	if err != nil {
		return empty, fmt.Errorf("sign leaf cert: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der, c.Cert.Raw},
		PrivateKey:  leafKey,
		Leaf:        mustParse(der),
	}, nil
}

func mustParse(der []byte) *x509.Certificate {
	c, _ := x509.ParseCertificate(der)
	return c
}
