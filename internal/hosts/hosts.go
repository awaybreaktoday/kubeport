// Package hosts manages entries in the OS hosts file. All entries written
// by kubeport are tagged with a magic marker so that Remove/Cleanup only
// ever touches lines this tool created.
package hosts

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
)

const marker = "# kubeport"

var pathOverride string

// Path returns the absolute path to the OS hosts file.
func Path() string {
	if pathOverride != "" {
		return pathOverride
	}
	if runtime.GOOS == "windows" {
		sysroot := os.Getenv("SystemRoot")
		if sysroot == "" {
			sysroot = `C:\Windows`
		}
		return sysroot + `\System32\drivers\etc\hosts`
	}
	return "/etc/hosts"
}

// HasEntry reports whether the hosts file already contains a line mapping
// ip → hostname. Matching is case-insensitive on the hostname, and the
// kubeport marker is not required (so pre-existing manual entries also
// count as "present").
func HasEntry(ip, hostname string) (bool, error) {
	// #nosec G304 -- Path() returns the OS-constant hosts file path
	// (/etc/hosts or C:\Windows\System32\drivers\etc\hosts). Not user input.
	data, err := os.ReadFile(Path())
	if err != nil {
		return false, fmt.Errorf("read hosts file: %w", err)
	}
	return hasEntry(data, ip, hostname), nil
}

// HasTaggedEntry reports whether the hosts file contains a kubeport-owned
// entry for hostname.
func HasTaggedEntry(hostname string) (bool, error) {
	// #nosec G304 -- Path() returns the OS-constant hosts file path
	// (/etc/hosts or C:\Windows\System32\drivers\etc\hosts). Not user input.
	data, err := os.ReadFile(Path())
	if err != nil {
		return false, fmt.Errorf("read hosts file: %w", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if isKubeportLineFor(scanner.Text(), hostname) {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("scan hosts file: %w", err)
	}
	return false, nil
}

// Add ensures `ip hostname` is present in the hosts file, tagged with the
// kubeport marker. It returns true if a matching entry already existed
// (in which case the file is not modified).
func Add(ip, hostname string) (alreadyPresent bool, err error) {
	if err := validateEntry(ip, hostname); err != nil {
		return false, err
	}

	path := Path()
	// #nosec G304 -- path is the OS-constant hosts file; not user input.
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read hosts file: %w", err)
	}

	if hasEntry(data, ip, hostname) {
		return true, nil
	}

	line := fmt.Sprintf("%s %s %s\n", ip, hostname, marker)
	// Ensure the file ends with a newline before appending.
	if len(data) > 0 && data[len(data)-1] != '\n' {
		line = "\n" + line
	}

	// #nosec G302 G304 -- the hosts file must remain 0644 by POSIX convention
	// (DNS resolvers and other tools read it world-readable); path is the
	// OS-constant hosts file, not user input.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return false, fmt.Errorf("open hosts file: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return false, fmt.Errorf("append hosts entry: %w", err)
	}
	return false, nil
}

// Remove deletes any kubeport-tagged line matching the given hostname.
// Lines not tagged with the marker are left untouched.
func Remove(hostname string) error {
	path := Path()
	// #nosec G304 -- path is the OS-constant hosts file; not user input.
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read hosts file: %w", err)
	}

	var out bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	changed := false
	for scanner.Scan() {
		line := scanner.Text()
		if isKubeportLineFor(line, hostname) {
			changed = true
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan hosts file: %w", err)
	}

	if !changed {
		return nil
	}

	// Preserve the original trailing newline behaviour.
	result := out.Bytes()
	if len(data) > 0 && data[len(data)-1] != '\n' && len(result) > 0 && result[len(result)-1] == '\n' {
		result = result[:len(result)-1]
	}

	// In-place write. On Windows, atomic rename is not usable for the
	// hosts file because DNS Client opens it without FILE_SHARE_DELETE,
	// so MoveFileEx fails with a sharing violation. An O_TRUNC write
	// succeeds against the live handle and is what every other tool
	// (including the Windows built-in editors) does here.
	// #nosec G306 -- hosts file must remain 0644 by POSIX convention.
	return os.WriteFile(path, result, 0o644)
}

func hasEntry(data []byte, ip, hostname string) bool {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") && !strings.Contains(trimmed, marker) {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		if fields[0] != ip {
			continue
		}
		for _, f := range fields[1:] {
			if strings.EqualFold(f, hostname) {
				return true
			}
		}
	}
	return false
}

func validateEntry(ip, hostname string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid hosts IP %q", ip)
	}
	if hostname == "" || strings.TrimSpace(hostname) != hostname {
		return fmt.Errorf("invalid hosts hostname %q", hostname)
	}
	if strings.ContainsAny(hostname, " \t\r\n#") {
		return fmt.Errorf("invalid hosts hostname %q", hostname)
	}
	return nil
}

func isKubeportLineFor(line, hostname string) bool {
	if !strings.Contains(line, marker) {
		return false
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	for _, f := range fields[1:] {
		if strings.EqualFold(f, hostname) {
			return true
		}
	}
	return false
}
