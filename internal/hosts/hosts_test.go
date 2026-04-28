package hosts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func useTempHostsFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write temp hosts file: %v", err)
	}

	oldPath := pathOverride
	pathOverride = path
	t.Cleanup(func() { pathOverride = oldPath })
	return path
}

func TestAddAndRemoveTaggedEntry(t *testing.T) {
	path := useTempHostsFile(t, "127.0.0.1 localhost\n")

	present, err := Add("127.0.0.1", "app.local")
	if err != nil {
		t.Fatalf("Add returned error: %v", err)
	}
	if present {
		t.Fatal("Add reported entry already present")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read hosts file: %v", err)
	}
	if got, want := string(data), "127.0.0.1 localhost\n127.0.0.1 app.local # kubeport\n"; got != want {
		t.Fatalf("hosts after Add:\n got %q\nwant %q", got, want)
	}

	if err := Remove("app.local"); err != nil {
		t.Fatalf("Remove returned error: %v", err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read hosts file after remove: %v", err)
	}
	if got, want := string(data), "127.0.0.1 localhost\n"; got != want {
		t.Fatalf("hosts after Remove:\n got %q\nwant %q", got, want)
	}
}

func TestRemoveOnlyDeletesTaggedMatchingHostname(t *testing.T) {
	path := useTempHostsFile(t, strings.Join([]string{
		"127.0.0.1 localhost",
		"127.0.0.1 app.local",
		"127.0.0.1 app.local # kubeport",
		"127.0.0.1 other.local # kubeport",
		"",
	}, "\n"))

	if err := Remove("app.local"); err != nil {
		t.Fatalf("Remove returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read hosts file: %v", err)
	}
	if got, want := string(data), strings.Join([]string{
		"127.0.0.1 localhost",
		"127.0.0.1 app.local",
		"127.0.0.1 other.local # kubeport",
		"",
	}, "\n"); got != want {
		t.Fatalf("hosts after Remove:\n got %q\nwant %q", got, want)
	}
}

func TestHasTaggedEntryDistinguishesManualEntries(t *testing.T) {
	useTempHostsFile(t, strings.Join([]string{
		"127.0.0.1 manual.local",
		"127.0.0.1 owned.local # kubeport",
		"",
	}, "\n"))

	tagged, err := HasTaggedEntry("manual.local")
	if err != nil {
		t.Fatalf("HasTaggedEntry returned error: %v", err)
	}
	if tagged {
		t.Fatal("manual.local should not be reported as tagged")
	}

	tagged, err = HasTaggedEntry("owned.local")
	if err != nil {
		t.Fatalf("HasTaggedEntry returned error: %v", err)
	}
	if !tagged {
		t.Fatal("owned.local should be reported as tagged")
	}
}

func TestAddRejectsMalformedEntry(t *testing.T) {
	path := useTempHostsFile(t, "127.0.0.1 localhost\n")

	tests := []struct {
		name     string
		ip       string
		hostname string
	}{
		{name: "bad ip", ip: "not-an-ip", hostname: "app.local"},
		{name: "space", ip: "127.0.0.1", hostname: "app local"},
		{name: "newline", ip: "127.0.0.1", hostname: "app.local\n1.2.3.4 injected.local"},
		{name: "comment marker", ip: "127.0.0.1", hostname: "app.local # comment"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Add(tt.ip, tt.hostname); err == nil {
				t.Fatal("Add returned nil error")
			}
		})
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read hosts file: %v", err)
	}
	if got, want := string(data), "127.0.0.1 localhost\n"; got != want {
		t.Fatalf("hosts file changed after rejected entries:\n got %q\nwant %q", got, want)
	}
}
