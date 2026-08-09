package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/toolinstall"
	"github.com/AnimeshRy/pindrop/internal/toolpath"
)

func TestRunUninstallRemovesRecordedScanners(t *testing.T) {
	root := t.TempDir()
	t.Setenv(toolpath.HomeEnv, root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))

	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"trivy", "osv-scanner"} {
		path := filepath.Join(binDir, name)
		if err := os.WriteFile(path, []byte("stub"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	record := toolinstall.LoadRecord(root)
	record.Set("trivy", "v0.0.0", "abc")
	record.Set("osv-scanner", "v0.0.0", "def")
	if err := record.Save(root); err != nil {
		t.Fatal(err)
	}

	opts := &uninstallOptions{yes: true}
	if err := runUninstall(context.Background(), opts); err != nil {
		t.Fatalf("runUninstall: %v", err)
	}

	for _, name := range []string{"trivy", "osv-scanner"} {
		if _, err := os.Stat(filepath.Join(binDir, name)); !os.IsNotExist(err) {
			t.Errorf("%s still present after uninstall", name)
		}
	}
	if _, err := os.Stat(toolinstall.RecordPath(root)); !os.IsNotExist(err) {
		t.Error("install record still present")
	}
}

func TestConfirmUninstallDefaultsNo(t *testing.T) {
	ok, err := confirmUninstall(strings.NewReader("\n"), io.Discard, "/tmp/bin", 2)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("empty line should default to no")
	}
}

func TestConfirmUninstallYes(t *testing.T) {
	ok, err := confirmUninstall(strings.NewReader("yes\n"), io.Discard, "/tmp/bin", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("yes should confirm")
	}
}
