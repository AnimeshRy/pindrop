package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/toolinstall"
	"github.com/AnimeshRy/pindrop/internal/toolpath"
)

func TestSaveSetupHomeExpandsTilde(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HOME", filepath.Join(base, "user"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "config"))
	t.Setenv(toolpath.HomeEnv, "")

	if err := saveSetupHome("~/custom-pindrop"); err != nil {
		t.Fatalf("saveSetupHome: %v", err)
	}
	t.Cleanup(func() { _ = toolpath.ClearSettings() })

	want := filepath.Join(base, "user", "custom-pindrop")
	got, err := toolpath.Home()
	if err != nil {
		t.Fatalf("Home: %v", err)
	}
	if got != want {
		t.Errorf("Home() = %q, want %q", got, want)
	}
}

func TestMaybeAskSetupQuestionsSkipsWithSettings(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := toolpath.SaveHomeOverride(t.TempDir()); err != nil {
		t.Fatalf("SaveHomeOverride: %v", err)
	}
	t.Cleanup(func() { _ = toolpath.ClearSettings() })

	opts := &setupOptions{}
	manifest, err := toolinstall.Load()
	if err != nil {
		t.Fatalf("Load manifest: %v", err)
	}
	if err := maybeAskSetupQuestions(opts, manifest); err != nil {
		t.Fatalf("maybeAskSetupQuestions: %v", err)
	}
}

func TestReadLine(t *testing.T) {
	got, err := readLine(strings.NewReader("hello\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello" {
		t.Errorf("readLine = %q, want hello", got)
	}
}
