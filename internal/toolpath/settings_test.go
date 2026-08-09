package toolpath_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/toolpath"
)

func TestHomePrecedence(t *testing.T) {
	t.Setenv(toolpath.HomeEnv, "")
	base := t.TempDir()
	settingsHome := filepath.Join(base, "from-settings")
	defaultHome := filepath.Join(base, "user", ".pindrop")

	t.Setenv("HOME", filepath.Join(base, "user"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "xdg-config"))

	if err := toolpath.SaveHomeOverride(settingsHome); err != nil {
		t.Fatalf("SaveHomeOverride: %v", err)
	}
	t.Cleanup(func() { _ = toolpath.ClearSettings() })

	got, err := toolpath.Home()
	if err != nil {
		t.Fatalf("Home: %v", err)
	}
	if got != settingsHome {
		t.Errorf("Home() = %q, want settings %q", got, settingsHome)
	}

	envHome := filepath.Join(base, "from-env")
	t.Setenv(toolpath.HomeEnv, envHome)
	got, err = toolpath.Home()
	if err != nil {
		t.Fatalf("Home with env: %v", err)
	}
	if got != envHome {
		t.Errorf("Home() with PINDROP_HOME = %q, want %q", got, envHome)
	}

	t.Setenv(toolpath.HomeEnv, "")
	_ = toolpath.ClearSettings()
	got, err = toolpath.Home()
	if err != nil {
		t.Fatalf("Home after clear: %v", err)
	}
	if got != defaultHome {
		t.Errorf("Home() after clear = %q, want default %q", got, defaultHome)
	}
}

func TestSaveHomeOverridePersists(t *testing.T) {
	t.Setenv(toolpath.HomeEnv, "")
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))

	want := filepath.Join(dir, "pindrop-data")
	if err := toolpath.SaveHomeOverride(want); err != nil {
		t.Fatalf("SaveHomeOverride: %v", err)
	}
	t.Cleanup(func() { _ = toolpath.ClearSettings() })

	if !toolpath.SettingsExist() {
		t.Fatal("SettingsExist = false, want true")
	}
	if got := toolpath.LoadSettings().Home; got != want {
		t.Errorf("LoadSettings().Home = %q, want %q", got, want)
	}
}

func TestClearSettingsMissingIsOK(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := toolpath.ClearSettings(); err != nil {
		t.Fatalf("ClearSettings on missing file: %v", err)
	}
}

func TestDefaultHome(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HOME", filepath.Join(base, "user"))
	want := filepath.Join(base, "user", ".pindrop")
	got, err := toolpath.DefaultHome()
	if err != nil {
		t.Fatalf("DefaultHome: %v", err)
	}
	if got != want {
		t.Errorf("DefaultHome() = %q, want %q", got, want)
	}
}

func TestSettingsPathUnderConfigDir(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	path, err := toolpath.SettingsPath()
	if err != nil {
		t.Fatalf("SettingsPath: %v", err)
	}
	want := filepath.Join(configRoot, "pindrop", "config.json")
	if path != want {
		t.Errorf("SettingsPath() = %q, want %q", path, want)
	}
}

func init() {
	// Some platforms ignore XDG_CONFIG_HOME for UserConfigDir; tests set it
	// where supported. Ensure HOME exists for DefaultHome tests.
	if os.Getenv("HOME") == "" {
		_ = os.Setenv("HOME", os.TempDir())
	}
}
