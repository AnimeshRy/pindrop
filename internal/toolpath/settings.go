package toolpath

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	settingsDirName  = "pindrop"
	settingsFileName = "config.json"
	settingsSchema   = 1
)

// Settings holds machine-global preferences persisted outside PINDROP_HOME.
//
// The file lives under the OS config directory so a custom PINDROP_HOME can
// still be discovered on the next run without requiring a shell export.
type Settings struct {
	Schema int    `json:"schema"`
	Home   string `json:"home,omitempty"`
}

// SettingsPath returns the path to the persisted settings file.
func SettingsPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locating the config directory: %w", err)
	}
	return filepath.Join(configDir, settingsDirName, settingsFileName), nil
}

// SettingsExist reports whether a settings file is present on disk.
func SettingsExist() bool {
	path, err := SettingsPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

// LoadSettings reads persisted settings.
//
// A missing, unreadable, or unrecognized file yields a zero value rather than
// an error, matching [toolinstall.LoadRecord].
func LoadSettings() Settings {
	path, err := SettingsPath()
	if err != nil {
		return Settings{}
	}

	// #nosec G304 -- path is under UserConfigDir with a constant file name.
	raw, err := os.ReadFile(path)
	if err != nil {
		return Settings{}
	}

	var s Settings
	if err := json.Unmarshal(raw, &s); err != nil || s.Schema != settingsSchema {
		return Settings{}
	}
	return s
}

// SaveHomeOverride records home as the directory for PINDROP_HOME-equivalent state.
func SaveHomeOverride(home string) error {
	abs, err := filepath.Abs(home)
	if err != nil {
		return fmt.Errorf("resolving home directory %q: %w", home, err)
	}

	path, err := SettingsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}

	s := Settings{Schema: settingsSchema, Home: abs}
	encoded, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding settings: %w", err)
	}
	encoded = append(encoded, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), settingsFileName+".*")
	if err != nil {
		return fmt.Errorf("creating a temporary settings file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing settings: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing settings: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("setting permissions on settings: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("saving settings: %w", err)
	}
	return nil
}

// ClearSettings removes the persisted settings file.
//
// Missing file is not an error.
func ClearSettings() error {
	path, err := SettingsPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing settings: %w", err)
	}
	return nil
}

// DefaultHome returns ~/.pindrop without reading settings or the environment.
func DefaultHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating your home directory: %w", err)
	}
	return filepath.Join(home, dirName), nil
}

const (
	credentialsFileName = "credentials.json"
	syncStateFileName   = "sync-state.json"
)

// CredentialsPath returns ~/.pindrop/credentials.json for CLI auth tokens.
func CredentialsPath() (string, error) {
	home, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, credentialsFileName), nil
}

// SyncStatePath returns ~/.pindrop/sync-state.json for sync checkpoints.
func SyncStatePath() (string, error) {
	home, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, syncStateFileName), nil
}

// WritePrivateFile writes data to path atomically with mode 0600.
func WritePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("creating a temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("setting permissions on %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("saving %s: %w", path, err)
	}
	return nil
}
