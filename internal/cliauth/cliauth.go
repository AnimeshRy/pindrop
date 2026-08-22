package cliauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/AnimeshRy/pindrop/internal/toolpath"
)

const credentialsSchema = 1

// ErrNotLoggedIn reports that no saved credentials exist.
var ErrNotLoggedIn = errors.New("not logged in")

// Credentials holds the refresh token and user identity persisted on disk.
//
// Access tokens are short-lived and are minted on demand by [Refresh]; they are
// never written to disk.
type Credentials struct {
	Schema       int       `json:"schema"`
	RefreshToken string    `json:"refreshToken"`
	UserID       string    `json:"userId"`
	Email        string    `json:"email"`
	Provider     Provider  `json:"provider,omitempty"`
	SavedAt      time.Time `json:"savedAt"`
}

// DisplayEmail returns the best label for the signed-in user.
func (c Credentials) DisplayEmail() string {
	if c.Email != "" {
		return c.Email
	}
	return c.UserID
}

// DisplayProvider returns a human-readable OAuth provider name.
func (c Credentials) DisplayProvider() string {
	switch c.Provider {
	case ProviderGitHub:
		return "GitHub"
	case ProviderGoogle:
		return "Google"
	default:
		if c.Provider != "" {
			return string(c.Provider)
		}
		return ""
	}
}

// Load reads saved credentials from ~/.pindrop/credentials.json.
func Load() (Credentials, error) {
	path, err := toolpath.CredentialsPath()
	if err != nil {
		return Credentials{}, err
	}

	raw, err := os.ReadFile(path) //nolint:gosec // path is under ~/.pindrop
	if err != nil {
		if os.IsNotExist(err) {
			return Credentials{}, ErrNotLoggedIn
		}
		return Credentials{}, fmt.Errorf("reading credentials: %w", err)
	}

	var creds Credentials
	if err := json.Unmarshal(raw, &creds); err != nil || creds.Schema != credentialsSchema {
		return Credentials{}, fmt.Errorf("credentials file at %s is unreadable — run: pindrop login",
			toolpath.Display(path))
	}
	if creds.RefreshToken == "" {
		return Credentials{}, fmt.Errorf("credentials file at %s is incomplete — run: pindrop login",
			toolpath.Display(path))
	}
	return creds, nil
}

// Save writes credentials atomically with mode 0600.
func Save(creds Credentials) error {
	creds.Schema = credentialsSchema
	if creds.SavedAt.IsZero() {
		creds.SavedAt = time.Now().UTC()
	}

	path, err := toolpath.CredentialsPath()
	if err != nil {
		return err
	}
	return writeJSONFile(path, creds)
}

// Clear removes saved credentials. A missing file is not an error.
func Clear() error {
	path, err := toolpath.CredentialsPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing credentials: %w", err)
	}
	return nil
}

// writeJSONFile atomically writes v as indented JSON with mode 0600.
func writeJSONFile(path string, v any) error {
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	encoded = append(encoded, '\n')
	return toolpath.WritePrivateFile(path, encoded)
}
