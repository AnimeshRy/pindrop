package tui

import (
	"errors"
	"fmt"
	"os"

	"github.com/charmbracelet/huh"
)

const (
	oauthGitHub = "github"
	oauthGoogle = "google"
)

// OAuthProviderChoice holds the selected OAuth provider.
type OAuthProviderChoice struct {
	Provider string
	Cancelled bool
}

// AskOAuthProvider prompts for GitHub or Google sign-in.
func AskOAuthProvider() (OAuthProviderChoice, error) {
	var choice string

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Sign in with").
				Options(
					huh.NewOption("GitHub", oauthGitHub),
					huh.NewOption("Google", oauthGoogle),
				).
				Value(&choice),
		),
	).WithOutput(os.Stderr)

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return OAuthProviderChoice{Cancelled: true}, nil
		}
		return OAuthProviderChoice{}, fmt.Errorf("login prompt: %w", err)
	}

	return OAuthProviderChoice{Provider: choice}, nil
}
