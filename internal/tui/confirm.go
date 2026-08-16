package tui

import (
	"errors"
	"os"

	"github.com/charmbracelet/huh"
)

// Confirm presents a yes/no question on stderr.
func Confirm(question string) (bool, error) {
	confirmed := true
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(question).
				Affirmative("Yes").
				Negative("No").
				Value(&confirmed),
		),
	).WithOutput(os.Stderr)

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return false, nil
		}
		return false, err
	}
	return confirmed, nil
}
