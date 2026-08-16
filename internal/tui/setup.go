package tui

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
)

const (
	dataDirDefault = "default"
	dataDirCustom  = "custom"
)

// SetupDataDirChoice holds the result of the data directory question.
type SetupDataDirChoice struct {
	UseDefault bool   // user accepted the default ~/.pindrop
	CustomPath string // non-empty if user chose a custom path
	Cancelled  bool   // user cancelled/aborted the form
}

// SetupScannerChoice holds the result of the scanner selection question.
type SetupScannerChoice struct {
	InstallAll bool     // user chose to install all scanners
	Selected   []string // non-empty if user picked specific scanners
	Cancelled  bool     // user cancelled
}

// ScannerOption describes one scanner available for installation.
type ScannerOption struct {
	Name    string
	Version string
	Size    string // human-readable, e.g. "45 MB"
}

// InstallConfirmation holds the result of the install confirmation prompt.
type InstallConfirmation struct {
	Confirmed bool
}

// AskDataDir presents the first-run data directory question.
//
// defaultPath is the display path (e.g. "~/.pindrop"). Output goes to stderr.
func AskDataDir(defaultPath string) (SetupDataDirChoice, error) {
	var choice string
	var customPath string

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("First-time setup").
				Description("Two quick questions before we download anything."),
			huh.NewSelect[string]().
				Title(fmt.Sprintf("Store scanner binaries and scan history in %s?", defaultPath)).
				Options(
					huh.NewOption(fmt.Sprintf("Yes, use %s", defaultPath), dataDirDefault),
					huh.NewOption("Choose a different directory", dataDirCustom),
				).
				Value(&choice),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("Directory path").
				Placeholder(defaultPath).
				Value(&customPath).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return errors.New("enter a directory path")
					}
					return nil
				}),
		).WithHideFunc(func() bool { return choice != dataDirCustom }),
	).WithOutput(os.Stderr)

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return SetupDataDirChoice{Cancelled: true}, nil
		}
		return SetupDataDirChoice{}, err
	}

	switch choice {
	case dataDirDefault:
		return SetupDataDirChoice{UseDefault: true}, nil
	case dataDirCustom:
		return SetupDataDirChoice{CustomPath: strings.TrimSpace(customPath)}, nil
	default:
		return SetupDataDirChoice{Cancelled: true}, nil
	}
}

// AskScannerSelection presents the scanner selection question.
func AskScannerSelection(scanners []ScannerOption) (SetupScannerChoice, error) {
	if len(scanners) == 0 {
		return SetupScannerChoice{InstallAll: true}, nil
	}

	options := make([]huh.Option[string], len(scanners))
	for i, s := range scanners {
		label := s.Name
		if s.Version != "" {
			label = fmt.Sprintf("%s (%s)", s.Name, s.Version)
		}
		if s.Size != "" {
			label = fmt.Sprintf("%s — %s", label, s.Size)
		}
		options[i] = huh.NewOption(label, s.Name).Selected(true)
	}

	var selected []string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title(fmt.Sprintf("Install %d scanners?", len(scanners))).
				Description("Uncheck any you do not need. At least one is required.").
				Options(options...).
				Value(&selected).
				Validate(func(values []string) error {
					if len(values) == 0 {
						return errors.New("select at least one scanner")
					}
					return nil
				}),
		),
	).WithOutput(os.Stderr)

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return SetupScannerChoice{Cancelled: true}, nil
		}
		return SetupScannerChoice{}, err
	}

	if len(selected) == len(scanners) {
		return SetupScannerChoice{InstallAll: true}, nil
	}
	return SetupScannerChoice{Selected: selected}, nil
}

// AskInstallConfirm presents the pre-download confirmation after printing
// the security disclosure table to stderr.
func AskInstallConfirm(summary, details string) (InstallConfirmation, error) {
	fmt.Fprintf(os.Stderr, "%s\n\n%s\n\n", summary, details)

	confirmed, err := Confirm("Continue?")
	if err != nil {
		return InstallConfirmation{}, err
	}
	return InstallConfirmation{Confirmed: confirmed}, nil
}

// AskInstallOffer presents the JIT install offer during scan.
func AskInstallOffer(prompt string) (bool, error) {
	return Confirm(prompt)
}
