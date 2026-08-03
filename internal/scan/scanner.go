package scan

import (
	"context"
	"errors"
	"fmt"
)

// ErrUnavailable is returned by [Scanner.Preflight] when a scanner cannot run
// because its backing tool is missing or unusable. Callers use
// [errors.Is](err, ErrUnavailable) to distinguish "not installed" from
// "installed but broken", and should surface installation guidance rather than
// a raw exec error.
var ErrUnavailable = errors.New("scanner unavailable")

// A Scanner runs one external analysis tool and normalizes its output into
// Pindrop's [Finding] model.
//
// Implementations wrap a tool rather than reimplementing it. Most shell out to
// a CLI binary; see the trivy subpackage for the reference implementation and
// docs/decisions/0002-trivy-subprocess.md for why subprocess is preferred over
// library embedding.
//
// Implementations must be safe for concurrent use by multiple goroutines, so
// that Run can fan scanners out in parallel.
type Scanner interface {
	// Name returns the stable identifier recorded on every finding this
	// scanner produces. It must be lowercase and constant across versions,
	// since it appears in stored data.
	Name() string

	// Preflight reports whether the scanner can run. It wraps
	// [ErrUnavailable] when the backing tool is missing or too old, and the
	// error text is shown directly to the user, so it should say how to
	// install or upgrade.
	Preflight(ctx context.Context) error

	// Scan analyzes target and returns normalized findings.
	//
	// Every returned finding has its Scanner field set to Name() and its
	// Fingerprint populated. A scan that finds nothing returns an empty
	// Findings slice and a nil error; a non-nil error means the tool itself
	// failed.
	Scan(ctx context.Context, target Target) (Result, error)
}

// UnavailableError reports that a scanner's backing tool cannot be used, and
// carries the guidance shown to the user.
type UnavailableError struct {
	Scanner string
	// Reason states what is wrong, in lowercase without trailing punctuation.
	Reason string
	// Hint is an actionable remedy, such as an install command.
	Hint string
	// Err is the underlying cause, if any.
	Err error
}

// Error implements the error interface.
func (e *UnavailableError) Error() string {
	msg := fmt.Sprintf("%s is unavailable: %s", e.Scanner, e.Reason)
	if e.Hint != "" {
		msg += "\n  " + e.Hint
	}
	return msg
}

// Unwrap allows [errors.Is] to match both [ErrUnavailable] and any wrapped
// cause.
func (e *UnavailableError) Unwrap() []error {
	if e.Err == nil {
		return []error{ErrUnavailable}
	}
	return []error{ErrUnavailable, e.Err}
}
