package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/scan"
	"github.com/AnimeshRy/pindrop/internal/toolinstall"
)

// notFound builds the error an adapter produces when its binary is absent.
func notFound(scanner string) error {
	return &scan.UnavailableError{
		Scanner: scanner,
		Reason:  `"` + scanner + `" not found in PATH, alongside the pindrop binary, or in ~/.pindrop/bin`,
		Hint:    "Run `pindrop setup`",
		Err:     errors.New("exec: not found"),
	}
}

// broken builds the error an adapter produces when its binary is present but
// unusable — a case installing does not fix.
func broken(scanner string) error {
	return &scan.UnavailableError{
		Scanner: scanner,
		Reason:  "the binary is present but did not run",
		Err:     errors.New("exit status 1"),
	}
}

// TestUnavailableScannersDoesNotDescendThroughNodes is a regression test.
//
// UnavailableError itself unwraps to several errors, so a tree walk that recurses
// into every multi-unwrap node yields its causes and loses the node carrying the
// scanner name. That produced an empty result, so `pindrop scan` silently never
// offered to install anything.
func TestUnavailableScannersDoesNotDescendThroughNodes(t *testing.T) {
	t.Parallel()

	joined := errors.Join(notFound("trivy"), nil, notFound("osv"), broken("opengrep"))

	got := unavailableScanners(joined)
	if len(got) != 3 {
		t.Fatalf("got %d scanners, want 3: %+v", len(got), got)
	}

	var names []string
	for _, u := range got {
		names = append(names, u.Scanner)
	}
	if want := "trivy,osv,opengrep"; strings.Join(names, ",") != want {
		t.Errorf("got = %q, want %q", strings.Join(names, ","), want)
	}
}

func TestUnavailableScannersHandlesShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "nil", err: nil, want: 0},
		{name: "a single error", err: notFound("trivy"), want: 1},
		{name: "an unrelated error", err: errors.New("nope"), want: 0},
		{name: "a wrapped single error", err: wrap(notFound("trivy")), want: 1},
		{name: "a join of one", err: errors.Join(notFound("trivy")), want: 1},
		{
			name: "a join mixing related and unrelated",
			err:  errors.Join(errors.New("nope"), notFound("osv")),
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := len(unavailableScanners(tt.err)); got != tt.want {
				t.Errorf("got = %d, want %d", got, tt.want)
			}
		})
	}
}

// wrap produces a single-unwrap wrapper, as fmt.Errorf with %w does.
func wrap(err error) error { return errWrapper{err} }

type errWrapper struct{ err error }

func (e errWrapper) Error() string { return "wrapped: " + e.err.Error() }
func (e errWrapper) Unwrap() error { return e.err }

func TestMissingInstallable(t *testing.T) {
	t.Parallel()

	manifest, err := toolinstall.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	tests := []struct {
		name        string
		unavailable error
		overridden  map[string]bool
		want        []string
	}{
		{
			name:        "a missing scanner is offered",
			unavailable: errors.Join(notFound("trivy")),
			want:        []string{"trivy"},
		},
		{
			name: "the osv adapter's name is mapped onto its binary",
			// The adapter reports "osv"; the executable is "osv-scanner".
			unavailable: errors.Join(notFound("osv")),
			want:        []string{"osv-scanner"},
		},
		{
			name:        "a present-but-broken scanner is not offered",
			unavailable: errors.Join(broken("trivy")),
			want:        nil,
		},
		{
			name:        "an explicitly overridden binary is not offered",
			unavailable: errors.Join(notFound("trivy")),
			overridden:  map[string]bool{"trivy": true},
			want:        nil,
		},
		{
			name:        "several missing scanners come back in manifest order",
			unavailable: errors.Join(notFound("trivy"), notFound("opengrep")),
			want:        []string{"opengrep", "trivy"},
		},
		{
			name:        "nothing unavailable offers nothing",
			unavailable: nil,
			want:        nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := missingInstallable(manifest, tt.unavailable, tt.overridden)
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadYesNo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want bool
	}{
		{in: "\n", want: true}, // the default
		{in: "y\n", want: true},
		{in: "Y\n", want: true},
		{in: "yes\n", want: true},
		{in: "  yes  \n", want: true},
		{in: "n\n", want: false},
		{in: "no\n", want: false},
		{in: "anything else\n", want: false},
		{in: "", want: true}, // EOF with no newline reads as the default
	}

	for _, tt := range tests {
		t.Run(strings.TrimSpace(tt.in), func(t *testing.T) {
			t.Parallel()

			got, err := readYesNo(strings.NewReader(tt.in))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestOverriddenBinaries(t *testing.T) {
	t.Parallel()

	defaults := &scanOptions{
		trivyBinary: "trivy", osvBinary: "osv-scanner",
		opengrepBinary: "opengrep", trufflehogBinary: "trufflehog",
	}
	if got := defaults.overriddenBinaries(); len(got) != 0 {
		t.Errorf("defaults: got = %v, want none", got)
	}

	custom := *defaults
	custom.trivyBinary = "/opt/trivy"
	got := custom.overriddenBinaries()
	if !got["trivy"] || len(got) != 1 {
		t.Errorf("got = %v, want only trivy", got)
	}
}
