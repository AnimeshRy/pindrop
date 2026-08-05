package opengrep

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// The adapter must satisfy the scanner contract at compile time.
var _ scan.Scanner = (*Scanner)(nil)

func TestNewDefaults(t *testing.T) {
	t.Parallel()

	s := New()

	if got, want := s.binary, "opengrep"; got != want {
		t.Errorf("binary = %q, want %q", got, want)
	}
	if got, want := s.timeout, defaultTimeout; got != want {
		t.Errorf("timeout = %s, want %s", got, want)
	}
	if len(s.configs) != 0 {
		t.Errorf("configs = %v, want empty so the bundled ruleset is used", s.configs)
	}
	if got, want := s.Name(), Name; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestOptionsIgnoreZeroValues(t *testing.T) {
	t.Parallel()

	s := New(
		WithBinary(""),
		WithTimeout(0),
		WithTimeout(-time.Second),
		WithRules("", "   "),
	)

	if got, want := s.binary, "opengrep"; got != want {
		t.Errorf("binary = %q, want the default %q", got, want)
	}
	if got, want := s.timeout, defaultTimeout; got != want {
		t.Errorf("timeout = %s, want the default %s", got, want)
	}
	// A blank --opengrep-rules must not count as "the user supplied rules", or the
	// bundled set would be skipped and Opengrep would fall back to its own `auto`
	// default, which downloads third-party rules from semgrep.dev.
	if len(s.configs) != 0 {
		t.Errorf("configs = %v, want empty", s.configs)
	}
}

func TestOptionsApply(t *testing.T) {
	t.Parallel()

	s := New(
		WithBinary("/opt/opengrep"),
		WithTimeout(90*time.Second),
		WithRules("/etc/rules", "p/security-audit"),
	)

	if got, want := s.binary, "/opt/opengrep"; got != want {
		t.Errorf("binary = %q, want %q", got, want)
	}
	if got, want := s.timeout, 90*time.Second; got != want {
		t.Errorf("timeout = %s, want %s", got, want)
	}
	if got, want := strings.Join(s.configs, ","), "/etc/rules,p/security-audit"; got != want {
		t.Errorf("configs = %q, want %q", got, want)
	}
}

func TestPreflightMissingBinary(t *testing.T) {
	t.Parallel()

	err := New(WithBinary("pindrop-opengrep-does-not-exist")).Preflight(context.Background())
	if err == nil {
		t.Fatal("Preflight() = nil, want an error")
	}
	if !errors.Is(err, scan.ErrUnavailable) {
		t.Errorf("error does not wrap scan.ErrUnavailable: %v", err)
	}

	// The message is shown verbatim to a user who is not a security engineer, so
	// it has to say how to fix the problem.
	msg := err.Error()
	for _, want := range []string{"Install Opengrep", "--opengrep-binary"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q:\n%s", want, msg)
		}
	}
}

func TestResultExit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		code int
		want bool
	}{
		{"ok", exitOK, true},
		{"findings", exitFindings, true},
		// One file that will not parse must not cost the repository its analysis.
		{"unparseable target", exitInvalidTarget, true},
		{"fatal", exitFatal, false},
		// These mean the ruleset failed to load. It is normally ours, so silence
		// here would ship an adapter that reports nothing and looks healthy.
		{"invalid pattern", exitInvalidPattern, false},
		{"invalid yaml", exitInvalidYAML, false},
		{"missing config", exitMissingConfig, false},
		{"invalid language", exitInvalidLanguage, false},
		{"scan failure", exitScanFailure, false},
		{"unknown code", 42, false},
		{"killed by signal", -1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := resultExit(tt.code); got != tt.want {
				t.Errorf("resultExit(%d) = %t, want %t", tt.code, got, tt.want)
			}
		})
	}
}

func TestExtractRules(t *testing.T) {
	t.Parallel()

	dir, cleanup, err := extractRules()
	if err != nil {
		t.Fatalf("extractRules() error = %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading extracted rules: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no rules extracted; --config would point at an empty directory")
	}

	for _, e := range entries {
		if ext := filepath.Ext(e.Name()); ext != ".yaml" && ext != ".yml" {
			t.Errorf("extracted %q, want only rule files", e.Name())
		}
	}

	// Every embedded rule must land on disk. A rule that is embedded but not
	// written is a rule that silently stops running.
	embedded, err := bundledRules.ReadDir(rulesRoot)
	if err != nil {
		t.Fatalf("reading embedded rules: %v", err)
	}
	var wantCount int
	for _, e := range embedded {
		if ext := filepath.Ext(e.Name()); ext == ".yaml" || ext == ".yml" {
			wantCount++
		}
	}
	if got := len(entries); got != wantCount {
		t.Errorf("extracted %d rules, want %d", got, wantCount)
	}

	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("cleanup left %s behind (stat error = %v)", dir, err)
	}
}

// TestExtractRulesIsolated guards the concurrency claim in the Scanner doc
// comment: scan.Run fans scanners out in parallel, so two extractions sharing a
// directory would be a filesystem race.
func TestExtractRulesIsolated(t *testing.T) {
	t.Parallel()

	a, cleanupA, err := extractRules()
	if err != nil {
		t.Fatalf("extractRules() error = %v", err)
	}
	defer cleanupA()

	b, cleanupB, err := extractRules()
	if err != nil {
		t.Fatalf("extractRules() error = %v", err)
	}
	defer cleanupB()

	if a == b {
		t.Errorf("both extractions used %s, want separate directories", a)
	}
}
