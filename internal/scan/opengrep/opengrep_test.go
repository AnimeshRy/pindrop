package opengrep

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
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

// TestUTF8Env pins down the locale guarantee.
//
// Without it, Opengrep's bundled CPython defaults to ASCII, fails to read a rule
// file containing an em dash, and the scan silently reports zero code findings as
// a partial success. That is the worst failure mode this adapter has, and the
// only symptom is a missing scanner line.
func TestUTF8Env(t *testing.T) {
	tests := []struct {
		name string
		// env is set before building the child environment.
		env map[string]string
		// wantForced is whether LC_ALL should be appended by us.
		wantForced bool
	}{
		{
			name:       "no locale at all is forced to UTF-8",
			env:        map[string]string{"LC_ALL": "", "LC_CTYPE": "", "LANG": ""},
			wantForced: true,
		},
		{
			name:       "a non-UTF-8 LC_ALL is overridden",
			env:        map[string]string{"LC_ALL": "C", "LC_CTYPE": "", "LANG": ""},
			wantForced: true,
		},
		{
			name:       "an existing UTF-8 LC_ALL is respected",
			env:        map[string]string{"LC_ALL": "en_US.UTF-8", "LC_CTYPE": "", "LANG": ""},
			wantForced: false,
		},
		{
			name:       "a UTF-8 LANG is respected when LC_ALL is unset",
			env:        map[string]string{"LC_ALL": "", "LC_CTYPE": "", "LANG": "C.UTF-8"},
			wantForced: false,
		},
		{
			name:       "LC_ALL wins over a UTF-8 LANG",
			env:        map[string]string{"LC_ALL": "C", "LC_CTYPE": "", "LANG": "en_US.UTF-8"},
			wantForced: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// t.Setenv forbids t.Parallel.
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			env := utf8Env()

			// Count only the trailing override this function appends, so an
			// inherited LC_ALL is not mistaken for a forced one.
			var forced bool
			if n := len(env); n > 0 && env[n-1] == "LC_ALL="+fallbackLocale {
				forced = true
			}

			if forced != tt.wantForced {
				t.Errorf("forced LC_ALL: got = %t, want %t", forced, tt.wantForced)
			}
		})
	}
}

// TestArgs pins the three flags that are not optional and the one that must
// never appear. Each was previously guarded only by a comment.
func TestArgs(t *testing.T) {
	t.Parallel()

	got := New().args("/tmp/target", []string{"/rules"}, scan.Excludes{})

	if got[0] != "scan" {
		t.Errorf("subcommand = %q, want %q", got[0], "scan")
	}

	// Omitting --config does not mean "no rules"; it means `auto`, which
	// downloads ~2.4 MB of Semgrep-licensed rules from semgrep.dev on every
	// scan. That is both an unwanted network dependency and a licensing problem.
	if i := slices.Index(got, "--config"); i < 0 || got[i+1] != "/rules" {
		t.Errorf("--config /rules missing from %q", got)
	}

	// check_id becomes Finding.RuleID, which is a fingerprint input. Without
	// this flag Opengrep prefixes each rule id with the path of the file it
	// came from, so reorganizing the rules directory would orphan every triage
	// decision.
	if !slices.Contains(got, "--no-rewrite-rule-ids") {
		t.Errorf("--no-rewrite-rule-ids missing from %q", got)
	}

	// Without this, Opengrep scans only git-tracked files, so an untracked
	// target scans to a silent, successful zero findings — the most dangerous
	// failure mode a security tool has.
	if !slices.Contains(got, "--no-git-ignore") {
		t.Errorf("--no-git-ignore missing from %q", got)
	}

	// Findings must exit 0, so that a non-zero exit unambiguously means the
	// tool broke.
	if slices.Contains(got, "--error") {
		t.Errorf("--error must never be passed: %q", got)
	}

	if !slices.Contains(got, "--disable-version-check") {
		t.Errorf("--disable-version-check missing from %q", got)
	}
	if got[len(got)-1] != "/tmp/target" {
		t.Errorf("target is not the final argument: %q", got)
	}
}

// TestArgsExcludeDirsHaveTrailingSlash is the .env guard at the adapter level.
//
// Opengrep uses gitignore syntax, in which a bare "env" matches a file named
// env as well as the directory — and an entry for the virtualenv directory
// must never cause a .env credential file to be skipped.
func TestArgsExcludeDirsHaveTrailingSlash(t *testing.T) {
	t.Parallel()

	excludes := scan.Excludes{Dirs: []string{"env", "node_modules"}, Files: []string{"*.min.js"}}
	got := New().args("/t", nil, excludes)

	for _, want := range []string{"env/", "node_modules/"} {
		if !slices.Contains(got, want) {
			t.Errorf("%q missing from %q", want, got)
		}
	}
	for _, unwanted := range []string{"env", "node_modules"} {
		if slices.Contains(got, unwanted) {
			t.Errorf("bare %q would match a file under gitignore syntax: %q", unwanted, got)
		}
	}
	// File patterns are passed through unchanged.
	if !slices.Contains(got, "*.min.js") {
		t.Errorf("*.min.js missing from %q", got)
	}
}

// TestArgsMultipleConfigs covers a rules directory split across several paths.
func TestArgsMultipleConfigs(t *testing.T) {
	t.Parallel()

	got := New().args("/t", []string{"/a", "/b"}, scan.Excludes{})

	var configs []string
	for i := 0; i < len(got)-1; i++ {
		if got[i] == "--config" {
			configs = append(configs, got[i+1])
		}
	}
	if !slices.Equal(configs, []string{"/a", "/b"}) {
		t.Errorf("configs = %q, want [/a /b]", configs)
	}
}
