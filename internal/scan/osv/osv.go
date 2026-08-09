// Package osv adapts Google's OSV-Scanner to [scan.Scanner].
//
// It is Pindrop's second SCA opinion. OSV-Scanner draws on osv.dev rather than
// Trivy's database, so where the two agree that agreement is a confidence signal,
// and where they disagree the union is better coverage than either alone. It is
// also the only freely available source of reachability analysis: --call-analysis
// is enabled by default for Go and narrows "this vulnerable package is present"
// to "this vulnerable function is actually called".
//
// Invoked as a subprocess, for the reasons in
// docs/decisions/0002-trivy-subprocess.md. Importing the library would pull in
// its extractor tree, deps.dev clients, and a SQLite driver.
//
// The two tools disagree about how to spell everything that matters for identity
// — advisory IDs, ecosystem names, version strings, and whether paths are
// absolute. Reconciling that is what
// docs/decisions/0006-canonical-identity-before-dedup.md exists for, and it is
// why this adapter must populate [scan.Finding.Aliases].
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/AnimeshRy/pindrop/internal/scan"
	"github.com/AnimeshRy/pindrop/internal/toolpath"
)

// Name is the scanner identifier recorded on every finding this adapter
// produces. It is persisted, so it must not change.
const Name = "osv"

// defaultTimeout bounds a single OSV-Scanner invocation. Call analysis compiles
// Go packages, so this is more generous than a pure lockfile parse would need.
const defaultTimeout = 10 * time.Minute

// installHint is shown when the binary is missing. It is user-facing text.
const installHint = "Run `pindrop setup` to install a pinned, checksum-verified copy.\n" +
	"  Install OSV-Scanner yourself: https://google.github.io/osv-scanner/installation/"

// OSV-Scanner's exit codes, from its documented contract and verified against
// v2.4.0.
//
// This is the same trap as Trivy's --exit-code, except OSV-Scanner has no flag
// to flatten it: a scan that finds vulnerabilities exits non-zero, so treating
// any non-zero exit as failure would report every vulnerable repository as a
// broken tool.
const (
	// exitNoFindings means packages were scanned and nothing was found.
	exitNoFindings = 0
	// exitMaxFindings is the top of the range reserved for result-related exits.
	// Anything in 1..126 means "packages were scanned and something was found".
	exitMaxFindings = 126
	// exitGeneralError is a genuine failure.
	exitGeneralError = 127
	// exitNoPackages means no scannable manifests were found. Not an error: a
	// repository with no lockfiles is a legitimate scan with no findings.
	exitNoPackages = 128
)

// Scanner runs the OSV-Scanner CLI against a filesystem target.
//
// The zero value is not usable; construct one with [New]. A Scanner holds no
// mutable state after construction and is safe for concurrent use.
type Scanner struct {
	binary       string
	timeout      time.Duration
	callAnalysis bool
	offline      bool
}

// An Option configures a [Scanner].
type Option func(*Scanner)

// WithBinary overrides the OSV-Scanner executable, which may be a bare name
// resolved through PATH or an absolute path. Defaults to "osv-scanner".
func WithBinary(path string) Option {
	return func(s *Scanner) {
		if path != "" {
			s.binary = path
		}
	}
}

// WithTimeout bounds a single scan. Non-positive values leave the default.
func WithTimeout(d time.Duration) Option {
	return func(s *Scanner) {
		if d > 0 {
			s.timeout = d
		}
	}
}

// WithCallAnalysis enables reachability analysis, which narrows findings to
// vulnerabilities whose affected function the code actually calls.
//
// Off by default here even though OSV-Scanner enables it for Go on its own,
// because it compiles the packages under analysis: that needs a working
// toolchain for the target language and turns a second-long lockfile parse into
// a build. Phase 6 will make this a first-class prioritization input.
func WithCallAnalysis(enabled bool) Option {
	return func(s *Scanner) { s.callAnalysis = enabled }
}

// WithOffline restricts OSV-Scanner to locally cached advisory databases, making
// the scan hermetic. The caller is responsible for having populated the cache.
func WithOffline(enabled bool) Option {
	return func(s *Scanner) { s.offline = enabled }
}

// New returns a Scanner configured by opts.
func New(opts ...Option) *Scanner {
	s := &Scanner{
		binary:  "osv-scanner",
		timeout: defaultTimeout,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name returns the scanner identifier.
func (s *Scanner) Name() string { return Name }

// Preflight verifies that the OSV-Scanner binary is present. It wraps
// [scan.ErrUnavailable].
func (s *Scanner) Preflight(ctx context.Context) error {
	path, err := s.resolve()
	if err != nil {
		return &scan.UnavailableError{
			Scanner: Name,
			Reason: fmt.Sprintf("%q not found in PATH, alongside the pindrop binary, or in %s",
				s.binary, toolpath.Display(toolpath.ManagedDir())),
			Hint: installHint + "\n  Or point at an existing copy: --osv-binary /path/to/osv-scanner",
			Err:  err,
		}
	}

	// No minimum version is enforced. The JSON layout this adapter reads has been
	// stable across v2, and blocking a scan over an unparseable version string is
	// a worse failure than decoding defensively.
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return &scan.UnavailableError{
			Scanner: Name,
			Reason:  "the binary is present but did not run",
			Hint:    fmt.Sprintf("Check that it works: %s --version", path),
			Err:     err,
		}
	}

	return nil
}

// resolve locates the OSV-Scanner executable. See [toolpath.LookupOrigin] for the
// search order, which is shared by every adapter.
func (s *Scanner) resolve() (string, error) {
	return toolpath.Lookup(s.binary, toolpath.Env(s.binary))
}

// Scan runs OSV-Scanner against target and converts its report into findings.
func (s *Scanner) Scan(ctx context.Context, target scan.Target) (scan.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	started := time.Now()

	raw, err := s.run(ctx, target.Path, target.Excludes)
	if err != nil {
		return scan.Result{}, err
	}

	// A scan that found no manifests produces no report body at all, which is a
	// successful empty scan rather than a decode failure.
	findings := []scan.Finding(nil)
	if len(bytes.TrimSpace(raw)) > 0 {
		var rep report
		if err := json.Unmarshal(raw, &rep); err != nil {
			return scan.Result{}, fmt.Errorf("decoding %s report: %w", Name, err)
		}
		findings = convert(rep, target.Path)
	}

	return scan.Result{
		Scanner:   Name,
		Target:    target,
		StartedAt: started,
		Duration:  time.Since(started),
		Findings:  findings,
	}, nil
}

// args builds the OSV-Scanner command line.
//
// Split out from [Scanner.run] so that the invariants below are enforced by
// tests rather than asserted in comments.
func (s *Scanner) args(path string, excludes scan.Excludes) []string {
	args := []string{
		"scan", "source",
		"--format", "json",
		"--recursive",
		// Progress and walk statistics go to stderr at the default level and are
		// noise in a wrapped invocation. The scan display also renders to
		// stderr, and a child writing there would shred every frame.
		"--verbosity", "error",
	}
	if !s.callAnalysis {
		args = append(args, "--no-call-analysis", "all")
	}
	if s.offline {
		args = append(args, "--offline-vulnerabilities")
	}
	// Directories only, and the flag carries an experimental- prefix upstream,
	// so this is a speed optimization rather than the correctness mechanism —
	// scan.Run filters what comes back regardless. TestArgs pins the flag name
	// so an upstream rename fails a test instead of a user's scan.
	args = append(args, excludes.OSVArgs()...)
	return append(args, path)
}

// run invokes OSV-Scanner and returns its raw JSON report.
func (s *Scanner) run(ctx context.Context, path string, excludes scan.Excludes) ([]byte, error) {
	binary, err := s.resolve()
	if err != nil {
		return nil, &scan.UnavailableError{
			Scanner: Name,
			Reason:  fmt.Sprintf("%q not found", s.binary),
			Hint:    installHint,
			Err:     err,
		}
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, s.args(path, excludes)...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err == nil {
		return stdout.Bytes(), nil
	}

	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s timed out after %s: %w", Name, s.timeout, ctx.Err())
	}

	// Findings are reported through the exit code, so a non-zero exit has to be
	// classified rather than treated as failure.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && resultExit(exitErr.ExitCode()) {
		return stdout.Bytes(), nil
	}

	return nil, fmt.Errorf("running %s: %w%s", Name, err, stderrSuffix(&stderr))
}

// resultExit reports whether an exit code describes a completed scan rather than
// a failure. See the exit code constants for the full contract.
func resultExit(code int) bool {
	switch {
	case code == exitNoFindings, code == exitNoPackages:
		return true
	case code > exitNoFindings && code <= exitMaxFindings:
		return true
	case code == exitGeneralError:
		return false
	default:
		// 129-255 are reserved for non-result errors, as is anything negative
		// (which signals death by signal).
		return false
	}
}

// stderrSuffix formats captured stderr for inclusion in an error message,
// trimming it so a runaway tool cannot flood the terminal.
func stderrSuffix(stderr *bytes.Buffer) string {
	const maxLen = 2000

	out := strings.TrimSpace(stderr.String())
	if out == "" {
		return ""
	}
	if len(out) > maxLen {
		out = "..." + out[len(out)-maxLen:]
	}
	return ": " + out
}
