// Package opengrep adapts Opengrep to [scan.Scanner].
//
// Opengrep is Pindrop's static analysis engine: the first scanner that reads
// source code rather than manifests and configuration. It is the 2025 LGPL-2.1
// fork of Semgrep, chosen over Semgrep CE because Semgrep's rule registry moved
// to a license prohibiting its use in competing products — see
// docs/architecture/scanners.md.
//
// Invoked as a subprocess. LGPL-2.1 makes that the only safe option anyway, but
// the tool is an OCaml engine wrapped in a Nuitka-compiled Python CLI, so there
// is nothing importable from Go regardless.
//
// # Rules
//
// Opengrep ships no rules, and neither available corpus can be redistributed by a
// commercial product: opengrep-rules carries the Commons Clause, and registry
// rules carry the Semgrep Rules License. Pindrop therefore embeds its own — see
// rules/README.md and docs/decisions/0007-first-party-opengrep-rules.md.
//
// # Identity
//
// Findings are [scan.CategoryCode], which fingerprints on rule ID, file path, and
// normalized snippet. Two consequences worth knowing before changing anything
// here: a rule's id is a persisted identifier (hence --no-rewrite-rule-ids), and
// extra.lines must reach Location.Snippet or every hit of one rule in one file
// collapses into a single finding.
//
// Unlike the SCA adapters this one populates no [scan.Finding.Aliases]. That is
// deliberate rather than an oversight: Opengrep reports no second identifier for
// a match, and two SAST engines' rule IDs for "SQL injection" share no namespace
// to canonicalize onto, so cross-tool SAST dedup stays unsolved. See
// docs/decisions/0006-canonical-identity-before-dedup.md.
package opengrep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/AnimeshRy/pindrop/internal/scan"
	"github.com/AnimeshRy/pindrop/internal/toolpath"
)

// Name is the scanner identifier recorded on every finding this adapter
// produces. It is persisted, so it must not change.
const Name = "opengrep"

// defaultTimeout bounds a single Opengrep invocation.
//
// More generous than the tool's own analysis needs: the distributed binary is
// Nuitka --onefile, so the first run of a given version self-extracts its
// embedded engine into the user cache before doing any work.
const defaultTimeout = 10 * time.Minute

// installHint is shown when the binary is missing. It is user-facing text.
const installHint = "Run `pindrop setup` to install a pinned, checksum-verified copy.\n" +
	"  Install Opengrep yourself: https://github.com/opengrep/opengrep#installation"

// Opengrep's exit codes, from src/osemgrep/core/Exit_code.ml at v1.26.0 and
// verified against the binary.
//
// The inverse of the Trivy and OSV-Scanner problem: findings do *not* produce a
// non-zero exit here, because error_on_findings defaults to false and this
// adapter never passes --error. A scan with four hundred findings exits 0. So
// non-zero genuinely means something went wrong, and the only question is whether
// it went wrong enough to discard the report.
const (
	// exitOK is a completed scan.
	exitOK = 0
	// exitFindings is only produced with --error, which is never passed. Accepted
	// anyway so that adding that flag by accident degrades to a correct result
	// rather than to "the tool crashed".
	exitFindings = 1
	// exitFatal is an unhandled failure.
	exitFatal = 2
	// exitInvalidTarget means at least one source file failed to parse. The report
	// is still written and still covers every other file.
	exitInvalidTarget = 3
	// exitInvalidPattern, exitInvalidYAML, and exitMissingConfig all mean the
	// ruleset failed to load. Since the ruleset is normally ours, these are bugs
	// in Pindrop and must be loud.
	exitInvalidPattern = 4
	exitInvalidYAML    = 5
	exitMissingConfig  = 7
	// exitInvalidLanguage is a rule declaring a language the engine lacks.
	exitInvalidLanguage = 8
	// exitScanFailure is the engine failing partway through.
	exitScanFailure = 14
)

// Scanner runs the Opengrep CLI against a filesystem target.
//
// The zero value is not usable; construct one with [New]. A Scanner holds no
// mutable state after construction and is safe for concurrent use — each Scan
// extracts the bundled rules into its own temporary directory.
type Scanner struct {
	binary  string
	timeout time.Duration
	configs []string
}

// An Option configures a [Scanner].
type Option func(*Scanner)

// WithBinary overrides the Opengrep executable, which may be a bare name
// resolved through PATH or an absolute path. Defaults to "opengrep".
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

// WithRules replaces the embedded ruleset with the given --config values, each a
// rule file, a directory of rule files, or a registry shorthand.
//
// It replaces rather than extends. A user who has curated a ruleset does not want
// ours silently mixed in, and a merged set would make the finding count depend on
// a Pindrop release rather than on their configuration.
//
// Values are passed through untouched, so a registry shorthand such as
// p/security-audit works. Pindrop bundles nothing from a registry for licensing
// reasons; what a user chooses to fetch on their own machine is their decision,
// and this is the flag that lets them make it.
func WithRules(configs ...string) Option {
	return func(s *Scanner) {
		for _, c := range configs {
			if strings.TrimSpace(c) != "" {
				s.configs = append(s.configs, c)
			}
		}
	}
}

// New returns a Scanner configured by opts.
func New(opts ...Option) *Scanner {
	s := &Scanner{
		binary:  "opengrep",
		timeout: defaultTimeout,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name returns the scanner identifier.
func (s *Scanner) Name() string { return Name }

// Preflight verifies that the Opengrep binary is present. It wraps
// [scan.ErrUnavailable].
func (s *Scanner) Preflight(ctx context.Context) error {
	path, err := s.resolve()
	if err != nil {
		return &scan.UnavailableError{
			Scanner: Name,
			Reason: fmt.Sprintf("%q not found in PATH, alongside the pindrop binary, or in %s",
				s.binary, toolpath.Display(toolpath.ManagedDir())),
			Hint: installHint + "\n  Or point at an existing copy: --opengrep-binary /path/to/opengrep",
			Err:  err,
		}
	}

	// No minimum version is enforced, matching the OSV-Scanner adapter: the
	// output fields this adapter reads have been stable across the fork's life,
	// and refusing to scan over a version string is a worse failure than decoding
	// defensively.
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

// fallbackLocale is used when the inherited environment names no UTF-8 locale.
//
// C.UTF-8 rather than a language-specific value: it needs no generated locale
// data, Python accepts it on every platform including macOS, and it does not
// change any tool's message language.
const fallbackLocale = "C.UTF-8"

// utf8Env returns the parent environment, guaranteeing a UTF-8 locale.
//
// Opengrep is a Nuitka-compiled CPython program, so it derives its default text
// encoding from the locale. In an environment naming none — a cron job, a systemd
// unit, a slim container, many CI runners — that default is ASCII, and reading a
// rule file containing any non-ASCII byte then dies with UnicodeDecodeError.
//
// This is not hypothetical: Pindrop's own bundled rules use em dashes in their
// messages, so with no locale set every Opengrep finding vanishes and the scan
// reports a *partial success* — the silent-zero-findings failure that is the worst
// outcome this adapter can produce.
//
// Only set when the inherited locale is not already UTF-8, so a user who has
// chosen one keeps it. Note PYTHONUTF8 does not work here: the Nuitka build
// ignores it, which is why this sets the locale instead.
//
// Applied to the scan and not to Preflight because --version reads no rule files
// and so never trips the bug — which is exactly why this stayed invisible until a
// scan ran with a stripped environment.
func utf8Env() []string {
	env := os.Environ()

	// LC_ALL overrides LC_CTYPE, which overrides LANG. If any of them already
	// selects UTF-8, leave the environment alone.
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		value := os.Getenv(key)
		if value == "" {
			continue
		}
		if strings.Contains(strings.ToUpper(value), "UTF-8") ||
			strings.Contains(strings.ToUpper(value), "UTF8") {
			return env
		}
		// A non-UTF-8 locale is set deliberately or inherited from a service
		// manager; either way the rules cannot be read under it.
		break
	}

	return append(env, "LC_ALL="+fallbackLocale)
}

// resolve locates the Opengrep executable. See [toolpath.LookupOrigin] for the
// search order, which is shared by every adapter.
func (s *Scanner) resolve() (string, error) {
	return toolpath.Lookup(s.binary, toolpath.Env(s.binary))
}

// Scan runs Opengrep against target and converts its report into findings.
func (s *Scanner) Scan(ctx context.Context, target scan.Target) (scan.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	started := time.Now()

	configs := s.configs
	if len(configs) == 0 {
		dir, cleanup, err := extractRules()
		if err != nil {
			return scan.Result{}, err
		}
		defer cleanup()
		configs = []string{dir}
	}

	raw, err := s.run(ctx, target.Path, configs)
	if err != nil {
		return scan.Result{}, err
	}

	// A run that matched no supported language can produce an empty body, which
	// is a successful empty scan rather than a decode failure.
	findings := []scan.Finding(nil)
	if len(bytes.TrimSpace(raw)) > 0 {
		var rep report
		if err := json.Unmarshal(raw, &rep); err != nil {
			return scan.Result{}, fmt.Errorf("decoding %s report: %w", Name, err)
		}

		// Engine errors are logged, never converted into findings: "your code has
		// a problem" and "one file would not parse" are different claims, and
		// dressing the second as the first is how a security tool loses trust.
		if len(rep.Errors) > 0 {
			slog.Warn("opengrep reported engine errors",
				"count", len(rep.Errors), "first", rep.Errors[0].Message)
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

// run invokes Opengrep and returns its raw JSON report.
func (s *Scanner) run(ctx context.Context, path string, configs []string) ([]byte, error) {
	binary, err := s.resolve()
	if err != nil {
		return nil, &scan.UnavailableError{
			Scanner: Name,
			Reason:  fmt.Sprintf("%q not found", s.binary),
			Hint:    installHint,
			Err:     err,
		}
	}

	args := []string{
		"scan",
		"--json",
		// Otherwise every scan makes a network call to check for a newer release.
		"--disable-version-check",
		// Without this, Opengrep prefixes each rule's id with the path of the file
		// it came from. check_id becomes Finding.RuleID, which is a fingerprint
		// input, so the default would make every finding's identity depend on the
		// layout of the rules directory — reorganizing it would orphan every
		// triage decision. Not optional.
		"--no-rewrite-rule-ids",
		// Opengrep consults .gitignore by default and scans only tracked files. A
		// target that is not a git repository, or a working tree with uncommitted
		// code, would otherwise scan to a silent, successful zero findings — the
		// most dangerous failure mode a security tool has.
		"--no-git-ignore",
		// Disabling git-ignore also un-excludes dependency and build directories,
		// which are megabytes of third-party and generated code. These are stated
		// explicitly rather than left to Opengrep's bundled default ignore file,
		// because that file is resolved relative to the process working directory
		// rather than the target, so relying on it would make results depend on
		// where pindrop happened to be invoked from.
		"--exclude", "node_modules",
		"--exclude", "vendor",
		"--exclude", "dist",
		"--exclude", "build",
		"--exclude", ".git",
		"--exclude", "*.min.js",
	}
	for _, c := range configs {
		// Omitting --config entirely is not an option: Opengrep defaults to
		// `auto`, which downloads a ~2.4 MB third-party ruleset from semgrep.dev
		// on every scan. That is both an unwanted network dependency and a
		// licensing problem.
		args = append(args, "--config", c)
	}
	args = append(args, path)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = utf8Env()

	err = cmd.Run()
	if err == nil {
		return stdout.Bytes(), nil
	}

	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s timed out after %s: %w", Name, s.timeout, ctx.Err())
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && resultExit(exitErr.ExitCode()) {
		return stdout.Bytes(), nil
	}

	return nil, fmt.Errorf("running %s: %w%s", Name, err, stderrSuffix(&stderr))
}

// resultExit reports whether an exit code describes a report worth reading rather
// than a failure. See the exit code constants for the full contract.
func resultExit(code int) bool {
	switch code {
	case exitOK, exitFindings:
		return true
	case exitInvalidTarget:
		// One unparseable source file must not cost the whole repository its
		// static analysis. The report covers every file that did parse, and the
		// failure is already described in the report's own errors array.
		return true
	case exitFatal, exitInvalidPattern, exitInvalidYAML, exitMissingConfig,
		exitInvalidLanguage, exitScanFailure:
		return false
	default:
		// Unknown codes, and anything negative (death by signal), are failures.
		// A new exit code should surface as a loud error, not as an empty scan.
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
