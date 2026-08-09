// Package trivy adapts the Trivy vulnerability scanner to [scan.Scanner].
//
// Trivy is invoked as a subprocess rather than imported as a Go library. The
// short version: Trivy downloads its vulnerability database from a remote
// registry at runtime no matter how it is invoked, so embedding the library
// buys no self-contained binary while costing a ~500-module dependency graph
// and an API its maintainers explicitly decline to support. The long version is
// in docs/decisions/0002-trivy-subprocess.md.
package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/AnimeshRy/pindrop/internal/scan"
	"github.com/AnimeshRy/pindrop/internal/toolpath"
)

// Name is the scanner identifier recorded on every finding this adapter
// produces. It is persisted, so it must not change.
const Name = "trivy"

// minVersion is the oldest Trivy release whose JSON report layout this adapter
// is known to parse. Trivy's schema is versioned and moves slowly, but its
// field population rules have tightened over time.
const minVersion = "0.50.0"

// defaultTimeout bounds a single Trivy invocation. Large monorepos with many
// lockfiles can legitimately take minutes, especially on a cold database.
const defaultTimeout = 10 * time.Minute

// installHint is shown when the binary is missing. It is user-facing text.
const installHint = "Run `pindrop setup` to install a pinned, checksum-verified copy.\n" +
	"  Install Trivy yourself: https://trivy.dev/latest/getting-started/installation/"

// DefaultScanners are the Trivy sub-scanners enabled unless overridden.
//
// Trivy defaults `fs` scans to vuln,secret only; misconfig and license are off.
// Pindrop turns all four on because a dashboard that silently skips
// infrastructure-as-code findings is misleading.
//
// Enabling "license" is safe only because permissive results are filtered out
// during conversion — see actionableLicense in convert.go. Without that filter
// the license scanner alone contributes one finding per dependency.
var DefaultScanners = []string{"vuln", "misconfig", "secret", "license"}

// Scanner runs the Trivy CLI against a filesystem target.
//
// The zero value is not usable; construct one with [New]. A Scanner holds no
// mutable state after construction and is safe for concurrent use.
type Scanner struct {
	binary   string
	scanners []string
	timeout  time.Duration
	cacheDir string
}

// An Option configures a [Scanner].
type Option func(*Scanner)

// WithBinary overrides the Trivy executable, which may be a bare name resolved
// through PATH or an absolute path. Defaults to "trivy".
func WithBinary(path string) Option {
	return func(s *Scanner) {
		if path != "" {
			s.binary = path
		}
	}
}

// WithScanners overrides which Trivy sub-scanners run. Valid values are "vuln",
// "misconfig", "secret", and "license". Passing none leaves the default set.
func WithScanners(names ...string) Option {
	return func(s *Scanner) {
		if len(names) > 0 {
			s.scanners = names
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

// WithCacheDir sets Trivy's cache directory, which holds the downloaded
// vulnerability database. Sharing it across runs avoids repeated downloads.
func WithCacheDir(dir string) Option {
	return func(s *Scanner) {
		s.cacheDir = dir
	}
}

// New returns a Scanner configured by opts.
func New(opts ...Option) *Scanner {
	s := &Scanner{
		binary:   "trivy",
		scanners: DefaultScanners,
		timeout:  defaultTimeout,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name returns the scanner identifier.
func (s *Scanner) Name() string { return Name }

// Preflight verifies that the Trivy binary is present and recent enough for
// its report layout to be relied on. It wraps [scan.ErrUnavailable].
func (s *Scanner) Preflight(ctx context.Context) error {
	path, err := s.resolve()
	if err != nil {
		return &scan.UnavailableError{
			Scanner: Name,
			Reason: fmt.Sprintf("%q not found in PATH, alongside the pindrop binary, or in %s",
				s.binary, toolpath.Display(toolpath.ManagedDir())),
			Hint: installHint + "\n  Or point at an existing copy: --trivy-binary /path/to/trivy",
			Err:  err,
		}
	}

	version, err := s.version(ctx, path)
	if err != nil {
		return &scan.UnavailableError{
			Scanner: Name,
			Reason:  "could not determine version",
			Hint:    fmt.Sprintf("Check that %q runs: %s version", Name, path),
			Err:     err,
		}
	}

	// An unparseable version is not worth blocking on — Trivy ships nightly and
	// distro builds with non-semver strings. Only a confidently-too-old version
	// is an error.
	if cmp, ok := compareVersions(version, minVersion); ok && cmp < 0 {
		return &scan.UnavailableError{
			Scanner: Name,
			Reason:  fmt.Sprintf("version %s is older than the required %s", version, minVersion),
			Hint:    installHint,
		}
	}

	return nil
}

// resolve locates the Trivy executable. The search order — an explicit
// --trivy-binary path, then PATH, then beside the pindrop binary, then the
// directory `pindrop setup` installs into — lives in toolpath, because all four
// adapters need exactly the same answer.
func (s *Scanner) resolve() (string, error) {
	return toolpath.Lookup(s.binary, toolpath.Env(s.binary))
}

// version reports the Trivy release at path.
func (s *Scanner) version(ctx context.Context, path string) (string, error) {
	var stdout, stderr bytes.Buffer

	cmd := exec.CommandContext(ctx, path, "version", "--format", "json")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("running %s version: %w%s", Name, err, stderrSuffix(&stderr))
	}

	var v struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &v); err != nil {
		return "", fmt.Errorf("decoding %s version output: %w", Name, err)
	}
	if v.Version == "" {
		return "", fmt.Errorf("%s reported an empty version", Name)
	}
	return v.Version, nil
}

// Scan runs Trivy against target and converts its report into findings.
func (s *Scanner) Scan(ctx context.Context, target scan.Target) (scan.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	started := time.Now()

	raw, err := s.run(ctx, target.Path, target.Excludes)
	if err != nil {
		return scan.Result{}, err
	}

	var rep report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return scan.Result{}, fmt.Errorf("decoding %s report: %w", Name, err)
	}

	return scan.Result{
		Scanner:   Name,
		Target:    target,
		StartedAt: started,
		Duration:  time.Since(started),
		Findings:  convert(rep),
	}, nil
}

// licenseSourceDirs are directories Trivy must be allowed to walk when the
// license sub-scanner is enabled.
//
// Trivy identifies npm licenses by reading LICENSE files under node_modules,
// and Go licenses from vendor/ when it exists. Skipping them therefore trades
// scan time for the copyleft findings actionableLicense exists to surface —
// not a trade this product should make silently. When "license" is off they are
// skipped like anything else.
//
// Dropping them from the skip list does not put their findings in the report:
// scan.Run applies the same exclusions to everything that comes back, so a
// secret Trivy finds under node_modules is still filtered. Only the wall-clock
// cost differs.
var licenseSourceDirs = []string{"node_modules", "vendor", ".yarn"}

// args builds the Trivy command line.
//
// Split out from [Scanner.run] so that the invariants below are enforced by
// tests rather than asserted in comments.
func (s *Scanner) args(path string, excludes scan.Excludes) []string {
	args := []string{
		"fs",
		"--scanners", strings.Join(s.scanners, ","),
		"--format", "json",
		"--quiet",
		// Without this, Trivy exits non-zero when it finds vulnerabilities,
		// making "the tool failed" indistinguishable from "the code has bugs".
		"--exit-code", "0",
	}
	if s.cacheDir != "" {
		args = append(args, "--cache-dir", s.cacheDir)
	}
	args = append(args, s.skipArgs(excludes)...)
	return append(args, path)
}

// skipArgs returns the exclusion flags for this invocation, holding back the
// directories the license sub-scanner needs when it is enabled.
func (s *Scanner) skipArgs(excludes scan.Excludes) []string {
	if !s.licensesEnabled() {
		return excludes.TrivyArgs()
	}

	kept := make([]string, 0, len(excludes.Dirs))
	for _, d := range excludes.Dirs {
		if !slices.Contains(licenseSourceDirs, d) {
			kept = append(kept, d)
		}
	}
	excludes.Dirs = kept
	return excludes.TrivyArgs()
}

// licensesEnabled reports whether the license sub-scanner will run.
func (s *Scanner) licensesEnabled() bool {
	return slices.Contains(s.scanners, "license")
}

// run invokes Trivy and returns its raw JSON report.
func (s *Scanner) run(ctx context.Context, path string, excludes scan.Excludes) ([]byte, error) {
	// Resolve again rather than trusting PATH here: Scan must work even when it
	// is called without a prior Preflight, and the sibling-directory fallback
	// only applies to a resolved path.
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

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s timed out after %s: %w", Name, s.timeout, ctx.Err())
		}
		return nil, fmt.Errorf("running %s: %w%s", Name, err, stderrSuffix(&stderr))
	}

	return stdout.Bytes(), nil
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

// compareVersions compares dotted numeric version strings, returning a
// negative, zero, or positive value as a is less than, equal to, or greater
// than b. The second return is false when either string is not dotted-numeric,
// in which case the comparison is meaningless and should be ignored.
func compareVersions(a, b string) (int, bool) {
	as, aok := parseVersion(a)
	bs, bok := parseVersion(b)
	if !aok || !bok {
		return 0, false
	}

	for i := range max(len(as), len(bs)) {
		av, bv := atIndex(as, i), atIndex(bs, i)
		if av != bv {
			return av - bv, true
		}
	}
	return 0, true
}

// parseVersion splits a version like "0.72.0" or "v0.72.0-rc1" into its
// leading numeric components.
func parseVersion(v string) ([]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	// Discard any pre-release or build suffix.
	if i := strings.IndexAny(v, "-+ "); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return nil, false
	}

	fields := strings.Split(v, ".")
	nums := make([]int, 0, len(fields))
	for _, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil {
			return nil, false
		}
		nums = append(nums, n)
	}
	return nums, true
}

// atIndex returns nums[i], treating out-of-range indexes as zero so that
// "1.2" and "1.2.0" compare equal.
func atIndex(nums []int, i int) int {
	if i < len(nums) {
		return nums[i]
	}
	return 0
}
