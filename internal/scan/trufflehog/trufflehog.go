// Package trufflehog adapts TruffleHog's secret scanner to Pindrop's
// [scan.Scanner] contract.
//
// # Subprocess only, non-negotiably
//
// TruffleHog is AGPL-3.0. Importing it as a library would place all of Pindrop
// under AGPL, so it is invoked as a subprocess and never appears in go.mod. The
// Makefile installs it from a pinned release rather than with `go install` for
// the same reason: keeping it out of the module graph entirely means nobody can
// later move it into a tools file by accident.
//
// # Verification is opt-in
//
// TruffleHog's distinguishing capability is that its detectors can authenticate
// a discovered credential against its issuer, which turns "twelve secret-shaped
// strings" into "one live key". That requires sending the user's credentials to
// third-party endpoints, so it is off by default and enabled with
// --verify-secrets. See docs/decisions/0008-trufflehog-verification-opt-in.md.
//
// The cost is worth stating plainly: with verification off, this adapter is a
// regex-and-format engine much like Trivy's built-in secret scanner, and the two
// will report the same credential twice under different rule IDs. See
// docs/architecture/scanners.md.
//
// # Plaintext never leaves this package
//
// The reported records carry the credential itself in Raw, RawV2, and every
// SecretParts value. None of those reach a [scan.Finding]: they are read to
// derive an identity digest and then discarded. Pindrop writes findings to a
// report file and serves them over HTTP, so a Finding holding a secret would
// make a secret-scanning run into a second copy of every secret it found. The
// captured stdout buffer is never logged for the same reason.
package trufflehog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// Name is the scanner identifier recorded on every finding. It is persisted, so
// it must not change.
const Name = "trufflehog"

// defaultTimeout bounds a single scan. Secret detection reads every file in the
// tree rather than only manifests, so it is given the same headroom as the SAST
// engine.
const defaultTimeout = 10 * time.Minute

// installHint is shown verbatim when the binary is missing. Our users are not
// security engineers, so it names the tool and gives a command.
const installHint = "Install TruffleHog: https://github.com/trufflesecurity/trufflehog#installation\n" +
	"  Or run: make trufflehog"

// Exit codes.
//
// TruffleHog signals findings through its exit code only when asked to, via
// --fail, which this adapter never passes. Omitting it buys the property that
// Trivy's --exit-code 0 buys: a clean scan and a scan that found secrets both
// exit zero, so a non-zero status unambiguously means the tool broke rather than
// that the code has problems.
const (
	exitOK = 0
	// exitFail is what --fail would produce. It is listed so that if a future
	// change adds the flag, the classifier below already says what it means
	// rather than treating findings as a crash.
	exitFail = 183
)

// Scanner runs TruffleHog against a filesystem target.
type Scanner struct {
	binary       string
	timeout      time.Duration
	verify       bool
	excludePaths []string
	concurrency  int
}

// Option configures a [Scanner].
type Option func(*Scanner)

// WithBinary overrides the executable name or path. An empty value is ignored.
func WithBinary(binary string) Option {
	return func(s *Scanner) {
		if binary != "" {
			s.binary = binary
		}
	}
}

// WithTimeout overrides the per-scan timeout. Zero and negative values are
// ignored.
func WithTimeout(d time.Duration) Option {
	return func(s *Scanner) {
		if d > 0 {
			s.timeout = d
		}
	}
}

// WithVerification enables authenticating discovered credentials against their
// issuers.
//
// This makes outbound network calls carrying the user's secrets, which is why it
// is off unless explicitly requested.
func WithVerification(verify bool) Option {
	return func(s *Scanner) {
		s.verify = verify
	}
}

// WithExcludePaths appends caller-supplied path patterns to the built-in set.
// Blank entries are ignored. Patterns are regular expressions, not globs.
func WithExcludePaths(patterns ...string) Option {
	return func(s *Scanner) {
		for _, p := range patterns {
			if strings.TrimSpace(p) != "" {
				s.excludePaths = append(s.excludePaths, p)
			}
		}
	}
}

// New constructs a [Scanner].
func New(opts ...Option) *Scanner {
	s := &Scanner{
		binary:  "trufflehog",
		timeout: defaultTimeout,
		// Bounded explicitly rather than left to TruffleHog's NumCPU default:
		// scan.Run already fans every scanner out in parallel, so an unbounded
		// worker pool per scanner oversubscribes the machine.
		concurrency: max(1, runtime.NumCPU()/2),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name implements [scan.Scanner].
func (s *Scanner) Name() string { return Name }

// Preflight implements [scan.Scanner].
//
// The --version call is safe to make unconditionally: TruffleHog's update check
// is wired after flag parsing, and --version terminates during it, so this does
// not reach the network despite --no-update being a scan-time flag.
func (s *Scanner) Preflight(ctx context.Context) error {
	binary, err := s.resolve()
	if err != nil {
		return &scan.UnavailableError{
			Scanner: Name,
			Reason:  fmt.Sprintf("%q not found in PATH or alongside the pindrop binary", s.binary),
			Hint:    installHint + "\n  Or point at an existing copy: --trufflehog-binary /path/to/trufflehog",
			Err:     err,
		}
	}

	cmd := exec.CommandContext(ctx, binary, "--version")
	if out, err := cmd.CombinedOutput(); err != nil {
		return &scan.UnavailableError{
			Scanner: Name,
			Reason:  "the binary is present but did not run",
			Hint:    installHint,
			Err:     fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out))),
		}
	}

	return nil
}

// resolve locates the executable, preferring PATH and then the directory holding
// the running pindrop binary, so that `make setup`'s ./bin copy is found without
// ./bin being on PATH.
func (s *Scanner) resolve() (string, error) {
	if strings.ContainsRune(s.binary, filepath.Separator) {
		return exec.LookPath(s.binary)
	}

	path, pathErr := exec.LookPath(s.binary)
	if pathErr == nil {
		return path, nil
	}

	self, err := os.Executable()
	if err != nil {
		return "", pathErr
	}
	beside := filepath.Join(filepath.Dir(self), s.binary)
	if path, err := exec.LookPath(beside); err == nil {
		return path, nil
	}

	// The PATH error is the actionable one.
	return "", pathErr
}

// Scan implements [scan.Scanner].
func (s *Scanner) Scan(ctx context.Context, target scan.Target) (scan.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	started := time.Now()

	patterns := append(append([]string(nil), defaultExcludes...), s.excludePaths...)
	if err := validateExcludes(s.excludePaths); err != nil {
		return scan.Result{}, err
	}

	excludeFile, cleanup, err := writeExcludeFile(patterns)
	// Deferred here rather than inside run: the file has to outlive cmd.Wait.
	defer cleanup()
	if err != nil {
		return scan.Result{}, err
	}

	raw, err := s.run(ctx, target.Path, excludeFile)
	if err != nil {
		return scan.Result{}, err
	}

	results, err := decode(raw)
	if err != nil {
		return scan.Result{}, err
	}

	return scan.Result{
		Scanner:   Name,
		Target:    target,
		StartedAt: started,
		Duration:  time.Since(started),
		Findings:  convert(results, target.Path, s.verify),
	}, nil
}

// decode reads TruffleHog's JSON Lines output.
//
// A streaming [json.Decoder] rather than a [bufio.Scanner]: Scanner caps a single
// token at 64KB and hard-fails above whatever Buffer size is chosen, and a
// credential found inside a minified bundle or a base64 blob produces lines far
// longer than any figure worth guessing. Decoder has no such limit, skips the
// whitespace between values so blank lines cost nothing, and would keep working
// if a future release stopped emitting exactly one object per line.
//
// A malformed line fails the scan rather than being skipped. This is the opposite
// of how the Opengrep adapter treats that tool's engine errors, and deliberately
// so: an engine error is the tool reporting something about the target, whereas a
// syntax error means we have misunderstood the tool's output contract — the exact
// failure that shipped Trivy's phantom AVDID field. Silently skipping a line we
// cannot parse would be silently dropping a secret. It is also not implementable
// here: after a syntax error a Decoder cannot resync, because it has no way to
// know where the next value begins.
func decode(raw []byte) ([]finding, error) {
	var results []finding

	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		var res finding
		if err := dec.Decode(&res); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// The error is not wrapped with the offending input: a malformed line
			// may still contain a credential.
			return nil, fmt.Errorf("decoding %s output at offset %d: %w", Name, dec.InputOffset(), err)
		}
		results = append(results, res)
	}

	return results, nil
}

// run invokes the tool and returns its stdout.
func (s *Scanner) run(ctx context.Context, path, excludeFile string) ([]byte, error) {
	binary, err := s.resolve()
	if err != nil {
		// Preflight passed but the tool has since gone. Degrade the same way.
		return nil, &scan.UnavailableError{
			Scanner: Name,
			Reason:  fmt.Sprintf("%q could not be executed", s.binary),
			Hint:    installHint,
			Err:     err,
		}
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, s.args(path, excludeFile)...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

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

	return nil, fmt.Errorf("running %s: %w%s", Name, err, stderrTail(&stderr))
}

// args builds the command line.
//
// Split out from [Scanner.run] so that the invariants below are enforced by tests
// rather than asserted in comments — every one of them is a flag whose absence or
// presence changes behaviour silently.
func (s *Scanner) args(path, excludeFile string) []string {
	args := []string{
		"filesystem",
		"--json",
		// Without this TruffleHog downloads and re-execs a newer build of itself
		// mid-scan. That makes every scan a network dependency and means the
		// version that produced a report is not the version that was pinned.
		"--no-update",
		"--no-color",
		// Quiet. Logs go to stderr, but see stderrTail for why we want as little
		// of it as possible. The `=` is required for a negative value.
		"--log-level=-1",
		"--concurrency", strconv.Itoa(s.concurrency),
		"--exclude-paths", excludeFile,
	}

	if s.verify {
		// Narrowing to live-or-unknown is the point of paying for verification:
		// the value is "this key works", and a report that still lists every
		// unverified match has not used the signal it just spent network calls
		// acquiring.
		args = append(args, "--results=verified,unknown")
	} else {
		args = append(args, "--no-verification")
		// --results is deliberately not set here. With verification off every
		// record is unverified, so the only coherent value is the default; naming
		// one invites the --no-verification --results=verified combination, which
		// is a scan that cannot report anything.
	}

	// --fail is never passed. See the exit code constants.
	return append(args, path)
}

// resultExit reports whether code means "the scan completed" rather than "the
// tool failed".
func resultExit(code int) bool {
	switch code {
	case exitOK:
		return true
	case exitFail:
		// Only reachable if --fail is ever added. Findings are a result, not a
		// failure.
		return true
	default:
		// Everything else is a real failure, including anything negative, which
		// signals death by signal.
		return false
	}
}

// stderrTail renders stderr for inclusion in an error message.
//
// Unlike the equivalent helper in the other adapters, this one keeps only the
// final line. TruffleHog's stderr carries scan progress and verification
// diagnostics, and while its logger applies global redaction, a diagnostic
// naming the value it failed on is not a risk worth taking in the one adapter
// whose entire input is credentials. One line is enough to say what broke.
func stderrTail(buf *bytes.Buffer) string {
	out := strings.TrimSpace(buf.String())
	if out == "" {
		return ""
	}

	if i := strings.LastIndexByte(out, '\n'); i >= 0 {
		out = strings.TrimSpace(out[i+1:])
	}

	const maxLen = 500
	if len(out) > maxLen {
		out = out[len(out)-maxLen:]
	}

	return ": " + out
}
