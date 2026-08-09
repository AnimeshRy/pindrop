package trufflehog

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// The adapter must satisfy the contract at compile time.
var _ scan.Scanner = (*Scanner)(nil)

func TestNewDefaults(t *testing.T) {
	t.Parallel()

	s := New()

	if got, want := s.binary, "trufflehog"; got != want {
		t.Errorf("binary = %q, want %q", got, want)
	}
	if got, want := s.timeout, defaultTimeout; got != want {
		t.Errorf("timeout = %v, want %v", got, want)
	}
	if s.verify {
		t.Error("verify = true, want false: verification must be opt-in")
	}
	if len(s.excludePaths) != 0 {
		t.Errorf("excludePaths = %v, want empty", s.excludePaths)
	}
	if s.concurrency < 1 {
		t.Errorf("concurrency = %d, want >= 1", s.concurrency)
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
		WithExcludePaths("", "   "),
	)

	if got, want := s.binary, "trufflehog"; got != want {
		t.Errorf("binary = %q, want %q", got, want)
	}
	if got, want := s.timeout, defaultTimeout; got != want {
		t.Errorf("timeout = %v, want %v", got, want)
	}
	if len(s.excludePaths) != 0 {
		t.Errorf("excludePaths = %v, want empty", s.excludePaths)
	}
}

func TestOptionsApply(t *testing.T) {
	t.Parallel()

	s := New(
		WithBinary("/opt/trufflehog"),
		WithTimeout(90*time.Second),
		WithVerification(true),
		WithExcludePaths(`(^|/)fixtures/`),
	)

	if got, want := s.binary, "/opt/trufflehog"; got != want {
		t.Errorf("binary = %q, want %q", got, want)
	}
	if got, want := s.timeout, 90*time.Second; got != want {
		t.Errorf("timeout = %v, want %v", got, want)
	}
	if !s.verify {
		t.Error("verify = false, want true")
	}
	if got, want := len(s.excludePaths), 1; got != want {
		t.Fatalf("len(excludePaths) = %d, want %d", got, want)
	}
}

func TestPreflightMissingBinary(t *testing.T) {
	t.Parallel()

	s := New(WithBinary("pindrop-trufflehog-does-not-exist"))

	err := s.Preflight(context.Background())
	if err == nil {
		t.Fatal("Preflight() = nil, want an error")
	}
	if !errors.Is(err, scan.ErrUnavailable) {
		t.Errorf("error does not match scan.ErrUnavailable: %v", err)
	}
	// The message is shown verbatim to a user who is not a security engineer, so
	// it has to say how to fix the problem.
	for _, want := range []string{"Install TruffleHog", "--trufflehog-binary"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message missing %q:\n%s", want, err)
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
		{"clean scan", 0, true},
		{"findings via --fail", 183, true},
		{"generic failure", 1, false},
		{"usage error", 2, false},
		{"unknown code", 42, false},
		{"killed by signal", -1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := resultExit(tt.code); got != tt.want {
				t.Errorf("resultExit(%d) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}

// Each of these flags changes behaviour silently when absent, so the command line
// is asserted rather than trusted.
func TestArgs(t *testing.T) {
	t.Parallel()

	t.Run("mandatory flags on every scan", func(t *testing.T) {
		t.Parallel()

		got := New().args("/target", "/tmp/exclude.txt")

		// --no-update: without it TruffleHog fetches and re-execs a newer build
		// mid-scan, so the pinned version is not the version that ran.
		// --exclude-paths: without it `filesystem` walks .git, and a secret in a
		// packfile gets a path that churns on every gc.
		for _, want := range []string{
			"filesystem", "--json", "--no-update", "--no-color",
			"--log-level=-1", "--exclude-paths", "/tmp/exclude.txt", "/target",
		} {
			if !slices.Contains(got, want) {
				t.Errorf("args missing %q: %v", want, got)
			}
		}

		// --fail would make findings exit 183, collapsing "the code has secrets"
		// and "the tool broke" into one signal.
		if slices.Contains(got, "--fail") {
			t.Errorf("args must never include --fail: %v", got)
		}

		// The target must be last, after every flag.
		if got[len(got)-1] != "/target" {
			t.Errorf("target is not the final argument: %v", got)
		}
	})

	t.Run("verification off", func(t *testing.T) {
		t.Parallel()

		got := New(WithVerification(false)).args("/target", "/x")

		if !slices.Contains(got, "--no-verification") {
			t.Errorf("args missing --no-verification: %v", got)
		}
		// --no-verification with --results=verified is a scan that cannot report
		// anything, so --results is never named on this path.
		for _, arg := range got {
			if strings.HasPrefix(arg, "--results") {
				t.Errorf("--results must not be set without verification: %v", got)
			}
		}
	})

	t.Run("verification on", func(t *testing.T) {
		t.Parallel()

		got := New(WithVerification(true)).args("/target", "/x")

		if slices.Contains(got, "--no-verification") {
			t.Errorf("args must not disable verification: %v", got)
		}
		if !slices.Contains(got, "--results=verified,unknown") {
			t.Errorf("args should narrow to live-or-unknown: %v", got)
		}
	})
}

// oneRecord is a minimal well-formed output line.
const oneRecord = `{"DetectorName":"AWS","Raw":"x","SourceMetadata":{"Data":{"Filesystem":{"file":"/a","line":1}}}}`

// TestDecodeFraming covers the framing properties the streaming decoder exists to
// provide. These are properties of the decode loop rather than shapes the tool
// emits, which is why they use inline input instead of the golden fixture.
func TestDecodeFraming(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"empty output is an empty scan", "", 0},
		{"whitespace only is an empty scan", "\n\n   \n", 0},
		{"single record", oneRecord + "\n", 1},
		{"no trailing newline", oneRecord, 1},
		{"blank lines between records are skipped", oneRecord + "\n\n" + oneRecord + "\n", 2},
		{"leading blank lines", "\n\n" + oneRecord + "\n", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := decode([]byte(tt.input))
			if err != nil {
				t.Fatalf("decode() error = %v", err)
			}
			if len(got) != tt.want {
				t.Errorf("len = %d, want %d", len(got), tt.want)
			}
		})
	}
}

// The reason this adapter does not use bufio.Scanner: a credential inside a
// minified bundle or a base64 blob produces a line far past Scanner's 64KB token
// limit, and any Buffer size chosen instead would be a guess.
func TestDecodeHandlesVeryLongLine(t *testing.T) {
	t.Parallel()

	huge := strings.Repeat("A", 512*1024)
	body := `{"DetectorName":"Github","Raw":"` + huge +
		`","SourceMetadata":{"Data":{"Filesystem":{"file":"/a","line":1}}}}` + "\n"

	got, err := decode([]byte(body))
	if err != nil {
		t.Fatalf("decode() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if len(got[0].Raw) != len(huge) {
		t.Errorf("Raw length = %d, want %d", len(got[0].Raw), len(huge))
	}
}

// A line we cannot parse means we have misunderstood the output contract.
// Skipping it would be silently dropping a secret.
func TestDecodeRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	_, err := decode([]byte(oneRecord + "\n{not json}\n"))
	if err == nil {
		t.Fatal("decode() = nil error, want a failure")
	}
	if !strings.Contains(err.Error(), Name) {
		t.Errorf("error should name the scanner: %v", err)
	}
}

// The error must not quote the input, which may hold a credential.
func TestDecodeErrorDoesNotEchoInput(t *testing.T) {
	t.Parallel()

	const secret = "ghp_averyrealisticlookingtokenvalue00"

	_, err := decode([]byte(`{"Raw":"` + secret + `", BROKEN`))
	if err == nil {
		t.Fatal("decode() = nil error, want a failure")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error leaked the input: %v", err)
	}
}

func TestValidateExcludes(t *testing.T) {
	t.Parallel()

	if err := validateExcludes([]string{`(^|/)ok/`, `\.pem$`}); err != nil {
		t.Errorf("validateExcludes() error = %v, want nil", err)
	}

	err := validateExcludes([]string{`(unclosed`})
	if err == nil {
		t.Fatal("validateExcludes() = nil, want an error")
	}
	// The user cannot act on "the tool exited 1"; the message must name their
	// pattern and the flag that carried it.
	for _, want := range []string{"(unclosed", "--trufflehog-exclude-paths"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
}

// The built-in patterns must compile, or every scan fails at run time.
func TestDefaultExcludesCompile(t *testing.T) {
	t.Parallel()

	if err := validateExcludes(excludePatterns(scan.DefaultExcludes(), nil)); err != nil {
		t.Fatalf("the default patterns do not compile: %v", err)
	}
}

// .git must be excluded, and it comes from the shared scan.Excludes set rather
// than a list local to this adapter. trufflehog filesystem walks the object
// store, and a secret reported at .git/objects/pack/pack-<sha>.pack has a path
// that churns on every gc — which, since the path is a fingerprint input, would
// report the finding as fixed and reintroduced forever.
//
// Lockfiles must be excluded too, but from secretNoiseExcludes: they are
// dependency manifests, so excluding them in the shared set would blind Trivy
// and OSV-Scanner to every dependency in the tree.
func TestDefaultExcludesCoverGitAndLockfiles(t *testing.T) {
	t.Parallel()

	paths := []string{
		".git/objects/pack/pack-abc123.pack",
		"sub/.git/config",
		"node_modules/pkg/index.js",
		"web/dist/assets/main.js",
		"vendor/github.com/x/y.go",
		".pindrop/report.json",
		"web/src/vendor.min.js",
		"package-lock.json",
		"web/pnpm-lock.yaml",
		"go.sum",
	}

	for _, p := range paths {
		if !matchesAnyExclude(t, p) {
			t.Errorf("path %q is not excluded by default", p)
		}
	}

	// And the adapter must still look at ordinary source, and at the dotfiles
	// that are among the highest-yield real secret locations.
	for _, p := range []string{"internal/scan/run.go", "web/src/App.tsx", ".env", ".env.example"} {
		if matchesAnyExclude(t, p) {
			t.Errorf("path %q must not be excluded", p)
		}
	}
}

func matchesAnyExclude(t *testing.T, path string) bool {
	t.Helper()
	for _, pattern := range excludePatterns(scan.DefaultExcludes(), nil) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			t.Fatalf("pattern %q does not compile: %v", pattern, err)
		}
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func TestWriteExcludeFile(t *testing.T) {
	t.Parallel()

	patterns := []string{`(^|/)\.git/`, `\.min\.js$`}

	path, cleanup, err := writeExcludeFile(patterns)
	if err != nil {
		t.Fatalf("writeExcludeFile() error = %v", err)
	}
	defer cleanup()

	body, err := os.ReadFile(path) //nolint:gosec // path is created by the function under test
	if err != nil {
		t.Fatalf("reading exclude file: %v", err)
	}

	got := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(got) != len(patterns) {
		t.Fatalf("wrote %d lines, want %d: %q", len(got), len(patterns), body)
	}
	for i, want := range patterns {
		if got[i] != want {
			t.Errorf("line %d = %q, want %q", i, got[i], want)
		}
	}

	cleanup()
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Errorf("cleanup left the directory behind: %v", err)
	}
}

// A fresh directory per call: Scanner is documented concurrent-safe and scan.Run
// fans scanners out in parallel, so a shared path would be a filesystem race.
func TestWriteExcludeFileIsolated(t *testing.T) {
	t.Parallel()

	first, cleanupFirst, err := writeExcludeFile(secretNoiseExcludes)
	if err != nil {
		t.Fatalf("writeExcludeFile() error = %v", err)
	}
	defer cleanupFirst()

	second, cleanupSecond, err := writeExcludeFile(secretNoiseExcludes)
	if err != nil {
		t.Fatalf("writeExcludeFile() error = %v", err)
	}
	defer cleanupSecond()

	if filepath.Dir(first) == filepath.Dir(second) {
		t.Errorf("both calls used %s", filepath.Dir(first))
	}

	// Cleaning one must not disturb the other.
	cleanupFirst()
	if _, err := os.Stat(second); err != nil {
		t.Errorf("second file gone after cleaning the first: %v", err)
	}
}
