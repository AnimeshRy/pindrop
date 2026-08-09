package scan

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
)

// Excludes describes paths not worth scanning, in a form independent of any one
// tool's flag syntax.
//
// Two lists rather than one, because the distinction is load-bearing in both
// directions. Every tool Pindrop drives separates them — Trivy has --skip-dirs
// and --skip-files, OSV-Scanner's --experimental-exclude handles only
// directories — and because a Python virtualenv is a directory named env while
// a file named .env is a credential store a secret scanner must never skip.
//
// The invariant that makes that safe is enforced by [Excludes.Match] and by
// every translator below: a Dirs entry can never cause a file to be skipped.
type Excludes struct {
	// Dirs are directory base names or globs, matched against each path
	// segment above the last: "node_modules", "*.egg-info".
	Dirs []string `json:"dirs,omitempty"`

	// Files are globs matched against a path's final segment only:
	// "*.min.js", "*.pyc".
	Files []string `json:"files,omitempty"`
}

// defaultDirs are directories excluded from every scan.
//
// Sources cross-checked when assembling this: Opengrep's bundled .semgrepignore,
// gitleaks' default allowlist paths, and the GitHub gitignore templates. Entries
// deliberately absent are documented in [DefaultExcludes].
var defaultDirs = []string{
	// Version control and tooling metadata. .git is load-bearing beyond noise:
	// a secret inside a packfile gets a path that churns on every gc, and the
	// path is a fingerprint input.
	".git", ".svn", ".hg", "CVS", "_darcs", ".pindrop",

	// JavaScript and TypeScript dependencies and caches.
	"node_modules", "bower_components", ".yarn", ".pnpm-store", ".npm",

	// JavaScript and TypeScript build output.
	".next", ".nuxt", ".svelte-kit", ".angular", ".parcel-cache", ".turbo",
	"storybook-static",

	// Python virtualenvs, installed packages and caches. Note these are
	// directories; the file .env is deliberately not excluded.
	".venv", "venv", "env", "virtualenv", "site-packages", "__pycache__",
	".tox", ".nox", ".eggs", "*.egg-info", ".mypy_cache", ".pytest_cache",
	".ruff_cache",

	// Go, PHP and Ruby vendored dependencies.
	"vendor", ".bundle",

	// Rust.
	"target", ".cargo",

	// Java, Gradle and Android.
	".gradle", ".m2", ".ivy2", "captures",

	// iOS, macOS and Swift.
	"Pods", "Carthage", "DerivedData",

	// Terraform. Note .tfstate files are deliberately not excluded.
	".terraform", ".terragrunt-cache",

	// Generic build output and caches.
	"dist", "build", "out", "obj", "coverage", ".cache", ".sass-cache",
	".idea",
}

// defaultFiles are files excluded from every scan.
var defaultFiles = []string{
	// Minified and generated JavaScript. Scanning these produces findings
	// against a single unreadable line that no user can act on.
	"*.min.js", "*.min.css", "*.bundle.js", "*.map",

	// Compiled artifacts.
	"*.pyc", "*.pyo", "*.class", "*.o", "*.a", "*.so", "*.dylib", "*.dll",
	"*.exe", "*.wasm",

	// Archives and media.
	"*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.jar", "*.war",
	"*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.pdf",
	"*.woff", "*.woff2", "*.ttf", "*.eot", "*.mp4",

	// Operating-system junk.
	".DS_Store", "Thumbs.db",
}

// DefaultExcludes returns the built-in exclusion set, which applies unless a
// caller explicitly replaces it.
//
// The returned value shares no memory with the package's own copy, so callers
// may append to it freely.
//
// Four omissions are deliberate and should not be "fixed" without an ADR:
//
//   - test and tests directories, and *_test.go, are NOT excluded, despite all
//     three appearing in Opengrep's own bundled .semgrepignore. Test fixtures
//     are one of the most common places a real credential is committed, and
//     inheriting that default would make secret scanning worse than git grep.
//   - bin is NOT excluded; it is too often a directory of shell scripts. obj is
//     safely .NET-shaped, bin is not.
//   - .vscode is NOT excluded; settings.json and launch.json routinely carry
//     tokens.
//   - Lockfiles are NOT excluded here. They are dependency manifests, so
//     excluding them would blind Trivy and OSV-Scanner to everything. The
//     TruffleHog adapter excludes them for secret scanning only.
//
// Note also that .terraform is excluded while *.tfstate is not: state files
// carry plaintext credentials by design. That is the same distinction as the
// env directory versus the .env file.
func DefaultExcludes() Excludes {
	return Excludes{
		Dirs:  slices.Clone(defaultDirs),
		Files: slices.Clone(defaultFiles),
	}
}

// Empty reports whether e excludes nothing.
func (e Excludes) Empty() bool {
	return len(e.Dirs) == 0 && len(e.Files) == 0
}

// Match reports whether path — relative to the scan root, with forward slashes —
// falls inside an excluded directory or is an excluded file.
//
// Dirs are tested against every segment except the last, which is what
// guarantees a directory pattern can never skip a file: an entry of "env"
// cannot match the final segment ".env", and could not match a file named
// "env" either.
//
// Three inputs are never excluded, all failing open rather than silently
// dropping a finding:
//
//   - The empty path. Cloud and cluster findings are identified by resource
//     rather than by file, and dropping them here would make an exclusion list
//     delete a whole category of finding.
//   - An absolute path. Adapters relativize against the scan root; one that
//     forgets should report too much, not too little.
//   - A path escaping the root with "..".
func (e Excludes) Match(p string) bool {
	if p == "" {
		return false
	}
	p = path.Clean(p)
	if path.IsAbs(p) || p == ".." || strings.HasPrefix(p, "../") {
		return false
	}

	segments := strings.Split(p, "/")
	for _, segment := range segments[:len(segments)-1] {
		for _, pattern := range e.Dirs {
			// The only possible error is ErrBadPattern, which Validate
			// reports up front; treat an unparseable pattern as no match.
			if ok, _ := path.Match(pattern, segment); ok {
				return true
			}
		}
	}

	last := segments[len(segments)-1]
	for _, pattern := range e.Files {
		if ok, _ := path.Match(pattern, last); ok {
			return true
		}
	}
	return false
}

// Filter drops findings whose location falls inside an excluded path.
//
// Native scanner flags are the fast path — a tool told to skip node_modules
// never reads it. This is the correctness path. The four tools' exclusion
// vocabularies genuinely differ: OSV-Scanner's excludes directories only and is
// flagged experimental, Trivy's globs do not match the scan root without a
// second form, Opengrep's are gitignore patterns, TruffleHog's are regular
// expressions. "All four honour the same set" therefore cannot be established
// by four independent correct translations. It is established here, once.
//
// It is also what lets the Trivy adapter keep walking node_modules for license
// files without that directory's secret findings reaching a report.
func (e Excludes) Filter(findings []Finding) []Finding {
	if e.Empty() {
		return findings
	}

	kept := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if e.Match(f.Location.Path) {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// Merge returns the union of e and other, deduplicated and sorted.
//
// Sorting is what makes the argv a scanner receives deterministic, which is
// what makes that argv assertable in a test.
func (e Excludes) Merge(other Excludes) Excludes {
	return Excludes{
		Dirs:  mergePatterns(e.Dirs, other.Dirs),
		Files: mergePatterns(e.Files, other.Files),
	}
}

// mergePatterns concatenates two pattern lists into a sorted, deduplicated one.
func mergePatterns(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}

	merged := make([]string, 0, len(a)+len(b))
	merged = append(merged, a...)
	merged = append(merged, b...)
	slices.Sort(merged)
	return slices.Compact(merged)
}

// Validate reports the first entry that is not a valid glob, naming it. Callers
// surface this before any scanner is preflighted, so a typo is a startup error
// rather than a silently ineffective exclusion.
func (e Excludes) Validate() error {
	for _, group := range []struct {
		kind     string
		patterns []string
	}{{"directory", e.Dirs}, {"file", e.Files}} {
		for _, pattern := range group.patterns {
			if pattern == "" {
				return fmt.Errorf("empty %s exclude pattern", group.kind)
			}
			if _, err := path.Match(pattern, "probe"); err != nil {
				return fmt.Errorf("invalid %s exclude pattern %q: %w",
					group.kind, pattern, err)
			}
		}
	}
	return nil
}

// ParsePatterns converts user-written patterns, from a --exclude flag or a
// config file, into an [Excludes].
//
// The grammar is deliberately biased toward the safe reading:
//
//	dir:NAME  or  NAME/     always a directory
//	file:NAME               always a file
//	NAME containing * ? [   a file
//	NAME otherwise          a directory
//
// So "--exclude .env" excludes a directory named .env and leaves the file
// alone. Excluding the file requires "--exclude file:.env", which is a
// deliberate act rather than a typo — a user who wants to blind their own
// secret scanner should have to say so in a form that reads like what it is.
//
// Patterns match a single path segment at any depth, so one containing a
// separator is rejected rather than silently never matching.
func ParsePatterns(patterns []string) (Excludes, error) {
	var ex Excludes

	for _, raw := range patterns {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}

		isDir := true
		switch {
		case strings.HasPrefix(p, "dir:"):
			p = strings.TrimPrefix(p, "dir:")
		case strings.HasPrefix(p, "file:"):
			p, isDir = strings.TrimPrefix(p, "file:"), false
		case strings.HasSuffix(p, "/"):
		default:
			isDir = !strings.ContainsAny(p, "*?[")
		}

		p = strings.TrimSuffix(p, "/")
		if p == "" {
			return Excludes{}, fmt.Errorf("exclude pattern %q names nothing", raw)
		}
		if strings.Contains(p, "/") {
			return Excludes{}, fmt.Errorf(
				"exclude pattern %q contains a path separator; "+
					"patterns match one path segment at any depth, so use %q",
				raw, path.Base(p))
		}

		if isDir {
			ex.Dirs = append(ex.Dirs, p)
			continue
		}
		ex.Files = append(ex.Files, p)
	}

	if err := ex.Validate(); err != nil {
		return Excludes{}, err
	}
	return ex, nil
}

// TrivyArgs returns --skip-dirs and --skip-files arguments for `trivy fs`.
//
// Each pattern is emitted twice, bare and **/-prefixed. Trivy matches with
// doublestar semantics in which "**/node_modules" matches ./foo/node_modules
// but NOT ./node_modules at the scan root — so a single form silently misses
// the one occurrence that matters most.
//
// The flags also accept a comma-joined value, but repeating them keeps a
// directory name containing a comma from splitting into two useless patterns.
func (e Excludes) TrivyArgs() []string {
	args := make([]string, 0, 4*(len(e.Dirs)+len(e.Files)))
	for _, d := range e.Dirs {
		args = append(args, "--skip-dirs", d, "--skip-dirs", "**/"+d)
	}
	for _, f := range e.Files {
		args = append(args, "--skip-files", f, "--skip-files", "**/"+f)
	}
	return args
}

// OpengrepArgs returns --exclude arguments for `opengrep scan`.
//
// Directory patterns carry a trailing slash. Opengrep uses gitignore syntax, in
// which a bare "env" matches a file named env as well as the directory; the
// trailing slash is what makes a Dirs entry mean a directory. Opengrep already
// matches at any depth, so no **/ form is needed.
func (e Excludes) OpengrepArgs() []string {
	args := make([]string, 0, 2*(len(e.Dirs)+len(e.Files)))
	for _, d := range e.Dirs {
		args = append(args, "--exclude", d+"/")
	}
	for _, f := range e.Files {
		args = append(args, "--exclude", f)
	}
	return args
}

// OSVArgs returns --experimental-exclude arguments for `osv-scanner scan
// source`.
//
// Only Dirs are emitted: the flag excludes directories only. Files are handled
// by [Excludes.Filter]. The flag is experimental-prefixed upstream, so this is
// a speed optimization and not the correctness mechanism; the adapter's TestArgs
// pins the name so an upstream rename fails a test rather than a user's scan.
func (e Excludes) OSVArgs() []string {
	args := make([]string, 0, 2*len(e.Dirs))
	for _, d := range e.Dirs {
		args = append(args, "--experimental-exclude", d)
	}
	return args
}

// TruffleHogPatterns returns anchored regular expressions for the file passed
// to `trufflehog filesystem --exclude-paths`.
//
// Directories become (^|/)NAME/ and files (^|/)NAME$. The trailing slash on a
// directory is not cosmetic: an unanchored (^|/)env would match .env as a
// substring of a path segment, which is exactly the failure this type exists to
// prevent.
func (e Excludes) TruffleHogPatterns() []string {
	patterns := make([]string, 0, len(e.Dirs)+len(e.Files))
	for _, d := range e.Dirs {
		patterns = append(patterns, `(^|/)`+globToRegexp(d)+`/`)
	}
	for _, f := range e.Files {
		patterns = append(patterns, `(^|/)`+globToRegexp(f)+`$`)
	}
	return patterns
}

// globToRegexp translates a single-segment glob into a regular expression
// fragment, quoting everything it does not understand.
//
// Only * and ? are translated; a character class is quoted literally rather
// than converted. That is deliberate: over-quoting matches less, so a pattern
// this does not understand lets findings through to [Excludes.Filter], which
// does understand it. Failing open is the right direction for a security tool.
func globToRegexp(glob string) string {
	var b strings.Builder
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteString(`[^/]*`)
		case '?':
			b.WriteString(`[^/]`)
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return b.String()
}
