package scan_test

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

func TestMatch(t *testing.T) {
	t.Parallel()

	ex := scan.DefaultExcludes()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"excluded directory at the scan root", "node_modules/lodash/index.js", true},
		{"excluded directory nested", "web/node_modules/lodash/index.js", true},
		{"excluded directory deeply nested", "a/b/c/vendor/pkg/mod.go", true},
		{"excluded directory glob", "src/pindrop.egg-info/PKG-INFO", true},
		{"excluded file at the root", "app.min.js", true},
		{"excluded file nested", "web/dist/app.min.js", true},
		{"ordinary source file", "internal/scan/finding.go", false},
		{"file whose name contains an excluded directory name", "src/vendored.go", false},
		{"directory whose name merely starts with an excluded one", "distribution/main.go", false},
		{"the empty path is never excluded", "", false},
		{"an absolute path is never excluded", "/etc/passwd", false},
		{"a path escaping the root is never excluded", "../secrets/key.pem", false},
		{"a leading ./ is cleaned before matching", "./node_modules/x.js", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := ex.Match(tt.path); got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestEnvFileIsNeverExcluded is the named invariant that keeps an exclusion set
// from blinding the secret scanner.
//
// A Python virtualenv is a directory named env, venv or .venv; a file named
// .env is a credential store, and a committed one is among the highest-value
// findings a secret scanner produces. The hazard is not in Match — ".env" does
// not equal "env" under any comparison — it is in translation, where a naive
// regex (^|/)env matches .env as a substring and Opengrep's gitignore syntax
// treats a bare "env" as a file pattern too. So this asserts both.
func TestEnvFileIsNeverExcluded(t *testing.T) {
	t.Parallel()

	ex := scan.DefaultExcludes()

	envFiles := []string{".env", "app/.env", "srv/.env.production", ".envrc", "config/.env.local"}
	venvDirs := []string{"env/bin/pip", "venv/lib/site.py", ".venv/lib/site.py", "src/venv/x.py"}

	t.Run("Match", func(t *testing.T) {
		t.Parallel()

		for _, p := range envFiles {
			if ex.Match(p) {
				t.Errorf("Match(%q) = true, want false: .env files must stay scannable", p)
			}
		}
		for _, p := range venvDirs {
			if !ex.Match(p) {
				t.Errorf("Match(%q) = false, want true: virtualenv dirs must be excluded", p)
			}
		}
	})

	t.Run("TruffleHogPatterns", func(t *testing.T) {
		t.Parallel()

		for _, pattern := range ex.TruffleHogPatterns() {
			re, err := regexp.Compile(pattern)
			if err != nil {
				t.Fatalf("pattern %q does not compile: %v", pattern, err)
			}
			for _, p := range envFiles {
				if re.MatchString(p) {
					t.Errorf("pattern %q matches %q, which would hide a credential", pattern, p)
				}
			}
		}
	})

	t.Run("OpengrepArgs", func(t *testing.T) {
		t.Parallel()

		// Under gitignore syntax a bare "env" matches a file named env as well
		// as the directory. The trailing slash is the entire defense.
		for _, value := range flagValues(ex.OpengrepArgs(), "--exclude") {
			if value == "env" || value == ".env" {
				t.Errorf("--exclude %q would match the .env file under gitignore syntax", value)
			}
		}
	})
}

// TestTfstateIsNeverExcluded guards the same distinction one layer out: the
// .terraform directory is cache, while a .tfstate file carries plaintext
// credentials by design.
func TestTfstateIsNeverExcluded(t *testing.T) {
	t.Parallel()

	ex := scan.DefaultExcludes()

	if !ex.Match(".terraform/modules/x.tf") {
		t.Error("the .terraform cache directory should be excluded")
	}
	for _, p := range []string{"terraform.tfstate", "infra/terraform.tfstate.backup"} {
		if ex.Match(p) {
			t.Errorf("Match(%q) = true, want false: state files carry credentials", p)
		}
	}
}

// TestDefaultExcludesIsIndependent checks that a caller appending to the
// returned value cannot corrupt the package's own copy.
func TestDefaultExcludesIsIndependent(t *testing.T) {
	t.Parallel()

	first := scan.DefaultExcludes()
	first.Dirs = append(first.Dirs, "poisoned")

	if slices.Contains(scan.DefaultExcludes().Dirs, "poisoned") {
		t.Error("DefaultExcludes returned a slice aliasing the package's own copy")
	}
}

func TestParsePatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		patterns  []string
		wantDirs  []string
		wantFiles []string
	}{
		{"bare name is a directory", []string{"third_party"}, []string{"third_party"}, nil},
		{"trailing slash is a directory", []string{"build/"}, []string{"build"}, nil},
		{"dir: prefix is a directory", []string{"dir:fixtures"}, []string{"fixtures"}, nil},
		{"file: prefix is a file", []string{"file:secrets.txt"}, nil, []string{"secrets.txt"}},
		{"a glob is a file", []string{"*.generated.go"}, nil, []string{"*.generated.go"}},
		{"dir: wins over a glob", []string{"dir:*.egg-info"}, []string{"*.egg-info"}, nil},
		{"blank entries are skipped", []string{"", "  ", "x"}, []string{"x"}, nil},
		{
			// The safe reading: a bare .env names a directory, so a typo cannot
			// silently blind the secret scanner.
			name:     "a bare .env is a directory, not the file",
			patterns: []string{".env"},
			wantDirs: []string{".env"},
		},
		{
			name:      "the file must be named explicitly",
			patterns:  []string{"file:.env"},
			wantFiles: []string{".env"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := scan.ParsePatterns(tt.patterns)
			if err != nil {
				t.Fatalf("ParsePatterns(%q) returned error: %v", tt.patterns, err)
			}
			if !slices.Equal(got.Dirs, tt.wantDirs) {
				t.Errorf("Dirs = %q, want %q", got.Dirs, tt.wantDirs)
			}
			if !slices.Equal(got.Files, tt.wantFiles) {
				t.Errorf("Files = %q, want %q", got.Files, tt.wantFiles)
			}
		})
	}
}

func TestParsePatternsRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		wantIn  string
	}{
		{"a path separator", "src/fixtures", "one path segment"},
		{"a pattern naming nothing", "dir:", "names nothing"},
		{"an unclosed character class", "[unclosed", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := scan.ParsePatterns([]string{tt.pattern})
			if err == nil {
				t.Fatalf("ParsePatterns(%q) returned no error", tt.pattern)
			}
			if !strings.Contains(err.Error(), tt.wantIn) {
				t.Errorf("error %q does not mention %q", err, tt.wantIn)
			}
			// Users are not security engineers: the message must name the
			// pattern they typed.
			if !strings.Contains(err.Error(), tt.pattern) {
				t.Errorf("error %q does not name the offending pattern", err)
			}
		})
	}
}

// TestTrivyArgsEmitBothDepthForms pins the trap that makes a single form wrong:
// Trivy's doublestar "**/node_modules" matches ./web/node_modules but NOT
// ./node_modules at the scan root, which is the occurrence that matters most.
func TestTrivyArgsEmitBothDepthForms(t *testing.T) {
	t.Parallel()

	ex := scan.Excludes{Dirs: []string{"node_modules"}, Files: []string{"*.min.js"}}
	got := ex.TrivyArgs()

	want := []string{
		"--skip-dirs", "node_modules",
		"--skip-dirs", "**/node_modules",
		"--skip-files", "*.min.js",
		"--skip-files", "**/*.min.js",
	}
	if !slices.Equal(got, want) {
		t.Errorf("TrivyArgs() = %q, want %q", got, want)
	}
}

func TestTrivyArgsNeverSkipDirsAsFiles(t *testing.T) {
	t.Parallel()

	ex := scan.DefaultExcludes()
	skipFiles := flagValues(ex.TrivyArgs(), "--skip-files")

	for _, dir := range ex.Dirs {
		if slices.Contains(skipFiles, dir) {
			t.Errorf("directory %q was emitted as --skip-files", dir)
		}
	}
}

func TestOpengrepArgsDirsHaveTrailingSlash(t *testing.T) {
	t.Parallel()

	ex := scan.DefaultExcludes()
	values := flagValues(ex.OpengrepArgs(), "--exclude")

	for _, dir := range ex.Dirs {
		if !slices.Contains(values, dir+"/") {
			t.Errorf("directory %q was not emitted as %q", dir, dir+"/")
		}
	}
	for _, file := range ex.Files {
		if !slices.Contains(values, file) {
			t.Errorf("file %q was not emitted verbatim", file)
		}
	}
}

// TestOSVArgsOmitFiles records that OSV-Scanner's flag excludes directories
// only, which is why Filter is the correctness mechanism rather than the flags.
func TestOSVArgsOmitFiles(t *testing.T) {
	t.Parallel()

	ex := scan.Excludes{Dirs: []string{"node_modules"}, Files: []string{"*.min.js"}}
	got := ex.OSVArgs()

	want := []string{"--experimental-exclude", "node_modules"}
	if !slices.Equal(got, want) {
		t.Errorf("OSVArgs() = %q, want %q", got, want)
	}
}

func TestTruffleHogPatternsCompileAndAreAnchored(t *testing.T) {
	t.Parallel()

	ex := scan.DefaultExcludes()
	patterns := ex.TruffleHogPatterns()

	if len(patterns) != len(ex.Dirs)+len(ex.Files) {
		t.Fatalf("got %d patterns for %d dirs and %d files",
			len(patterns), len(ex.Dirs), len(ex.Files))
	}

	for _, pattern := range patterns {
		if _, err := regexp.Compile(pattern); err != nil {
			t.Errorf("pattern %q does not compile: %v", pattern, err)
		}
		if !strings.HasPrefix(pattern, `(^|/)`) {
			t.Errorf("pattern %q is not anchored to a segment boundary", pattern)
		}
		if !strings.HasSuffix(pattern, "/") && !strings.HasSuffix(pattern, "$") {
			t.Errorf("pattern %q ends neither in a slash nor an anchor", pattern)
		}
	}
}

func TestTruffleHogPatternsMatchWhatTheyShould(t *testing.T) {
	t.Parallel()

	ex := scan.Excludes{Dirs: []string{"node_modules", "*.egg-info"}, Files: []string{"*.min.js"}}
	patterns := ex.TruffleHogPatterns()

	tests := []struct {
		path string
		want bool
	}{
		{"node_modules/lodash/index.js", true},
		{"web/node_modules/lodash/index.js", true},
		{"src/pindrop.egg-info/PKG-INFO", true},
		{"web/dist/app.min.js", true},
		{"internal/scan/finding.go", false},
		{"src/node_modules_helper.go", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()

			got := slices.ContainsFunc(patterns, func(p string) bool {
				return regexp.MustCompile(p).MatchString(tt.path)
			})
			if got != tt.want {
				t.Errorf("patterns matched %q = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestMergeIsDeterministic is what makes an adapter's argv assertable: an
// unsorted union would make the flag order depend on map iteration or on the
// order a config file happened to list things.
func TestMergeIsDeterministic(t *testing.T) {
	t.Parallel()

	a := scan.Excludes{Dirs: []string{"vendor", "node_modules"}, Files: []string{"*.map"}}
	b := scan.Excludes{Dirs: []string{"dist", "vendor"}, Files: []string{"*.map", "*.pyc"}}

	forward, backward := a.Merge(b), b.Merge(a)
	if !slices.Equal(forward.Dirs, backward.Dirs) || !slices.Equal(forward.Files, backward.Files) {
		t.Errorf("Merge is not order-independent: %+v versus %+v", forward, backward)
	}

	wantDirs := []string{"dist", "node_modules", "vendor"}
	if !slices.Equal(forward.Dirs, wantDirs) {
		t.Errorf("Dirs = %q, want %q sorted and deduplicated", forward.Dirs, wantDirs)
	}
	wantFiles := []string{"*.map", "*.pyc"}
	if !slices.Equal(forward.Files, wantFiles) {
		t.Errorf("Files = %q, want %q sorted and deduplicated", forward.Files, wantFiles)
	}
}

func TestFilter(t *testing.T) {
	t.Parallel()

	ex := scan.DefaultExcludes()
	findings := []scan.Finding{
		{RuleID: "kept", Location: scan.Location{Path: "internal/scan/finding.go"}},
		{RuleID: "dropped-dir", Location: scan.Location{Path: "web/node_modules/x/index.js"}},
		{RuleID: "dropped-file", Location: scan.Location{Path: "web/dist/app.min.js"}},
		{RuleID: "kept-env-file", Location: scan.Location{Path: "app/.env"}},
		// Cloud and cluster findings are identified by resource, not by file.
		// Dropping these would make an exclusion list delete a whole category.
		{RuleID: "kept-pathless", Location: scan.Location{}},
	}

	got := ex.Filter(findings)

	want := []string{"kept", "kept-env-file", "kept-pathless"}
	if len(got) != len(want) {
		t.Fatalf("Filter kept %d findings, want %d", len(got), len(want))
	}
	for i, rule := range want {
		if got[i].RuleID != rule {
			t.Errorf("kept[%d] = %q, want %q", i, got[i].RuleID, rule)
		}
	}
}

func TestFilterOnEmptyExcludesReturnsInput(t *testing.T) {
	t.Parallel()

	findings := []scan.Finding{{RuleID: "a"}, {RuleID: "b"}}
	if got := (scan.Excludes{}).Filter(findings); len(got) != len(findings) {
		t.Errorf("Filter with no patterns kept %d findings, want %d", len(got), len(findings))
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	if err := scan.DefaultExcludes().Validate(); err != nil {
		t.Fatalf("the built-in set does not validate: %v", err)
	}

	for _, ex := range []scan.Excludes{
		{Dirs: []string{"[unclosed"}},
		{Files: []string{"[unclosed"}},
		{Dirs: []string{""}},
	} {
		if err := ex.Validate(); err == nil {
			t.Errorf("Validate(%+v) returned no error", ex)
		}
	}
}

// flagValues returns the value following each occurrence of flag in args.
func flagValues(args []string, flag string) []string {
	var values []string
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			values = append(values, args[i+1])
		}
	}
	return values
}
