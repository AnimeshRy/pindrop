package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

func TestDecodeConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      string
		wantDirs  []string
		wantFiles []string
		wantAll   bool // ReplaceDefaults
	}{
		{
			name:      "exclusions",
			body:      `{"exclude":{"dirs":["third_party"],"files":["*.generated.go"]}}`,
			wantDirs:  []string{"third_party"},
			wantFiles: []string{"*.generated.go"},
		},
		{
			name:     "an explicit version matching this build",
			body:     `{"version":1,"exclude":{"dirs":["fixtures"]}}`,
			wantDirs: []string{"fixtures"},
		},
		{
			name:     "replaceDefaults",
			body:     `{"exclude":{"dirs":["only"],"replaceDefaults":true}}`,
			wantDirs: []string{"only"},
			wantAll:  true,
		},
		{
			// JSON has no comments, so one key is reserved for the purpose.
			name:     "a $comment is permitted and ignored",
			body:     `{"$comment":"why we skip these","exclude":{"dirs":["x"]}}`,
			wantDirs: []string{"x"},
		},
		{name: "an empty object", body: `{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeConfig(strings.NewReader(tt.body), ConfigName)
			if err != nil {
				t.Fatalf("decodeConfig() error = %v", err)
			}
			if !slices.Equal(got.Exclude.Dirs, tt.wantDirs) {
				t.Errorf("dirs = %q, want %q", got.Exclude.Dirs, tt.wantDirs)
			}
			if !slices.Equal(got.Exclude.Files, tt.wantFiles) {
				t.Errorf("files = %q, want %q", got.Exclude.Files, tt.wantFiles)
			}
			if got.Exclude.ReplaceDefaults != tt.wantAll {
				t.Errorf("replaceDefaults = %v, want %v", got.Exclude.ReplaceDefaults, tt.wantAll)
			}
		})
	}
}

// TestDecodeConfigErrors covers the messages a user actually has to act on.
// Our users are not security engineers, so a bare "invalid character" with no
// position is not something anyone can fix.
func TestDecodeConfigErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		body   string
		wantIn []string
	}{
		{
			name:   "malformed JSON names the position",
			body:   "{\n  \"exclude\": {\n    \"dirs\": [\"a\",]\n  }\n}",
			wantIn: []string{ConfigName, "line 3"},
		},
		{
			name:   "an unknown field is rejected rather than ignored",
			body:   `{"excludes":{"dirs":["a"]}}`,
			wantIn: []string{"unknown field", "excludes", "exclude.dirs"},
		},
		{
			name:   "a wrong type names the field",
			body:   `{"exclude":{"dirs":"notalist"}}`,
			wantIn: []string{ConfigName},
		},
		{
			name:   "a future schema version says what to do",
			body:   `{"version":2}`,
			wantIn: []string{"version 2", "upgrade pindrop"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := decodeConfig(strings.NewReader(tt.body), ConfigName)
			if err == nil {
				t.Fatalf("decodeConfig(%q) returned no error", tt.body)
			}
			for _, want := range tt.wantIn {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

// TestLoadConfigMissing covers the asymmetry: a repository need not carry a
// config, but a user who names one with --config and gets it wrong must be told
// rather than silently scanned with defaults.
func TestLoadConfigMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if _, err := loadConfig(dir, ""); err != nil {
		t.Errorf("an absent default config should not be an error: %v", err)
	}

	_, err := loadConfig(dir, filepath.Join(dir, "nope.json"))
	if err == nil {
		t.Error("an explicit --config that does not exist must be an error")
	}
}

func TestLoadConfigReadsTargetDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	body := `{"exclude":{"dirs":["from_target_dir"]}}`
	if err := os.WriteFile(filepath.Join(dir, ConfigName), []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	// Resolved against the scanned directory, not the process working
	// directory, so results do not depend on where pindrop was invoked from.
	got, err := loadConfig(dir, "")
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if !slices.Equal(got.Exclude.Dirs, []string{"from_target_dir"}) {
		t.Errorf("dirs = %q, want [from_target_dir]", got.Exclude.Dirs)
	}
}

// The resolution order is defaults, then config, then flags, and every step is
// additive. That is load-bearing: .git is in the built-in set for fingerprint
// stability rather than merely to reduce noise, so adding one project directory
// must not silently drop it.

func TestResolveExcludesAppliesDefaults(t *testing.T) {
	t.Parallel()

	defaults := scan.DefaultExcludes()

	got, err := resolveExcludes(config{}, nil, false)
	if err != nil {
		t.Fatalf("resolveExcludes() error = %v", err)
	}
	if !slices.Contains(got.Dirs, ".git") {
		t.Error(".git missing from the resolved set")
	}
	if len(got.Dirs) != len(defaults.Dirs) {
		t.Errorf("got %d dirs, want the %d built-in ones", len(got.Dirs), len(defaults.Dirs))
	}
}

func TestResolveExcludesConfigIsAdditive(t *testing.T) {
	t.Parallel()

	cfg := config{Exclude: configExclude{Dirs: []string{"third_party"}}}
	got, err := resolveExcludes(cfg, nil, false)
	if err != nil {
		t.Fatalf("resolveExcludes() error = %v", err)
	}
	for _, want := range []string{"third_party", ".git", "node_modules"} {
		if !slices.Contains(got.Dirs, want) {
			t.Errorf("%q missing from the resolved set", want)
		}
	}
}

func TestResolveExcludesFlagsStackOnConfig(t *testing.T) {
	t.Parallel()

	cfg := config{Exclude: configExclude{Dirs: []string{"from_config"}}}
	got, err := resolveExcludes(cfg, []string{"from_flag", "file:*.tmp"}, false)
	if err != nil {
		t.Fatalf("resolveExcludes() error = %v", err)
	}
	for _, want := range []string{"from_config", "from_flag", ".git"} {
		if !slices.Contains(got.Dirs, want) {
			t.Errorf("%q missing from dirs", want)
		}
	}
	if !slices.Contains(got.Files, "*.tmp") {
		t.Errorf("*.tmp missing from files: %q", got.Files)
	}
}

func TestResolveExcludesReplaceDefaults(t *testing.T) {
	t.Parallel()

	cfg := config{Exclude: configExclude{Dirs: []string{"only"}, ReplaceDefaults: true}}
	got, err := resolveExcludes(cfg, nil, false)
	if err != nil {
		t.Fatalf("resolveExcludes() error = %v", err)
	}
	if !slices.Equal(got.Dirs, []string{"only"}) {
		t.Errorf("dirs = %q, want [only]", got.Dirs)
	}
}

func TestResolveExcludesNoDefaultExcludesFlag(t *testing.T) {
	t.Parallel()

	got, err := resolveExcludes(config{}, []string{"just_this"}, true)
	if err != nil {
		t.Fatalf("resolveExcludes() error = %v", err)
	}
	if !slices.Equal(got.Dirs, []string{"just_this"}) {
		t.Errorf("dirs = %q, want [just_this]", got.Dirs)
	}
}

// A bad pattern must name where it came from, so the user knows which file or
// flag to go and fix.
func TestResolveExcludesBadPatternNamesItsSource(t *testing.T) {
	t.Parallel()

	if _, err := resolveExcludes(config{}, []string{"src/nested"}, false); err == nil ||
		!strings.Contains(err.Error(), "--exclude") {
		t.Errorf("error should name --exclude, got %v", err)
	}

	cfg := config{Exclude: configExclude{Dirs: []string{"[unclosed"}}}
	if _, err := resolveExcludes(cfg, nil, false); err == nil ||
		!strings.Contains(err.Error(), ConfigName) {
		t.Errorf("error should name %s, got %v", ConfigName, err)
	}
}
