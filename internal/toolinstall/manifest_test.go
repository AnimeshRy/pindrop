package toolinstall

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// wantTools is every scanner `pindrop setup` must be able to install. It is
// spelled out rather than derived from the manifest so that a tool accidentally
// dropped during a regeneration fails a test instead of silently disappearing
// from setup.
var wantTools = []string{"opengrep", "osv-scanner", "trivy", "trufflehog"}

// wantPlatforms is every platform key the manifest must cover. Windows is
// deliberately absent — see ADR 0012.
var wantPlatforms = []string{
	"darwin/amd64",
	"darwin/arm64",
	"linux/amd64",
	"linux/amd64+musl",
	"linux/arm64",
	"linux/arm64+musl",
}

func TestEmbeddedManifestLoads(t *testing.T) {
	t.Parallel()

	m, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := m.Names(); len(got) != len(wantTools) {
		t.Errorf("tools: got = %v, want %v", got, wantTools)
	}
	for _, name := range wantTools {
		if _, ok := m.Tool(name); !ok {
			t.Errorf("manifest is missing %q", name)
		}
	}
}

// TestEveryToolCoversEveryPlatform is the test that catches a forgotten
// `make manifest` after adding a platform: a missing entry means `pindrop setup`
// silently installs three of four scanners there.
func TestEveryToolCoversEveryPlatform(t *testing.T) {
	t.Parallel()

	m, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)

	for _, tool := range m.Tools {
		t.Run(tool.Name, func(t *testing.T) {
			t.Parallel()

			for _, key := range wantPlatforms {
				asset, ok := tool.Asset(key)
				if !ok {
					t.Errorf("%s has no asset for %s", tool.Name, key)
					continue
				}

				if !hex64.MatchString(asset.SHA256) {
					t.Errorf("%s/%s: digest %q is not a lowercase sha-256",
						tool.Name, key, asset.SHA256)
				}
				if asset.Size <= 0 {
					t.Errorf("%s/%s: got size = %d, want > 0", tool.Name, key, asset.Size)
				}
				if !strings.HasPrefix(asset.URL, "https://github.com/"+tool.Repo+"/") {
					t.Errorf("%s/%s: URL %q is not under the tool's own repo",
						tool.Name, key, asset.URL)
				}

				// The version must appear in the URL. This is the assertion that
				// catches the trap that a bump edited the version but left an
				// asset name — or its {version} substitution — behind.
				bare := strings.TrimPrefix(tool.Version, "v")
				if !strings.Contains(asset.URL, tool.Version) && !strings.Contains(asset.URL, bare) {
					t.Errorf("%s/%s: URL %q mentions neither %q nor %q",
						tool.Name, key, asset.URL, tool.Version, bare)
				}
				if strings.Contains(asset.URL, "{version}") {
					t.Errorf("%s/%s: URL %q has an unexpanded placeholder",
						tool.Name, key, asset.URL)
				}

				// Member is set if and only if the asset is an archive; a bare
				// binary with a member, or an archive without one, is a
				// generator bug that would surface only at install time.
				if (asset.Archive == ArchiveTarGz) != (asset.Member != "") {
					t.Errorf("%s/%s: archive = %q but member = %q",
						tool.Name, key, asset.Archive, asset.Member)
				}
			}
		})
	}
}

// TestOpengrepDigestsAreDistinctPerPlatform guards against the specific
// generator bug that would be invisible otherwise: Opengrep is the one tool whose
// digests come from downloads rather than an upstream checksum file, and it is
// also the one tool with a genuinely different binary per platform. Two platforms
// sharing a digest would mean the same asset was hashed twice.
func TestOpengrepDigestsAreDistinctPerPlatform(t *testing.T) {
	t.Parallel()

	m, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	tool, ok := m.Tool("opengrep")
	if !ok {
		t.Fatal("manifest is missing opengrep")
	}

	seen := map[string]string{}
	for _, key := range tool.SupportedKeys() {
		digest := tool.Platforms[key].SHA256
		if other, dup := seen[digest]; dup {
			t.Errorf("%s and %s share a digest; the same asset was hashed twice", key, other)
		}
		seen[digest] = key
	}
}

// TestManifestVersionsMatchTheMakefile keeps the pins from drifting.
//
// The Makefile, mise.toml, ci.yml and now this manifest have all held scanner
// versions at some point, and CLAUDE.md already flags that class of duplication.
// Until the Makefile's copies are removed entirely, assert they agree.
func TestManifestVersionsMatchTheMakefile(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Skipf("Makefile unavailable: %v", err)
	}

	// TRIVY_VERSION := v0.72.0
	pin := regexp.MustCompile(`(?m)^([A-Z_]+)_VERSION\s*:?=\s*(v[0-9][^\s]*)`)

	// Makefile variable prefix to manifest tool name.
	makeVar := map[string]string{
		"TRIVY":       "trivy",
		"OSV_SCANNER": "osv-scanner",
		"OPENGREP":    "opengrep",
		"TRUFFLEHOG":  "trufflehog",
	}

	m, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	var checked int
	for _, match := range pin.FindAllStringSubmatch(string(raw), -1) {
		name, ok := makeVar[match[1]]
		if !ok {
			continue // a Go tool pin, not a scanner
		}

		tool, ok := m.Tool(name)
		if !ok {
			t.Errorf("Makefile pins %s but the manifest has no %q", match[1], name)
			continue
		}
		if tool.Version != match[2] {
			t.Errorf("%s: Makefile pins %s, manifest pins %s — run `make manifest`",
				name, match[2], tool.Version)
		}
		checked++
	}

	if checked == 0 {
		// The Makefile no longer pins scanners, which is the intended end state.
		t.Skip("the Makefile pins no scanner versions; the manifest is the only source")
	}
}

func TestPlatformKeyFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		goos, goarch  string
		libc          Libc
		want          string
		wantUnchanged bool
	}{
		{
			name: "darwin ignores libc entirely",
			goos: "darwin", goarch: "arm64", libc: LibcMusl,
			want: "darwin/arm64",
		},
		{
			name: "explicit musl on linux",
			goos: "linux", goarch: "amd64", libc: LibcMusl,
			want: "linux/amd64+musl",
		},
		{
			name: "explicit gnu on linux never gets the suffix",
			goos: "linux", goarch: "arm64", libc: LibcGnu,
			want: "linux/arm64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := PlatformKeyFor(tt.goos, tt.goarch, tt.libc); got != tt.want {
				t.Errorf("got = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseLibc(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    Libc
		wantErr bool
	}{
		{in: "", want: LibcAuto},
		{in: "auto", want: LibcAuto},
		{in: "musl", want: LibcMusl},
		{in: "gnu", want: LibcGnu},
		{in: "glibc", want: LibcGnu},
		{in: "uclibc", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()

			got, err := ParseLibc(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("got = %q with nil error, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeManifestRejectsBadDocuments(t *testing.T) {
	t.Parallel()

	const goodPlatform = `"darwin/arm64":{"url":"https://github.com/a/b/releases/download/v1/x",
		"sha256":"0000000000000000000000000000000000000000000000000000000000000000","size":1}`

	tests := []struct {
		name string
		json string
	}{
		{
			name: "wrong schema version",
			json: `{"schema":99,"tools":[]}`,
		},
		{
			name: "no tools",
			json: `{"schema":1,"tools":[]}`,
		},
		{
			name: "unknown field from a hand edit",
			json: `{"schema":1,"tolls":[]}`,
		},
		{
			name: "http url",
			json: `{"schema":1,"tools":[{"name":"t","version":"v1","platforms":{
				"darwin/arm64":{"url":"http://example.com/x","size":1,
				"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}}}]}`,
		},
		{
			name: "uppercase digest",
			json: `{"schema":1,"tools":[{"name":"t","version":"v1","platforms":{
				"darwin/arm64":{"url":"https://example.com/x","size":1,
				"sha256":"AAAA000000000000000000000000000000000000000000000000000000000000"}}}]}`,
		},
		{
			name: "truncated digest",
			json: `{"schema":1,"tools":[{"name":"t","version":"v1","platforms":{
				"darwin/arm64":{"url":"https://example.com/x","size":1,"sha256":"abc"}}}]}`,
		},
		{
			name: "zero size",
			json: `{"schema":1,"tools":[{"name":"t","version":"v1","platforms":{
				"darwin/arm64":{"url":"https://example.com/x","size":0,
				"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}}}]}`,
		},
		{
			name: "unsupported archive format",
			json: `{"schema":1,"tools":[{"name":"t","version":"v1","platforms":{
				"darwin/arm64":{"url":"https://example.com/x","size":1,"archive":"zip","member":"t",
				"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}}}]}`,
		},
		{
			name: "archive without a member",
			json: `{"schema":1,"tools":[{"name":"t","version":"v1","platforms":{
				"darwin/arm64":{"url":"https://example.com/x","size":1,"archive":"tar.gz",
				"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}}}]}`,
		},
		{
			name: "member without an archive",
			json: `{"schema":1,"tools":[{"name":"t","version":"v1","platforms":{
				"darwin/arm64":{"url":"https://example.com/x","size":1,"member":"t",
				"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}}}]}`,
		},
		{
			name: "tool with no platforms",
			json: `{"schema":1,"tools":[{"name":"t","version":"v1","platforms":{}}]}`,
		},
		{
			name: "tool with no version",
			json: `{"schema":1,"tools":[{"name":"t","platforms":{` + goodPlatform + `}}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if m, err := decodeManifest(strings.NewReader(tt.json)); err == nil {
				t.Errorf("got = %+v with nil error, want an error", m)
			}
		})
	}
}
