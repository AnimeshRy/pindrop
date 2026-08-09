// Package toolinstall downloads, verifies, and installs the scanner binaries
// Pindrop drives, into the directory named by internal/toolpath.
//
// # Why Pindrop installs its own tools
//
// Pindrop ships as one binary and drives four separate executables. Telling a
// non-expert to install Trivy, OSV-Scanner, Opengrep, and TruffleHog by hand
// before the product does anything is the point at which most people stop, so
// `pindrop setup` does it for them.
//
// # Integrity
//
// Every download is checked against a SHA-256 digest committed in [manifest.json]
// and embedded in the binary. A file that does not match is deleted and never
// made executable.
//
// Be precise about what that buys. It gives **immutability, not provenance**: a
// release asset cannot be swapped out after we pinned it, which is the actual
// failure mode when an upstream release is retagged or a channel is compromised
// — the thing that happened to Trivy twice in 2026. It cannot detect a release
// that was already malicious when the digest was captured. Sigstore verification
// would close that gap and is a deliberate follow-up; see ADR 0011.
//
// # TruffleHog
//
// TruffleHog is AGPL-3.0. Fetching its published binary over HTTPS is not
// linking: nothing about it enters go.mod, and `go mod graph` will never mention
// it. That is exactly the relationship the Makefile already had, moved into Go,
// and it is why this package holds a URL and a hex string rather than an import.
package toolinstall

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"sort"
	"strings"
)

// manifestFile holds the pinned versions and digests.
//
// Embedded rather than read from disk because verification has to work on a
// machine with no network and no checkout — the digest must travel inside the
// binary that uses it.
//
//go:embed manifest.json
var manifestFile embed.FS

// SchemaVersion is the manifest layout this build understands. It is checked on
// decode so that a manifest from a newer Pindrop fails loudly rather than being
// half-understood.
const SchemaVersion = 1

// Archive names how an asset is packaged.
type Archive string

// Supported packaging. Two of the four tools ship a bare executable and two ship
// a gzipped tarball; nothing else is accepted, and zip waits for Windows support.
const (
	ArchiveNone  Archive = ""
	ArchiveTarGz Archive = "tar.gz"
)

// Manifest is the decoded contents of manifest.json.
type Manifest struct {
	Schema int `json:"schema"`
	// Generated is the date the digests were captured, for the release checklist.
	Generated string `json:"generated"`
	Tools     []Tool `json:"tools"`
}

// A Tool is one scanner Pindrop can install.
type Tool struct {
	// Name is the executable's name, which is what gets installed and what
	// toolpath.Lookup searches for.
	//
	// It is not always the scanner's name: the OSV adapter reports "osv" while
	// its binary is "osv-scanner". Keying on the binary name is deliberate,
	// since this package's whole job is producing files on disk.
	Name string `json:"name"`
	// Version is the upstream release tag, including any leading "v".
	Version string `json:"version"`
	// Repo is "owner/name" on GitHub, shown in the setup prompt so a user can
	// see which hosts are about to be contacted.
	Repo string `json:"repo"`
	// Checksums is the URL of the upstream checksum file the digests below were
	// cross-checked against, or empty when upstream publishes none.
	//
	// Opengrep is the empty case: it publishes sigstore .sig/.cert files but no
	// checksum list, so its digests are trust-on-first-pin. Recorded here rather
	// than in a comment because the generator reads it.
	Checksums string               `json:"checksums,omitempty"`
	Platforms map[string]*Platform `json:"platforms"`
}

// A Platform is one downloadable asset for one platform.
type Platform struct {
	// URL is the fully-resolved download URL.
	//
	// Literal per platform rather than built from a template on purpose. The
	// four tools disagree on every axis — macOS-ARM64 vs darwin_arm64 vs
	// osx_arm64 vs manylinux_x86, "v"-prefixed tags against stripped versions,
	// archive against bare binary. A template encoding all of that is
	// unreadable and its mistakes are invisible; a literal URL is auditable in a
	// diff, which is the property that matters for the file guarding the supply
	// chain.
	URL string `json:"url"`
	// SHA256 is the hex digest of the asset at URL, lowercase.
	SHA256 string `json:"sha256"`
	// Size is the asset's size in bytes, so the setup prompt can state what it
	// is about to download without a network round trip.
	Size int64 `json:"size"`
	// Archive is how the asset is packaged.
	Archive Archive `json:"archive,omitempty"`
	// Member is the path of the executable inside the archive. Set if and only if
	// Archive is set.
	Member string `json:"member,omitempty"`
}

// Load decodes the embedded manifest.
func Load() (*Manifest, error) {
	f, err := manifestFile.Open("manifest.json")
	if err != nil {
		return nil, fmt.Errorf("opening the embedded manifest: %w", err)
	}
	defer func() { _ = f.Close() }()

	return decodeManifest(f)
}

// decodeManifest reads and validates a manifest document.
func decodeManifest(r io.Reader) (*Manifest, error) {
	dec := json.NewDecoder(r)
	// A misspelled key in a hand-edited manifest must fail rather than silently
	// leaving a digest empty.
	dec.DisallowUnknownFields()

	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decoding the scanner manifest: %w", err)
	}
	if m.Schema != SchemaVersion {
		return nil, fmt.Errorf(
			"scanner manifest schema %d, want %d; this pindrop build is too old for it",
			m.Schema, SchemaVersion)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// validate rejects a structurally impossible manifest. It runs on every load, so
// a hand-edit that breaks an invariant fails at startup rather than mid-install.
func (m *Manifest) validate() error {
	if len(m.Tools) == 0 {
		return fmt.Errorf("the scanner manifest lists no tools")
	}
	for _, t := range m.Tools {
		if t.Name == "" || t.Version == "" {
			return fmt.Errorf("scanner manifest: a tool is missing its name or version")
		}
		if len(t.Platforms) == 0 {
			return fmt.Errorf("scanner manifest: %s lists no platforms", t.Name)
		}
		for key, p := range t.Platforms {
			if err := p.validate(t.Name, key); err != nil {
				return err
			}
		}
	}
	return nil
}

// validate checks one platform entry.
func (p *Platform) validate(tool, key string) error {
	switch {
	case !strings.HasPrefix(p.URL, "https://"):
		return fmt.Errorf("scanner manifest: %s/%s URL is not https", tool, key)
	case len(p.SHA256) != 64 || strings.ToLower(p.SHA256) != p.SHA256:
		return fmt.Errorf("scanner manifest: %s/%s digest is not a lowercase sha-256", tool, key)
	case p.Size <= 0:
		return fmt.Errorf("scanner manifest: %s/%s has no size", tool, key)
	case p.Archive != ArchiveNone && p.Archive != ArchiveTarGz:
		return fmt.Errorf("scanner manifest: %s/%s has unsupported archive %q", tool, key, p.Archive)
	case p.Archive == ArchiveNone && p.Member != "":
		return fmt.Errorf("scanner manifest: %s/%s names a member but is not an archive", tool, key)
	case p.Archive != ArchiveNone && p.Member == "":
		return fmt.Errorf("scanner manifest: %s/%s is an archive but names no member", tool, key)
	}
	return nil
}

// Tool returns the entry for the named binary.
func (m *Manifest) Tool(name string) (Tool, bool) {
	for _, t := range m.Tools {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

// Names lists every installable tool, in manifest order.
func (m *Manifest) Names() []string {
	names := make([]string, 0, len(m.Tools))
	for _, t := range m.Tools {
		names = append(names, t.Name)
	}
	return names
}

// PlatformKeys lists every platform key the manifest mentions, sorted. It exists
// for the unsupported-platform message and for tests.
func (m *Manifest) PlatformKeys() []string {
	seen := map[string]bool{}
	for _, t := range m.Tools {
		for key := range t.Platforms {
			seen[key] = true
		}
	}

	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// PlatformKey is the manifest key for the running machine, such as
// "darwin/arm64" or "linux/amd64+musl".
//
// The key is derived from runtime.GOOS and runtime.GOARCH rather than by running
// uname. We are the Go binary; shelling out to describe ourselves is how the
// Makefile's Opengrep rule ended up with a case statement over uname output.
func PlatformKey() string { return PlatformKeyFor(runtime.GOOS, runtime.GOARCH, LibcAuto) }

// PlatformKeyFor builds a platform key from explicit values, so the mapping can
// be tested without pretending to be another machine.
func PlatformKeyFor(goos, goarch string, libc Libc) string {
	key := goos + "/" + goarch
	if goos != "linux" {
		return key
	}

	switch libc {
	case LibcMusl:
		return key + "+musl"
	case LibcGnu:
		return key
	default:
		if isMusl() {
			return key + "+musl"
		}
		return key
	}
}

// Asset returns the download for the given platform key.
func (t Tool) Asset(key string) (*Platform, bool) {
	p, ok := t.Platforms[key]
	return p, ok
}

// SupportedKeys reports which platform keys t supports, sorted.
func (t Tool) SupportedKeys() []string {
	keys := make([]string, 0, len(t.Platforms))
	for key := range t.Platforms {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// muslMarkers are the musl dynamic loaders. Only Opengrep's asset differs by libc
// — the other three tools are static Go binaries — but that one difference is the
// difference between working and a cryptic loader error on Alpine.
var muslMarkers = []string{
	"/lib/ld-musl-x86_64.so.1",
	"/lib/ld-musl-aarch64.so.1",
}

// Libc selects which C library variant to install for. Only Opengrep publishes
// separate builds; the other three tools are static Go binaries.
type Libc string

// Libc variants. LibcAuto detects from the filesystem.
const (
	LibcAuto Libc = "auto"
	LibcGnu  Libc = "gnu"
	LibcMusl Libc = "musl"
)

// ParseLibc validates a --libc value.
func ParseLibc(value string) (Libc, error) {
	switch Libc(value) {
	case "", LibcAuto:
		return LibcAuto, nil
	case LibcGnu, LibcMusl:
		return Libc(value), nil
	case "glibc":
		return LibcGnu, nil
	default:
		return "", fmt.Errorf("invalid --libc %q: want auto, gnu, or musl", value)
	}
}

// isMusl reports whether the running Linux system uses musl rather than glibc.
//
// Detected by the presence of musl's dynamic loader, which is the cheapest
// reliable signal: no subprocess and no cgo. A false negative installs a glibc
// Opengrep that fails to start with a loader error, which is why PlatformKeyFor
// accepts an explicit override.
func isMusl() bool {
	for _, marker := range muslMarkers {
		if _, err := os.Stat(marker); err == nil {
			return true
		}
	}
	return false
}

// UnsupportedPlatformError reports that a tool publishes no asset for this
// machine.
//
// It is not fatal on its own. A platform without an Opengrep build should still
// get the other three scanners, for the same reason a missing scanner does not
// fail a scan: reduced coverage beats no product.
type UnsupportedPlatformError struct {
	Tool     string
	Platform string
	// Supported lists the platform keys the tool does publish.
	Supported []string
	// Flag is the --<tool>-binary escape hatch for pointing at a manual install.
	Flag string
}

// Error implements the error interface.
func (e *UnsupportedPlatformError) Error() string {
	msg := fmt.Sprintf("%s publishes no build for %s", e.Tool, e.Platform)
	if len(e.Supported) > 0 {
		msg += fmt.Sprintf("\n  It supports: %s", strings.Join(e.Supported, ", "))
	}
	if e.Flag != "" {
		msg += fmt.Sprintf("\n  Install it yourself and point at it with %s /path/to/%s", e.Flag, e.Tool)
	}
	return msg
}

// Select resolves the assets to install for this platform.
//
// only, when non-empty, restricts the result to the named tools. Tools with no
// build for this platform are returned separately as errors rather than omitted,
// so the caller can report them instead of silently installing three of four.
func (m *Manifest) Select(only []string, libc Libc) ([]Selected, []error) {
	key := PlatformKeyFor(runtime.GOOS, runtime.GOARCH, libc)

	var (
		out  []Selected
		errs []error
	)
	for _, t := range m.Tools {
		if len(only) > 0 && !slices.Contains(only, t.Name) {
			continue
		}

		asset, ok := t.Asset(key)
		if !ok {
			errs = append(errs, &UnsupportedPlatformError{
				Tool:      t.Name,
				Platform:  key,
				Supported: t.SupportedKeys(),
				Flag:      "--" + flagName(t.Name) + "-binary",
			})
			continue
		}
		out = append(out, Selected{Tool: t, Platform: key, Asset: asset})
	}
	return out, errs
}

// Selected is one tool resolved to a concrete download.
type Selected struct {
	Tool     Tool
	Platform string
	Asset    *Platform
}

// flagName maps a binary name to the CLI flag that overrides it. The OSV adapter
// is the reason this is not the identity function: its binary is "osv-scanner"
// but the flag is --osv-binary.
func flagName(binary string) string {
	if binary == "osv-scanner" {
		return "osv"
	}
	return binary
}
