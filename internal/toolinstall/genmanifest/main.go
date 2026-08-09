// Command genmanifest regenerates internal/toolinstall/manifest.json, the pinned
// versions and SHA-256 digests `pindrop setup` verifies its downloads against.
//
// Run it with `make manifest` after changing a scanner version. The digests it
// writes are what makes an upstream release immutable from Pindrop's point of
// view, so the output diff is the thing to review carefully — see ADR 0011.
//
// Digests come from upstream's own published checksum file wherever one exists,
// and a mismatch aborts generation. That makes the manifest a cross-check of two
// independently published values rather than a record of whatever this machine
// happened to download. Opengrep publishes no checksum file, only sigstore
// signatures, so its digest is computed from a download and is trust-on-first-pin;
// the tool prints the cosign command to verify it by hand.
//
// It lives under internal/ rather than cmd/ deliberately: cmd/ holds exactly one
// program, the one GoReleaser ships, and a second main there is an accident
// waiting to be released.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/AnimeshRy/pindrop/internal/toolinstall"
)

// platforms are the platform keys the manifest covers.
//
// Windows is absent on purpose: Opengrep publishes no windows/arm64 build at all,
// and shipping a pindrop.exe that cannot install its own scanners is a support
// burden with no upside. See ADR 0012.
var platforms = []string{
	"darwin/amd64",
	"darwin/arm64",
	"linux/amd64",
	"linux/arm64",
	"linux/amd64+musl",
	"linux/arm64+musl",
}

// source describes one tool's upstream release, and is the only hand-maintained
// table in the system. Bumping a scanner means editing a version here and
// re-running.
type source struct {
	// binary is the executable's name, and the manifest key.
	binary string
	repo   string
	tag    string
	// checksums is the upstream checksum asset's name, or "" when upstream
	// publishes none.
	checksums string
	archive   toolinstall.Archive
	// member is the path inside the archive; empty for a bare binary.
	member string
	// asset maps a platform key to the release asset's file name. Returning ""
	// means the tool publishes nothing for that platform.
	asset func(key string) string
}

// version strips the leading "v" from a tag, which Trivy and TruffleHog do in
// their asset names and OSV-Scanner and Opengrep do not.
func version(tag string) string { return strings.TrimPrefix(tag, "v") }

var sources = []source{
	{
		binary:    "trivy",
		repo:      "aquasecurity/trivy",
		tag:       "v0.72.0",
		checksums: "trivy_{version}_checksums.txt",
		archive:   toolinstall.ArchiveTarGz,
		member:    "trivy",
		// Trivy's own vocabulary: macOS/Linux capitalized, "64bit" for amd64.
		// Its static Go binary is libc-independent, so musl reuses the glibc asset.
		asset: func(key string) string {
			switch strings.TrimSuffix(key, "+musl") {
			case "darwin/amd64":
				return "trivy_{version}_macOS-64bit.tar.gz"
			case "darwin/arm64":
				return "trivy_{version}_macOS-ARM64.tar.gz"
			case "linux/amd64":
				return "trivy_{version}_Linux-64bit.tar.gz"
			case "linux/arm64":
				return "trivy_{version}_Linux-ARM64.tar.gz"
			}
			return ""
		},
	},
	{
		binary: "osv-scanner",
		repo:   "google/osv-scanner",
		tag:    "v2.4.0",
		// Not the goreleaser-conventional name the other two use.
		checksums: "osv-scanner_SHA256SUMS",
		// A bare executable, not an archive — the simplest of the four.
		archive: toolinstall.ArchiveNone,
		asset: func(key string) string {
			base := strings.TrimSuffix(key, "+musl")
			if !slices.Contains([]string{
				"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64",
			}, base) {
				return ""
			}
			return "osv-scanner_" + strings.ReplaceAll(base, "/", "_")
		},
	},
	{
		binary: "opengrep",
		repo:   "opengrep/opengrep",
		tag:    "v1.26.0",
		// Opengrep publishes .sig and .cert per asset, but no checksum list.
		checksums: "",
		// A bare executable. Note it must be the opengrep_* asset and never
		// opengrep-core_*, which is the internal OCaml engine alone — the single
		// file already embeds it.
		archive: toolinstall.ArchiveNone,
		// The only tool whose asset differs by libc, because it is not a Go binary.
		asset: func(key string) string {
			switch key {
			case "darwin/amd64":
				return "opengrep_osx_x86"
			case "darwin/arm64":
				return "opengrep_osx_arm64"
			case "linux/amd64":
				return "opengrep_manylinux_x86"
			case "linux/arm64":
				return "opengrep_manylinux_aarch64"
			case "linux/amd64+musl":
				return "opengrep_musllinux_x86"
			case "linux/arm64+musl":
				return "opengrep_musllinux_aarch64"
			}
			return ""
		},
	},
	{
		binary:    "trufflehog",
		repo:      "trufflesecurity/trufflehog",
		tag:       "v3.96.0",
		checksums: "trufflehog_{version}_checksums.txt",
		archive:   toolinstall.ArchiveTarGz,
		member:    "trufflehog",
		asset: func(key string) string {
			base := strings.TrimSuffix(key, "+musl")
			if !slices.Contains([]string{
				"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64",
			}, base) {
				return ""
			}
			return "trufflehog_{version}_" + strings.ReplaceAll(base, "/", "_") + ".tar.gz"
		},
	},
}

func main() {
	out := flag.String("out", "internal/toolinstall/manifest.json", "path to write")
	only := flag.String("tool", "", "regenerate only this tool")
	check := flag.Bool("check", false, "verify the committed manifest against upstream without writing")
	flag.Parse()

	if err := run(*out, *only, *check); err != nil {
		fmt.Fprintf(os.Stderr, "genmanifest: %v\n", err)
		os.Exit(1)
	}
}

func run(out, only string, check bool) error {
	client := &http.Client{Timeout: 10 * time.Minute}

	manifest := toolinstall.Manifest{
		Schema:    toolinstall.SchemaVersion,
		Generated: time.Now().UTC().Format(time.DateOnly),
	}

	for _, src := range sources {
		if only != "" && src.binary != only {
			continue
		}

		fmt.Fprintf(os.Stderr, "%s %s\n", src.binary, src.tag)
		tool, err := src.build(client)
		if err != nil {
			return fmt.Errorf("%s: %w", src.binary, err)
		}
		manifest.Tools = append(manifest.Tools, tool)
	}

	if only != "" {
		// Regenerating one tool must not drop the others.
		existing, err := readManifest(out)
		if err != nil {
			return err
		}
		manifest.Tools = merge(existing.Tools, manifest.Tools)
	}

	encoded, err := encode(manifest)
	if err != nil {
		return err
	}

	if check {
		return compare(out, encoded)
	}
	if err := os.WriteFile(out, encoded, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", out, err)
	}
	fmt.Fprintf(os.Stderr, "\nwrote %s\n", out)
	return nil
}

// downloadURL is a release asset's canonical location.
//
// Built directly rather than looked up through the GitHub API, for two reasons:
// the API's unauthenticated limit is 60 requests an hour, which makes `make
// manifest` fail for anyone without a token; and release downloads are served
// from a different host that imposes no such limit. A misspelled asset name still
// fails loudly, as a 404 from the HEAD below.
func (s source) downloadURL(assetName string) string {
	return fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", s.repo, s.tag, assetName)
}

// build resolves every platform's asset for one tool.
func (s source) build(client *http.Client) (toolinstall.Tool, error) {
	// Upstream digests, when published. Fetched once for the whole tool.
	var (
		published map[string]string
		err       error
	)
	if s.checksums != "" {
		if published, err = fetchChecksums(client, s.downloadURL(s.expand(s.checksums))); err != nil {
			return toolinstall.Tool{}, err
		}
	} else {
		fmt.Fprintf(os.Stderr, "  no upstream checksum file; digests are trust-on-first-pin\n")
	}

	tool := toolinstall.Tool{
		Name:      s.binary,
		Version:   s.tag,
		Repo:      s.repo,
		Platforms: map[string]*toolinstall.Platform{},
	}
	if s.checksums != "" {
		tool.Checksums = s.downloadURL(s.expand(s.checksums))
	}

	for _, key := range platforms {
		name := s.expand(s.asset(key))
		if name == "" {
			fmt.Fprintf(os.Stderr, "  %-18s no build published\n", key)
			continue
		}
		url := s.downloadURL(name)

		size, err := assetSize(client, url)
		if err != nil {
			return toolinstall.Tool{}, err
		}

		digest, from := published[name], "upstream checksums"
		if digest == "" {
			if s.checksums != "" {
				return toolinstall.Tool{}, fmt.Errorf(
					"%q is missing from upstream's checksum file", name)
			}
			if digest, err = hashAsset(client, url); err != nil {
				return toolinstall.Tool{}, fmt.Errorf("hashing %s: %w", name, err)
			}
			from = "downloaded"
		}

		tool.Platforms[key] = &toolinstall.Platform{
			URL:     url,
			SHA256:  digest,
			Size:    size,
			Archive: s.archive,
			Member:  s.member,
		}
		fmt.Fprintf(os.Stderr, "  %-18s %-42s %5.1f MB  %s\n",
			key, name, float64(size)/1e6, from)
	}

	if len(tool.Platforms) == 0 {
		return toolinstall.Tool{}, fmt.Errorf("no supported platform")
	}
	if s.checksums == "" {
		s.printCosignHint(tool)
	}
	return tool, nil
}

// assetSize reports a release asset's size, and doubles as the check that the
// asset name in the table above is real.
func assetSize(client *http.Client, url string) (int64, error) {
	resp, err := client.Head(url)
	if err != nil {
		return 0, fmt.Errorf("checking %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("checking %s: %s (is the asset name right?)", url, resp.Status)
	}
	if resp.ContentLength <= 0 {
		return 0, fmt.Errorf("checking %s: no content length", url)
	}
	return resp.ContentLength, nil
}

// printCosignHint tells the operator how to verify a trust-on-first-pin digest by
// hand. Deliberately a printed command rather than a Go dependency: adding cosign
// to go.mod to close this gap would add far more supply-chain surface than it
// removes.
func (s source) printCosignHint(tool toolinstall.Tool) {
	fmt.Fprintf(os.Stderr, "\n  Verify %s by hand before committing:\n", s.binary)
	for _, key := range sortedKeys(tool.Platforms) {
		asset := filepath.Base(tool.Platforms[key].URL)
		fmt.Fprintf(os.Stderr,
			"    cosign verify-blob --certificate-identity-regexp '.*' \\\n"+
				"      --certificate-oidc-issuer-regexp '.*' \\\n"+
				"      --certificate %[1]s.cert --signature %[1]s.sig %[1]s\n", asset)
		break // one worked example is enough; the rest follow the same shape
	}
	fmt.Fprintln(os.Stderr)
}

// expand substitutes {version} in an asset name.
func (s source) expand(name string) string {
	return strings.ReplaceAll(name, "{version}", version(s.tag))
}

// fetchChecksums parses a "<digest>  <filename>" list.
func fetchChecksums(client *http.Client, url string) (map[string]string, error) {
	body, err := get(client, url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()

	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", url, err)
	}

	out := map[string]string{}
	for line := range strings.Lines(string(raw)) {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 {
			continue
		}
		// Some tools prefix the name with "*" for binary mode.
		out[strings.TrimPrefix(fields[1], "*")] = strings.ToLower(fields[0])
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no digests found in %s", url)
	}
	return out, nil
}

// hashAsset downloads url and returns its SHA-256, streaming so a 45 MB binary is
// never held in memory.
func hashAsset(client *http.Client, url string) (string, error) {
	body, err := get(client, url)
	if err != nil {
		return "", err
	}
	defer func() { _ = body.Close() }()

	sum := sha256.New()
	if _, err := io.Copy(sum, body); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// get performs a GET, returning the body for the caller to close.
func get(client *http.Client, url string) (io.ReadCloser, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("fetching %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}

// encode renders the manifest with stable key order and a trailing newline, so
// regenerating without a change produces no diff.
func encode(m toolinstall.Manifest) ([]byte, error) {
	// Sort tools by name so the file order does not depend on the sources table.
	sort.Slice(m.Tools, func(i, j int) bool { return m.Tools[i].Name < m.Tools[j].Name })

	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	// Digests contain no HTML-significant characters, and escaping them would
	// make the file harder to compare against upstream by eye.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("encoding the manifest: %w", err)
	}
	return []byte(buf.String()), nil
}

// readManifest loads the committed manifest for a partial regeneration.
func readManifest(path string) (toolinstall.Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return toolinstall.Manifest{}, fmt.Errorf("reading %s: %w", path, err)
	}

	var m toolinstall.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return toolinstall.Manifest{}, fmt.Errorf("decoding %s: %w", path, err)
	}
	return m, nil
}

// merge replaces entries in old with same-named entries from fresh.
func merge(old, fresh []toolinstall.Tool) []toolinstall.Tool {
	out := append([]toolinstall.Tool(nil), old...)
	for _, f := range fresh {
		if i := slices.IndexFunc(out, func(t toolinstall.Tool) bool { return t.Name == f.Name }); i >= 0 {
			out[i] = f
			continue
		}
		out = append(out, f)
	}
	return out
}

// compare implements -check: the committed manifest must match what upstream
// publishes today. A difference means either a pending regeneration or a
// re-tagged upstream release, which is the incident this catches.
func compare(path string, fresh []byte) error {
	committed, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	// The generated timestamp is expected to differ; nothing else may.
	if normalize(committed) == normalize(fresh) {
		fmt.Fprintln(os.Stderr, "\nmanifest matches upstream")
		return nil
	}
	return fmt.Errorf("%s does not match upstream; run `make manifest` and review the diff", path)
}

// normalize drops the generated date so -check compares only the pinned content.
func normalize(raw []byte) string {
	var out []string
	for line := range strings.Lines(string(raw)) {
		if strings.Contains(line, `"generated"`) {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "")
}

// sortedKeys returns a map's keys in sorted order.
func sortedKeys(m map[string]*toolinstall.Platform) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
