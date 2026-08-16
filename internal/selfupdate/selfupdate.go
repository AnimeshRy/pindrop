package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	owner         = "AnimeshRy"
	repo          = "pindrop"
	maxMemberSize = 512 << 20
	binaryName    = "pindrop"
	binaryNameWin = "pindrop.exe"
)

// Release is the subset of a GitHub release we need.
type Release struct {
	TagName string  `json:"tag_name"`
	HTMLURL string  `json:"html_url"`
	Assets  []Asset `json:"assets"`
}

// Asset is one downloadable file in a release.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// Result is the outcome of checking for updates.
type Result struct {
	Current   string
	Latest    string
	Available bool
	Release   *Release
	Asset     *Asset
}

// Check queries the GitHub Releases API for the latest release.
func Check(ctx context.Context, currentVersion string) (*Result, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "pindrop-self-update")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("checking for updates: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return &Result{Current: currentVersion, Available: false}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decoding release: %w", err)
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	current := strings.TrimPrefix(currentVersion, "v")

	result := &Result{
		Current:   current,
		Latest:    latest,
		Available: latest != current && currentVersion != "dev",
		Release:   &release,
		Asset:     findAsset(release.Assets, runtime.GOOS, runtime.GOARCH),
	}
	return result, nil
}

// Apply downloads the asset and atomically replaces the current executable.
func Apply(ctx context.Context, asset *Asset) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating executable: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("resolving symlinks: %w", err)
	}

	dir := filepath.Dir(execPath)
	tmp, err := os.CreateTemp(dir, ".pindrop-update-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.BrowserDownloadURL, nil)
	if err != nil {
		_ = tmp.Close()
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("downloading update: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_ = tmp.Close()
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	if err := extractBinary(resp.Body, asset.Name, tmp); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("extracting binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	info, err := os.Stat(execPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, info.Mode()); err != nil {
		return err
	}

	return os.Rename(tmpPath, execPath)
}

func findAsset(assets []Asset, goos, goarch string) *Asset {
	archAliases := map[string][]string{
		"amd64": {"amd64", "x86_64"},
		"arm64": {"arm64", "aarch64"},
	}

	wantOS := strings.ToLower(goos)
	wantArchList := archAliases[goarch]
	if wantArchList == nil {
		wantArchList = []string{goarch}
	}

	for i, a := range assets {
		name := strings.ToLower(a.Name)
		if !strings.Contains(name, wantOS) {
			continue
		}
		for _, arch := range wantArchList {
			if strings.Contains(name, arch) {
				return &assets[i]
			}
		}
	}
	return nil
}

func extractBinary(r io.Reader, assetName string, dest *os.File) error {
	name := strings.ToLower(assetName)
	switch {
	case strings.HasSuffix(name, ".zip"):
		return extractZip(r, dest)
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".tgz"):
		return extractTarGz(r, dest)
	default:
		return fmt.Errorf("unsupported archive format in %q", assetName)
	}
}

func extractTarGz(r io.Reader, dest *os.File) error {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("reading gzip: %w", err)
	}
	defer func() { _ = zr.Close() }()

	tr := tar.NewReader(zr)
	want := wantedBinaryName()

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("archive does not contain %q", want)
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}

		name, err := safeName(header.Name)
		if err != nil {
			return err
		}
		if path.Base(name) != want {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return fmt.Errorf("%s in the archive is not a regular file", want)
		}
		if header.Size > maxMemberSize {
			return fmt.Errorf("%s declares %d bytes, above the %d-byte limit",
				want, header.Size, int64(maxMemberSize))
		}
		return copyMember(tr, header.Size, dest)
	}
}

func extractZip(r io.Reader, dest *os.File) error {
	data, err := io.ReadAll(io.LimitReader(r, maxMemberSize+1))
	if err != nil {
		return fmt.Errorf("reading zip: %w", err)
	}
	if int64(len(data)) > maxMemberSize {
		return fmt.Errorf("zip archive exceeds the %d-byte limit", maxMemberSize)
	}

	zr, err := zip.NewReader(bytesReaderAt(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("reading zip: %w", err)
	}

	want := wantedBinaryName()
	for _, f := range zr.File {
		name, err := safeName(f.Name)
		if err != nil {
			return err
		}
		if path.Base(name) != want {
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s in the archive is a symlink", want)
		}
		if f.UncompressedSize64 > maxMemberSize {
			return fmt.Errorf("%s declares %d bytes, above the %d-byte limit",
				want, f.UncompressedSize64, int64(maxMemberSize))
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("opening %s: %w", want, err)
		}
		err = copyMember(rc, int64(f.UncompressedSize64), dest)
		closeErr := rc.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		return nil
	}
	return fmt.Errorf("archive does not contain %q", want)
}

func wantedBinaryName() string {
	if runtime.GOOS == "windows" {
		return binaryNameWin
	}
	return binaryName
}

func safeName(name string) (string, error) {
	if strings.HasPrefix(name, "/") || filepath.IsAbs(name) {
		return "", fmt.Errorf("archive entry %q is an absolute path", name)
	}
	if strings.ContainsAny(name, `\:`) {
		return "", fmt.Errorf("archive entry %q contains a path separator we do not accept", name)
	}

	clean := path.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("archive entry %q escapes the archive root", name)
	}
	return clean, nil
}

func copyMember(r io.Reader, size int64, dest *os.File) error {
	if _, err := dest.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := dest.Truncate(0); err != nil {
		return err
	}

	written, err := io.Copy(dest, io.LimitReader(r, size+1))
	if err != nil {
		return err
	}
	if written != size {
		return fmt.Errorf("got %d bytes, want the declared %d", written, size)
	}
	return nil
}

type bytesReaderAt []byte

func (b bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
