package toolinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// downloadTimeout bounds a single asset download. Matched to the adapters'
// per-scan timeout so there is one number to remember rather than two.
const downloadTimeout = 10 * time.Minute

// maxRedirects caps a redirect chain. GitHub redirects release downloads to
// objects.githubusercontent.com, so cross-host redirects must be allowed; only
// the scheme and the chain length are constrained.
const maxRedirects = 10

// tempPrefix names in-progress downloads. They live in the destination directory,
// never os.TempDir(), because os.Rename across filesystems fails with EXDEV and
// the atomic install depends on the rename succeeding.
const tempPrefix = ".pindrop-download-"

// State is whether a tool is present and current.
type State string

// Installation states.
const (
	// StateMissing means no such executable in the target directory.
	StateMissing State = "missing"
	// StateInstalled means the recorded install matches the manifest's version.
	StateInstalled State = "installed"
	// StateOutdated means a Pindrop-installed copy is at a different version.
	StateOutdated State = "outdated"
	// StateForeign means an executable is present that Pindrop did not install.
	// Replacing it needs --force, so `pindrop setup --dir /usr/local/bin` cannot
	// silently overwrite a user's Homebrew Trivy.
	StateForeign State = "foreign"
)

// Options configure an install run.
type Options struct {
	// Dir is where binaries are installed. Defaults to toolpath.Dir().
	Dir string
	// Client performs the downloads. Defaults to a client with a 10-minute
	// timeout and an https-only redirect policy. Injected so the installer can be
	// tested against an httptest server without touching the network.
	Client *http.Client
	// Force reinstalls a tool that is already present and current, and replaces
	// one Pindrop did not install.
	Force bool
}

// client returns the HTTP client to use.
func (o Options) client() *http.Client {
	if o.Client != nil {
		return o.Client
	}
	return &http.Client{
		Timeout: downloadTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			// A downgrade to plaintext would expose the download to tampering
			// that the digest check would then attribute to a bad release.
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing a redirect to %s", req.URL.Scheme)
			}
			return nil
		},
	}
}

// DigestMismatchError reports that a downloaded asset did not match the digest
// committed in the manifest.
//
// This is the failure the manifest exists to produce, so it is a distinct type:
// the CLI states plainly that the file was refused rather than folding it in with
// network errors.
type DigestMismatchError struct {
	Tool string
	URL  string
	Want string
	Got  string
}

// Error implements the error interface.
func (e *DigestMismatchError) Error() string {
	return fmt.Sprintf(
		"checksum mismatch for %s\n"+
			"  expected %s\n"+
			"  received %s\n"+
			"  %s does not match the digest committed in this build of pindrop.\n"+
			"  Refusing to install it. This can mean the release was modified.",
		e.Tool, e.Want, e.Got, e.URL)
}

// Status reports whether sel is already installed in dir.
func Status(sel Selected, dir string, rec *Record) State {
	path := filepath.Join(dir, sel.Tool.Name)

	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return StateMissing
	}

	installed, ok := rec.Get(sel.Tool.Name)
	switch {
	case !ok:
		return StateForeign
	case installed.Version != sel.Tool.Version || installed.SHA256 != sel.Asset.SHA256:
		return StateOutdated
	default:
		return StateInstalled
	}
}

// Install downloads sel, verifies it, and installs it into opts.Dir.
//
// progress, if non-nil, is called with the bytes written so far and the total
// expected, as the download proceeds. It is a plain callback rather than an
// interface because a download reports one thing from one goroutine — unlike
// scan.Observer, which multiplexes several event kinds across many.
//
// The order of operations is load-bearing:
//
//  1. Stream to a temporary file in the destination directory, hashing as we go.
//  2. Compare digests. A mismatch deletes the file and returns.
//  3. Extract the named member, if the asset is an archive.
//  4. chmod, then rename into place.
//
// Verification precedes chmod, so a file that failed verification is never
// executable anywhere on disk. chmod precedes rename, so the final path is never
// briefly present but not executable. The rename is what makes the install
// atomic: either the old binary or the new one is at that path, never a partial
// download.
func Install(ctx context.Context, sel Selected, opts Options, progress func(done, total int64)) error {
	dir := opts.Dir
	if dir == "" {
		return errors.New("no install directory")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, tempPrefix+sel.Tool.Name+"-*")
	if err != nil {
		return fmt.Errorf("creating a temporary file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// Removed on every failure path. On success the rename has already moved it,
	// and Remove on a renamed path is a harmless no-op.
	defer func() { _ = os.Remove(tmpPath) }()

	digest, err := download(ctx, opts.client(), sel, tmp, progress)
	if err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing %s: %w", tmpPath, err)
	}

	if digest != sel.Asset.SHA256 {
		// Delete before returning: an unverified file must not be left lying in
		// the directory the adapters search.
		_ = os.Remove(tmpPath)
		return &DigestMismatchError{
			Tool: sel.Tool.Name + " " + sel.Tool.Version,
			URL:  sel.Asset.URL,
			Want: sel.Asset.SHA256,
			Got:  digest,
		}
	}

	// The verified payload for a bare binary is the file itself; for an archive it
	// is one member of it.
	binary := tmpPath
	if sel.Asset.Archive == ArchiveTarGz {
		extracted, err := extractMember(tmpPath, sel.Asset.Member, dir)
		if err != nil {
			return fmt.Errorf("unpacking %s: %w", sel.Tool.Name, err)
		}
		defer func() { _ = os.Remove(extracted) }()
		binary = extracted
	}

	return finalize(binary, filepath.Join(dir, sel.Tool.Name))
}

// download streams sel's asset into w, returning its hex SHA-256.
func download(ctx context.Context, client *http.Client, sel Selected, w io.Writer,
	progress func(done, total int64),
) (string, error) {
	if _, err := url.Parse(sel.Asset.URL); err != nil {
		return "", fmt.Errorf("invalid URL for %s: %w", sel.Tool.Name, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sel.Asset.URL, nil)
	if err != nil {
		return "", fmt.Errorf("preparing the %s download: %w", sel.Tool.Name, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w\n  "+
			"Check your network, then run `pindrop setup` again", sel.Tool.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("downloading %s: %s\n  %s",
			sel.Tool.Name, resp.Status, sel.Asset.URL)
	}

	total := sel.Asset.Size
	sum := sha256.New()

	// Capped at exactly one byte over the manifest's size. A body longer than the
	// pinned asset is refused before it can fill the disk, and a body shorter than
	// it fails the length check below — so truncation and overrun are both caught
	// here rather than surfacing as a confusing digest mismatch.
	body := io.LimitReader(resp.Body, total+1)
	written, err := io.Copy(io.MultiWriter(w, sum), &reporter{
		r:        body,
		total:    total,
		progress: progress,
	})
	if err != nil {
		// A read error mid-body is an incomplete download, not a bad release, and
		// the message has to say so or the user reaches for the digest mismatch
		// explanation instead of retrying.
		return "", fmt.Errorf("downloading %s: %w — the download did not complete",
			sel.Tool.Name, err)
	}
	if written != total {
		return "", fmt.Errorf(
			"downloading %s: got %d bytes, want %d — the download did not complete",
			sel.Tool.Name, written, total)
	}

	return hex.EncodeToString(sum.Sum(nil)), nil
}

// reporter wraps a reader to report progress. It exists so that Install's caller
// can render a progress bar without the downloader knowing what a bar is.
type reporter struct {
	r        io.Reader
	done     int64
	total    int64
	progress func(done, total int64)
}

// Read implements io.Reader.
func (p *reporter) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.done += int64(n)
	if p.progress != nil {
		p.progress(p.done, p.total)
	}
	return n, err
}

// finalize makes src executable and moves it to dst.
func finalize(src, dst string) error {
	// #nosec G302 -- 0755 is the point: this is an executable a scanner adapter
	// will run. It is applied only after the digest check has passed.
	if err := os.Chmod(src, 0o755); err != nil {
		return fmt.Errorf("making %s executable: %w", filepath.Base(dst), err)
	}

	// Flush before the rename: a crash immediately after an unsynced rename can
	// leave a zero-length file at a path the adapters will happily try to execute.
	// #nosec G304 -- src is a temporary file created by this package.
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("reopening %s: %w", src, err)
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if syncErr != nil {
		return fmt.Errorf("flushing %s: %w", src, syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("closing %s: %w", src, closeErr)
	}

	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("installing %s: %w", dst, err)
	}
	return nil
}

// CleanTemp removes download leftovers from a previous interrupted run. Called at
// the start of setup so an abandoned temp file does not accumulate.
func CleanTemp(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if name := e.Name(); len(name) > len(tempPrefix) && name[:len(tempPrefix)] == tempPrefix {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}
