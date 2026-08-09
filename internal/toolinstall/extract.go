package toolinstall

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// maxMemberSize caps an extracted executable at 512 MB.
//
// Every asset we pin is under 80 MB, so this is not a tuning parameter — it is the
// bound that stops a gzip bomb in a tampered archive from filling the disk. The
// digest check normally makes a tampered archive unreachable, but extraction must
// not depend on an earlier check having run.
const maxMemberSize = 512 << 20

// ErrMemberNotFound reports that the archive did not contain the expected
// executable.
var ErrMemberNotFound = errors.New("the archive does not contain the expected executable")

// extractMember writes the single named member of a gzipped tarball into dir and
// returns its path.
//
// Only one member is extracted, by exact name. That is not an optimization: it
// means the set of files this can ever create is fixed by the manifest, so an
// archive that grew extra entries upstream cannot scatter them into the directory
// the adapters search for executables.
//
// The entry checks below are deliberately strict. This code reads an archive
// fetched over the network in a program whose purpose is finding security
// problems, so every classic tar attack is refused explicitly rather than
// relying on the digest check having already made it impossible.
func extractMember(archivePath, member, dir string) (string, error) {
	// #nosec G304 -- archivePath is the temporary file this package just wrote
	// from a digest-verified download, not a user-supplied path.
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	zr, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("reading gzip: %w", err)
	}
	defer func() { _ = zr.Close() }()

	want := path.Clean(member)
	tr := tar.NewReader(zr)

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return "", fmt.Errorf("%w: %s", ErrMemberNotFound, member)
		}
		if err != nil {
			return "", fmt.Errorf("reading tar: %w", err)
		}

		name, err := safeName(header.Name)
		if err != nil {
			return "", err
		}
		if name != want {
			continue
		}

		// Only a plain file can be an executable. A symlink or hard link named
		// like the member could point anywhere on the filesystem, and a device
		// node or fifo has no business in a release archive at all.
		if header.Typeflag != tar.TypeReg {
			return "", fmt.Errorf("%s in the archive is not a regular file (type %q)",
				member, string(rune(header.Typeflag)))
		}
		if header.Size > maxMemberSize {
			return "", fmt.Errorf("%s declares %d bytes, above the %d-byte limit",
				member, header.Size, int64(maxMemberSize))
		}

		return writeMember(tr, header.Size, dir, path.Base(want))
	}
}

// safeName rejects an archive entry whose path escapes the extraction directory.
func safeName(name string) (string, error) {
	// Reject before cleaning, so an absolute path is refused rather than quietly
	// relativized.
	if strings.HasPrefix(name, "/") || filepath.IsAbs(name) {
		return "", fmt.Errorf("archive entry %q is an absolute path", name)
	}
	// Windows drive letters and backslash separators, which path.Clean does not
	// understand and which would survive the checks below.
	if strings.ContainsAny(name, `\:`) {
		return "", fmt.Errorf("archive entry %q contains a path separator we do not accept", name)
	}

	clean := path.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("archive entry %q escapes the archive root", name)
	}
	return clean, nil
}

// writeMember copies exactly size bytes from tr into a new file in dir.
func writeMember(tr io.Reader, size int64, dir, name string) (string, error) {
	out, err := os.CreateTemp(dir, tempPrefix+name+"-*")
	if err != nil {
		return "", fmt.Errorf("creating a temporary file in %s: %w", dir, err)
	}
	outPath := out.Name()

	// Read one byte past the declared size: a member that keeps producing data
	// beyond its header is a malformed archive, not something to write out.
	written, err := io.Copy(out, io.LimitReader(tr, size+1))
	closeErr := out.Close()

	switch {
	case err != nil:
		_ = os.Remove(outPath)
		return "", fmt.Errorf("extracting %s: %w", name, err)
	case closeErr != nil:
		_ = os.Remove(outPath)
		return "", fmt.Errorf("writing %s: %w", name, closeErr)
	case written != size:
		_ = os.Remove(outPath)
		return "", fmt.Errorf("extracting %s: got %d bytes, want the declared %d",
			name, written, size)
	}

	return outPath, nil
}
