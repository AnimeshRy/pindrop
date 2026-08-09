package toolinstall

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// payload is the fake executable every test installs.
var payload = []byte("#!/bin/sh\necho pindrop-test\n")

// digest returns the hex SHA-256 of b.
func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// tarGz builds a gzipped tarball from the given entries.
func tarGz(t *testing.T, entries ...*tar.Header) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)

	for _, h := range entries {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("writing tar header %q: %v", h.Name, err)
		}
		if h.Typeflag == tar.TypeReg && h.Size > 0 {
			if _, err := tw.Write(payload[:h.Size]); err != nil {
				t.Fatalf("writing tar body: %v", err)
			}
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing gzip: %v", err)
	}
	return buf.Bytes()
}

// tarGzHeaderOnly builds a tarball containing h's header and no body.
//
// This is how a size-lying entry is expressed: tar.Writer refuses to close if a
// declared size is not filled, so an archive claiming half a gigabyte cannot be
// produced honestly. Omitting the trailer is fine for the property under test —
// extractMember must reject the declared size before it reads any body at all.
func tarGzHeaderOnly(t *testing.T, h *tar.Header) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)

	// WriteHeader emits the header block immediately, so the bytes are already in
	// the gzip writer. Neither tw.Flush nor tw.Close is called, because both
	// enforce that the declared size was filled — which is precisely the lie
	// under test.
	if err := tw.WriteHeader(h); err != nil {
		t.Fatalf("writing tar header %q: %v", h.Name, err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing gzip: %v", err)
	}
	return buf.Bytes()
}

// file is a regular-file tar header for the test payload.
func file(name string) *tar.Header {
	return &tar.Header{
		Name:     name,
		Typeflag: tar.TypeReg,
		Size:     int64(len(payload)),
		Mode:     0o755,
	}
}

// server serves body at /asset and counts requests, so a test can assert that an
// idempotent run made no network calls at all.
func server(t *testing.T, body []byte) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/asset" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	return srv, &hits
}

// selected builds a Selected pointing at url.
func selected(name, url string, body []byte, archive Archive, member string) Selected {
	return Selected{
		Tool:     Tool{Name: name, Version: "v1.2.3", Repo: "test/test"},
		Platform: "test/test",
		Asset: &Platform{
			URL:     url,
			SHA256:  digest(body),
			Size:    int64(len(body)),
			Archive: archive,
			Member:  member,
		},
	}
}

func TestInstallBareBinary(t *testing.T) {
	t.Parallel()

	srv, hits := server(t, payload)
	dir := t.TempDir()

	sel := selected("osv-scanner", srv.URL+"/asset", payload, ArchiveNone, "")

	var lastDone, lastTotal int64
	err := Install(context.Background(), sel, Options{Dir: dir}, func(done, total int64) {
		lastDone, lastTotal = done, total
	})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	path := filepath.Join(dir, "osv-scanner")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the installed binary: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("contents: got = %q, want %q", got, payload)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o755 {
			t.Errorf("mode: got = %o, want 755", perm)
		}
	}

	if lastTotal != int64(len(payload)) || lastDone != lastTotal {
		t.Errorf("progress: got = %d/%d, want %d/%d",
			lastDone, lastTotal, len(payload), len(payload))
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("requests: got = %d, want 1", n)
	}

	assertNoLeftovers(t, dir, "osv-scanner")
}

func TestInstallFromArchive(t *testing.T) {
	t.Parallel()

	body := tarGz(t, file("trivy"))
	srv, _ := server(t, body)
	dir := t.TempDir()

	sel := selected("trivy", srv.URL+"/asset", body, ArchiveTarGz, "trivy")
	if err := Install(context.Background(), sel, Options{Dir: dir}, nil); err != nil {
		t.Fatalf("Install: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "trivy"))
	if err != nil {
		t.Fatalf("reading the installed binary: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("contents: got = %q, want %q", got, payload)
	}

	assertNoLeftovers(t, dir, "trivy")
}

// TestInstallRefusesADigestMismatch is the test the manifest exists for. Both
// assertions matter: the error must be the distinct type the CLI reports
// specially, and — more importantly — nothing may be left on disk, since a file
// in this directory is a file the adapters will execute.
func TestInstallRefusesADigestMismatch(t *testing.T) {
	t.Parallel()

	srv, _ := server(t, payload)
	dir := t.TempDir()

	sel := selected("trivy", srv.URL+"/asset", payload, ArchiveNone, "")
	// Flip the committed digest, as a tampered release would.
	sel.Asset.SHA256 = strings.Repeat("0", 64)

	err := Install(context.Background(), sel, Options{Dir: dir}, nil)
	if err == nil {
		t.Fatal("got nil error, want a digest mismatch")
	}

	var mismatch *DigestMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("got %T (%v), want *DigestMismatchError", err, err)
	}
	if !strings.Contains(err.Error(), "Refusing to install") {
		t.Errorf("the message must say the file was refused; got:\n%s", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "trivy")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an unverified binary was installed anyway: %v", err)
	}
	assertNoLeftovers(t, dir, "")
}

func TestInstallRejectsHostileArchives(t *testing.T) {
	t.Parallel()

	symlink := &tar.Header{Name: "trivy", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}
	hardlink := &tar.Header{Name: "trivy", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"}
	device := &tar.Header{Name: "trivy", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3}
	fifo := &tar.Header{Name: "trivy", Typeflag: tar.TypeFifo}
	huge := &tar.Header{Name: "trivy", Typeflag: tar.TypeReg, Size: maxMemberSize + 1}

	tests := []struct {
		name    string
		entries []*tar.Header
		// headerOnly builds the archive without a body, for a size-lying entry.
		headerOnly bool
		member     string
		wantErr    string
	}{
		{
			name:    "traversal out of the archive root",
			entries: []*tar.Header{file("../../../../etc/passwd")},
			member:  "../../../../etc/passwd",
			wantErr: "escapes the archive root",
		},
		{
			name:    "absolute path",
			entries: []*tar.Header{file("/etc/passwd")},
			member:  "trivy",
			wantErr: "absolute path",
		},
		{
			name:    "windows path separators",
			entries: []*tar.Header{file(`..\..\windows\system32`)},
			member:  "trivy",
			wantErr: "path separator",
		},
		{
			name:    "symlink standing in for the executable",
			entries: []*tar.Header{symlink},
			member:  "trivy",
			wantErr: "not a regular file",
		},
		{
			name:    "hard link standing in for the executable",
			entries: []*tar.Header{hardlink},
			member:  "trivy",
			wantErr: "not a regular file",
		},
		{
			name:    "character device",
			entries: []*tar.Header{device},
			member:  "trivy",
			wantErr: "not a regular file",
		},
		{
			name:    "fifo",
			entries: []*tar.Header{fifo},
			member:  "trivy",
			wantErr: "not a regular file",
		},
		{
			name:       "member declaring an absurd size",
			entries:    []*tar.Header{huge},
			headerOnly: true,
			member:     "trivy",
			wantErr:    "above the",
		},
		{
			name:    "the expected member is absent",
			entries: []*tar.Header{file("README.md")},
			member:  "trivy",
			wantErr: "does not contain the expected executable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var body []byte
			if tt.headerOnly {
				body = tarGzHeaderOnly(t, tt.entries[0])
			} else {
				body = tarGz(t, tt.entries...)
			}
			srv, _ := server(t, body)
			dir := t.TempDir()

			sel := selected("trivy", srv.URL+"/asset", body, ArchiveTarGz, tt.member)

			err := Install(context.Background(), sel, Options{Dir: dir}, nil)
			if err == nil {
				t.Fatal("got nil error, want a rejection")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error: got = %q, want it to contain %q", err, tt.wantErr)
			}

			// However the archive was malformed, nothing may be installed.
			if _, err := os.Stat(filepath.Join(dir, "trivy")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a binary was installed from a hostile archive: %v", err)
			}
			assertNoLeftovers(t, dir, "")
		})
	}
}

func TestInstallDownloadFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler http.HandlerFunc
		// tamper adjusts the Selected before installing.
		tamper  func(s *Selected)
		wantErr string
	}{
		{
			name: "not found",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			wantErr: "404",
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr: "500",
		},
		{
			name: "truncated body",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				// Promise the full length, deliver half.
				w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
				_, _ = w.Write(payload[:len(payload)/2])
			},
			wantErr: "did not complete",
		},
		{
			name: "body longer than the pinned size",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(append(append([]byte(nil), payload...), payload...))
			},
			wantErr: "did not complete",
		},
		{
			name: "redirect downgraded to plaintext",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Redirect(w, &http.Request{}, "http://example.invalid/asset", http.StatusFound)
			},
			wantErr: "refusing a redirect to http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(tt.handler)
			t.Cleanup(srv.Close)

			dir := t.TempDir()
			sel := selected("trivy", srv.URL+"/asset", payload, ArchiveNone, "")
			if tt.tamper != nil {
				tt.tamper(&sel)
			}

			// The real client's redirect policy is under test, so it is used here
			// rather than httptest's default.
			err := Install(context.Background(), sel, Options{Dir: dir}, nil)
			if err == nil {
				t.Fatal("got nil error, want a failure")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error: got = %q, want it to contain %q", err, tt.wantErr)
			}

			if _, err := os.Stat(filepath.Join(dir, "trivy")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a binary was installed despite the failure: %v", err)
			}
			assertNoLeftovers(t, dir, "")
		})
	}
}

func TestInstallCancellation(t *testing.T) {
	t.Parallel()

	srv, _ := server(t, payload)
	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sel := selected("trivy", srv.URL+"/asset", payload, ArchiveNone, "")
	if err := Install(ctx, sel, Options{Dir: dir}, nil); err == nil {
		t.Fatal("got nil error, want a cancellation")
	}
	assertNoLeftovers(t, dir, "")
}

func TestStatus(t *testing.T) {
	t.Parallel()

	sel := selected("trivy", "https://example.com/asset", payload, ArchiveNone, "")

	tests := []struct {
		name string
		// setup writes the directory contents and returns the record to consult.
		setup func(t *testing.T, dir string) *Record
		want  State
	}{
		{
			name:  "nothing installed",
			setup: func(*testing.T, string) *Record { return LoadRecord(t.TempDir()) },
			want:  StateMissing,
		},
		{
			name: "present and recorded at the manifest version",
			setup: func(t *testing.T, dir string) *Record {
				writeStub(t, dir, "trivy")
				r := LoadRecord(t.TempDir())
				r.Set("trivy", sel.Tool.Version, sel.Asset.SHA256)
				return r
			},
			want: StateInstalled,
		},
		{
			name: "present but recorded at another version",
			setup: func(t *testing.T, dir string) *Record {
				writeStub(t, dir, "trivy")
				r := LoadRecord(t.TempDir())
				r.Set("trivy", "v0.0.1", strings.Repeat("a", 64))
				return r
			},
			want: StateOutdated,
		},
		{
			name: "present but never recorded, so somebody else installed it",
			setup: func(t *testing.T, dir string) *Record {
				writeStub(t, dir, "trivy")
				return LoadRecord(t.TempDir())
			},
			want: StateForeign,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			record := tt.setup(t, dir)

			if got := Status(sel, dir, record); got != tt.want {
				t.Errorf("got = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordRoundTrip(t *testing.T) {
	t.Parallel()

	home := t.TempDir()

	r := LoadRecord(home)
	if _, ok := r.Get("trivy"); ok {
		t.Error("a fresh record must be empty")
	}

	r.Set("trivy", "v0.72.0", strings.Repeat("b", 64))
	if err := r.Save(home); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded := LoadRecord(home)
	got, ok := reloaded.Get("trivy")
	if !ok {
		t.Fatal("trivy is missing after a round trip")
	}
	if got.Version != "v0.72.0" {
		t.Errorf("version: got = %q, want v0.72.0", got.Version)
	}

	reloaded.Forget("trivy")
	if _, ok := reloaded.Get("trivy"); ok {
		t.Error("Forget did not drop the entry")
	}
}

// TestLoadRecordToleratesCorruption pins down that a damaged cache file degrades
// to "nothing is installed" rather than failing setup. Being wrong here costs a
// redundant download; erroring would strand the user.
func TestLoadRecordToleratesCorruption(t *testing.T) {
	t.Parallel()

	for _, content := range []string{"", "{", "not json at all", `{"schema":99,"tools":{}}`} {
		home := t.TempDir()
		if err := os.WriteFile(filepath.Join(home, recordName), []byte(content), 0o600); err != nil {
			t.Fatalf("writing the record: %v", err)
		}

		r := LoadRecord(home)
		if r == nil || r.Tools == nil {
			t.Fatalf("content %q produced an unusable record", content)
		}
		if len(r.Tools) != 0 {
			t.Errorf("content %q: got %d tools, want 0", content, len(r.Tools))
		}
	}
}

// writeStub creates an executable placeholder.
func writeStub(t *testing.T, dir, name string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, name), payload, 0o755); err != nil {
		t.Fatalf("writing stub: %v", err)
	}
}

// assertNoLeftovers checks that dir holds nothing but the expected binary. A
// stray temp file in the directory the adapters search is a bug regardless of
// whether the install succeeded.
func assertNoLeftovers(t *testing.T, dir, expected string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.Name() == expected {
			continue
		}
		t.Errorf("leftover file in the install directory: %s", e.Name())
	}
}
