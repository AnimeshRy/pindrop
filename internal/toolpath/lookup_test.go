package toolpath

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// stub writes an executable file named name into dir and returns its path.
func stub(t *testing.T, dir, name string) string {
	t.Helper()

	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("creating %s: %v", dir, err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("writing stub %s: %v", path, err)
	}
	return path
}

func TestLookupOrigin(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("executable-bit semantics differ on Windows, which is unsupported")
	}

	const tool = "trivy"

	tests := []struct {
		name string
		// build populates a temp root and returns the Origins to search plus the
		// path expected to win.
		build      func(t *testing.T, root string) (Origins, string)
		wantOrigin Origin
		wantErr    bool
	}{
		{
			name: "explicit path wins over everything",
			build: func(t *testing.T, root string) (Origins, string) {
				want := stub(t, filepath.Join(root, "opt"), tool)
				stub(t, filepath.Join(root, "path"), tool)
				stub(t, filepath.Join(root, "managed"), tool)
				return Origins{
					Explicit:   want,
					PathDirs:   []string{filepath.Join(root, "path")},
					SelfDir:    filepath.Join(root, "self"),
					ManagedDir: filepath.Join(root, "managed"),
				}, want
			},
			wantOrigin: OriginExplicit,
		},
		{
			name: "a bare explicit name is not treated as a path",
			build: func(t *testing.T, root string) (Origins, string) {
				want := stub(t, filepath.Join(root, "path"), tool)
				return Origins{
					Explicit: tool,
					PathDirs: []string{filepath.Join(root, "path")},
				}, want
			},
			wantOrigin: OriginPath,
		},
		{
			name: "PATH beats the managed directory",
			build: func(t *testing.T, root string) (Origins, string) {
				want := stub(t, filepath.Join(root, "path"), tool)
				stub(t, filepath.Join(root, "managed"), tool)
				return Origins{
					PathDirs:   []string{filepath.Join(root, "path")},
					ManagedDir: filepath.Join(root, "managed"),
				}, want
			},
			wantOrigin: OriginPath,
		},
		{
			name: "sibling beats the managed directory",
			build: func(t *testing.T, root string) (Origins, string) {
				want := stub(t, filepath.Join(root, "self"), tool)
				stub(t, filepath.Join(root, "managed"), tool)
				return Origins{
					PathDirs:   []string{filepath.Join(root, "empty")},
					SelfDir:    filepath.Join(root, "self"),
					ManagedDir: filepath.Join(root, "managed"),
				}, want
			},
			wantOrigin: OriginSibling,
		},
		{
			name: "the managed directory is used when nothing else has it",
			build: func(t *testing.T, root string) (Origins, string) {
				want := stub(t, filepath.Join(root, "managed"), tool)
				return Origins{
					PathDirs:   []string{filepath.Join(root, "empty")},
					SelfDir:    filepath.Join(root, "self"),
					ManagedDir: filepath.Join(root, "managed"),
				}, want
			},
			wantOrigin: OriginManaged,
		},
		{
			name: "earlier PATH entries win",
			build: func(t *testing.T, root string) (Origins, string) {
				want := stub(t, filepath.Join(root, "first"), tool)
				stub(t, filepath.Join(root, "second"), tool)
				return Origins{PathDirs: []string{
					filepath.Join(root, "first"),
					filepath.Join(root, "second"),
				}}, want
			},
			wantOrigin: OriginPath,
		},
		{
			name: "a non-executable file is not a match",
			build: func(t *testing.T, root string) (Origins, string) {
				dir := filepath.Join(root, "path")
				if err := os.MkdirAll(dir, 0o750); err != nil {
					t.Fatalf("creating %s: %v", dir, err)
				}
				if err := os.WriteFile(filepath.Join(dir, tool), []byte("text"), 0o600); err != nil {
					t.Fatalf("writing file: %v", err)
				}
				return Origins{PathDirs: []string{dir}}, ""
			},
			wantErr: true,
		},
		{
			name: "nothing anywhere is an error",
			build: func(t *testing.T, root string) (Origins, string) {
				return Origins{
					PathDirs:   []string{filepath.Join(root, "empty")},
					SelfDir:    filepath.Join(root, "self"),
					ManagedDir: filepath.Join(root, "managed"),
				}, ""
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			origins, want := tt.build(t, root)

			got, origin, err := LookupOrigin(tool, origins)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("got = %q with nil error, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != want {
				t.Errorf("path: got = %q, want %q", got, want)
			}
			if origin != tt.wantOrigin {
				t.Errorf("origin: got = %q, want %q", origin, tt.wantOrigin)
			}
		})
	}
}

// TestLookupSkipsEmptyPathElement pins down a security property rather than a
// convenience: POSIX reads an empty PATH element as the current directory, and a
// scanner resolved out of the directory being scanned would let a hostile
// repository supply the binary that audits it.
//
// It cannot be parallel, because it changes the working directory to make the
// bad outcome reachable in the first place.
func TestLookupSkipsEmptyPathElement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executable-bit semantics differ on Windows, which is unsupported")
	}

	root := t.TempDir()
	stub(t, root, "trivy")
	t.Chdir(root)

	if got, err := Lookup("trivy", Origins{PathDirs: []string{""}}); err == nil {
		t.Errorf("got = %q from an empty PATH element, want an error", got)
	}
}

func TestHome(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want func(t *testing.T) string
	}{
		{
			name: "PINDROP_HOME wins",
			env:  "/tmp/pindrop-home-test",
			want: func(*testing.T) string { return "/tmp/pindrop-home-test" },
		},
		{
			name: "defaults to ~/.pindrop",
			want: func(t *testing.T) string {
				home, err := os.UserHomeDir()
				if err != nil {
					t.Skipf("no home directory: %v", err)
				}
				return filepath.Join(home, ".pindrop")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// t.Setenv forbids t.Parallel.
			t.Setenv(HomeEnv, tt.env)

			got, err := Home()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if want := tt.want(t); got != want {
				t.Errorf("got = %q, want %q", got, want)
			}
		})
	}
}

func TestDirIsUnderHome(t *testing.T) {
	root := t.TempDir()
	t.Setenv(HomeEnv, root)

	dir, err := Dir()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := filepath.Join(root, "bin"); dir != want {
		t.Errorf("got = %q, want %q", dir, want)
	}

	// EnsureDir must be safe to call when the directory already exists, because
	// every setup run calls it.
	for range 2 {
		if _, err := EnsureDir(); err != nil {
			t.Fatalf("EnsureDir: %v", err)
		}
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Errorf("EnsureDir did not create %q: %v", dir, err)
	}
}

func TestDisplay(t *testing.T) {
	t.Parallel()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "collapses the home directory",
			path: filepath.Join(home, ".pindrop", "bin"),
			want: filepath.Join("~", ".pindrop", "bin"),
		},
		{
			name: "leaves an unrelated absolute path alone",
			path: filepath.Join("/usr", "local", "bin"),
			want: filepath.Join("/usr", "local", "bin"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := Display(tt.path); got != tt.want {
				t.Errorf("got = %q, want %q", got, tt.want)
			}
		})
	}
}
