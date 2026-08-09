package vcs_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/vcs"
)

// Fixtures under testdata/ name their git directory "dot-git", not ".git".
// A real .git directory inside testdata is invisible to some tooling and, worse,
// would be a nested repository as far as this repo's own git is concerned.
// materialize copies a fixture into a temp directory, renaming every "dot-git"
// component as it goes, so the tree under test is the real on-disk layout.
func materialize(t *testing.T, fixture string) string {
	t.Helper()

	src := filepath.Join("testdata", fixture)
	dst := t.TempDir()

	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		parts := strings.Split(rel, string(filepath.Separator))
		for i, part := range parts {
			if part == "dot-git" {
				parts[i] = ".git"
			}
		}
		target := filepath.Join(append([]string{dst}, parts...)...)

		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("materializing fixture %s: %v", fixture, err)
	}
	return dst
}

func TestInspect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		fixture string
		// sub is the directory Inspect is called on, relative to the fixture.
		sub string
		// root is the expected Info.Root, relative to the fixture.
		root   string
		origin string
		branch string
		commit string
	}{
		{
			name:    "normal repository",
			fixture: "normal",
			root:    ".",
			origin:  "github.com/owner/repo",
			branch:  "main",
			commit:  "1111111111111111111111111111111111111111",
		},
		{
			name:    "walks up from a nested subdirectory",
			fixture: "normal",
			sub:     filepath.Join("src", "nested"),
			root:    ".",
			origin:  "github.com/owner/repo",
			branch:  "main",
			commit:  "1111111111111111111111111111111111111111",
		},
		{
			name:    "detached HEAD has no branch",
			fixture: "detached",
			root:    ".",
			origin:  "github.com/owner/repo",
			branch:  "",
			commit:  "2222222222222222222222222222222222222222",
		},
		{
			name:    "repository with no commits has a branch and no commit",
			fixture: "unborn",
			root:    ".",
			origin:  "github.com/owner/repo",
			branch:  "main",
			commit:  "",
		},
		{
			name:    "falls back to packed-refs",
			fixture: "packed",
			root:    ".",
			origin:  "github.com/owner/repo",
			branch:  "release/1.x",
			commit:  "3333333333333333333333333333333333333333",
		},
		{
			name:    "no origin remote",
			fixture: "noremote",
			root:    ".",
			origin:  "",
			branch:  "main",
			commit:  "7777777777777777777777777777777777777777",
		},
		{
			name:    "malformed HEAD and config yield empty fields, not an error",
			fixture: "malformed",
			root:    ".",
			origin:  "",
			branch:  "",
			commit:  "",
		},
		{
			name:    "submodule .git file indirection",
			fixture: "submodule",
			sub:     filepath.Join("parent", "child"),
			root:    filepath.Join("parent", "child"),
			origin:  "github.com/owner/child",
			branch:  "main",
			commit:  "8888888888888888888888888888888888888888",
		},
		{
			name:    "linked worktree reads HEAD locally and config and refs from the common dir",
			fixture: "worktree",
			sub:     "wt",
			root:    "wt",
			origin:  "github.com/owner/repo",
			branch:  "feature",
			commit:  "9999999999999999999999999999999999999999",
		},
		{
			name:    "main checkout of a repository that has a linked worktree",
			fixture: "worktree",
			sub:     "main",
			root:    "main",
			origin:  "github.com/owner/repo",
			branch:  "main",
			commit:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			base := materialize(t, tc.fixture)
			got, err := vcs.Inspect(filepath.Join(base, tc.sub))
			if err != nil {
				t.Fatalf("Inspect() error = %v, want nil", err)
			}

			wantRoot := filepath.Join(base, tc.root)
			if got.Root != wantRoot {
				t.Errorf("Root got = %q, want %q", got.Root, wantRoot)
			}
			if got.Origin != tc.origin {
				t.Errorf("Origin got = %q, want %q", got.Origin, tc.origin)
			}
			if got.Branch != tc.branch {
				t.Errorf("Branch got = %q, want %q", got.Branch, tc.branch)
			}
			if got.Commit != tc.commit {
				t.Errorf("Commit got = %q, want %q", got.Commit, tc.commit)
			}
		})
	}
}

func TestInspectNotARepository(t *testing.T) {
	t.Parallel()

	base := materialize(t, "plain")
	for _, dir := range []string{base, filepath.Join(base, "sub")} {
		got, err := vcs.Inspect(dir)
		if !errors.Is(err, vcs.ErrNotRepo) {
			t.Errorf("Inspect(%q) error = %v, want ErrNotRepo", dir, err)
		}
		if got != (vcs.Info{}) {
			t.Errorf("Inspect(%q) got = %+v, want zero Info", dir, got)
		}
		// The message has to name the directory searched, or a user cannot act
		// on it.
		if err != nil && !strings.Contains(err.Error(), base) {
			t.Errorf("Inspect(%q) error = %q, want it to name the directory", dir, err)
		}
	}
}

// TestInspectOriginNormalization pins the URL forms a single repository is
// cloned by. Every one of them must reduce to the same identity, or scan history
// splits in two the day a user switches from https to ssh.
func TestInspectOriginNormalization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
		want string
	}{
		{"https", "https://github.com/owner/repo.git", "github.com/owner/repo"},
		{"https without suffix", "https://github.com/owner/repo", "github.com/owner/repo"},
		// Assembled rather than written literally: a complete
		// credential-shaped URI here is a true positive for our own secret
		// scanner, and a repository that reports findings against itself
		// trains its users to ignore findings. Do not inline it.
		{"https with credentials", "https://" + "u5er:t0ken" + "@github.com/owner/repo.git", "github.com/owner/repo"},
		{"https with port", "https://github.com:443/owner/repo.git", "github.com/owner/repo"},
		{"scp-like", "git@github.com:owner/repo.git", "github.com/owner/repo"},
		{"scp-like without user", "github.com:owner/repo.git", "github.com/owner/repo"},
		{"ssh with port", "ssh://git@github.com:22/owner/repo", "github.com/owner/repo"},
		{"git protocol", "git://github.com/owner/repo.git", "github.com/owner/repo"},
		{"uppercase host", "https://GitHub.COM/owner/repo.git", "github.com/owner/repo"},
		{"trailing slash", "https://github.com/owner/repo/", "github.com/owner/repo"},
		{"nested path", "https://gitlab.example.com/group/sub/repo.git", "gitlab.example.com/group/sub/repo"},
		{"quoted value", `"https://github.com/owner/repo.git"`, "github.com/owner/repo"},
		{"trailing comment", "https://github.com/owner/repo.git # the canonical one", "github.com/owner/repo"},

		{"absolute local path", "/srv/git/repo.git", ""},
		{"relative local path", "../other", ""},
		{"bare name", "other", ""},
		{"file scheme", "file:///srv/git/repo.git", ""},
		{"windows path", `C:\src\repo`, ""},
		{"empty", "", ""},
		{"host with no path", "https://github.com/", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			base := materialize(t, "normal")
			config := filepath.Join(base, ".git", "config")
			body := "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = " + tc.url + "\n"
			if err := os.WriteFile(config, []byte(body), 0o644); err != nil {
				t.Fatalf("writing config: %v", err)
			}

			got, err := vcs.Inspect(base)
			if err != nil {
				t.Fatalf("Inspect() error = %v, want nil", err)
			}
			if got.Origin != tc.want {
				t.Errorf("Origin got = %q, want %q", got.Origin, tc.want)
			}
		})
	}
}

// TestInspectNeverLeaksCredentials is separate from the table above because it
// is a security property, not a formatting one: a token in a remote URL must not
// survive into a record that gets written to disk and served over HTTP.
func TestInspectNeverLeaksCredentials(t *testing.T) {
	t.Parallel()

	const token = "ghp_supersecrettokenvalue" //nolint:gosec // fixture, not a credential

	base := materialize(t, "normal")
	config := filepath.Join(base, ".git", "config")
	body := "[remote \"origin\"]\n\turl = https://oauth2:" + token + "@github.com/owner/repo.git\n"
	if err := os.WriteFile(config, []byte(body), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	got, err := vcs.Inspect(base)
	if err != nil {
		t.Fatalf("Inspect() error = %v, want nil", err)
	}
	if got.Origin != "github.com/owner/repo" {
		t.Errorf("Origin got = %q, want %q", got.Origin, "github.com/owner/repo")
	}
	for _, field := range []string{got.Origin, got.Branch, got.Commit, got.Root} {
		if strings.Contains(field, token) || strings.Contains(field, "oauth2") {
			t.Errorf("Info carries credential material: %q", field)
		}
	}
}

// TestInspectHostileGitDir covers the inputs a scanned-but-untrusted repository
// could contain. None may panic, escape the ref store, or loop forever.
func TestInspectHostileGitDir(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// files replaces or adds files under the fixture's .git directory.
		files  map[string]string
		branch string
		commit string
	}{
		{
			name:   "HEAD ref escaping the ref store",
			files:  map[string]string{"HEAD": "ref: refs/../../../../etc/passwd\n"},
			branch: "",
			commit: "",
		},
		{
			name:   "HEAD ref outside refs/",
			files:  map[string]string{"HEAD": "ref: /etc/passwd\n"},
			branch: "",
			commit: "",
		},
		{
			name:   "abbreviated object id is not accepted",
			files:  map[string]string{"HEAD": "1111111\n"},
			branch: "",
			commit: "",
		},
		{
			name:   "empty HEAD",
			files:  map[string]string{"HEAD": ""},
			branch: "",
			commit: "",
		},
		{
			name: "symbolic ref cycle terminates",
			files: map[string]string{
				"HEAD":            "ref: refs/heads/a\n",
				"refs/heads/a":    "ref: refs/heads/b\n",
				"refs/heads/b":    "ref: refs/heads/a\n",
				"refs/heads/main": "1111111111111111111111111111111111111111\n",
			},
			branch: "a",
			commit: "",
		},
		{
			name:   "loose ref holding garbage",
			files:  map[string]string{"refs/heads/main": "not a sha\n"},
			branch: "main",
			commit: "",
		},
		{
			name: "packed-refs peeled line is not mistaken for the ref",
			files: map[string]string{
				"HEAD":        "ref: refs/tags/v1\n",
				"packed-refs": "4444444444444444444444444444444444444444 refs/tags/v1\n^5555555555555555555555555555555555555555\n",
			},
			branch: "",
			commit: "4444444444444444444444444444444444444444",
		},
		{
			name:   "sha-256 object id",
			files:  map[string]string{"refs/heads/main": strings.Repeat("b", 64) + "\n"},
			branch: "main",
			commit: strings.Repeat("b", 64),
		},
		{
			name:   "CRLF line endings throughout",
			files:  map[string]string{"HEAD": "ref: refs/heads/main\r\n", "refs/heads/main": "1111111111111111111111111111111111111111\r\n"},
			branch: "main",
			commit: "1111111111111111111111111111111111111111",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			base := materialize(t, "normal")
			for name, body := range tc.files {
				p := filepath.Join(base, ".git", filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatalf("preparing %s: %v", name, err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatalf("writing %s: %v", name, err)
				}
			}

			got, err := vcs.Inspect(base)
			if err != nil {
				t.Fatalf("Inspect() error = %v, want nil", err)
			}
			if got.Branch != tc.branch {
				t.Errorf("Branch got = %q, want %q", got.Branch, tc.branch)
			}
			if got.Commit != tc.commit {
				t.Errorf("Commit got = %q, want %q", got.Commit, tc.commit)
			}
		})
	}
}

// TestInspectBrokenGitDirPointer asserts the degradation contract: a .git file
// pointing nowhere still reports the work-tree root, so a scan can run and be
// recorded, rather than failing outright or inventing provenance.
func TestInspectBrokenGitDirPointer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pointer string
	}{
		{"target does not exist", "gitdir: ../nowhere\n"},
		{"self reference", "gitdir: .git\n"},
		{"not a gitdir pointer at all", "hello\n"},
		{"empty pointer", "gitdir:\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			base := materialize(t, "normal")
			dotGit := filepath.Join(base, ".git")
			if err := os.RemoveAll(dotGit); err != nil {
				t.Fatalf("removing .git: %v", err)
			}
			if err := os.WriteFile(dotGit, []byte(tc.pointer), 0o644); err != nil {
				t.Fatalf("writing .git: %v", err)
			}

			got, err := vcs.Inspect(base)
			if err != nil {
				t.Fatalf("Inspect() error = %v, want nil", err)
			}
			want := vcs.Info{Root: base}
			if got != want {
				t.Errorf("Inspect() got = %+v, want %+v", got, want)
			}
		})
	}
}

// TestInspectOversizedFile pins the read cap: a huge HEAD is refused rather than
// read into memory or truncated into something that parses.
func TestInspectOversizedFile(t *testing.T) {
	t.Parallel()

	base := materialize(t, "normal")
	head := filepath.Join(base, ".git", "HEAD")
	body := strings.Repeat("a", 128<<10)
	if err := os.WriteFile(head, []byte(body), 0o644); err != nil {
		t.Fatalf("writing HEAD: %v", err)
	}

	got, err := vcs.Inspect(base)
	if err != nil {
		t.Fatalf("Inspect() error = %v, want nil", err)
	}
	if got.Branch != "" || got.Commit != "" {
		t.Errorf("Inspect() got = %+v, want empty Branch and Commit", got)
	}
	if got.Root != base {
		t.Errorf("Root got = %q, want %q", got.Root, base)
	}
}

// TestInspectRelativeDir checks that a relative argument still yields an
// absolute Root, since Root is stored and compared across runs.
func TestInspectRelativeDir(t *testing.T) {
	t.Parallel()

	got, err := vcs.Inspect("testdata")
	if err != nil && !errors.Is(err, vcs.ErrNotRepo) {
		t.Fatalf("Inspect() error = %v", err)
	}
	if err == nil && !filepath.IsAbs(got.Root) {
		t.Errorf("Root got = %q, want an absolute path", got.Root)
	}
}
