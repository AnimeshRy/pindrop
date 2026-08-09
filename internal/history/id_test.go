package history

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIDValidation(t *testing.T) {
	t.Parallel()

	const goodRepo = "r_0123456789abcdef0123456789abcdef"
	const goodRun = "20240301T120000Z-abcdef12"

	tests := []struct {
		name string
		repo string
		run  string
		want bool
	}{
		{name: "well formed", repo: goodRepo, run: goodRun, want: true},
		{name: "empty", repo: "", run: ""},
		{name: "parent directory", repo: "..", run: ".."},
		{name: "traversal", repo: "../../etc/passwd", run: "../../etc/passwd"},
		{name: "percent encoded traversal", repo: "%2e%2e%2f%2e%2e", run: "%2e%2e%2f%2e%2e"},
		{name: "decoded traversal", repo: mustUnescape(t, "..%2f..%2fetc"), run: mustUnescape(t, "..%2f..%2fetc")},
		{name: "absolute path", repo: "/etc/passwd", run: "/etc/passwd"},
		{name: "valid prefix then traversal", repo: goodRepo + "/../..", run: goodRun + "/../.."},
		{name: "null byte", repo: goodRepo + "\x00", run: goodRun + "\x00"},
		{name: "newline", repo: goodRepo + "\n", run: goodRun + "\n"},
		{name: "uppercase hex", repo: "r_0123456789ABCDEF0123456789ABCDEF", run: "20240301T120000Z-ABCDEF12"},
		{name: "too short", repo: "r_0123", run: "20240301T120000Z-abcd"},
		{name: "wrong prefix", repo: "x_0123456789abcdef0123456789abcdef", run: "20240301-120000Z-abcdef12"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := RepoID(tt.repo).Valid(); got != tt.want {
				t.Errorf("RepoID(%q).Valid() = %v, want %v", tt.repo, got, tt.want)
			}
			if got := RunID(tt.run).Valid(); got != tt.want {
				t.Errorf("RunID(%q).Valid() = %v, want %v", tt.run, got, tt.want)
			}
		})
	}
}

// mustUnescape decodes a percent-encoded path segment, so the table can assert
// on what a router hands us rather than on what a URL contains.
func mustUnescape(t *testing.T, s string) string {
	t.Helper()
	decoded, err := url.PathUnescape(s)
	if err != nil {
		t.Fatalf("unescaping %q: %v", s, err)
	}
	return decoded
}

func TestStoreRejectsTraversalIdentifiers(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t)

	// A file the store must never be able to reach by identifier alone.
	outside := filepath.Join(filepath.Dir(store.Dir()), "secret.json")
	if err := os.WriteFile(outside, []byte(`{"schemaVersion":2,"findings":[]}`), 0o600); err != nil {
		t.Fatalf("writing %s: %v", outside, err)
	}

	hostile := []string{
		"..",
		"../..",
		mustUnescape(t, "..%2f.."),
		filepath.Base(filepath.Dir(outside)),
		strings.TrimSuffix(filepath.Base(outside), ".json"),
	}

	for _, id := range hostile {
		if _, err := store.RepoByID(ctx, RepoID(id)); !errors.Is(err, ErrNotFound) {
			t.Errorf("RepoByID(%q): err = %v, want ErrNotFound", id, err)
		}
		if _, err := store.Runs(ctx, RepoID(id), RunQuery{}); !errors.Is(err, ErrNotFound) {
			t.Errorf("Runs(%q): err = %v, want ErrNotFound", id, err)
		}
		if _, err := store.Document(ctx, RepoID(id), RunID(id)); !errors.Is(err, ErrNotFound) {
			t.Errorf("Document(%q): err = %v, want ErrNotFound", id, err)
		}
		if err := store.Forget(ctx, RepoID(id)); !errors.Is(err, ErrNotFound) {
			t.Errorf("Forget(%q): err = %v, want ErrNotFound", id, err)
		}
	}

	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("a file outside the store was removed: %v", err)
	}
}

func TestStoreRejectsATraversalRunIdentifier(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t)
	root := repoRoot(t, "proj")
	run := put(t, store, makeRecord(root, recordOpts{at: baseTime}, finding("fp", "trivy")))

	escape := RunID("../" + repoFileName)
	if _, err := store.Document(ctx, run.RepoID, escape); !errors.Is(err, ErrNotFound) {
		t.Errorf("Document with a traversal run id: err = %v, want ErrNotFound", err)
	}
	if _, err := store.RunByID(ctx, run.RepoID, escape); !errors.Is(err, ErrNotFound) {
		t.Errorf("RunByID with a traversal run id: err = %v, want ErrNotFound", err)
	}
}

func TestRepoIDIsDerivedFromThePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		left  string
		right string
		same  bool
	}{
		{name: "identical paths", left: "/src/proj", right: "/src/proj", same: true},
		{name: "trailing slash", left: "/src/proj/", right: "/src/proj", same: true},
		{name: "same basename", left: "/a/proj", right: "/b/proj"},
		{name: "case differs", left: "/src/Proj", right: "/src/proj"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			left := repoIDFor(filepath.Clean(tt.left))
			right := repoIDFor(filepath.Clean(tt.right))
			if !left.Valid() || !right.Valid() {
				t.Fatalf("minted ids %q and %q, want both valid", left, right)
			}
			if got := left == right; got != tt.same {
				t.Errorf("%q == %q is %v, want %v", tt.left, tt.right, got, tt.same)
			}
		})
	}
}

func TestRunIDTime(t *testing.T) {
	t.Parallel()

	at, ok := RunID("20240301T120000Z-abcdef12").Time()
	if !ok {
		t.Fatal("Time reported failure for a valid run id")
	}
	if got := at.Format(runIDLayout); got != "20240301T120000Z" {
		t.Errorf("Time = %v, want 2024-03-01 12:00:00 UTC", at)
	}
	if _, ok := RunID("nonsense").Time(); ok {
		t.Error("Time succeeded for an invalid run id")
	}
}
