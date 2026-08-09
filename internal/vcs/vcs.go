// Package vcs reads the version-control state of a working tree: which
// repository it came from, which branch is checked out, and at which commit.
//
// It exists because scan history is meaningless without it. "Eight issues" is
// only comparable to a previous run if both runs recorded the same repo and the
// commit each ran against, and a triage decision made on one branch should be
// attributable to that branch.
//
// # It never executes git
//
// Every fact here is read straight out of the .git directory. Nothing in this
// package spawns a process, and it deliberately does not fall back to doing so.
// Three reasons, in increasing order of importance: it works on a machine with
// no git installed, which is the normal state of a slim CI container; it cannot
// be slowed down or broken by a repository hook or a pathological config; and it
// cannot be made to execute anything. Pindrop is a security tool, and the
// directory it is pointed at is the directory it is pointed at *because nobody
// trusts it yet*. Resolving a binary through PATH and running it inside such a
// tree, to learn a branch name, is a bad trade.
//
// The cost of that choice is that this package reimplements a small slice of
// git's on-disk formats, and so it must treat every file it reads as hostile:
// reads are size-capped, pointer indirection is bounded, and malformed input
// yields an empty field rather than an error and never a panic. A field this
// package could not determine is empty; only "there is no repository here" is an
// error ([ErrNotRepo]).
//
// # What it deliberately does not report
//
// There is no Dirty field. It looks like one line of code and is not: deciding
// whether a work tree has uncommitted changes without `git status` means
// implementing the binary index format, then stat-matching every tracked file
// against it, then the full .gitignore precedence rules for the untracked ones.
// That is a package, not a field, and nothing needs it yet.
//
// A remote that is a local path (/srv/git/repo.git, ../other) yields an empty
// [Info.Origin]. Origin is meant to identify a repository across the machines
// that scan it; a path on one developer's disk does not, and inventing a
// hostname for it would produce a stable-looking identifier that silently
// collides between users.
package vcs

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ErrNotRepo reports that dir is not inside a git work tree. Callers should test
// for it with [errors.Is]; it is always returned wrapped with the path that was
// searched, because "not a git repository" on its own does not tell a user which
// directory Pindrop actually looked at.
var ErrNotRepo = errors.New("not a git repository")

// Info is the version-control state of a working tree.
//
// Every field except Root may legitimately be empty — a repository with no
// origin remote, a detached HEAD, a repository with no commits — so callers must
// treat empty as "unknown or not applicable", not as an error.
type Info struct {
	// Root is the absolute path of the work-tree root: the directory holding
	// the .git entry. Findings' paths are relative to this.
	Root string
	// Origin is the normalized "origin" remote, e.g. "github.com/owner/repo",
	// with scheme, credentials, port and .git suffix stripped. Empty when there
	// is no origin remote, or when it is a local path.
	//
	// Credentials are stripped rather than preserved because scan records are
	// written to disk and served over HTTP; a token embedded in a remote URL
	// must never reach one. See also the same rule for secrets in
	// internal/scan/trufflehog.
	Origin string
	// Branch is the checked-out branch, or "" on a detached HEAD.
	Branch string
	// Commit is the full HEAD SHA, or "" in a repository with no commits.
	Commit string
}

// Size caps. These bound what a hostile repository can make us allocate. They
// are generous next to real files — a HEAD is 41 bytes, a config a few hundred —
// but packed-refs grows with the ref count and reaches megabytes on large repos,
// so it gets its own, larger cap.
const (
	maxSmallFile  = 64 << 10 // HEAD, a loose ref, a .git pointer, commondir
	maxConfigFile = 1 << 20  // config
	maxPackedRefs = 32 << 20 // packed-refs
)

// maxIndirection bounds every pointer chase: .git files naming a gitdir, and
// symbolic refs naming another ref. Git itself allows a handful of hops; a cycle
// is either corruption or an attack, and either way must terminate.
const maxIndirection = 8

// maxWalkUp bounds the search for a work-tree root. filepath.Dir already
// terminates at the filesystem root, but a path assembled from untrusted input
// should not be able to turn a typo into an unbounded loop.
const maxWalkUp = 256

// Inspect walks up from dir looking for a work tree and reads its state.
//
// It returns [ErrNotRepo], wrapped, when neither dir nor any ancestor holds a
// .git entry. Anything else that goes wrong inside a repository that does exist
// — an unreadable config, a truncated HEAD, a ref that points nowhere — leaves
// the corresponding field empty and is not an error, because a scan should still
// run and still be recorded when only its provenance is unreadable.
func Inspect(dir string) (Info, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Info{}, fmt.Errorf("resolving %q to an absolute path: %w", dir, err)
	}

	root, dotGit, ok := findRoot(abs)
	if !ok {
		return Info{}, fmt.Errorf("no .git found at or above %s: %w", abs, ErrNotRepo)
	}

	info := Info{Root: root}

	// A gitdir we cannot resolve means the repository is broken, not absent.
	// Report the root we did find and leave the rest blank.
	gitDir, commonDir, ok := resolveGitDir(dotGit)
	if !ok {
		return info, nil
	}

	info.Origin = originRemote(filepath.Join(commonDir, "config"))
	info.Branch, info.Commit = head(gitDir, commonDir)
	return info, nil
}

// findRoot walks from abs upward, returning the first directory containing a
// .git entry along with the path of that entry.
func findRoot(abs string) (root, dotGit string, ok bool) {
	dir := filepath.Clean(abs)
	for range maxWalkUp {
		candidate := filepath.Join(dir, ".git")
		// Stat, not Lstat: a .git symlink into a shared store is a supported
		// git layout, and following it is what git does.
		if _, err := os.Stat(candidate); err == nil {
			return dir, candidate, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", "", false
		}
		dir = parent
	}
	return "", "", false
}

// resolveGitDir turns the .git entry at dotGit into the pair of directories git
// itself distinguishes.
//
// gitDir is where this checkout's own state lives — HEAD above all. commonDir is
// where state shared between checkouts lives: config, packed-refs, refs/heads.
// For an ordinary repository the two are the same directory. They differ for a
// linked worktree (`git worktree add`), whose .git is a file naming
// <main>/.git/worktrees/<name>; that directory holds its own HEAD and a
// "commondir" file pointing back at the main .git. Submodules use the same .git
// file indirection but have no commondir, so both land on the same path.
//
// Reading commondir is what makes a linked worktree report a correct origin and
// commit rather than nothing: its config and refs/heads simply are not where the
// naive answer would look.
func resolveGitDir(dotGit string) (gitDir, commonDir string, ok bool) {
	gitDir = dotGit
	for range maxIndirection {
		fi, err := os.Stat(gitDir)
		if err != nil {
			return "", "", false
		}
		if fi.IsDir() {
			return gitDir, resolveCommonDir(gitDir), true
		}

		target, ok := gitdirPointer(gitDir)
		if !ok {
			return "", "", false
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(gitDir), target)
		}
		next := filepath.Clean(target)
		if next == gitDir {
			return "", "", false // self-reference; the bound below catches longer cycles
		}
		gitDir = next
	}
	return "", "", false
}

// gitdirPointer reads a "gitdir: <path>" pointer file.
func gitdirPointer(file string) (string, bool) {
	data, err := readCapped(file, maxSmallFile)
	if err != nil {
		return "", false
	}
	for _, line := range lines(data) {
		if line == "" {
			continue
		}
		rest, found := strings.CutPrefix(line, "gitdir:")
		if !found {
			return "", false
		}
		rest = strings.TrimSpace(rest)
		if rest == "" {
			return "", false
		}
		return rest, true
	}
	return "", false
}

// resolveCommonDir returns the common directory for gitDir, which is gitDir
// itself unless a "commondir" file says otherwise.
func resolveCommonDir(gitDir string) string {
	data, err := readCapped(filepath.Join(gitDir, "commondir"), maxSmallFile)
	if err != nil {
		return gitDir
	}
	for _, line := range lines(data) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !filepath.IsAbs(line) {
			line = filepath.Join(gitDir, line)
		}
		common := filepath.Clean(line)
		if fi, err := os.Stat(common); err != nil || !fi.IsDir() {
			return gitDir
		}
		return common
	}
	return gitDir
}

// head reads HEAD and resolves it, returning the branch name (empty when
// detached) and the commit SHA (empty in a repository with no commits).
//
// HEAD holds either "ref: refs/heads/<name>" or a raw object ID. The ref form is
// followed — a loose ref may itself be symbolic — up to [maxIndirection] hops.
func head(gitDir, commonDir string) (branch, commit string) {
	data, err := readCapped(filepath.Join(gitDir, "HEAD"), maxSmallFile)
	if err != nil {
		return "", ""
	}
	value := firstLine(data)

	ref, isRef := symref(value)
	if !isRef {
		if isObjectID(value) {
			return "", value // detached HEAD
		}
		return "", "" // malformed; not worth an error
	}

	branch = strings.TrimPrefix(ref, "refs/heads/")
	if branch == ref {
		// HEAD on something that is not a branch (refs/tags/..., or a bare
		// name). There is no branch to report, but the commit is still useful.
		branch = ""
	}

	for range maxIndirection {
		value, ok := readRef(gitDir, commonDir, ref)
		if !ok {
			return branch, "" // unborn branch: HEAD names a ref not yet written
		}
		if isObjectID(value) {
			return branch, value
		}
		next, isRef := symref(value)
		if !isRef || next == ref {
			return branch, ""
		}
		ref = next
	}
	return branch, ""
}

// symref parses the "ref: <name>" form, validating the name is usable as a
// relative path before any caller joins it to a directory.
func symref(value string) (string, bool) {
	rest, found := strings.CutPrefix(value, "ref:")
	if !found {
		return "", false
	}
	ref := strings.TrimSpace(rest)
	if !validRefName(ref) {
		return "", false
	}
	return ref, true
}

// validRefName rejects anything that would escape the ref store when joined to
// it. This is the one place a hostile HEAD could turn into an arbitrary file
// read, so the rule is deliberately narrow rather than clever: refs/-rooted,
// slash-separated, no empty or dot components, no control characters.
func validRefName(ref string) bool {
	if !strings.HasPrefix(ref, "refs/") || len(ref) > 512 {
		return false
	}
	if strings.ContainsAny(ref, `\:?*[~^ `) {
		return false
	}
	for _, r := range ref {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	for _, part := range strings.Split(ref, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// readRef resolves one ref to its stored value.
//
// Loose refs are tried in gitDir first and commonDir second, in that order,
// because a linked worktree has its own refs/bisect and refs/worktree but shares
// refs/heads with the main checkout. packed-refs lives only in the common dir.
func readRef(gitDir, commonDir, ref string) (string, bool) {
	rel := filepath.FromSlash(path.Clean(ref))
	for _, base := range []string{gitDir, commonDir} {
		data, err := readCapped(filepath.Join(base, rel), maxSmallFile)
		if err != nil {
			continue
		}
		if value := firstLine(data); value != "" {
			return value, true
		}
	}
	return packedRef(filepath.Join(commonDir, "packed-refs"), ref)
}

// packedRef scans packed-refs for ref.
//
// The format is one "<sha> <refname>" per line. Lines starting with '#' are the
// header or a comment; lines starting with '^' are the peeled target of the
// previous line — an annotated tag's commit — and must be skipped, or a tag
// would resolve to the wrong object.
func packedRef(file, ref string) (string, bool) {
	data, err := readCapped(file, maxPackedRefs)
	if err != nil {
		return "", false
	}
	for _, line := range lines(data) {
		if line == "" || line[0] == '#' || line[0] == '^' {
			continue
		}
		id, name, found := strings.Cut(line, " ")
		if !found || !isObjectID(id) {
			continue
		}
		if strings.TrimSpace(name) == ref {
			return id, true
		}
	}
	return "", false
}

// isObjectID reports whether s is a full object ID: 40 lowercase hex characters
// for SHA-1, or 64 for the SHA-256 object format. Abbreviations are rejected,
// because a truncated ID is not a stable identity.
func isObjectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// originRemote reads a git config file and returns the normalized url of the
// "origin" remote, or "" if there is none.
//
// The format is INI-ish and only a subset matters here: [section] and
// [section "subsection"] headers, key = value lines, '#' and ';' comments, and
// leading tab indentation. Subsection names are case-sensitive while section and
// key names are not — which is why [Remote "origin"] matches and
// [remote "Origin"] does not. Later definitions win, as they do in git.
func originRemote(file string) string {
	data, err := readCapped(file, maxConfigFile)
	if err != nil {
		return ""
	}

	var section, subsection, raw string
	for _, line := range lines(data) {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			section, subsection = parseSectionHeader(line)
			continue
		}
		if section != "remote" || subsection != "origin" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || strings.ToLower(strings.TrimSpace(key)) != "url" {
			continue
		}
		if v := configValue(value); v != "" {
			raw = v
		}
	}
	return normalizeRemote(raw)
}

// parseSectionHeader parses "[remote \"origin\"]" into ("remote", "origin"). A
// header it cannot parse yields an empty section, which makes every following
// key belong to nothing — the safe direction, since the alternative is
// attributing a stray url to origin.
func parseSectionHeader(line string) (section, subsection string) {
	end := strings.LastIndex(line, "]")
	if end <= 0 {
		return "", ""
	}
	body := strings.TrimSpace(line[1:end])
	name, rest, hasSub := strings.Cut(body, " ")
	section = strings.ToLower(strings.TrimSpace(name))
	if !hasSub {
		// The dotted form, [remote.origin], is not valid git config, so it is
		// not accepted here either.
		return section, ""
	}
	rest = strings.TrimSpace(rest)
	if len(rest) >= 2 && rest[0] == '"' && rest[len(rest)-1] == '"' {
		rest = rest[1 : len(rest)-1]
	}
	return section, rest
}

// configValue trims a config value: surrounding whitespace, an optional pair of
// quotes, and an unquoted trailing comment.
func configValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' {
		if end := strings.Index(value[1:], `"`); end >= 0 {
			return value[1 : 1+end]
		}
		return strings.TrimSpace(value[1:])
	}
	if i := strings.IndexAny(value, "#;"); i >= 0 {
		value = value[:i]
	}
	return strings.TrimSpace(value)
}

// normalizeRemote reduces a remote URL to "host/path", the part that identifies
// the repository rather than the way one particular machine reaches it.
//
//	https://github.com/owner/repo.git              -> github.com/owner/repo
//	https://<user>:<token>@github.com/owner/repo   -> github.com/owner/repo
//	git@github.com:owner/repo.git                  -> github.com/owner/repo
//	ssh://git@github.com:22/owner/repo             -> github.com/owner/repo
//	git://github.com/owner/repo.git                -> github.com/owner/repo
//
// The credential form is written with placeholders rather than a literal
// user:token pair on purpose: a complete credential-shaped URI in this file is
// a true positive for our own secret scanner, and a repository that reports
// findings against itself trains its users to ignore findings.
//
// Scheme, credentials and port are all dropped because each of them varies
// between two clones of the same repository, and an identity that changes when a
// colleague switches from https to ssh is not an identity. A local path yields
// "" — see the package doc.
func normalizeRemote(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	host, p, ok := splitRemote(raw)
	if !ok {
		return ""
	}

	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	p = strings.Trim(strings.TrimSpace(p), "/")
	p = strings.TrimSuffix(p, ".git")
	p = strings.Trim(p, "/")
	if host == "" || p == "" || strings.Contains(host, "/") {
		return ""
	}
	return host + "/" + p
}

// splitRemote separates a remote URL into host and path, or reports that it
// names no host at all.
func splitRemote(raw string) (host, p string, ok bool) {
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", "", false
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "ssh", "git", "git+ssh", "ftp", "ftps":
		default:
			// file:// and anything unrecognized names a location, not a
			// repository identity.
			return "", "", false
		}
		// Hostname drops both the port and the userinfo; u.User is never read.
		return u.Hostname(), u.Path, true
	}

	// scp-like: [user@]host:path. The colon must come before any slash, or this
	// is a path that merely contains one.
	colon := strings.Index(raw, ":")
	if colon < 0 {
		return "", "", false // plain local path
	}
	if slash := strings.Index(raw, "/"); slash >= 0 && slash < colon {
		return "", "", false
	}
	hostPart, pathPart := raw[:colon], raw[colon+1:]
	if at := strings.LastIndex(hostPart, "@"); at >= 0 {
		hostPart = hostPart[at+1:]
	}
	// A single character before the colon is a Windows drive letter, not a host.
	if len(hostPart) < 2 || pathPart == "" {
		return "", "", false
	}
	return hostPart, pathPart, true
}

// readCapped reads at most limit bytes from file, failing rather than
// truncating: a file larger than the cap is corrupt or hostile, and half of one
// parses into plausible-looking nonsense.
func readCapped(file string, limit int64) ([]byte, error) {
	// gosec flags the variable path; every caller builds it from a validated ref
	// name or a fixed filename joined to a directory this package resolved, and
	// the read is capped, so there is nothing further to constrain.
	f, err := os.Open(file) //nolint:gosec // G304: path is derived, validated, and the read is capped
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", file, err)
	}
	// Read-only: a failed Close has nothing to report that the read did not.
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", file, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("reading %s: larger than %d bytes", file, limit)
	}
	return data, nil
}

// lines splits data on \n and strips a trailing \r, so a repository cloned with
// core.autocrlf on parses the same as one cloned without it.
func lines(data []byte) []string {
	split := strings.Split(string(data), "\n")
	for i, line := range split {
		split[i] = strings.TrimSuffix(line, "\r")
	}
	return split
}

// firstLine returns the first non-empty line of data, trimmed.
func firstLine(data []byte) string {
	for _, line := range lines(data) {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}
