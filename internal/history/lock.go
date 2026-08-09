package history

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AnimeshRy/pindrop/internal/toolpath"
)

// Lock tuning.
//
// staleLockAge is how long a lock file may go untouched before it is assumed to
// belong to a process that died. It is generous relative to a Put, which writes
// a few files, and short relative to a user's patience. lockTimeout is how long
// a Put waits for a live lock before giving up with an error naming the file.
const (
	lockName     = ".lock"
	staleLockAge = 60 * time.Second
	lockTimeout  = 5 * time.Second
	lockMinWait  = 10 * time.Millisecond
	lockMaxWait  = 250 * time.Millisecond
)

// lockFile is a held cross-process lock on one repository directory.
type lockFile struct{ path string }

// acquireLock takes the lock for a repository directory, creating the directory
// if needed.
//
// The mechanism is O_CREATE|O_EXCL, not flock and not x/sys. Exclusive create is
// the one file operation that behaves the same on every filesystem and every
// platform Pindrop ships to, and adding golang.org/x/sys to a security tool to
// serialize a JSON write is a supply-chain trade that does not pay. The cost is
// that a lock cannot be released by the kernel when a process dies, which is
// what staleLockAge handles.
//
// A stale lock is broken rather than reported, because the alternative is a
// machine that stops recording scans until someone reads an error message about
// a hidden file. A live lock that outlasts lockTimeout is reported, and the
// message names the file to delete, because at that point guessing is worse.
func acquireLock(ctx context.Context, dir string) (*lockFile, error) {
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}
	path := filepath.Join(dir, lockName)

	deadline := time.Now().Add(lockTimeout)
	wait := lockMinWait
	for {
		// #nosec G304 -- the path is the store directory plus a validated RepoID
		// and a constant file name; O_EXCL is the point of the call.
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fileMode)
		if err == nil {
			// Best effort: the contents are for a human debugging a stuck lock,
			// so a failed write must not fail an otherwise acquired lock.
			_, _ = fmt.Fprintf(f, "pid %d\nstarted %s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
			_ = f.Close()
			return &lockFile{path: path}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("locking %s: %w", toolpath.Display(path), err)
		}

		if breakStaleLock(path) {
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf(
				"another pindrop scan is already writing this repository's history; "+
					"if none is running, delete %s and try again",
				toolpath.Display(path))
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for %s: %w", toolpath.Display(path), ctx.Err())
		case <-time.After(wait):
		}
		if wait *= 2; wait > lockMaxWait {
			wait = lockMaxWait
		}
	}
}

// breakStaleLock removes a lock older than staleLockAge and reports whether it
// did. A lock that vanished between the failed create and the stat is also
// reported as broken, since the next attempt will succeed.
func breakStaleLock(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return errors.Is(err, os.ErrNotExist)
	}
	if time.Since(info.ModTime()) < staleLockAge {
		return false
	}
	return os.Remove(path) == nil
}

// release drops the lock. A failure to remove is not reported: the caller is on
// its way out with a result worth returning, and the lock will age out.
func (l *lockFile) release() {
	if l == nil {
		return
	}
	_ = os.Remove(l.path)
}
