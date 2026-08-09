package history

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquireLockBreaksAStaleLock(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, lockName)
	if err := os.WriteFile(path, []byte("pid 999999\n"), fileMode); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	old := time.Now().Add(-2 * staleLockAge)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("ageing %s: %v", path, err)
	}

	lock, err := acquireLock(context.Background(), dir)
	if err != nil {
		t.Fatalf("acquireLock: %v — a lock left behind by a dead process must not stop recording scans", err)
	}
	lock.release()

	if _, err := os.Stat(path); err == nil {
		t.Error("the lock file survived release")
	}
}

func TestAcquireLockWaitsForALiveLock(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	first, err := acquireLock(context.Background(), dir)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}

	released := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		first.release()
		close(released)
	}()

	second, err := acquireLock(context.Background(), dir)
	if err != nil {
		t.Fatalf("acquireLock while held: %v", err)
	}
	defer second.release()

	select {
	case <-released:
	default:
		t.Error("the second lock was taken before the first was released")
	}
}

func TestAcquireLockHonorsContextCancellation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	held, err := acquireLock(context.Background(), dir)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}
	defer held.release()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := acquireLock(ctx, dir); err == nil {
		t.Error("acquireLock succeeded with a cancelled context")
	}
}
