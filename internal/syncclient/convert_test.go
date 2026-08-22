package syncclient

import (
	"testing"

	"github.com/AnimeshRy/pindrop/internal/history"
)

func TestRunsToSync(t *testing.T) {
	t.Parallel()

	runs := []history.Run{
		{ID: "20260102T120000Z-aaaaaaaa"},
		{ID: "20260101T120000Z-bbbbbbbb"},
		{ID: "20251231T120000Z-cccccccc"},
	}

	got := RunsToSync(runs, "20260101T120000Z-bbbbbbbb")
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].ID != "20260102T120000Z-aaaaaaaa" {
		t.Fatalf("got %s, want newest pending run first in push order after reverse", got[0].ID)
	}

	all := RunsToSync(runs, "")
	if len(all) != 3 {
		t.Fatalf("len = %d, want 3", len(all))
	}
	if all[0].ID != "20251231T120000Z-cccccccc" {
		t.Fatalf("first push should be oldest run, got %s", all[0].ID)
	}
}
