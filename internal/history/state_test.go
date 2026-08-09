package history

import (
	"testing"
	"time"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// finding builds a minimal finding with an identity and a reporting scanner.
func finding(fingerprint, scanner string) scan.Finding {
	return scan.Finding{
		Fingerprint: fingerprint,
		Scanner:     scanner,
		Category:    scan.CategoryVulnerability,
		Severity:    scan.SeverityHigh,
		Title:       "example",
	}
}

// ranSet is shorthand for the set of scanners a run executed.
func ranSet(names ...string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return set
}

// state builds a prior lifecycle entry.
func state(fingerprint string, status scan.Status, scanners ...string) FindingState {
	return FindingState{
		Fingerprint: fingerprint,
		Status:      status,
		Scanners:    scanners,
		Occurrences: 1,
		FirstRun:    RunID("20240101T000000Z-00000001"),
		LastRun:     RunID("20240101T000000Z-00000001"),
	}
}

func TestAdvanceTransitions(t *testing.T) {
	t.Parallel()

	run := RunID("20240102T000000Z-0000000a")
	at := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name         string
		prev         map[string]FindingState
		cur          []scan.Finding
		ran          map[string]bool
		scopeChanged bool
		wantStatus   scan.Status
		wantDelta    DeltaCounts
	}{
		{
			name:       "absent then present is new",
			cur:        []scan.Finding{finding("fp1", "trivy")},
			ran:        ranSet("trivy"),
			wantStatus: scan.StatusNew,
			wantDelta:  DeltaCounts{New: 1},
		},
		{
			name:       "new then present is open",
			prev:       map[string]FindingState{"fp1": state("fp1", scan.StatusNew, "trivy")},
			cur:        []scan.Finding{finding("fp1", "trivy")},
			ran:        ranSet("trivy"),
			wantStatus: scan.StatusOpen,
			wantDelta:  DeltaCounts{StillOpen: 1},
		},
		{
			name:       "open then present stays open",
			prev:       map[string]FindingState{"fp1": state("fp1", scan.StatusOpen, "trivy")},
			cur:        []scan.Finding{finding("fp1", "trivy")},
			ran:        ranSet("trivy"),
			wantStatus: scan.StatusOpen,
			wantDelta:  DeltaCounts{StillOpen: 1},
		},
		{
			name:       "fixed then present is regressed",
			prev:       map[string]FindingState{"fp1": state("fp1", scan.StatusFixed, "trivy")},
			cur:        []scan.Finding{finding("fp1", "trivy")},
			ran:        ranSet("trivy"),
			wantStatus: scan.StatusRegressed,
			wantDelta:  DeltaCounts{Regressed: 1},
		},
		{
			name:       "regressed then present is open",
			prev:       map[string]FindingState{"fp1": state("fp1", scan.StatusRegressed, "trivy")},
			cur:        []scan.Finding{finding("fp1", "trivy")},
			ran:        ranSet("trivy"),
			wantStatus: scan.StatusOpen,
			wantDelta:  DeltaCounts{StillOpen: 1},
		},
		{
			name:       "open then absent with its scanner run is fixed",
			prev:       map[string]FindingState{"fp1": state("fp1", scan.StatusOpen, "trivy")},
			ran:        ranSet("trivy"),
			wantStatus: scan.StatusFixed,
			wantDelta:  DeltaCounts{Fixed: 1},
		},
		{
			name:       "open then absent with only another scanner run is unchanged",
			prev:       map[string]FindingState{"fp1": state("fp1", scan.StatusOpen, "trufflehog")},
			ran:        ranSet("trivy"),
			wantStatus: scan.StatusOpen,
		},
		{
			name:       "open then absent with no scanners run is unchanged",
			prev:       map[string]FindingState{"fp1": state("fp1", scan.StatusOpen, "trivy")},
			ran:        ranSet(),
			wantStatus: scan.StatusOpen,
		},
		{
			name:         "open then absent with changed excludes is unchanged",
			prev:         map[string]FindingState{"fp1": state("fp1", scan.StatusOpen, "trivy")},
			ran:          ranSet("trivy"),
			scopeChanged: true,
			wantStatus:   scan.StatusOpen,
		},
		{
			name:       "fixed then absent stays fixed",
			prev:       map[string]FindingState{"fp1": state("fp1", scan.StatusFixed, "trivy")},
			ran:        ranSet("trivy"),
			wantStatus: scan.StatusFixed,
		},
		{
			name:       "one of two reporting scanners running is enough to fix",
			prev:       map[string]FindingState{"fp1": state("fp1", scan.StatusOpen, "osv", "trivy")},
			ran:        ranSet("osv"),
			wantStatus: scan.StatusFixed,
			wantDelta:  DeltaCounts{Fixed: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			next, _, delta := advance(tt.prev, tt.cur, tt.ran, tt.scopeChanged, run, at)
			got := next["fp1"].Status
			if got != tt.wantStatus {
				t.Errorf("status = %q, want %q", got, tt.wantStatus)
			}
			if delta != tt.wantDelta {
				t.Errorf("delta = %+v, want %+v", delta, tt.wantDelta)
			}
		})
	}
}

func TestAdvanceRecordsLifecycleDetail(t *testing.T) {
	t.Parallel()

	first := RunID("20240101T000000Z-00000001")
	second := RunID("20240102T000000Z-00000002")
	third := RunID("20240103T000000Z-00000003")
	t1 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.AddDate(0, 0, 1)
	t3 := t1.AddDate(0, 0, 2)
	ran := ranSet("trivy")

	index, _, _ := advance(nil, []scan.Finding{finding("fp1", "trivy")}, ran, false, first, t1)
	index, _, _ = advance(index, nil, ran, false, second, t2)
	index, statuses, delta := advance(index, []scan.Finding{finding("fp1", "trivy")}, ran, false, third, t3)

	got := index["fp1"]
	if got.Status != scan.StatusRegressed {
		t.Fatalf("status = %q, want %q", got.Status, scan.StatusRegressed)
	}
	if got.Regressions != 1 {
		t.Errorf("regressions = %d, want 1", got.Regressions)
	}
	if got.Occurrences != 2 {
		t.Errorf("occurrences = %d, want 2", got.Occurrences)
	}
	if got.FirstRun != first {
		t.Errorf("firstRun = %q, want %q", got.FirstRun, first)
	}
	if got.FixedRun != second {
		t.Errorf("fixedRun = %q, want %q — a regression must not forget when it was fixed", got.FixedRun, second)
	}
	if !got.FirstSeenAt.Equal(t1) || !got.LastSeenAt.Equal(t3) {
		t.Errorf("seen window = %v..%v, want %v..%v", got.FirstSeenAt, got.LastSeenAt, t1, t3)
	}
	if statuses["fp1"] != scan.StatusRegressed {
		t.Errorf("statuses[fp1] = %q, want %q", statuses["fp1"], scan.StatusRegressed)
	}
	if delta != (DeltaCounts{Regressed: 1}) {
		t.Errorf("delta = %+v, want one regression", delta)
	}
}

func TestAdvanceDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	prev := map[string]FindingState{"fp1": state("fp1", scan.StatusOpen, "trivy")}
	advance(prev, nil, ranSet("trivy"), false, "20240102T000000Z-0000000a", time.Now())

	if got := prev["fp1"].Status; got != scan.StatusOpen {
		t.Errorf("prior index was mutated: status = %q, want %q", got, scan.StatusOpen)
	}
}

func TestAdvanceSkipsUnfingerprintedFindings(t *testing.T) {
	t.Parallel()

	next, statuses, delta := advance(nil, []scan.Finding{
		finding("", "trivy"),
		finding("", "trivy"),
	}, ranSet("trivy"), false, "20240102T000000Z-0000000a", time.Now())

	if len(next) != 0 {
		t.Errorf("index has %d entries, want 0 — a finding with no fingerprint has no identity to track", len(next))
	}
	if len(statuses) != 0 {
		t.Errorf("statuses has %d entries, want 0", len(statuses))
	}
	if delta != (DeltaCounts{}) {
		t.Errorf("delta = %+v, want zero", delta)
	}
}

func TestAdvanceMergesScannersOfOneFingerprint(t *testing.T) {
	t.Parallel()

	dup := finding("fp1", "osv")
	dup.Scanners = []string{"osv", "trivy"}

	next, _, delta := advance(nil, []scan.Finding{
		finding("fp1", "trivy"),
		dup,
	}, ranSet("trivy", "osv"), false, "20240102T000000Z-0000000a", time.Now())

	got := next["fp1"]
	if len(got.Scanners) != 2 || got.Scanners[0] != "osv" || got.Scanners[1] != "trivy" {
		t.Errorf("scanners = %v, want [osv trivy]", got.Scanners)
	}
	if delta.New != 1 {
		t.Errorf("delta.New = %d, want 1 — one fingerprint reported twice is one finding", delta.New)
	}
	if got.Occurrences != 1 {
		t.Errorf("occurrences = %d, want 1", got.Occurrences)
	}
}
