package scan

// Status is where a finding sits in its lifecycle.
//
// This is the vocabulary that makes a second scan worth running. A scanner
// reports what is wrong now; a user needs to know what changed since they last
// looked, and specifically whether the thing they fixed is actually gone. That
// question is answerable only because [Fingerprint] gives a finding an identity
// that survives edits, reformatting, and a different tool reporting it.
type Status string

// Finding lifecycle states.
const (
	// StatusNew is a finding not present in any prior run.
	StatusNew Status = "new"
	// StatusOpen is a finding that was present in the previous run too.
	StatusOpen Status = "open"
	// StatusFixed is a finding that was present before and is absent now.
	StatusFixed Status = "fixed"
	// StatusRegressed is a finding that was fixed and has returned. It is the
	// one status that cannot be derived from two runs alone — see [Diff].
	StatusRegressed Status = "regressed"
)

// Valid reports whether s is a known status.
func (s Status) Valid() bool {
	switch s {
	case StatusNew, StatusOpen, StatusFixed, StatusRegressed:
		return true
	default:
		return false
	}
}

// Open reports whether s describes a finding that is currently present.
//
// New, Open and Regressed are open; Fixed is not. Callers use this rather than
// comparing against [StatusOpen], because "still open since last time" and
// "open right now" are different questions and only the second one decides
// whether a finding belongs in the report a user acts on.
//
// An unrecognized status is not open: a value we cannot interpret must not
// silently inflate the count of live problems.
func (s Status) Open() bool {
	switch s {
	case StatusNew, StatusOpen, StatusRegressed:
		return true
	default:
		return false
	}
}

// Delta is one finding paired with its status in the run being viewed.
//
// It exists so a report can carry lifecycle information alongside each finding
// without [Finding] itself growing a field that would then have to be excluded
// from [Fingerprint].
type Delta struct {
	Status  Status  `json:"status"`
	Finding Finding `json:"finding"`
}

// DiffResult partitions two finding sets by fingerprint.
type DiffResult struct {
	// New are findings present in current but not in previous.
	New []Finding `json:"new"`
	// StillOpen are findings present in both runs.
	StillOpen []Finding `json:"stillOpen"`
	// Fixed are findings present in previous but not in current.
	Fixed []Finding `json:"fixed"`
}

// Deltas flattens a [DiffResult] into one entry per finding, tagged with its
// status: New, then StillOpen, then Fixed, each preserving the order of the
// slice it came from.
//
// It never emits [StatusRegressed], for the reason given on [Diff].
func (d DiffResult) Deltas() []Delta {
	deltas := make([]Delta, 0, len(d.New)+len(d.StillOpen)+len(d.Fixed))
	for _, f := range d.New {
		deltas = append(deltas, Delta{Status: StatusNew, Finding: f})
	}
	for _, f := range d.StillOpen {
		deltas = append(deltas, Delta{Status: StatusOpen, Finding: f})
	}
	for _, f := range d.Fixed {
		deltas = append(deltas, Delta{Status: StatusFixed, Finding: f})
	}
	if len(deltas) == 0 {
		return nil
	}
	return deltas
}

// Diff partitions current against previous by fingerprint, answering "what
// changed since the last scan" without needing anything persisted. It is the
// no-store path: comparing two report files directly, or running with
// --no-history.
//
// Diff never reports [StatusRegressed]. Whether a returning finding was ever
// fixed is a property of a finding's whole history, not of two sets — a
// finding absent from `previous` is indistinguishable from one that was never
// seen. A history store computes that distinction later; conflating the two
// here would mean the same pair of runs could be labelled differently
// depending on what the caller happened to know, which is exactly the kind of
// unstable identity this product exists to avoid.
//
// Matching is strictly on [Finding.Fingerprint]; no other field is compared.
// That is load-bearing rather than an optimization. Fingerprints deliberately
// exclude line numbers and scanner names, so a finding that moved down a file
// after an unrelated edit is the same finding, and two tools reporting one
// problem is one finding. Comparing anything else here would reintroduce the
// churn [Fingerprint] exists to prevent.
//
// A finding with an empty fingerprint has no identity, so it can match
// nothing: such findings in current are all reported New and such findings in
// previous are all reported Fixed, each kept distinct rather than collapsed
// together. This follows [Dedup], which passes unfingerprinted findings
// through untouched — an unfingerprinted finding is an adapter bug, and
// merging several into one would hide it.
//
// Output order is deterministic and never depends on map iteration: New and
// StillOpen preserve the order of current, Fixed preserves the order of
// previous. Repeated fingerprints within one input slice yield a single output
// entry, the first one seen. Both properties matter because this feeds a CLI
// table and an HTTP API, where identical inputs must render identically.
func Diff(previous, current []Finding) DiffResult {
	before := make(map[string]struct{}, len(previous))
	for _, f := range previous {
		if f.Fingerprint != "" {
			before[f.Fingerprint] = struct{}{}
		}
	}

	now := make(map[string]struct{}, len(current))
	var result DiffResult

	for _, f := range current {
		if f.Fingerprint == "" {
			result.New = append(result.New, f)
			continue
		}
		if _, repeated := now[f.Fingerprint]; repeated {
			continue
		}
		now[f.Fingerprint] = struct{}{}

		if _, seen := before[f.Fingerprint]; seen {
			result.StillOpen = append(result.StillOpen, f)
		} else {
			result.New = append(result.New, f)
		}
	}

	emitted := make(map[string]struct{}, len(previous))
	for _, f := range previous {
		if f.Fingerprint == "" {
			result.Fixed = append(result.Fixed, f)
			continue
		}
		if _, repeated := emitted[f.Fingerprint]; repeated {
			continue
		}
		emitted[f.Fingerprint] = struct{}{}

		if _, still := now[f.Fingerprint]; !still {
			result.Fixed = append(result.Fixed, f)
		}
	}

	return result
}
