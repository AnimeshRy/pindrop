package httpapi

import (
	"fmt"
	"os"
	"strings"

	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
)

// FileSource reads a Pindrop JSON report from disk on every request.
//
// Re-reading rather than caching means `pindrop scan --out report.json` in one
// terminal shows up on the next dashboard refresh in another, which is the
// workflow Phase 0 is built around. It is replaced by a database in Phase 3.
type FileSource struct {
	Path string
}

// Document implements [FindingSource].
func (s FileSource) Document() (report.Document, error) {
	f, err := os.Open(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return report.Document{}, fmt.Errorf(
				"no scan report at %s — run: pindrop scan . --format json --out %s",
				s.Path, s.Path)
		}
		return report.Document{}, fmt.Errorf("opening report: %w", err)
	}
	// Read-only: nothing to flush, so a close error is not actionable.
	defer func() { _ = f.Close() }()

	return report.DecodeDocument(f)
}

// filterSeverity keeps findings whose severity matches any of the
// comma-separated values in the query.
func filterSeverity(findings []scan.Finding, query string) []scan.Finding {
	wanted := splitSet(query)

	out := make([]scan.Finding, 0, len(findings))
	for _, f := range findings {
		if wanted[strings.ToLower(string(f.Severity))] {
			out = append(out, f)
		}
	}
	return out
}

// filterCategory keeps findings whose category matches any of the
// comma-separated values in the query.
func filterCategory(findings []scan.Finding, query string) []scan.Finding {
	wanted := splitSet(query)

	out := make([]scan.Finding, 0, len(findings))
	for _, f := range findings {
		if wanted[strings.ToLower(string(f.Category))] {
			out = append(out, f)
		}
	}
	return out
}

// splitSet parses a comma-separated query value into a lookup set.
func splitSet(query string) map[string]bool {
	parts := strings.Split(query, ",")
	set := make(map[string]bool, len(parts))
	for _, p := range parts {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			set[p] = true
		}
	}
	return set
}
