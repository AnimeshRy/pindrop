package analyzer

import "context"

// NoopAnalyzer is a simple starter analyzer that returns no findings.
// Keep this as a baseline integration target while adding real analyzers.
type NoopAnalyzer struct{}

// Name returns the analyzer identifier.
func (NoopAnalyzer) Name() string {
	return "noop"
}

// Analyze performs a no-op scan and returns an empty result.
func (n NoopAnalyzer) Analyze(_ context.Context, _ string) (Result, error) {
	return NewResult(n.Name(), nil), nil
}
