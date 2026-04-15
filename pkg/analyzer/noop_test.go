package analyzer

import (
	"context"
	"testing"
)

func TestNoopAnalyzerAnalyze(t *testing.T) {
	t.Parallel()

	a := NoopAnalyzer{}
	got, err := a.Analyze(context.Background(), ".")
	if err != nil {
		t.Fatalf("Analyze() error = %v, want nil", err)
	}

	if got.AnalyzerName != a.Name() {
		t.Fatalf("AnalyzerName = %q, want %q", got.AnalyzerName, a.Name())
	}

	if len(got.Findings) != 0 {
		t.Fatalf("Findings length = %d, want 0", len(got.Findings))
	}

	if got.StartedAt.IsZero() || got.FinishedAt.IsZero() {
		t.Fatal("timestamps should not be zero")
	}
}
