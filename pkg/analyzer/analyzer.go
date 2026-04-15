package analyzer

import (
	"context"
	"time"
)

// Severity describes the impact level of a finding.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Category groups findings by concern area.
type Category string

const (
	CategorySecurity    Category = "security"
	CategoryCodeQuality Category = "code_quality"
)

// Finding represents one issue discovered by an analyzer.
type Finding struct {
	RuleID      string
	Title       string
	Description string
	Severity    Severity
	Category    Category
	Path        string
	Line        int
}

// Result is the output of a single analyzer run.
type Result struct {
	AnalyzerName string
	StartedAt    time.Time
	FinishedAt   time.Time
	Findings     []Finding
}

// Analyzer is the minimal contract for any scanner implementation.
type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, target string) (Result, error)
}

// NewResult creates a basic result initialized with timestamps.
func NewResult(name string, findings []Finding) Result {
	now := time.Now().UTC()
	return Result{
		AnalyzerName: name,
		StartedAt:    now,
		FinishedAt:   now,
		Findings:     findings,
	}
}
