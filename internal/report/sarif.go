package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/AnimeshRy/pindrop/internal/buildinfo"
	"github.com/AnimeshRy/pindrop/internal/scan"
)

// SARIF 2.1.0 is the OASIS standard that GitHub code scanning, GitLab, and most
// IDE security plugins consume. Emitting it is what lets Pindrop findings show
// up as inline pull-request annotations without any bespoke integration.
const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
)

// fingerprintKey names Pindrop's fingerprint in SARIF output. Consumers use
// partial fingerprints to match a finding across runs even when it moves, which
// is exactly what [scan.Fingerprint] is built for. The version suffix lets
// consumers cope if the algorithm ever changes.
const fingerprintKey = "pindropFingerprint/v1"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription sarifText         `json:"shortDescription"`
	FullDescription  *sarifText        `json:"fullDescription,omitempty"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       *sarifRuleProps   `json:"properties,omitempty"`
	DefaultConfig    sarifRuleDefaults `json:"defaultConfiguration"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags,omitempty"`
	// Precision and security-severity are GitHub extensions that drive alert
	// ranking in the code scanning UI.
	SecuritySeverity string `json:"security-severity,omitempty"`
}

type sarifRuleDefaults struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
	Snippet   *struct {
		Text string `json:"text"`
	} `json:"snippet,omitempty"`
}

// SARIF writes doc as a SARIF 2.1.0 log.
func SARIF(w io.Writer, doc Document) error {
	findings := doc.Findings

	rules := make([]sarifRule, 0, len(findings))
	ruleIndex := make(map[string]int, len(findings))
	sarifResults := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		// SARIF requires each result to reference a rule declared once in the
		// driver, so rules are deduplicated by ID as findings are walked.
		idx, ok := ruleIndex[f.RuleID]
		if !ok {
			idx = len(rules)
			ruleIndex[f.RuleID] = idx
			rules = append(rules, newSARIFRule(f))
		}

		sarifResults = append(sarifResults, sarifResult{
			RuleID:              f.RuleID,
			RuleIndex:           idx,
			Level:               sarifLevel(f.Severity),
			Message:             sarifText{Text: sarifMessage(f)},
			Locations:           []sarifLocation{newSARIFLocation(f)},
			PartialFingerprints: map[string]string{fingerprintKey: f.Fingerprint},
		})
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           buildinfo.Name,
				Version:        buildinfo.Version(),
				InformationURI: buildinfo.Homepage,
				Rules:          rules,
			}},
			Results: sarifResults,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("writing SARIF report: %w", err)
	}
	return nil
}

func newSARIFRule(f scan.Finding) sarifRule {
	rule := sarifRule{
		ID:               f.RuleID,
		ShortDescription: sarifText{Text: summary(f)},
		DefaultConfig:    sarifRuleDefaults{Level: sarifLevel(f.Severity)},
		Properties: &sarifRuleProps{
			Tags:             []string{"security", string(f.Category)},
			SecuritySeverity: securitySeverity(f.Severity),
		},
	}
	if f.Message != "" && f.Message != f.Title {
		rule.FullDescription = &sarifText{Text: f.Message}
	}
	if len(f.References) > 0 {
		rule.HelpURI = f.References[0]
	}
	return rule
}

func newSARIFLocation(f scan.Finding) sarifLocation {
	loc := sarifLocation{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: f.Location.Path},
		},
	}

	// SARIF regions are 1-indexed and a startLine of 0 is invalid, so
	// dependency findings that point at a whole manifest get no region.
	if f.Location.StartLine > 0 {
		region := &sarifRegion{StartLine: f.Location.StartLine}
		if f.Location.EndLine > f.Location.StartLine {
			region.EndLine = f.Location.EndLine
		}
		loc.PhysicalLocation.Region = region
	}
	return loc
}

// sarifMessage builds the result message, folding in the remediation when one
// is known, since that is the first thing a reader wants.
func sarifMessage(f scan.Finding) string {
	msg := f.Title
	if msg == "" {
		msg = f.Message
	}
	if msg == "" {
		msg = f.RuleID
	}

	if f.Package != nil {
		msg = fmt.Sprintf("%s (%s %s)", msg, f.Package.Name, f.Package.Version)
	}
	if f.FixedIn != "" {
		msg += fmt.Sprintf(" — fixed in %s", f.FixedIn)
	}
	return msg
}

// sarifLevel maps Pindrop severities onto SARIF's four-value level enum.
func sarifLevel(s scan.Severity) string {
	switch s {
	case scan.SeverityCritical, scan.SeverityHigh:
		return "error"
	case scan.SeverityMedium:
		return "warning"
	case scan.SeverityLow, scan.SeverityInfo:
		return "note"
	case scan.SeverityUnknown:
		return "none"
	default:
		return "none"
	}
}

// securitySeverity renders a CVSS-like score for GitHub code scanning, which
// buckets alerts by numeric range rather than by SARIF level.
func securitySeverity(s scan.Severity) string {
	switch s {
	case scan.SeverityCritical:
		return "9.0"
	case scan.SeverityHigh:
		return "7.0"
	case scan.SeverityMedium:
		return "5.0"
	case scan.SeverityLow:
		return "3.0"
	case scan.SeverityInfo, scan.SeverityUnknown:
		return ""
	default:
		return ""
	}
}
