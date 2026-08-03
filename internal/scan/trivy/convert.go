package trivy

import (
	"strings"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// convert flattens a Trivy report into normalized findings.
//
// Trivy groups findings by target and class; Pindrop stores them flat, with the
// class folded into [scan.Category] and the target folded into the location.
func convert(rep report) []scan.Finding {
	var findings []scan.Finding

	for _, res := range rep.Results {
		for _, v := range res.Vulnerabilities {
			findings = append(findings, vulnerabilityFinding(res, v))
		}
		for _, m := range res.Misconfigurations {
			findings = append(findings, misconfigurationFinding(res, m))
		}
		for _, s := range res.Secrets {
			findings = append(findings, secretFinding(res, s))
		}
		for _, l := range res.Licenses {
			if !actionableLicense(l.Category) {
				continue
			}
			findings = append(findings, licenseFinding(res, l))
		}
	}

	for i := range findings {
		findings[i].Fingerprint = scan.Fingerprint(findings[i])
	}
	return findings
}

func vulnerabilityFinding(res result, v vulnerability) scan.Finding {
	title := v.Title
	if title == "" {
		title = v.VulnerabilityID + " in " + v.PkgName
	}

	return scan.Finding{
		Scanner:  Name,
		RuleID:   v.VulnerabilityID,
		Category: scan.CategoryVulnerability,
		Severity: severity(v.Severity),
		Title:    title,
		Message:  v.Description,
		Location: scan.Location{Path: res.Target},
		Package: &scan.PackageRef{
			Name:      v.PkgName,
			Version:   v.InstalledVersion,
			Ecosystem: strings.ToLower(res.Type),
			PURL:      v.PkgIdentifier.PURL,
		},
		FixedIn:    v.FixedVersion,
		References: references(v.PrimaryURL, v.References),
	}
}

func misconfigurationFinding(res result, m misconfiguration) scan.Finding {
	message := m.Message
	if m.Resolution != "" {
		message = strings.TrimSpace(message + "\n\nResolution: " + m.Resolution)
	}

	return scan.Finding{
		Scanner:  Name,
		RuleID:   m.ID,
		Category: scan.CategoryMisconfiguration,
		Severity: severity(m.Severity),
		Title:    m.Title,
		Message:  message,
		Location: scan.Location{
			Path:      res.Target,
			StartLine: m.CauseMetadata.StartLine,
			EndLine:   m.CauseMetadata.EndLine,
			Snippet:   causeSnippet(m.CauseMetadata),
		},
		References: references(m.PrimaryURL, m.References),
	}
}

func secretFinding(res result, s secret) scan.Finding {
	return scan.Finding{
		Scanner:  Name,
		RuleID:   s.RuleID,
		Category: scan.CategorySecret,
		Severity: severity(s.Severity),
		Title:    s.Title,
		// Trivy redacts the matched value, so Match is safe to store and show.
		Message: s.Match,
		Location: scan.Location{
			Path:      res.Target,
			StartLine: s.StartLine,
			EndLine:   s.EndLine,
			Snippet:   s.Match,
		},
	}
}

// actionableLicense reports whether a Trivy license category is worth showing.
//
// Trivy classifies every license it identifies, which means a clean repository
// still produces one "finding" per permissive dependency — scanning Pindrop
// itself yielded 24 MIT/Apache/BSD/ISC entries against 8 real problems. Burying
// the real problems under permissive-license noise is precisely the failure
// this product exists to prevent, so only the categories a team could actually
// have to act on are surfaced:
//
//   - forbidden and restricted: strong copyleft such as GPL or AGPL, which can
//     force a commercial product to publish its source
//   - reciprocal: weak copyleft such as MPL or LGPL, which carries real
//     obligations when a dependency is modified
//
// notice, permissive, unencumbered, and unknown are dropped. A user who wants
// the full inventory wants an SBOM, which is a different feature.
func actionableLicense(category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "forbidden", "restricted", "reciprocal":
		return true
	default:
		return false
	}
}

// licenseDescription renders a Trivy license category as a human explanation of
// why the finding is being shown at all.
func licenseDescription(category, name string) string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "forbidden":
		return name + " is a forbidden license: it is generally incompatible with distributing a commercial product."
	case "restricted":
		return name + " is a strong copyleft license: linking to it can require you to release your own source code."
	case "reciprocal":
		return name + " is a weak copyleft license: modifications to the dependency itself must usually be published."
	default:
		return name + " license (" + category + ")"
	}
}

func licenseFinding(res result, l license) scan.Finding {
	path := l.FilePath
	if path == "" {
		path = res.Target
	}

	return scan.Finding{
		Scanner:  Name,
		RuleID:   l.Name,
		Category: scan.CategoryLicense,
		Severity: severity(l.Severity),
		Title:    l.Name + " license in " + l.PkgName,
		Message:  licenseDescription(l.Category, l.Name),
		Location: scan.Location{Path: path},
		Package: &scan.PackageRef{
			Name:      l.PkgName,
			Ecosystem: strings.ToLower(res.Type),
		},
		References: references(l.Link, nil),
	}
}

// causeSnippet reassembles the source lines Trivy captured around a
// misconfiguration, so the finding can be fingerprinted on content rather than
// on a line number.
func causeSnippet(c causeMetadata) string {
	if len(c.Code.Lines) == 0 {
		return ""
	}

	var b strings.Builder
	for i, line := range c.Code.Lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(line.Content)
	}
	return b.String()
}

// severity maps Trivy's severity vocabulary onto Pindrop's. Unrecognized
// values become [scan.SeverityUnknown] rather than guessing.
func severity(s string) scan.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return scan.SeverityCritical
	case "HIGH":
		return scan.SeverityHigh
	case "MEDIUM":
		return scan.SeverityMedium
	case "LOW":
		return scan.SeverityLow
	case "INFO", "INFORMATIONAL":
		return scan.SeverityInfo
	default:
		return scan.SeverityUnknown
	}
}

// references merges Trivy's primary URL with its reference list, putting the
// primary first and dropping duplicates and blanks.
func references(primary string, rest []string) []string {
	if primary == "" && len(rest) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(rest)+1)
	out := make([]string, 0, len(rest)+1)
	for _, u := range append([]string{primary}, rest...) {
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}
