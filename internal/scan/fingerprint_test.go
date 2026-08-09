package scan_test

import (
	"testing"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// vulnFinding returns a representative dependency finding that tests mutate.
func vulnFinding() scan.Finding {
	return scan.Finding{
		Scanner:  "trivy",
		RuleID:   "CVE-2024-21538",
		Category: scan.CategoryVulnerability,
		Severity: scan.SeverityHigh,
		Location: scan.Location{Path: "package-lock.json", StartLine: 412},
		Package: &scan.PackageRef{
			Name:      "cross-spawn",
			Version:   "7.0.3",
			Ecosystem: "npm",
		},
	}
}

// codeFinding returns a representative location-scoped finding.
func codeFinding() scan.Finding {
	return scan.Finding{
		Scanner:  "semgrep",
		RuleID:   "go.lang.security.audit.database.string-formatted-query",
		Category: scan.CategoryCode,
		Severity: scan.SeverityHigh,
		Location: scan.Location{
			Path:      "internal/api/users.go",
			StartLine: 42,
			Snippet:   `db.Query("SELECT * FROM users WHERE id = " + id)`,
		},
	}
}

// TestFingerprintStability covers the mutations that must NOT change a
// finding's identity. Each of these would otherwise show up as "one issue
// resolved, one new issue introduced" on the next scan.
func TestFingerprintStability(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		base   scan.Finding
		mutate func(scan.Finding) scan.Finding
	}{
		{
			name: "line shifted by an inserted import",
			base: codeFinding(),
			mutate: func(f scan.Finding) scan.Finding {
				f.Location.StartLine += 7
				f.Location.EndLine += 7
				return f
			},
		},
		{
			// The version is the finding's current state, not its identity.
			// A partial upgrade — to a version that is still subject to the
			// same advisory — is the most common way a dependency finding
			// changes, and it must read as one unresolved issue rather than
			// as one resolved and one new.
			name: "package bumped to a version the advisory still covers",
			base: vulnFinding(),
			mutate: func(f scan.Finding) scan.Finding {
				f.Package.Version = "7.0.4"
				return f
			},
		},
		{
			name: "snippet reindented",
			base: codeFinding(),
			mutate: func(f scan.Finding) scan.Finding {
				f.Location.Snippet = "\t\t" + f.Location.Snippet
				return f
			},
		},
		{
			name: "snippet whitespace collapsed by a formatter",
			base: codeFinding(),
			mutate: func(f scan.Finding) scan.Finding {
				f.Location.Snippet = `db.Query("SELECT * FROM users WHERE id = "   +    id)`
				return f
			},
		},
		{
			name: "reported by a different scanner",
			base: vulnFinding(),
			mutate: func(f scan.Finding) scan.Finding {
				f.Scanner = "grype"
				return f
			},
		},
		{
			name: "severity re-graded by an updated advisory",
			base: vulnFinding(),
			mutate: func(f scan.Finding) scan.Finding {
				f.Severity = scan.SeverityCritical
				return f
			},
		},
		{
			name: "fix version published",
			base: vulnFinding(),
			mutate: func(f scan.Finding) scan.Finding {
				f.FixedIn = "7.0.5"
				return f
			},
		},
		{
			name: "advisory text rewritten",
			base: vulnFinding(),
			mutate: func(f scan.Finding) scan.Finding {
				f.Title = "Regular Expression Denial of Service in cross-spawn"
				f.Message = "A completely different description."
				return f
			},
		},
		{
			name: "manifest path expressed with backslashes",
			base: vulnFinding(),
			mutate: func(f scan.Finding) scan.Finding {
				f.Location.Path = `.\package-lock.json`
				return f
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			want := scan.Fingerprint(tt.base)
			got := scan.Fingerprint(tt.mutate(tt.base))
			if got != want {
				t.Errorf("Fingerprint() = %q after mutation, want unchanged %q", got, want)
			}
		})
	}
}

// TestFingerprintDistinguishes covers the mutations that MUST change identity.
// Merging these would hide real problems behind a single triaged issue.
func TestFingerprintDistinguishes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		base   scan.Finding
		mutate func(scan.Finding) scan.Finding
	}{
		{
			name: "different CVE",
			base: vulnFinding(),
			mutate: func(f scan.Finding) scan.Finding {
				f.RuleID = "CVE-2024-37890"
				return f
			},
		},
		{
			name: "same CVE in a different service of a monorepo",
			base: vulnFinding(),
			mutate: func(f scan.Finding) scan.Finding {
				f.Location.Path = "services/billing/package-lock.json"
				return f
			},
		},
		{
			name: "same package name in a different ecosystem",
			base: vulnFinding(),
			mutate: func(f scan.Finding) scan.Finding {
				f.Package.Ecosystem = "pypi"
				return f
			},
		},
		{
			name: "same rule in a different file",
			base: codeFinding(),
			mutate: func(f scan.Finding) scan.Finding {
				f.Location.Path = "internal/api/orders.go"
				return f
			},
		},
		{
			name: "code actually changed",
			base: codeFinding(),
			mutate: func(f scan.Finding) scan.Finding {
				f.Location.Snippet = `db.Query("SELECT * FROM accounts WHERE id = " + id)`
				return f
			},
		},
		{
			name: "same coordinates but a different category",
			base: codeFinding(),
			mutate: func(f scan.Finding) scan.Finding {
				f.Category = scan.CategoryVulnerability
				return f
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			base := scan.Fingerprint(tt.base)
			got := scan.Fingerprint(tt.mutate(tt.base))
			if got == base {
				t.Errorf("Fingerprint() = %q, want a value different from the base finding", got)
			}
		})
	}
}

func TestFingerprintIsDeterministic(t *testing.T) {
	t.Parallel()

	f := vulnFinding()
	want := scan.Fingerprint(f)
	for range 100 {
		if got := scan.Fingerprint(f); got != want {
			t.Fatalf("Fingerprint() = %q on repeat call, want %q", got, want)
		}
	}
}

func TestFingerprintLength(t *testing.T) {
	t.Parallel()

	for _, f := range []scan.Finding{vulnFinding(), codeFinding(), {}} {
		if got := len(scan.Fingerprint(f)); got != 32 {
			t.Errorf("len(Fingerprint()) = %d, want 32", got)
		}
	}
}

func TestNormalizeSnippet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"only whitespace", " \t\n ", ""},
		{"trims ends", "  foo  ", "foo"},
		{"collapses internal runs", "a \t  b", "a b"},
		{"flattens newlines", "if x {\n\treturn y\n}", "if x { return y }"},
		{"already normal", "a b c", "a b c"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := scan.NormalizeSnippet(tt.in); got != tt.want {
				t.Errorf("NormalizeSnippet(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
