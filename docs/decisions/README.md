# Architecture Decision Records

Each record captures a decision that was not obvious, along with the reasoning
and the alternatives rejected.

**These are append-only in spirit.** To reverse a decision, add a new record
that supersedes the old one rather than editing history. The reasoning that
turned out to be wrong is often the most useful thing in the file — it stops the
next person re-walking the same path.

| # | Decision | Status |
|---|---|---|
| [0001](0001-core-stack.md) | Go, cobra, sqlc over an ORM, Connect for later | Accepted |
| [0002](0002-trivy-subprocess.md) | Run Trivy as a subprocess, not a library | Accepted |
| [0003](0003-embedded-spa.md) | Embed the SPA into the binary with `go:embed` | Accepted |
| [0004](0004-typescript-6-pin.md) | Pin TypeScript to 6.x rather than 7.x | Accepted, temporary |
| [0005](0005-mise-optional.md) | mise as an optional layer, not a build dependency | Accepted |
| [0006](0006-canonical-identity-before-dedup.md) | Canonicalize advisory IDs and package coordinates before fingerprinting | Accepted |
| [0007](0007-first-party-opengrep-rules.md) | Ship our own Opengrep rules; bundle none from any registry | Accepted |
| [0008](0008-trufflehog-verification-opt-in.md) | TruffleHog secret verification is off by default and opt-in | Accepted |

## Format

Keep them short:

```markdown
# NNNN — Title

**Status:** Proposed | Accepted | Superseded by NNNN
**Date:** YYYY-MM-DD

## Context
What forced a decision.

## Decision
What we chose.

## Consequences
What this makes easy, and what it costs.

## Alternatives considered
What was rejected and why.
```
