# Pindrop documentation

These documents exist to carry design context forward. When you (or an AI
assistant) return to this repository in three months, the code will say *what*
it does; these say *why*.

## Start here

| If you want to… | Read |
|---|---|
| Understand what Pindrop is for | [product/vision.md](product/vision.md) |
| Know what to build next | [product/roadmap.md](product/roadmap.md) |
| Find your way around the code | [architecture/repo-layout.md](architecture/repo-layout.md) |
| Change how findings are identified | [architecture/finding-model.md](architecture/finding-model.md) |
| Add a new scanner | [architecture/scanners.md](architecture/scanners.md) |
| Get set up locally | [development/setup.md](development/setup.md) |
| Know the coding conventions | [development/conventions.md](development/conventions.md) |
| Understand why a choice was made | [decisions/](decisions/) |

## How these are organized

- **product/** — what we are building and for whom. Changes when strategy
  changes.
- **architecture/** — how the system is shaped. Should stay accurate against the
  code; if it drifts, fix the doc in the same change that caused the drift.
- **decisions/** — Architecture Decision Records. Append-only in spirit: to
  reverse a decision, add a new record superseding the old one rather than
  rewriting history. The reasoning that turned out to be wrong is the most
  valuable part.
- **development/** — how to work on the code.

## The one-paragraph version

Pindrop runs existing security scanners (Trivy today; Gitleaks, Opengrep, and
others later), normalizes their wildly different outputs into a single
[`scan.Finding`](../internal/scan/finding.go), gives each finding a **stable
fingerprint** so it keeps its identity across scans, and ranks the result so a
user reads eight lines instead of two thousand. The scanners are commodity. The
normalization, identity, and ranking are the product.
