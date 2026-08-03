# Vision

## The problem

Small teams are shipping a lot of AI-generated code. It works, it ships, and
nobody on the team is a security engineer. They know they *should* be scanning
it, and the tools to do so are free — Trivy, Semgrep, Gitleaks are all one
`brew install` away.

They don't, for a reason that has nothing to do with cost: running those tools
on a real codebase produces thousands of findings, and a founder cannot triage
thousands of findings. The output is not actionable, so it gets ignored, so the
tool gets uninstalled.

## The thesis

**The scanners are commodity. The correlation layer is the product.**

Anyone can run Trivy. What nobody wants to build is the machinery that turns
scanner *events* into user *issues*:

1. **Normalization** — one model instead of four incompatible JSON shapes.
2. **Identity** — a fingerprint that survives code moving around, so an issue is
   still the same issue next week.
3. **Deduplication** — two tools finding one problem is one issue, and the
   agreement is a confidence signal rather than noise.
4. **Lifecycle** — mark something a false positive once and it stays marked,
   forever, across every future scan.
5. **Prioritization** — reachability, direct-vs-transitive, dev-vs-production,
   known exploits. Rank, then cut.

Concretely, the transformation we are selling:

| | Raw | After correlation |
|---|---|---|
| Trivy CVEs | 1,847 | 4 reachable and in CISA KEV |
| Secrets | 12 | 1 live key, verified |
| SAST | 340 | 3 in internet-facing handlers |
| **Total** | **2,288** | **8** |

A security engineer at a bank can grind through 2,288 findings; that is their
job. Our user cannot and will not. For them, the tool that shows 2,288 findings
is worth nothing and the tool that says "fix these 8, here is the diff" is worth
paying for.

## Who it is for

Small teams and solo founders shipping AI-assisted products. They are technical
but not security specialists. They want a verdict, not a dataset.

This shapes every product decision:

- **Defaults over configuration.** The table is capped at 25 rows by default,
  not because 25 is special but because an uncapped wall of text is the failure
  mode we exist to prevent.
- **Errors must be actionable.** "trivy not found in PATH" plus an install URL,
  never `exec: "trivy": executable file not found`.
- **Zero-setup first run.** `pindrop scan .` works with no account, no config
  file, no server. The CLI is the marketing.

## An angle nobody else has

AI-generated code fails in characteristic ways: credentials copied verbatim from
documentation examples, missing authorization on newly scaffolded routes,
string-concatenated SQL, permissive CORS, and **hallucinated packages** — the
model invents a dependency name, an attacker registers it, and the install
pulls malware.

Rules tuned specifically for these patterns would be a genuine differentiator.
No incumbent is aimed at this audience.

## Where this sits

| Product | Position |
|---|---|
| **DefectDojo** | The open-source incumbent. BSD, Django, ~10 years old, widely used and widely disliked. Correlation exists but is clunky. |
| **Dependency-Track** | Owns SBOM continuous monitoring. Narrow but excellent at it. |
| **Aikido, Jit, Arnica, Endor** | Commercial ASPM. Priced and scoped for security teams, not for a three-person startup. |
| **Pindrop** | Single binary, great defaults, aggressive noise reduction, aimed at people who are not security engineers. |

## Business shape

Open-core:

- **Open source** — the CLI and the scanner adapters. Distribution and trust.
- **Commercial** — the correlation engine, prioritization, dashboard, and
  multi-tenant platform. That is the moat, so it does not get given away.

No license file has been added yet; see
[decisions/](../decisions/) when that is settled.

## What would falsify the thesis

Worth stating plainly so we notice if it happens:

- If users want the full 2,288 findings and resent the truncation, the product
  premise is wrong and this is just a worse DefectDojo.
- If reachability analysis turns out not to cut noise meaningfully on real
  codebases, the prioritization story collapses into severity sorting, which
  Trivy already does for free.
