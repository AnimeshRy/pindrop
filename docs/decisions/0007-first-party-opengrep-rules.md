# 0007 — Pindrop ships its own Opengrep rules

**Status:** accepted
**Date:** 2026-08-05

## Context

Opengrep is the SAST engine ([scanners.md](../architecture/scanners.md)), and it
ships **no rules at all**. The release assets are binaries. A bare
`opengrep scan` has nothing to match with.

Three sources of rules exist, and the licensing of each decides this:

| Source | License | Usable by a commercial Pindrop |
|---|---|---|
| `opengrep/opengrep-rules` | LGPL-2.1 **+ Commons Clause** | **No** |
| Semgrep registry (`p/…`, `r/…`, `auto`) | Semgrep Rules License v1.0 | **No** |
| Written here | ours | Yes |

The Commons Clause removes "the right to Sell the Software", and defines *Sell*
to include providing a paid product or service "whose value derives, entirely or
substantially, from the functionality of the Software." A commercial security
scanner bundling those rules is the central example, not an edge case. That repo
additionally scopes itself to "research, testing & benchmarking" and is frozen at
December 2024.

Registry rules carry `license: Semgrep Rules License v1.0` in their own metadata.
Semgrep's CLI relicensing is what caused the Opengrep fork to exist; the rules
moved the same way. Using them to build a competitor is specifically what that
license prohibits.

There is a trap attached. **`--config` is not optional.** Omitting it makes
Opengrep fall back to `auto`, which resolves to `https://semgrep.dev/c/p/default`
and downloads ~2.4 MB of Semgrep-licensed rules from Semgrep Inc.'s servers on
every scan. Forgetting one flag turns a hermetic local scan into both a network
dependency and a licensing violation, with no error message.

## Decision

**Pindrop embeds a small ruleset written from scratch**, in
`internal/scan/opengrep/rules/`, compiled into the binary with `go:embed` and
extracted to a temporary directory per scan because `--config` requires a
filesystem path.

**`--opengrep-rules` replaces it** with any `--config` value: a file, a
directory, or a registry shorthand. Values pass through untouched, so a user who
wants a registry ruleset can have one. That is their licensing decision on their
own machine; the line we hold is that Pindrop does not distribute those rules.

The adapter **always passes an explicit `--config`**, so the `auto` default can
never be reached by accident.

## Consequences

**Coverage starts small.** Ten rules across JavaScript/TypeScript, Python, and
Go, against thousands in the registry. This is a real cost and the least bad one:
a curated set is also the only version of this that fits the product thesis. A
generic corpus contributes hundreds of findings, most of them
`subcategory: audit`, to a product whose entire claim is eight findings a
non-expert can act on. `p/security-audit` alone is 225 rules.

**The ruleset is now product surface, not configuration.** Rules need
maintenance, review, and tests like any other code. In exchange this is the host
for the AI-generated-code rules the roadmap names as the actual differentiator —
which could never have lived in a third-party corpus anyway.

**A rule `id` is a persisted identifier.** The adapter passes
`--no-rewrite-rule-ids`, so `check_id` is the authored `id`, which becomes
`Finding.RuleID`, which is an input to `scan.Fingerprint`. **Renaming a rule
orphans every triage decision recorded against it** — the same class of change as
altering the fingerprint function, and it must be treated as a migration. Without
that flag it would be worse: Opengrep prefixes ids with the rule file's path by
default, so *moving a file* would break identity.

**Findings carry no `Aliases`.** There is no shared namespace across SAST engines
to canonicalize a rule ID onto, so cross-tool SAST dedup remains unsolved, as
[ADR 0006](0006-canonical-identity-before-dedup.md) describes. Merging Opengrep
with a future second SAST engine is not a thing this design supports, and
pretending otherwise would require inventing an identity mapping whose mistakes
would merge unrelated findings.

**A user-supplied ruleset gets no curation from us**, so
`opengrep/convert.go`'s `actionable` filter drops suppressed matches,
`EXPERIMENT`/`INVENTORY` severities, and self-declared `LOW` confidence. On the
bundled set this is nearly a no-op; on a registry corpus it is what stands
between the user and the noise.

## Alternatives rejected

**Bundle `opengrep-rules`.** Broad coverage immediately, and a license that
prohibits exactly our use of it.

**Fetch registry rules at scan time instead of bundling them.** Would sidestep
*redistribution* while still building the product's value on rules whose license
forbids it, and would add a hard runtime dependency on a competitor's server. It
is also what happens by accident if `--config` is ever dropped, which is why the
adapter guards against it.

**Require `--opengrep-rules`, ship nothing.** Zero licensing surface and zero
maintenance, and the adapter reports nothing on a first run. The zero-setup first
run is the property the whole CLI is organized around.

**Fork `opengrep-rules` and relicense.** Not available to us — a downstream
cannot remove the Commons Clause from someone else's work.
