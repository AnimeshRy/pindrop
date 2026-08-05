# The bundled Opengrep ruleset

Ten first-party rules, embedded into the `pindrop` binary and written to a
temporary directory at scan time because `opengrep --config` requires a
filesystem path.

## Why none of these were copied from anywhere

Opengrep ships no rules at all, and neither available corpus can be
redistributed by a commercial product:

- **`opengrep/opengrep-rules`** is LGPL-2.1 **plus the Commons Clause**, which
  removes "the right to Sell the Software" — defined to include a paid product
  whose value derives substantially from it. Its own README also scopes it to
  "research, testing & benchmarking". It is additionally frozen at December 2024.
- **Semgrep registry rules** (`p/...`, `r/...`, and the `auto` default) carry
  `license: Semgrep Rules License v1.0`, and are served from Semgrep Inc.'s
  infrastructure.

So these are written from scratch. See
[ADR 0007](../../../../docs/decisions/0007-first-party-opengrep-rules.md).

A user who wants a different corpus points `--opengrep-rules` at it, which
replaces this set entirely. What they choose to run locally is their licensing
decision, not one Pindrop makes for them by bundling.

## A rule `id` is a persisted identifier

The adapter passes `--no-rewrite-rule-ids`, so the `check_id` in Opengrep's
output is exactly the `id` written here. That `check_id` becomes
`Finding.RuleID`, which is an input to `scan.Fingerprint`.

**Renaming a rule therefore orphans every triage decision recorded against it**,
exactly as changing the fingerprint function would. Treat a rename as a data
migration. Adding and deleting rules is safe; deleting one resolves its findings,
which is correct.

Without `--no-rewrite-rule-ids` — Opengrep's default — the `id` would be
prefixed with the rule file's path, so moving a file between directories would
have the same effect. That is why the flag is not optional.

## Conventions every rule here follows

- `severity` uses `ERROR`/`WARNING`/`INFO`. The adapter also understands the
  newer `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` vocabulary, but the older words are
  accepted by every version.
- `metadata.confidence: HIGH`. The adapter drops `LOW`-confidence findings, so a
  rule that cannot honestly claim high confidence does not belong in a bundled
  set — the whole product thesis is that eight findings a non-expert can act on
  beats two thousand.
- `metadata.cwe` and `metadata.references` are populated. References become
  `Finding.References`; the CWE is appended to the message.
- Every rule states, in `message`, **what to do instead**. Our users are not
  security engineers.
- Taint rules are preferred over pattern rules where a source matters, and
  `focus-metavariable` narrows sinks so that the correct, parameterized form is
  not flagged alongside the vulnerable one.

## Adding a rule

Write it, then run it against `testdata/vulnerable-app` **and** against this
repository. A rule that fires on Pindrop's own source is either finding a real
bug or is too broad; there is no third case.
