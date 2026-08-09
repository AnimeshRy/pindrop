# 0009 — Pindrop is licensed Apache-2.0

**Status:** accepted
**Date:** 2026-08-07

## Context

The README has carried "Not yet chosen. All rights reserved for now; this will be
settled before the first public release" since the project started. That release
is now the work in progress, and it forces the decision: a GoReleaser pipeline, a
`curl | sh` installer, and a Homebrew tap all *distribute* the binary, and
distributing under all-rights-reserved gives the people we want adopting it no
right to run it.

Two constraints narrow the field.

The first is who the users are. The product thesis is small teams shipping
AI-generated code — people who are not security engineers and who will not read a
license, but whose employer's legal review might. A permissive license is the
difference between "someone tries it on Friday" and "someone files a ticket".

The second is that Pindrop is already downstream of four differently-licensed
tools ([docs/architecture/scanners.md](../architecture/scanners.md)). Trivy and
OSV-Scanner are Apache-2.0, Opengrep is LGPL-2.1, and TruffleHog is **AGPL-3.0**.
The standing rule that keeps this tractable is that every scanner runs as a
subprocess and none is ever imported — which is why `internal/scan/trufflehog`
shells out and why the Makefile deliberately avoids `go install` for it. Any
license we pick has to leave that arrangement intact.

## Decision

**Apache-2.0.** `LICENSE` holds the canonical text; `NOTICE` names the project
and lists the subprocess tools and their licenses.

`pindrop setup` downloading a TruffleHog binary onto the user's machine does not
change the analysis. Running an independent program as a subprocess does not
create a derivative work, and the binary is never redistributed by us — it is
fetched from TruffleHog's own release channel, at the user's request, at the
user's machine. The AGPL boundary stays exactly where ADR 0002 and
`docs/architecture/scanners.md` put it.

## Consequences

- Releases can ship. This was the blocking item.
- The patent grant in §3 is the concrete reason to prefer this over MIT: a
  security scanner is the kind of tool a company runs across its whole codebase,
  and an explicit grant removes a question a reviewer would otherwise have to
  ask.
- §4(b)'s notice requirement means `NOTICE` must ship inside the release archives.
  The GoReleaser config includes it alongside `LICENSE` and `README.md`.
- Every new subprocess scanner must be added to `NOTICE` with its license. This
  is now part of "adding a scanner", alongside the manifest entry.
- We keep no leverage against someone hosting the correlation layer as a service.
  That is a real cost, accepted below.

## Alternatives considered

**MIT.** Shorter and marginally more permissive, and no practical difference for a
CLI. Rejected only for the missing patent grant — for a tool that reads all of a
company's source, the explicit grant is worth the extra 190 lines.

**AGPL-3.0 with a commercial exception.** The open-core posture: since Phase 3
adds a hosted server, AGPL would stop a competitor from reselling the correlation
layer without contributing back. Rejected because it inverts the adoption
calculus at exactly the wrong moment. The scarce thing today is users, not
defensibility; AGPL is the license most likely to be blocked by a corporate
policy the user cannot influence, and it would also require a CLA to keep
relicensing possible. Note that
`docs/architecture/scanners.md` already records AGPL as "incompatible with the
commercial intent" in the context of *importing* TruffleHog — the same instinct,
applied to our own code.

**BSL or a source-available license.** Solves the hosted-competitor problem
without the AGPL's copyleft reach. Rejected as premature: it costs the "open
source security tool" framing that gets a scanner tried in the first place, in
exchange for protecting revenue that does not exist yet. Revisit if and when
Phase 3 has paying users — with a new ADR superseding this one, not an edit.

**Staying unlicensed and publishing anyway.** Rejected outright. It makes every
download a legal question mark and would make the Homebrew tap unpublishable.
