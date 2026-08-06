# 0008 — TruffleHog secret verification is opt-in

**Status:** accepted
**Date:** 2026-08-06

## Context

TruffleHog was chosen over Gitleaks for one reason, recorded in
[docs/architecture/scanners.md](../architecture/scanners.md) and
[docs/product/roadmap.md](../product/roadmap.md): its detectors can *verify* a
discovered credential by authenticating it against the service that issued it.
That turns "twelve secret-shaped strings" into "one live key", which is the
prioritization signal the vision doc's example depends on and the one thing no
amount of correlation can synthesize from regex hits.

Both documents also record that this needs a decision before the adapter ships,
because verification means taking a credential found in the user's code and
sending it to a third party over the network. Nothing else Pindrop does makes an
outbound request with the user's data.

The mitigating detail is that verification is not arbitrary egress. A verifier
calls the *issuer* of the credential it found — an AWS key goes to AWS, a GitHub
token to GitHub — so the secret is disclosed only to the party that already
holds it. The realistic harm is not disclosure but noise: a failed
authentication attempt appears in the account's audit log, may trip an alert, and
in aggregate looks like credential stuffing to whoever reads those logs.

Against that, this product's users are explicitly not security engineers. A tool
that reads your source code and, as a side effect of a `pindrop scan`, transmits
every credential it finds is not something a non-expert would predict from the
command they typed. Being surprised by that once is enough to lose the user.

## Decision

Verification is **off by default**. `pindrop scan` passes `--no-verification`.

It is enabled per-invocation with `--verify-secrets`, whose help text names the
consequence rather than the feature:

```
--verify-secrets   ask each provider whether a discovered secret is live;
                   SENDS the secrets it finds to third-party APIs
```

There is no config-file or environment-variable equivalent, and it is not
implied by any other flag. Enabling network egress of credentials should require
someone to have typed it.

When verification *is* enabled, the adapter also narrows output to
`--results=verified,unknown`. Having paid for the signal, a report that still
lists every unverified match has not used it.

Severity encodes the distinction so that turning the flag on is visible in the
output rather than only in the logs:

| Verification | Result | Severity |
|---|---|---|
| not requested | detected | high |
| requested | verified live | critical |
| requested | verification errored | high |
| requested | issuer says not live | medium |

An unverified detection is deliberately *not* critical. If it were, the
capability that justified choosing TruffleHog would make no difference to what
the user sees.

Separately, and for the same reason this decision was needed at all: the
plaintext credential never reaches a `scan.Finding`. `Raw`, `RawV2`, and
`SecretParts` are read inside the adapter to derive an identity digest and then
discarded. A Pindrop report is written to disk and served over HTTP, so a
finding carrying a secret would make a secret-scanning run into a second copy of
every secret it found.

## Consequences

**What this makes easy.** A default `pindrop scan` stays hermetic and offline,
like every other scanner Pindrop runs. Nobody can leak a credential by running
the tool the obvious way, and CI can adopt the secrets adapter without a review
of what it transmits.

**What it costs, plainly.** With verification off, TruffleHog is a
regex-and-format engine — which is what the roadmap criticized Gitleaks for
being. Trivy already ships 106 built-in secret rules, so on the default path this
adapter overlaps heavily with a scanner Pindrop already runs, and because secret
identity is rule ID plus path plus snippet, the two report the same credential
twice under different rule IDs rather than merging. The measured effect and the
mechanism are recorded in
[scanners.md](../architecture/scanners.md). Phase 0 therefore ships the tool
without the capability that motivated selecting it, and the value only arrives
for users who find the flag.

That cost is accepted because the failure modes are asymmetric. A user who never
enables verification gets a somewhat noisier secrets list, which the correlation
work in later phases can fix. A user surprised by credential egress has had
their credentials transmitted, which nothing can undo.

**A follow-up this creates.** Because unverified secrets grade `high`, anyone
running `--fail-on high` in CI will start failing on a repository containing a
secret-shaped placeholder that previously went unreported. Release-note it.

## Alternatives rejected

**Verification on by default.** TruffleHog's own default, and it makes the
product's headline claim work out of the box. Rejected because "reads your code"
and "transmits your credentials" are different permissions, and a CLI flag the
user did not pass cannot be treated as consent for the second.

**On by default with a first-run prompt.** Consent at the right moment, but
`pindrop scan` has to work non-interactively in CI, which is where it will mostly
run. A prompt that is skipped when stdin is not a terminal is a prompt that does
not protect the case that matters.

**Verify, but only credentials the user marks as non-production.** Sound in
principle and unimplementable in practice: knowing which of two AWS keys is the
staging one is exactly the knowledge the user does not have before triage, and it
is what they are running the scanner to acquire.

**Drop TruffleHog and reconsider Gitleaks.** Coherent, since without
verification the two are comparable and Gitleaks is MIT rather than AGPL and has
no egress question at all. Rejected because the verification capability is real
and is retained behind the flag, whereas choosing Gitleaks would foreclose it.
Superseding this decision to turn verification on by default remains available;
switching engines later would not.
