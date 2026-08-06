# TruffleHog golden fixture

`report.jsonl` is the adapter's golden report. This file carries the provenance
note that the other three adapters keep in a leading `_comment` key of their
`testdata/report.json` — JSON Lines has no place to put one, since every line
must decode as a finding. `docs/architecture/scanners.md` step 5 records this
exception.

Captured from a real TruffleHog run; do not hand-write findings here. Trivy
shipped reading a field its documentation described and the tool does not emit,
so adapter fixtures are captured and then trimmed, never transcribed.

**Tool:** trufflehog 3.96.0 (release binary, darwin/arm64).

**Command:**

```
trufflehog filesystem <scratch> --json --no-update --no-color \
  --no-verification --log-level=-1
```

## Why this fixture cannot be a verbatim capture

Real output contains the plaintext credential in `Raw`, `RawV2`, and every
`SecretParts` value. Committing a capture would mean committing working secrets,
so **every field carrying secret material has been substituted** with a
`FIXTURE-…-REMOVED` placeholder. Everything else — structure, key casing,
`DetectorType` numbers, `ExtraData`, `SourceName`, line numbers — is exactly what
the tool emitted.

The placeholders are deliberately shaped so that no detector matches them. This
file lives under `internal/`, which `docs/development/setup.md`'s healthy-repo
gate scans and requires to report zero secrets. A realistic-looking credential
here would make Pindrop report a critical secret in its own source on every scan.

The capture was taken against a scratch directory **outside this repository**
holding fabricated credentials, so no real secret was handled at any point. The
one exception is the `PrivateKey` entry, whose source was a throwaway RSA key
generated for the capture and then discarded.

## CAPTURED vs DERIVED

**CAPTURED** — the first six lines, one per detector: `PrivateKey`, `Stripe`,
`Github`, `Slack`, `AWS`, `Postgres`. Absolute paths were rewritten from the
capture machine to `/home/dev/pindrop/testdata/creds` so the fixture is stable
across machines; the adapter relativizes them against the scan root anyway.

These six exist to pin two things the adapter depends on and that no
documentation states:

- **`Redacted` is populated for `PrivateKey` and `AWS`, and empty for `Stripe`,
  `Github`, `Slack`, and `Postgres`.** It is per-detector implementation, not
  schema, which is why `Location.Snippet` is a digest of `Raw` rather than a
  conditional on `Redacted`. See `convert.go`.
- **`SourceMetadata.Data.Filesystem.line` is 1-based.** Verified against the
  source `.env`: `AWS_ACCESS_KEY_ID` on line 1, `GITHUB_TOKEN` on 3,
  `DATABASE_URL` on 4, `SLACK_BOT_TOKEN` on 5.

Also worth noting from the capture: `VerificationError` is **absent** rather than
empty when there is no error (`json:",omitempty"` upstream), and `RawV2` is
populated only for the multi-part detectors (`AWS`, `Postgres`) — which is why
identity digests `Raw` and not `RawV2`.

**DERIVED** — the last three lines, each a copy of a captured line with only the
named fields changed, so the structure stays exactly what the tool emits:

| Line | Change | Exercises |
|---|---|---|
| 7 | `AWS` with `Verified: true` | the `critical` severity branch |
| 8 | `Github` with a non-empty `VerificationError` | the verification-failed branch |
| 9 | `Github` at line 9 with a different `Raw` | two secrets of one detector in one file staying distinct |

They are derived because capturing them would require sending credentials to
third-party APIs, which is exactly what ADR 0008 makes opt-in.

## Not in this fixture, on purpose

Decoder edge cases — a blank line, a line above `bufio.Scanner`'s 64KB token
limit, and a malformed line — are covered by table tests with inline input in
`trufflehog_test.go` rather than here. They are properties of the decode loop,
not shapes the tool produces, and a 64KB base64 blob in a committed fixture is
noise that every other secret scanner would then have an opinion about.
