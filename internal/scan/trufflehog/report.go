package trufflehog

// Types mirroring one line of `trufflehog --json` output.
//
// Written from a real v3.96.0 capture, not from documentation or the protobuf
// definitions — see testdata/README.md for the exact command and for which parts
// of the fixture are captured and which are derived. The Trivy adapter shipped
// reading an `AVDID` field that documentation mentioned and the tool does not
// emit, which is why this is the rule.
//
// Two details are worth stating because they are not obvious from the wire
// format. The output is JSON Lines, one object per finding, so there is no
// enclosing report type here as there is for the other three adapters. And the
// field names come from Go's encoding/json marshalling the printer's anonymous
// struct, not from protojson: the outer keys are Go field names in PascalCase
// while the nested Filesystem keys carry the generated protobuf tags and are
// lowercase.
//
// Only consumed fields are modelled. Deliberately absent: SourceID, SourceType,
// DetectorType, StructuredData, VerificationFromCache, and Filesystem.link and
// .email, which the filesystem source leaves empty.

// finding is one credential detection.
type finding struct {
	// DetectorName is the detector's protobuf enum name, such as "AWS" or
	// "PrivateKey". It becomes Finding.RuleID and is therefore a fingerprint
	// input, so it must be stable — protobuf enum names are append-only, which
	// is why this is used rather than the numeric DetectorType.
	DetectorName        string `json:"DetectorName"`
	DetectorDescription string `json:"DetectorDescription"`

	// DecoderName is the decoder that surfaced the secret ("PLAIN", "BASE64").
	// Read for the message only, never for identity: the same secret found once
	// as plaintext and once inside a base64 blob is one problem, and digesting
	// Raw makes those two reports merge on their own.
	DecoderName string `json:"DecoderName"`

	// Verified reports that a verifier authenticated the credential against its
	// issuer. It is always false when the scan ran with --no-verification, which
	// is Pindrop's default, so it cannot be read without also knowing whether
	// verification was requested. See severity in convert.go.
	Verified bool `json:"Verified"`

	// VerificationError is absent rather than empty when verification succeeded
	// or was never attempted; upstream tags it `json:",omitempty"`.
	VerificationError string `json:"VerificationError"`

	// Raw is the PLAINTEXT credential. It must never reach a scan.Finding — it
	// is read only to derive the identity digest and is then discarded. RawV2 is
	// the same, and additionally is populated only by multi-part detectors such
	// as AWS and Postgres, which is why identity digests Raw.
	Raw   string `json:"Raw"`
	RawV2 string `json:"RawV2"`

	// SecretParts holds the credential broken into named components, every value
	// of which is plaintext. Modelled solely so that the "no plaintext escapes"
	// test can assert these values appear nowhere in a marshalled Finding.
	SecretParts map[string]string `json:"SecretParts"`

	// Redacted is TruffleHog's display-safe rendering. It is per-detector
	// implementation rather than schema — populated for PrivateKey and AWS,
	// empty for Stripe, Github, Slack, and Postgres in the captured fixture —
	// so it is used for display only and never for identity.
	Redacted string `json:"Redacted"`

	// ExtraData carries detector-specific context. The key worth surfacing is
	// "rotation_guide", a URL explaining how to rotate that credential type,
	// which is the most actionable thing in the whole record.
	ExtraData map[string]string `json:"ExtraData"`

	SourceMetadata sourceMetadata `json:"SourceMetadata"`
}

// sourceMetadata wraps the protobuf oneof. The nesting is real: the oneof
// wrapper type carries no json tag, so encoding/json emits the Go field name.
type sourceMetadata struct {
	Data metadataData `json:"Data"`
}

type metadataData struct {
	Filesystem *filesystemMetadata `json:"Filesystem"`
}

// filesystemMetadata locates a finding in the scanned tree.
type filesystemMetadata struct {
	// File is absolute, so it must be relativized against the scan root before
	// it reaches a Finding — the path is a fingerprint input.
	File string `json:"file"`

	// Line is 1-based, verified against the captured fixture's source file. It
	// is int64 on the wire because the protobuf field is; the conversion to int
	// is range-guarded in convert.go.
	Line int64 `json:"line"`
}
