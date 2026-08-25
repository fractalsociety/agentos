//! Contract tests for the HealthAdapterSummary / HealthSignal projection.
//!
//! These are schema tests: they assert on the normative text and typed shape
//! of `interfaces/wit/fractal-companion-v1/companion.wit` and on its
//! normative C mirror `companion_export_contract.h`, not on a running
//! adapter. The adapter that must satisfy them serves
//! `get-health-adapter`; every rule checked here (H1..H7 in the WIT) is a
//! property that implementation has to preserve.
//!
//! The six required enforcement cases are one test each: explicit
//! authorization (H1), minimum-necessary aggregation (H2), consent-window
//! expiry (H3), deletion or revocation (H4), deterministic projection (H5),
//! and canary-record non-disclosure (H6). A seventh test pins H7: source
//! credentials stay opaque and outside the canonical event stream and
//! immutable shared workspaces. Further tests hold the record shape, the
//! wire mirror, and the "no raw medical record fields" invariant.

#![cfg(test)]

const WIT: &str = include_str!("../../interfaces/wit/fractal-companion-v1/companion.wit");

/// The C mirror named as normative by the WIT preamble.
const ABI: &str =
    include_str!("../../kernel/fractalos-root-task/include/contracts/companion_export_contract.h");

/// Body of the first brace-balanced block introduced by `header`.
fn body_after(header: &str) -> &str {
    let start = WIT
        .find(header)
        .unwrap_or_else(|| panic!("missing WIT section: {}", header));
    let open = WIT[start..]
        .find('{')
        .map(|idx| start + idx + 1)
        .unwrap_or_else(|| panic!("missing opening brace for {}", header));
    let mut depth = 1usize;
    for (offset, ch) in WIT[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &WIT[open..open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("missing closing brace for {}", header);
}

/// Declared `(name, type)` pairs of a record, with doc comments stripped.
/// Matching on declarations rather than raw substrings keeps a field from
/// being "satisfied" by a mention inside a comment.
fn record_fields(record: &str) -> Vec<(String, String)> {
    let header = format!("record {record}");
    let body = body_after(&header);
    let mut fields = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("///") || line.starts_with("//") {
            continue;
        }
        let line = line.trim_end_matches(',');
        let (name, ty) = line
            .split_once(':')
            .unwrap_or_else(|| panic!("record {record} has a non-field line: {line:?}"));
        fields.push((name.trim().to_string(), ty.trim().to_string()));
    }
    assert!(!fields.is_empty(), "record {record} declared no fields");
    fields
}

/// Variants of an enum, with doc comments stripped.
fn enum_variants(name: &str) -> Vec<String> {
    let header = format!("enum {name}");
    body_after(&header)
        .lines()
        .map(|line| line.split("//").next().unwrap_or_default().trim())
        .filter(|line| line.ends_with(','))
        .map(|line| line.trim_end_matches(',').trim().to_owned())
        .collect()
}

#[track_caller]
fn assert_record_has_fields(record: &str, required: &[&str]) {
    let declared = record_fields(record);
    for want in required {
        let (name, ty) = want
            .split_once(':')
            .map(|(n, t)| (n.trim(), t.trim()))
            .unwrap_or_else(|| panic!("bad expectation {want:?}"));
        let found = declared
            .iter()
            .find(|(have, _)| have == name)
            .unwrap_or_else(|| {
                panic!("record {record} must declare field {name}; declared: {declared:?}")
            });
        assert_eq!(
            found.1, ty,
            "record {record} field {name} must have type {ty}, found {}",
            found.1
        );
    }
}

#[track_caller]
fn assert_wit_states(claim: &str) {
    assert!(
        WIT.contains(claim),
        "companion.wit must state, normatively: {claim:?}"
    );
}

/// Neither health record may carry a raw medical record -- or any free-form
/// value a medical record could be smuggled through -- in any encoding.
/// Enforced structurally (no free-form strings, no unstructured byte blobs,
/// no measurement-shaped names) rather than by keyword alone, so a renamed
/// field cannot smuggle a body through.
fn assert_health_records_omit_raw_fields() {
    const FORBIDDEN_NAMES: &[&str] = &[
        "diagnosis",
        "condition",
        "medication",
        "measurement",
        "value",
        "unit",
        "series",
        "trend",
        "patient",
        "record-id",
        "provider",
        "observation",
        "note",
        "body",
        "content",
        "credential",
        "token",
        "secret",
        "password",
        "path",
        "url",
        "command",
        "args",
        "canary",
        "sentinel",
    ];
    for record in ["health-signal", "health-adapter-summary"] {
        for (name, ty) in record_fields(record) {
            for forbidden in FORBIDDEN_NAMES {
                assert!(
                    !name.contains(forbidden),
                    "health projections must not expose raw field {name:?} in {record}"
                );
            }
            assert!(
                ty != "string",
                "{record}.{name} is a free-form string; health fields are typed and coarse"
            );
            assert!(
                ty != "list<u8>",
                "{record}.{name} is an unstructured byte blob"
            );
        }
    }
}

/// C mirror body of a wire typedef (comments stripped by the caller-side
/// field extraction, same approach as the daily-root contract test).
fn wire_struct_fields(typedef_name: &str) -> Vec<String> {
    let end_marker = format!("}} {typedef_name};");
    let end = ABI
        .find(&end_marker)
        .unwrap_or_else(|| panic!("missing C typedef {typedef_name}"));
    let start = ABI[..end].rfind("typedef struct").expect("typedef start");
    let open = start + ABI[start..end].find('{').expect("typedef brace");
    ABI[open + 1..end]
        .lines()
        .map(|line| line.split("/*").next().unwrap_or_default().trim())
        .filter(|line| line.ends_with(';'))
        .filter(|line| !line.trim_end_matches(';').trim().is_empty())
        .map(|line| {
            line.trim_end_matches(';')
                .split_whitespace()
                .last()
                .expect("C field")
                .split('[')
                .next()
                .expect("C array field")
                .to_owned()
        })
        .filter(|name| !name.starts_with("reserved"))
        .collect()
}

// ── Shape: the two records carry exactly the consented metadata ──────────

#[test]
fn health_records_are_consent_scoped_fresh_coarse_and_provenance_bound() {
    assert_record_has_fields(
        "health-signal",
        &[
            "source: health-source",
            "status: health-status",
            "provenance: object-id",
            "observed-unix: u64",
            "freshness-seconds: u32",
            "source-freshness: source-freshness",
            "redaction: redaction-class",
        ],
    );
    assert_record_has_fields(
        "health-adapter-summary",
        &[
            "schema: schema-version",
            "authority-epoch: u64",
            "source: source-handle",
            "origin: source-class",
            "consent-scope: list<health-source>",
            "consent-expires-unix: u64",
            "revoked: bool",
            "status: health-status",
            "freshness-seconds: u32",
            "signals: list<health-signal>",
            "provenance: object-id",
            "range: event-range",
            "redaction: redaction-class",
        ],
    );

    // The unit of consent and the unit of source identity are both coarse.
    assert_eq!(
        enum_variants("health-source"),
        ["unknown", "activity", "sleep", "readiness", "workload"]
    );
    // Coarse status only: the enum cannot grow a numeric-measurement case
    // without breaking this exact-set assertion.
    assert_eq!(
        enum_variants("health-status"),
        ["unknown", "ok", "attention", "stale"]
    );

    // The class of the ORIGINAL data is stated, and it pins the summary to
    // the never-exported-verbatim class.
    assert_wit_states("Class of the ORIGINAL data behind this summary");
    assert_wit_states("`source-class.personal-record`");
    let personal_record = body_after("enum source-class");
    assert!(
        personal_record.contains("personal-record") && personal_record.contains("Never exported"),
        "personal-record must remain a never-exported source class"
    );

    assert_health_records_omit_raw_fields();
}

#[test]
fn health_operation_has_one_typed_projection_result() {
    let operation = WIT
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("get-health-adapter:"))
        .expect("health operation");
    assert_eq!(
        operation,
        "get-health-adapter: func(epoch: u64) -> result<health-adapter-summary, export-error>;"
    );
    assert_record_has_fields(
        "limits",
        &["max-health-signals: u32", "max-consent-scopes: u32"],
    );
}

// ── 1. Explicit authorization ────────────────────────────────────────────

#[test]
fn authorization_is_explicit_grant_plus_per_family_consent() {
    // The projection is grantable, and a missing grant bit is a denial --
    // never a silent empty summary rendered as "everything is fine".
    let grants = body_after("flags grant");
    assert!(grants.contains("health"));
    assert_wit_states("Absence of a bit is a\n    /// denial, never a silent empty result");

    // Consent is explicit, per family, and checked per signal.
    assert_wit_states("Reading requires the `health` grant AND");
    assert_wit_states("per-family user consent recorded in `consent-scope`");
    assert_wit_states("missing is `export-error.denied` -- never an empty or default");
    assert_wit_states("A signal may only be emitted for a family listed in");
    assert_wit_states("consent is per family, never global");

    // Empty consent is a real state, distinct from revocation, and it must
    // deny rather than default-open.
    assert_wit_states("Empty means no\n        /// consent, which is distinct from `revoked`");
    let errors = enum_variants("export-error");
    assert!(
        errors.iter().any(|variant| variant == "denied"),
        "denial must be a typed failure"
    );

    // The operation doc restates the closed paths so the failure mode is
    // part of the operation contract, not an implementation detail.
    assert_wit_states("Returns `denied` when");
    assert_wit_states("never an empty summary in place of a denial");
}

// ── 2. Minimum-necessary aggregation ─────────────────────────────────────

#[test]
fn aggregation_is_minimum_necessary_and_coarse_only() {
    assert_wit_states("The only values that cross are");
    assert_wit_states("the coarse enums `health-source` and `health-status`");
    assert_wit_states(
        "No\n    //       measurement, value, unit, series, trend, record identifier,",
    );
    assert_wit_states("provider name, or timestamp series appears in any field at any");
    assert_wit_states("redaction class");
    assert_wit_states("`provenance` is a hash over exactly the");
    assert_wit_states("minimum-necessary aggregate that produced `status`");
    assert_wit_states("verifiable without being reversible");

    // The enums are closed sets (checked exactly above), and the records
    // have no free-form slot a raw record could occupy (checked in the
    // shape test). Redaction state is stated per record.
    assert_record_has_fields(
        "health-signal",
        &["redaction: redaction-class", "provenance: object-id"],
    );
    assert_record_has_fields(
        "health-adapter-summary",
        &["redaction: redaction-class", "provenance: object-id"],
    );
    assert_wit_states("the coarsest aggregate that still answers");
    assert_health_records_omit_raw_fields();
}

// ── 3. Expiry ────────────────────────────────────────────────────────────

#[test]
fn consent_window_expiry_is_typed_and_freshness_is_per_signal() {
    assert_record_has_fields("health-adapter-summary", &["consent-expires-unix: u64"]);
    assert_wit_states("Consent is a window, not a standing state");
    assert_wit_states("reads fail `export-error.expired`");
    assert_wit_states("rather than serving on stale consent");

    let errors = enum_variants("export-error");
    for expected in ["expired", "stale-source"] {
        assert!(
            errors.iter().any(|variant| variant == expected),
            "{expected} must be a typed failure"
        );
    }

    // Freshness is stated per signal so one stale family cannot hide behind
    // a fresh-looking rollup, and staleness is never rendered as currency.
    assert_record_has_fields(
        "health-signal",
        &[
            "freshness-seconds: u32",
            "source-freshness: source-freshness",
        ],
    );
    assert_record_has_fields(
        "health-adapter-summary",
        &["freshness-seconds: u32", "status: health-status"],
    );
    assert_wit_states("Each signal states its own");
    assert_wit_states("one stale family cannot hide behind a fresh");
    assert_wit_states("never rendered as a fresh, current, or empty");
    assert!(enum_variants("health-status").contains(&"stale".to_owned()));
    let freshness = body_after("enum source-freshness");
    assert!(freshness.contains("stale") && freshness.contains("offline"));
}

// ── 4. Deletion or revocation ────────────────────────────────────────────

#[test]
fn deletion_and_revocation_fail_closed() {
    assert_record_has_fields("health-adapter-summary", &["revoked: bool"]);
    assert_wit_states("`revoked` is true once the user revoked");
    assert_wit_states("consent or the source was deleted");
    assert_wit_states("serves `export-error.denied` -- never a cached summary");
    assert_wit_states("tombstone that still names the source");

    // Deleted source data removes the affected signals; a cached aggregate
    // may not outlive the deletion it summarizes.
    assert_wit_states("Deleting source data\n    //       removes the affected signals");
    assert_wit_states("a cached aggregate may not survive");
    assert_wit_states("the deletion it summarizes");
}

// ── 5. Deterministic projection ──────────────────────────────────────────

#[test]
fn projection_is_deterministic_and_pinned() {
    // Signals are totally ordered by family, never by arrival or iteration.
    assert_wit_states("At most one signal per family");
    assert_wit_states("ordered by ascending `health-source` ordinal");
    assert_wit_states("never arrival");
    assert_wit_states("adapter iteration order, or an implementation address");

    // Rebuild determinism: identity inputs are pinned, wall clock is not.
    assert_wit_states("Rebuilding from the same pinned `range`, consent state, and");
    assert_wit_states("source observations must produce a byte-identical `provenance`");
    assert_wit_states("wall-clock build time is not an input to any identity");

    // The summary is pinned to an immutable canonical event range, like
    // every other projection on this interface.
    assert_record_has_fields("health-adapter-summary", &["range: event-range"]);
    assert_wit_states("Every projection is pinned to an `event-range` and a root `object-id`");
}

// ── 6. Canary-record non-disclosure ──────────────────────────────────────

#[test]
fn canary_records_are_never_disclosed() {
    assert_wit_states("Canary or sentinel records planted in a");
    assert_wit_states("health source are never disclosed");
    // Not the values, not the existence, not the count, not the absence.
    assert_wit_states(
        "their\n    //       existence, their count, and their absence are not exported",
    );
    assert_wit_states("no field distinguishes them");
    // Canaries must not leak through the output shape either.
    assert_wit_states("contribute nothing to any signal, status, or provenance hash");
    assert_wit_states("cannot infer their presence from the output");
    assert_wit_states("shape or from any error path");

    // Structurally: no field in either record could name or flag a canary.
    for record in ["health-signal", "health-adapter-summary"] {
        assert!(
            record_fields(record)
                .into_iter()
                .all(|(name, _)| !name.contains("canary") && !name.contains("sentinel")),
            "{record} must not carry a canary-distinguishing field"
        );
    }
    assert_health_records_omit_raw_fields();
}

// ── 7. Credentials: opaque, outside canonical events and workspaces ──────

#[test]
fn credentials_are_opaque_and_outside_canonical_state() {
    assert_wit_states("Credentials stay behind the adapter");
    assert_wit_states("live only inside the adapter");
    assert_wit_states("salted, non-reversible `source` handle");
    assert_wit_states("never enter the canonical event stream");
    assert_wit_states("never enter an immutable shared workspace");

    // The handle is a fixed-size opaque alias, and the summary identifies
    // its source only through it.
    let aliases = WIT
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("type "))
        .collect::<Vec<_>>();
    assert!(aliases.contains(&"type source-handle = list<u8>;"));
    assert_wit_states("EXACTLY 32 bytes");
    assert_wit_states("carries no credential, account name, or address");
    assert_record_has_fields("health-adapter-summary", &["source: source-handle"]);
    let summary = record_fields("health-adapter-summary");
    assert!(
        !summary
            .iter()
            .any(|(name, _)| name == "source-id" || name == "account" || name == "provider-id"),
        "the summary must not identify the source beyond the opaque handle"
    );

    // The C mirror lowers the handle to the same opaque 32-byte type, so
    // credentials cannot ride along in the wire encoding either.
    assert!(ABI.contains("typedef companion_object_id_t companion_source_handle_t;"));
    let wire_summary = wire_struct_fields("companion_wire_health_adapter_summary_t");
    assert!(
        wire_summary.contains(&"source".to_owned()),
        "the wire summary must carry the opaque handle"
    );
    assert!(
        !wire_summary.iter().any(|name| name.contains("credential")
            || name.contains("token")
            || name.contains("secret")),
        "the wire summary must not carry credential-shaped fields"
    );

    // Top-level binding rule 4 already forbids credentials on the whole
    // interface; the health rules restate it for the adapter specifically.
    assert_wit_states("raw credentials or secret material");
}

// ── Wire mirror ───────────────────────────────────────────────────────────

#[test]
fn health_wire_mirror_matches_the_wit_records() {
    // The WIT preamble declares companion_export_contract.h normative.
    // A field that exists in only one of the two is an unimplementable
    // contract, not a documentation gap.
    for (record, typedef) in [
        ("health-signal", "companion_wire_health_signal_t"),
        (
            "health-adapter-summary",
            "companion_wire_health_adapter_summary_t",
        ),
    ] {
        let wire = wire_struct_fields(typedef);
        let wit_names = record_fields(record)
            .into_iter()
            .map(|(name, _)| name.replace('-', "_"))
            .collect::<Vec<_>>();
        assert_eq!(
            wire, wit_names,
            "semantic field drift between {record} and {typedef}"
        );
    }

    // The health result rides the bounded transport like every other
    // projection, and the record-type discriminant exists for it.
    assert!(ABI.contains("COMPANION_WIRE_HEALTH_ADAPTER_SUMMARY = 5u"));
    assert!(ABI.contains("_Static_assert(sizeof(companion_wire_record_t) + sizeof(companion_wire_health_adapter_summary_t)"));
}
