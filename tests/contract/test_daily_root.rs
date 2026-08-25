//! Contract tests for the DailyRoot / DailyItem projection.
//!
//! These are schema tests: they assert on the normative text and typed shape
//! of `interfaces/wit/fractal-companion-v1/companion.wit`, not on a running
//! adapter. The projector that must satisfy them lives behind
//! `userspace/sdk/src/daily_root.rs`; every rule checked here (D1..D7 in the
//! WIT) is a property that implementation has to preserve.
//!
//! The six required cases are one test each: deterministic rebuild, stale
//! source, unauthorized field projection, timezone rollover, offline branch
//! conflict, and schema-declared merge. Two further tests enforce that no raw
//! calendar, message, health, or file record can enter either record.

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

/// Neither daily record may carry a raw personal record in any encoding.
/// Enforced structurally (no free-form byte blobs, no unexpected strings)
/// rather than by keyword, so a renamed field cannot smuggle a body through.
fn assert_daily_records_omit_raw_fields() {
    const FORBIDDEN_NAMES: &[&str] = &[
        "calendar",
        "event-body",
        "message",
        "health",
        "medical",
        "file",
        "body",
        "content",
        "credential",
        "token",
        "secret",
        "path",
        "url",
        "command",
        "args",
        "argv",
        "note",
        "title",
        "summary",
        "text",
        "attendees",
        "location",
    ];
    // `ordering-key` is an opaque sort key; the two daily-root strings are the
    // bundle key itself. Nothing else may be a string or a byte list.
    const ALLOWED_STRINGS: &[&str] = &["ordering-key", "date-key", "tz-key"];

    for record in ["daily-root", "daily-item"] {
        for (name, ty) in record_fields(record) {
            for forbidden in FORBIDDEN_NAMES {
                assert!(
                    !name.contains(forbidden),
                    "daily projections must not expose raw field {name:?} in {record}"
                );
            }
            if ty == "string" {
                assert!(
                    ALLOWED_STRINGS.contains(&name.as_str()),
                    "{record}.{name} is a free-form string; only {ALLOWED_STRINGS:?} may be"
                );
            }
            assert!(
                ty != "list<u8>",
                "{record}.{name} is an unstructured byte blob"
            );
        }
    }
}

// ── 1. Deterministic rebuild ─────────────────────────────────────────────

#[test]
fn deterministic_rebuild_is_pinned_and_ordered() {
    assert_record_has_fields(
        "daily-root",
        &[
            "bundle-id: object-id",
            "project-root: object-id",
            "event-root: object-id",
            "range: event-range",
            "date-key: string",
            "tz-key: string",
            "provenance: object-id",
            "items: list<daily-item>",
            "item-count: u32",
            "redaction: redaction-class",
        ],
    );
    assert_record_has_fields(
        "daily-item",
        &[
            "item-id: object-id",
            "subject: object-id",
            "ordering-key: string",
            "ordinal: u32",
            "event-seq: u64",
            "provenance: object-id",
            "origin: source-class",
            "redaction: redaction-class",
        ],
    );

    assert!(
        WIT.contains("byte-identical") && WIT.contains("same roots and range"),
        "the bundle identity must be explicitly deterministic"
    );
    assert_wit_states("Items sort by this key's UTF-8 bytes, then by ordinal");
    assert_wit_states("ordering-key + ordinal is a TOTAL");

    // Observation state must be outside the identity, or a rebuild one second
    // later would produce a different bundle-id from identical inputs.
    assert_wit_states("is EXCLUDED from `bundle-id` and from");
    assert_wit_states("EXCLUDED\n        /// from `bundle-id` and from `provenance`");

    assert!(
        WIT.contains("get-daily-root: func") && WIT.contains("result<daily-root, export-error>"),
        "the daily root must be exposed as a typed projection"
    );
}

#[test]
fn daily_root_wire_mirror_matches_the_wit_record() {
    // The WIT preamble declares companion_export_contract.h normative.
    // A field that exists in only one of the two is an unimplementable
    // contract, not a documentation gap.
    let wire_root = ABI
        .split("companion_wire_daily_root_t")
        .next()
        .and_then(|head| head.rsplit_once("typedef struct"))
        .map(|(_, tail)| tail.to_string())
        .expect("missing companion_wire_daily_root_t");
    let wire_item = ABI
        .split("companion_wire_daily_item_t")
        .next()
        .and_then(|head| head.rsplit_once("typedef struct"))
        .map(|(_, tail)| tail.to_string())
        .expect("missing companion_wire_daily_item_t");

    for (record, wire) in [("daily-root", &wire_root), ("daily-item", &wire_item)] {
        for (name, _) in record_fields(record) {
            // The C mirror spells the IANA zone key out in full.
            let c_name = if name == "tz-key" {
                "timezone_key".to_string()
            } else {
                name.replace('-', "_")
            };
            assert!(
                wire.contains(&c_name),
                "{record}.{name} has no mirror field {c_name} in companion_export_contract.h"
            );
        }
    }
}

// ── 2. Stale source ──────────────────────────────────────────────────────

#[test]
fn stale_source_is_typed_and_never_silently_current() {
    let freshness = body_after("enum source-freshness");
    assert!(freshness.contains("fresh") && freshness.contains("stale"));
    assert!(freshness.contains("offline"));
    assert!(
        WIT.contains("stale-source"),
        "stale source must have a typed failure path"
    );
    assert_record_has_fields(
        "daily-root",
        &[
            "freshness-seconds: u32",
            "source-freshness: source-freshness",
        ],
    );
    assert_record_has_fields(
        "daily-item",
        &[
            "freshness-seconds: u32",
            "source-freshness: source-freshness",
        ],
    );

    // Per-item freshness exists so one stale adapter cannot be averaged away
    // behind a fresh-looking bundle.
    assert_wit_states("A stale or\n    /// offline source is reported explicitly");
    assert_wit_states("NEVER rendered as a fresh, empty, or partial day");
    assert_wit_states("Typed failures, never a silently empty day");
}

// ── 3. Unauthorized field projection ─────────────────────────────────────

#[test]
fn unauthorized_field_projection_has_denied_and_redacted_paths() {
    let lower = WIT.to_ascii_lowercase();
    assert!(
        lower.contains("daily-root,"),
        "daily-root must be a grantable projection"
    );
    assert!(lower.contains("denied") && lower.contains("redacted"));
    assert!(
        lower.contains("requested field's source-class is not exportable")
            && lower.contains("every field carries a `redaction-class`"),
        "authorization and source-class checks must be explicit"
    );

    // The grant is per projection, and its absence is a denial rather than an
    // empty bundle the companion would render as "nothing happened today".
    let grants = body_after("flags grant");
    assert!(grants.contains("daily-root"));
    assert_wit_states("Absence of a bit is a\n    /// denial, never a silent empty result");

    // Every projected field states how it survived redaction, and an item's
    // original source class must be `projection`.
    assert_record_has_fields("daily-root", &["redaction: redaction-class"]);
    assert_record_has_fields(
        "daily-item",
        &["origin: source-class", "redaction: redaction-class"],
    );
    assert_wit_states("Class of the ORIGINAL source. Must be `projection`");
    assert_daily_records_omit_raw_fields();
}

// ── 4. Timezone rollover ─────────────────────────────────────────────────

#[test]
fn timezone_rollover_is_part_of_the_daily_root_key() {
    assert_record_has_fields(
        "daily-root",
        &[
            "date-key: string",
            "tz-key: string",
            "utc-offset-minutes: s32",
        ],
    );
    let operation = WIT
        .lines()
        .find(|line| line.trim_start().starts_with("get-daily-root:"))
        .expect("missing get-daily-root operation");
    assert!(operation.contains("get-daily-root: func"));

    // The zone is a request parameter, so one instant can legitimately land in
    // two different days for two different zones.
    assert!(WIT.contains("epoch: u64,\n        date-key: string,\n        tz-key: string"));
    assert_wit_states("Offset actually used for the rollover decision");
    assert_wit_states("Local civil date, exactly \"YYYY-MM-DD\"");
    assert_wit_states("The bundle key is the pair");

    // A DST transition must not be resolved by coin flip: both the ambiguous
    // and the nonexistent local time have a stated winner.
    assert_wit_states("when a DST transition makes a local time ambiguous the");
    assert_wit_states("EARLIER (pre-transition) offset is chosen");
    assert_wit_states("nonexistent the later offset is chosen");
    assert_wit_states("its own `bundle-id`");
}

// ── 5. Offline branch conflict ───────────────────────────────────────────

#[test]
fn offline_branch_conflict_preserves_explicit_heads() {
    assert_record_has_fields(
        "daily-root",
        &[
            "conflict-heads: list<object-id>",
            "merge-policy: merge-policy",
            "source-freshness: source-freshness",
        ],
    );
    assert!(
        WIT.contains("Divergent heads preserved rather than silently merged")
            && WIT.contains("preserve-conflicts")
            && WIT.contains("conflict"),
        "offline branches must preserve all divergent heads"
    );

    // Preserved heads are themselves deterministic, and a preserved-conflict
    // bundle is servable rather than an error.
    assert_wit_states("Deduplicated and sorted in ascending byte order");
    assert_wit_states("Conflicts are preserved, never resolved by inference");
    assert_wit_states("is a valid, servable bundle");
    assert!(
        body_after("record limits")
            .lines()
            .any(|line| line.trim().starts_with("max-conflict-heads:")),
        "the preserved-head list must be bounded"
    );
}

// ── 6. Schema-declared merge ─────────────────────────────────────────────

#[test]
fn schema_declared_merge_is_explicit_and_typed() {
    let policy = body_after("enum merge-policy");
    assert!(policy.contains("preserve-conflicts") && policy.contains("schema-declared"));
    assert_record_has_fields(
        "daily-root",
        &[
            "merge-policy: merge-policy",
            "merge-schema: option<object-id>",
        ],
    );
    assert_wit_states("A merge is valid only when the schema explicitly declares it");

    // The declaring schema is not optional in practice: it is required exactly
    // when a merge happened, and forbidden when it did not.
    assert_wit_states("Present if and only if `merge-policy` is `schema-declared`");
    assert_wit_states("never by last-writer-wins");
    assert_wit_states("preserve-conflicts` is required when no schema-authorized merge exists");
}

// ── Typed intent, and no raw records at all ──────────────────────────────

#[test]
fn daily_items_carry_only_typed_task_intent_references() {
    assert_record_has_fields("daily-item", &["intent: option<task-intent-reference>"]);
    assert_record_has_fields(
        "task-intent-reference",
        &[
            "intent-id: object-id",
            "kind: intent-kind",
            "subject: object-id",
            "expect-root: object-id",
        ],
    );

    // The reference is a statement about pinned state, so it cannot grow a
    // command, a path, or an argument vector.
    for (name, ty) in record_fields("task-intent-reference") {
        assert!(
            ty != "string" && ty != "list<u8>",
            "task-intent-reference.{name} must be typed, not free-form ({ty})"
        );
    }
    let kinds = body_after("enum intent-kind");
    for kind in [
        "acknowledge",
        "defer",
        "prioritize",
        "request-proof",
        "cancel",
    ] {
        assert!(kinds.contains(kind), "intent-kind must include {kind}");
    }
    assert_wit_states("this enum cannot grow into a remote shell");
    assert!(
        WIT.contains("submit-task-intent: func"),
        "intent references must resolve through the typed task-intent operation"
    );
    // Acting on a stale day must fail loudly rather than mutate current state.
    assert_wit_states("Compare-and-swap against `expect-root`");
}

#[test]
fn daily_projection_never_contains_raw_personal_records() {
    assert_daily_records_omit_raw_fields();
    for record in ["daily-root", "daily-item"] {
        assert_record_has_fields(
            record,
            &["redaction: redaction-class", "provenance: object-id"],
        );
    }
    assert_wit_states("It is not a calendar,\n    // message, health, or file database");
    assert_wit_states("no calendar entry, message, file, or\n    /// health record ever crosses");
}
