#![cfg(test)]

const WIT: &str = include_str!("../../interfaces/wit/fractal-companion-v1/companion.wit");

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

fn assert_record_has_fields(record: &str, fields: &[&str]) {
    let header = format!("record {record}");
    let body = body_after(&header);
    for field in fields {
        assert!(
            body.contains(field),
            "record {} must include field {}; body was:\n{}",
            record,
            field,
            body
        );
    }
}

fn assert_daily_records_omit_raw_fields() {
    for record in ["daily-root", "daily-item"] {
        let header = format!("record {record}");
        let body = body_after(&header);
        for line in body
            .lines()
            .filter(|line| !line.trim_start().starts_with("///"))
        {
            let field = line.trim();
            for forbidden in [
                "calendar:",
                "message:",
                "health:",
                "file:",
                "credential:",
                "path:",
                "command:",
                "args:",
            ] {
                assert!(
                    !field.starts_with(forbidden),
                    "daily projections must not expose raw field {:?}: {}",
                    forbidden,
                    field
                );
            }
        }
    }
}

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
            "redaction: redaction-class",
        ],
    );
    assert_record_has_fields(
        "daily-item",
        &[
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
    assert!(
        WIT.contains("Items sort by this key's UTF-8 bytes, then by ordinal"),
        "DailyItem ordering must be deterministic and independent of arrival order"
    );
    assert!(
        WIT.contains("get-daily-root: func") && WIT.contains("result<daily-root, export-error>"),
        "the daily root must be exposed as a typed projection"
    );
}

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
}

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
    assert_daily_records_omit_raw_fields();
}

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
    assert!(WIT.contains("epoch: u64,\n        date-key: string,\n        tz-key: string"));
    assert!(WIT.contains("Offset actually used for the rollover decision"));
    assert!(WIT.contains("Local civil date, exactly \"YYYY-MM-DD\""));
}

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
}

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
    assert!(
        WIT.contains("A merge is valid only when the schema explicitly declares it"),
        "merging must be authorized by a declared schema, never inferred"
    );
}

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
    let item = body_after("record daily-item").to_ascii_lowercase();
    assert!(!item.contains("command:") && !item.contains("path:") && !item.contains("args:"));
    assert!(
        WIT.contains("submit-task-intent: func"),
        "intent references must resolve through the typed task-intent operation"
    );
}

#[test]
fn daily_projection_never_contains_raw_personal_records() {
    assert_daily_records_omit_raw_fields();
    for record in ["daily-root", "daily-item"] {
        let header = format!("record {record}");
        let body = body_after(&header);
        assert!(body.contains("redaction: redaction-class"));
        assert!(body.contains("provenance: object-id"));
    }
}
