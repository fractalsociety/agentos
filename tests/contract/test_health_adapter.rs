#![cfg(test)]

//! Contract tests for the privacy-bounded health adapter projection.
//!
//! These tests assert the WIT schema and normative binding rules that an
//! eventual adapter implementation must enforce: explicit authorization,
//! minimum-necessary aggregation, expiry, deletion/revocation fail-closed
//! behavior, deterministic projection, and canary-record non-disclosure.

use std::collections::BTreeMap;

const WIT: &str = include_str!("../../interfaces/wit/fractal-companion-v1/companion.wit");

fn block(kind: &str, name: &str) -> String {
    let clean = WIT
        .lines()
        .map(|line| line.split("//").next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");
    let start = clean
        .find(&format!("{kind} {name}"))
        .unwrap_or_else(|| panic!("missing {kind} {name}"));
    let open = start + clean[start..].find('{').expect("opening brace");
    let mut depth = 0usize;
    for (offset, ch) in clean[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return clean[open + 1..open + offset].to_owned();
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced {kind} {name}");
}

fn fields(name: &str) -> BTreeMap<String, String> {
    block("record", name)
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with(','))
        .map(|line| {
            let (name, ty) = line.trim_end_matches(',').split_once(':').expect("field");
            (name.trim().to_owned(), ty.trim().to_owned())
        })
        .collect()
}

fn variants(name: &str) -> Vec<String> {
    block("enum", name)
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with(','))
        .map(|line| line.trim_end_matches(',').to_owned())
        .collect()
}

#[track_caller]
fn assert_wit_states(claim: &str) {
    assert!(
        WIT.contains(claim),
        "companion.wit must state health adapter rule: {claim:?}"
    );
}

#[test]
fn health_adapter_summary_and_signal_are_coarse_consent_scoped_projections() {
    let signal = fields("health-signal");
    for (name, ty) in [
        ("source", "health-source"),
        ("origin", "source-class"),
        ("consent-scope", "health-source"),
        ("status", "health-status"),
        ("freshness-seconds", "u32"),
        ("source-freshness", "source-freshness"),
        ("provenance", "object-id"),
        ("redaction", "redaction-class"),
    ] {
        assert_eq!(signal.get(name).map(String::as_str), Some(ty), "{name}");
    }

    let summary = fields("health-adapter-summary");
    for (name, ty) in [
        ("source", "source-handle"),
        ("origin", "source-class"),
        ("consent-scope", "list<health-source>"),
        ("consent-expires-unix", "u64"),
        ("revoked", "bool"),
        ("status", "health-status"),
        ("freshness-seconds", "u32"),
        ("source-freshness", "source-freshness"),
        ("signals", "list<health-signal>"),
        ("provenance", "object-id"),
        ("range", "event-range"),
        ("redaction", "redaction-class"),
    ] {
        assert_eq!(summary.get(name).map(String::as_str), Some(ty), "{name}");
    }
}

#[test]
fn explicit_authorization_and_consent_are_normative_fail_closed_requirements() {
    assert_wit_states("H1. Explicit authorization");
    assert_wit_states("caller holds the health grant");
    assert_wit_states("non-empty\n    ///       `consent-scope`");
    assert_wit_states("included in that scope");
    assert_wit_states("consent window is still open");

    let errors = variants("export-error");
    for expected in ["denied", "expired", "stale-source"] {
        assert!(
            errors.iter().any(|variant| variant == expected),
            "{expected}"
        );
    }
    let grants = block("flags", "grant");
    assert!(grants.lines().map(str::trim).any(|line| line == "health,"));
}

#[test]
fn minimum_necessary_aggregation_excludes_raw_medical_records_and_credentials() {
    assert_wit_states("H2. Minimum necessary");
    assert_wit_states("never enter canonical\n    ///       events, immutable shared workspaces, logs, or this interface");
    assert_wit_states("only coarse statuses and provenance hashes");
    assert_wit_states("minimum aggregate needed");

    assert_eq!(
        variants("health-source"),
        ["unknown", "activity", "sleep", "readiness", "workload"]
    );
    assert_eq!(
        variants("health-status"),
        ["unknown", "ok", "attention", "stale"]
    );

    let combined = fields("health-signal")
        .into_iter()
        .chain(fields("health-adapter-summary"))
        .chain(fields("health-adapter"))
        .collect::<Vec<_>>();
    for (name, ty) in &combined {
        for forbidden in [
            "diagnosis",
            "condition",
            "medication",
            "measurement",
            "value",
            "unit",
            "patient",
            "medical-record",
            "record-id",
            "credential",
            "secret",
            "token",
            "account",
            "device-id",
            "calendar-body",
            "message-body",
            "note-text",
            "observed-unix",
            "canary",
        ] {
            assert!(!name.contains(forbidden), "forbidden health field {name:?}");
        }
        assert_ne!(
            ty, "string",
            "health field {name} must not be free-form text"
        );
        assert_ne!(ty, "list<u8>", "health field {name} must not be raw bytes");
    }
}

#[test]
fn expiry_deletion_and_revocation_cannot_serve_cached_summaries() {
    assert_wit_states("H3. Expiry, deletion, and revocation fail closed");
    assert_wit_states("Expired consent\n    ///       returns `expired`");
    assert_wit_states("deleted or revoked sources return `denied`");
    assert_wit_states("MUST NOT serve a cached summary");

    let summary = fields("health-adapter-summary");
    assert_eq!(summary.get("revoked").map(String::as_str), Some("bool"));
    assert_eq!(
        summary.get("consent-expires-unix").map(String::as_str),
        Some("u64")
    );
}

#[test]
fn deterministic_projection_is_bound_to_authorized_aggregates_not_source_order() {
    assert_wit_states("H4. Deterministic projection");
    assert_wit_states("Replaying the same authorized aggregate");
    assert_wit_states("source handle, event range, and status inputs");
    assert_wit_states("byte-identical `health-adapter-summary` and `health-signal`");
    assert_wit_states("Observation state is represented only as freshness");

    let summary = fields("health-adapter-summary");
    assert_eq!(
        summary.get("provenance").map(String::as_str),
        Some("object-id")
    );
    assert_eq!(
        summary.get("range").map(String::as_str),
        Some("event-range")
    );
    assert_eq!(
        summary.get("source-freshness").map(String::as_str),
        Some("source-freshness")
    );
    assert!(!summary.contains_key("built-at-unix"));
}

#[test]
fn canary_medical_records_have_no_semantic_or_fallback_export_path() {
    assert_wit_states("H5. Canary non-disclosure");
    assert_wit_states("no canary body, identifier,");
    assert_wit_states("fallback debug formatting");

    for record in ["health-signal", "health-adapter-summary", "health-adapter"] {
        assert!(
            fields(record).keys().all(|field| !field.contains("canary")),
            "{record}"
        );
    }
}

#[test]
fn source_credentials_remain_opaque_and_outside_canonical_surfaces() {
    let aliases = WIT
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("type "))
        .collect::<Vec<_>>();
    assert!(aliases.contains(&"type source-handle = list<u8>;"));
    assert_eq!(
        fields("health-adapter-summary")
            .get("source")
            .map(String::as_str),
        Some("source-handle")
    );
    assert!(!fields("health-adapter-summary").contains_key("source-id"));
    assert_wit_states("credentials live behind `source` and never leave the adapter");
    assert_wit_states("never enter canonical\n    ///       events, immutable shared workspaces, logs, or this interface");
}

#[test]
fn consent_and_signal_lists_have_negotiated_bounds() {
    let limits = fields("limits");
    assert_eq!(
        limits.get("max-consent-scopes").map(String::as_str),
        Some("u32")
    );
    assert_eq!(
        limits.get("max-health-signals").map(String::as_str),
        Some("u32")
    );
}

#[test]
fn health_operation_exposes_only_the_compat_projection_result() {
    let operation = WIT
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("get-health-adapter:"))
        .expect("health operation");
    assert_eq!(
        operation,
        "get-health-adapter: func(epoch: u64) -> result<health-adapter, export-error>;"
    );
    // `health-adapter` is kept as the wire-compatible spelling of the newly
    // specified HealthAdapterSummary shape.
    assert_eq!(fields("health-adapter"), fields("health-adapter-summary"));
}
