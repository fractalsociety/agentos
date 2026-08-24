#![cfg(test)]

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

#[test]
fn health_projection_is_coarse_consent_scoped_and_provenance_bound() {
    let signal = fields("health-signal");
    assert_eq!(
        signal.get("source").map(String::as_str),
        Some("health-source")
    );
    assert_eq!(
        signal.get("status").map(String::as_str),
        Some("health-status")
    );
    assert_eq!(
        signal.get("provenance").map(String::as_str),
        Some("object-id")
    );
    assert_eq!(
        signal.get("redaction").map(String::as_str),
        Some("redaction-class")
    );

    let adapter = fields("health-adapter");
    for (name, ty) in [
        ("source", "source-handle"),
        ("consent-scope", "list<health-source>"),
        ("consent-expires-unix", "u64"),
        ("revoked", "bool"),
        ("status", "health-status"),
        ("signals", "list<health-signal>"),
        ("provenance", "object-id"),
        ("range", "event-range"),
        ("redaction", "redaction-class"),
    ] {
        assert_eq!(adapter.get(name).map(String::as_str), Some(ty), "{name}");
    }
}

#[test]
fn health_enums_cannot_carry_measurements_or_source_records() {
    assert_eq!(
        variants("health-source"),
        ["unknown", "activity", "sleep", "readiness", "workload"]
    );
    assert_eq!(
        variants("health-status"),
        ["unknown", "ok", "attention", "stale"]
    );
    let combined = fields("health-signal")
        .into_keys()
        .chain(fields("health-adapter").into_keys())
        .collect::<Vec<_>>();
    for forbidden in [
        "diagnosis",
        "condition",
        "medication",
        "measurement",
        "value",
        "patient-name",
        "medical-record-number",
        "credential",
        "secret",
        "calendar-body",
        "message-body",
        "note-text",
        "canary",
    ] {
        assert!(
            !combined.iter().any(|field| field == forbidden),
            "{forbidden}"
        );
    }
}

#[test]
fn revocation_expiry_and_denial_are_typed_fail_closed_paths() {
    let errors = variants("export-error");
    for expected in ["denied", "redacted", "expired", "stale-source"] {
        assert!(
            errors.iter().any(|variant| variant == expected),
            "{expected}"
        );
    }
    let adapter = fields("health-adapter");
    assert_eq!(adapter.get("revoked").map(String::as_str), Some("bool"));
    assert_eq!(
        adapter.get("consent-expires-unix").map(String::as_str),
        Some("u64")
    );
}

#[test]
fn source_identity_is_only_an_opaque_fixed_semantic_handle() {
    let aliases = WIT
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("type "))
        .collect::<Vec<_>>();
    assert!(aliases.contains(&"type source-handle = list<u8>;"));
    assert_eq!(
        fields("health-adapter").get("source").map(String::as_str),
        Some("source-handle")
    );
    assert!(!fields("health-adapter").contains_key("source-id"));
}

#[test]
fn freshness_is_explicit_and_never_an_empty_current_result() {
    let adapter = fields("health-adapter");
    assert_eq!(
        adapter.get("freshness-seconds").map(String::as_str),
        Some("u32")
    );
    assert!(variants("health-status").contains(&"stale".to_owned()));
    assert!(variants("export-error").contains(&"stale-source".to_owned()));
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
fn health_operation_has_one_typed_projection_result() {
    let operation = WIT
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("get-health-adapter:"))
        .expect("health operation");
    assert_eq!(
        operation,
        "get-health-adapter: func(epoch: u64) -> result<health-adapter, export-error>;"
    );
}

#[test]
fn canary_material_has_no_semantic_export_field() {
    for record in ["health-signal", "health-adapter"] {
        assert!(
            fields(record).keys().all(|field| !field.contains("canary")),
            "{record}"
        );
    }
}
