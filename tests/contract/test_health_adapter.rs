#![cfg(test)]

const WIT: &str = include_str!("../../interfaces/wit/fractal-companion-v1/companion.wit");

fn lower_wit() -> String {
    WIT.to_ascii_lowercase()
}

fn body_after(header: &str) -> &str {
    let start = WIT
        .find(header)
        .unwrap_or_else(|| panic!("missing WIT section: {header}"));
    let open = WIT[start..]
        .find('{')
        .map(|idx| start + idx + 1)
        .unwrap_or_else(|| panic!("missing opening brace for {header}"));
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
    panic!("missing closing brace for {header}");
}

fn assert_record_has_fields(record: &str, fields: &[&str]) {
    let header = format!("record {record}");
    let body = body_after(&header);
    for field in fields {
        assert!(
            body.contains(field),
            "record {record} must include field {field}; body was:\n{body}"
        );
    }
}

fn assert_record_omits_terms(record: &str, terms: &[&str]) {
    let header = format!("record {record}");
    let body = body_after(&header).to_ascii_lowercase();
    for term in terms {
        assert!(
            !body.contains(term),
            "record {record} must not expose raw or credential term {term:?}; body was:\n{body}"
        );
    }
}

#[test]
fn health_projection_records_have_required_privacy_fields() {
    let required = [
        "source: source-class",
        "consent: consent-scope",
        "freshness: freshness",
        "status: coarse-status",
        "provenance-hash: string",
        "redaction: redaction-state",
    ];

    assert_record_has_fields("health-adapter-summary", &required);
    assert_record_has_fields("health-signal", &required);
}

#[test]
fn canonical_health_records_exclude_raw_medical_record_fields() {
    let forbidden = [
        "diagnosis",
        "condition",
        "procedure",
        "medication",
        "prescription",
        "lab-value",
        "lab_value",
        "result-value",
        "result_value",
        "observation-value",
        "observation_value",
        "clinical-note",
        "clinical_note",
        "note-text",
        "note_text",
        "patient-name",
        "patient_name",
        "date-of-birth",
        "date_of_birth",
        "medical-record-number",
        "medical_record_number",
        "mrn",
    ];

    assert_record_omits_terms("health-adapter-summary", &forbidden);
    assert_record_omits_terms("health-signal", &forbidden);
}

#[test]
fn adapter_contract_requires_explicit_bounded_authorization_before_projection() {
    let wit = lower_wit();
    assert!(
        wit.contains("authorize-health-source: func"),
        "adapter must expose an explicit authorization operation"
    );
    assert!(
        wit.contains("record health-authorization"),
        "authorization must be represented as a bounded grant"
    );
    assert!(
        wit.contains("expires-at-unix-ms"),
        "authorization and projections must carry expiry"
    );
    assert!(
        wit.contains("authorization-required") && wit.contains("consent-scope-denied"),
        "projection must be able to fail without explicit consent"
    );

    let summary_line = wit
        .lines()
        .find(|line| line.trim_start().starts_with("project-health-summary:"))
        .expect("missing project-health-summary function");
    let signal_line = wit
        .lines()
        .find(|line| line.trim_start().starts_with("project-health-signal:"))
        .expect("missing project-health-signal function");
    assert!(summary_line.contains("auth: health-authorization"));
    assert!(signal_line.contains("auth: health-authorization"));
}

#[test]
fn adapter_contract_requires_minimum_necessary_aggregation() {
    let wit = lower_wit();
    assert!(wit.contains("enum coarse-status"));
    assert!(wit.contains("enum freshness"));
    assert!(wit.contains("enum consent-scope"));
    assert!(wit.contains("aggregate-status"));
    assert!(wit.contains("trend-summary"));
    assert!(wit.contains("safety-signal"));

    let summary = body_after("record health-adapter-summary").to_ascii_lowercase();
    let signal = body_after("record health-signal").to_ascii_lowercase();
    for field in [
        "status: coarse-status",
        "freshness: freshness",
        "consent: consent-scope",
    ] {
        assert!(
            summary.contains(field),
            "summary must aggregate with {field}"
        );
        assert!(signal.contains(field), "signal must aggregate with {field}");
    }
}

#[test]
fn expiry_deletion_and_revocation_are_first_class_contract_paths() {
    let wit = lower_wit();
    assert!(wit.contains("authorization-expired"));
    assert!(wit.contains("authorization-revoked"));
    assert!(wit.contains("subject-deleted"));
    assert!(wit.contains("revoke-health-authorization: func"));
    assert!(wit.contains("delete-health-subject: func"));

    let redaction = body_after("enum redaction-state").to_ascii_lowercase();
    assert!(
        redaction.contains("revoked"),
        "revoked projections must be redacted"
    );
    assert!(
        redaction.contains("deleted"),
        "deleted subjects must be redacted"
    );
}

#[test]
fn projection_contract_is_deterministic_and_provenance_bound() {
    let wit = lower_wit();
    assert!(wit.contains("deterministic-projection-required"));
    assert_record_has_fields("health-adapter-summary", &["provenance-hash: string"]);
    assert_record_has_fields("health-signal", &["provenance-hash: string"]);

    let canonical = format!(
        "{}\n{}",
        body_after("record health-adapter-summary"),
        body_after("record health-signal")
    )
    .to_ascii_lowercase();
    for nondeterministic in [
        "nonce",
        "random",
        "uuid",
        "source-event-id",
        "source_event_id",
    ] {
        assert!(
            !canonical.contains(nondeterministic),
            "canonical health projections must not depend on nondeterministic/source ids: {nondeterministic}"
        );
    }
}

#[test]
fn canary_records_have_an_explicit_non_disclosure_path() {
    let wit = lower_wit();
    assert!(
        wit.contains("canary-record-blocked"),
        "adapter must be able to block canary records instead of projecting them"
    );

    assert_record_omits_terms("health-adapter-summary", &["canary"]);
    assert_record_omits_terms("health-signal", &["canary"]);
}

#[test]
fn source_credentials_are_opaque_and_never_part_of_canonical_health_events() {
    let wit = lower_wit();
    assert!(
        wit.contains("record credential-handle") && wit.contains("opaque-ref: string"),
        "source credentials must be represented only by an opaque boundary handle"
    );

    for record in ["health-adapter-summary", "health-signal"] {
        assert_record_omits_terms(
            record,
            &[
                "credential",
                "opaque-ref",
                "token",
                "secret",
                "password",
                "api-key",
                "api_key",
                "workspace",
                "path",
                "url",
            ],
        );
    }
}
