#![cfg(test)]

const WIT: &str = include_str!("../../interfaces/wit/fractal-companion-v1/companion.wit");

fn normalized_wit() -> String {
    WIT.lines()
        .map(|line| line.trim().trim_start_matches('/').trim())
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
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
            "record {record} must include {field}; body was:\n{body}"
        );
    }
}

fn field_lines(record: &str) -> Vec<String> {
    let header = format!("record {record}");
    body_after(&header)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("///"))
        .filter(|line| line.contains(':'))
        .map(str::to_owned)
        .collect()
}

/// The declaration of one `companion-export` operation, flattened to a single
/// line with doc comments stripped. Signatures are asserted against this
/// rather than against raw file text so a prose mention of a result type can
/// never stand in for the operation actually returning it.
fn operation_signature(operation: &str) -> String {
    let interface = body_after("interface companion-export");
    let start = interface
        .find(&format!("{operation}: func"))
        .unwrap_or_else(|| panic!("missing operation {operation}"));
    let end = interface[start..]
        .find(';')
        .map(|idx| start + idx)
        .unwrap_or_else(|| panic!("unterminated operation {operation}"));
    interface[start..end]
        .lines()
        .map(|line| line.split("///").next().unwrap_or_default().trim())
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// A typed page is a `page-info` frame plus a homogeneous item list. Neither
/// half may be dropped: a bare list has no cursor and no pinned range.
fn assert_typed_page(page: &str, item: &str) {
    let header = format!("record {page}");
    let body = body_after(&header);
    assert!(
        body.contains("page: page-info"),
        "{page} must carry the page-info frame; body was:\n{body}"
    );
    assert!(
        body.contains(&format!("items: list<{item}>")),
        "{page} must carry list<{item}>; body was:\n{body}"
    );
}

#[test]
fn deterministic_beads_and_fractal_projection_is_pinned() {
    assert_record_has_fields(
        "project-snapshot",
        &[
            "schema: schema-version",
            "project-id: object-id",
            "snapshot-root: object-id",
            "beads-reference: string",
            "range: event-range",
            "proof: proof-level",
            "redaction: redaction-class",
        ],
    );
    assert_record_has_fields(
        "progress-node",
        &[
            "node-id: object-id",
            "project-id: object-id",
            "beads-reference: string",
            "event-seq: u64",
            "range: event-range",
        ],
    );

    let lower = normalized_wit();
    for term in [
        "immutable",
        "canonical fractal",
        "beads contributes",
        "replaying the same inputs",
        "byte-identical",
    ] {
        assert!(
            lower.contains(term),
            "projection contract must state {term:?}"
        );
    }
    assert!(
        lower.contains("no writable tracker handle")
            || lower.contains("never writable beads internals"),
        "the adapter must expose read-only references rather than tracker internals"
    );
}

#[test]
fn dependency_edges_are_typed_and_deterministically_ordered() {
    let state = body_after("enum progress-state");
    for variant in ["open", "in-progress", "blocked", "superseded", "closed"] {
        assert!(
            state.contains(variant),
            "missing typed progress state {variant}"
        );
    }

    assert_record_has_fields(
        "progress-node",
        &[
            "depth: u32",
            "depends-on: list<object-id>",
            "depends-on-count: u32",
            "event-seq: u64",
        ],
    );
    let progress = normalized_wit();
    assert!(progress.contains("ascending `depth`"));
    assert!(progress.contains("lower depth"));

    // Dependency order only survives the boundary if nodes cross inside a
    // typed page: the page-info frame carries the cursor position that pins
    // where the deterministic ordering resumes.
    assert_typed_page("progress-node-page", "progress-node");
    let signature = operation_signature("list-progress");
    assert!(
        signature.contains("project-id: object-id") && signature.contains("page: page-request"),
        "list-progress must be scoped and bounded: {signature}"
    );
    assert!(
        signature.contains("-> result<progress-page, export-error>")
            || signature.contains("-> result<progress-node-page, export-error>"),
        "progress must be returned through a typed page: {signature}"
    );
}

#[test]
fn proof_level_is_explicit_and_never_inferred_upward() {
    let proof = body_after("enum proof-level");
    for level in ["none", "host", "target", "qemu", "live", "external"] {
        assert!(proof.contains(level), "missing proof level {level}");
    }
    let lower = normalized_wit();
    assert!(lower.contains("never inferred upward"));
    assert_record_has_fields("project-snapshot", &["proof: proof-level"]);
    assert_record_has_fields("progress-node", &["proof: proof-level"]);
    assert_record_has_fields("blocker-evidence", &["observed-proof: proof-level"]);
}

#[test]
fn blocker_evidence_and_worker_assignment_are_immutable_projections() {
    assert_record_has_fields(
        "blocker-evidence",
        &[
            "evidence-id: object-id",
            "event-seq: u64",
            "observed-proof: proof-level",
            "redaction: redaction-class",
        ],
    );
    assert_record_has_fields(
        "worker-assignment",
        &[
            "worker: source-handle",
            "kind: string",
            "assigned-event-seq: u64",
            "redaction: redaction-class",
        ],
    );
    assert!(
        field_lines("worker-assignment")
            .iter()
            .any(|line| line.starts_with("worker: source-handle")),
        "worker identity must be an opaque immutable handle"
    );
}

#[test]
fn active_and_dormant_memory_are_distinct_fields() {
    let state = body_after("enum worker-state");
    assert!(state.contains("active") && state.contains("dormant"));
    assert_record_has_fields(
        "worker-memory",
        &[
            "state: worker-state",
            "active-bytes: u64",
            "dormant-bytes: u64",
            "assignment: option<worker-assignment>",
            "range: event-range",
            "redaction: redaction-class",
        ],
    );
    assert!(
        body_after("record worker-memory").contains("Resident and in use right now")
            && body_after("record worker-memory").contains("Retained but paged down / idle")
    );
}

#[test]
fn typed_pagination_rejects_stale_cursors() {
    // Every dimension a cursor is bound to is a dimension staleness can be
    // detected in. Dropping one turns a stale-cursor error into a silently
    // wrong page.
    assert_record_has_fields(
        "event-cursor",
        &[
            "event-seq: u64",
            "authority-epoch: u64",
            "stream-id: u32",
            "schema-major: u32",
            "projection: projection-kind",
            "position: u64",
            "root: object-id",
        ],
    );
    assert_record_has_fields(
        "page-request",
        &[
            "max-items: u32",
            "max-bytes: u32",
            "cursor: option<event-cursor>",
        ],
    );
    assert_record_has_fields(
        "page-info",
        &[
            "item-count: u32",
            "item-bytes: u32",
            "more: bool",
            "next-cursor: option<event-cursor>",
            "range: event-range",
        ],
    );
    assert!(body_after("enum export-error").contains("stale-cursor"));
    assert!(
        normalized_wit().contains("stale the moment the epoch advances"),
        "cursor staleness must be normative, not advisory"
    );

    assert_typed_page("project-snapshot-page", "project-snapshot");
    assert_typed_page("progress-node-page", "progress-node");
    let projects = operation_signature("list-projects");
    assert!(
        projects.contains("page: page-request"),
        "list-projects must be bounded by a page-request: {projects}"
    );
    assert!(
        projects.contains("-> result<project-page, export-error>")
            || projects.contains("-> result<project-snapshot-page, export-error>"),
        "project snapshots must be returned through a typed page: {projects}"
    );
}

#[test]
fn projected_records_are_redacted_and_hide_promotion_details() {
    for record in [
        "project-snapshot",
        "progress-node",
        "blocker-evidence",
        "worker-assignment",
        "worker-memory",
    ] {
        assert_record_has_fields(record, &["redaction: redaction-class"]);
        for line in field_lines(record) {
            let field = line.to_ascii_lowercase();
            for forbidden in [
                "credential:",
                "secret:",
                "password:",
                "token:",
                "command:",
                "args:",
                "path:",
                "promotion:",
                "ranking:",
                "score:",
                "weight:",
                "placement:",
            ] {
                assert!(
                    !field.starts_with(forbidden),
                    "{record} must not expose hidden field {forbidden:?}: {line}"
                );
            }
        }
    }

    let source = body_after("enum source-class").to_ascii_lowercase();
    assert!(source.contains("promotion"));
    assert!(
        source.contains("never exported"),
        "promotion source data must be classified as non-exportable"
    );
}
