#![cfg(test)]

const WIT: &str = include_str!("../../interfaces/wit/fractal-companion-v1/companion.wit");
const HEADER: &str = include_str!("../../kernel/agentos-root-task/include/contracts/companion_export_contract.h");

fn body_after(header: &str) -> &str {
    // Match the declaration token, not a prefix of a longer type such as
    // `task-intent-reference`.
    let declaration = if header.starts_with("record ")
        || header.starts_with("enum ")
        || header.starts_with("interface ")
    {
        format!("{header} {{")
    } else {
        header.to_owned()
    };
    let start = WIT
        .find(&declaration)
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

fn uncomment(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase()
}

fn assert_record_has_fields(record: &str, fields: &[&str]) {
    let body = uncomment(body_after(&format!("record {record}")));
    for field in fields {
        assert!(body.contains(field), "record {record} must include {field}; body:\n{body}");
    }
}

#[test]
fn package_and_named_types_are_versioned() {
    assert!(WIT.contains("package agentos:fractal-companion@1.0.0;"));
    for record in [
        "project",
        "progress",
        "daily-root",
        "health-adapter",
        "worker-memory",
        "event-cursor",
        "task-intent",
    ] {
        assert!(WIT.contains(&format!("record {record}")), "missing {record}");
    }
    assert!(WIT.contains("world companion-gateway"));
}

#[test]
fn ids_ranges_epochs_and_redaction_are_first_class() {
    let lower = WIT.to_ascii_lowercase();
    assert!(lower.contains("type object-id = list<u8>"));
    assert!(lower.contains("exactly 32 bytes"));
    assert!(lower.contains("record event-range"));
    assert!(lower.contains("first-seq: u64") && lower.contains("last-seq: u64"));
    assert!(lower.contains("authority-epoch: u64"));
    assert!(lower.contains("enum source-class"));
    assert!(lower.contains("enum redaction-class"));
    assert_record_has_fields("event-cursor", &[
        "event-seq: u64",
        "authority-epoch: u64",
        "stream-id: u32",
        "schema-major: u32",
        "root: object-id",
    ]);
    for record in ["project", "progress", "daily-root", "health-adapter", "worker-memory"] {
        assert_record_has_fields(record, &["schema: schema-version", "authority-epoch: u64", "redaction: redaction-class"]);
    }
    assert_record_has_fields("task-intent", &["cursor: event-cursor", "authority-epoch: u64", "note-redaction: redaction-class"]);
}

#[test]
fn all_variable_fields_have_negotiated_bounds() {
    let limits = uncomment(body_after("record limits"));
    for bound in [
        "max-page-items: u32",
        "max-result-bytes: u32",
        "max-label-bytes: u32",
        "max-ref-bytes: u32",
        "max-note-bytes: u32",
        "max-daily-items: u32",
        "max-conflict-heads: u32",
        "max-health-signals: u32",
    ] {
        assert!(limits.contains(bound), "missing negotiated bound {bound}");
    }
    assert_record_has_fields("page-request", &["max-items: u32", "max-bytes: u32", "cursor: option<event-cursor>"]);
    assert_record_has_fields("page-info", &["authority-epoch: u64", "item-count: u32", "item-bytes: u32", "range: event-range"]);
    assert!(WIT.contains("next-cursor: option<event-cursor>"));
    assert!(WIT.contains("items: list<daily-item>"));
    assert!(WIT.contains("signals: list<health-signal>"));
}

#[test]
fn typed_errors_cover_each_required_failure_path() {
    let errors = uncomment(body_after("enum export-error"));
    for error in [
        "invalid",
        "unsupported-schema",
        "denied",
        "stale-authority",
        "stale-cursor",
        "result-too-large",
        "not-found",
        "unavailable",
        "conflict",
        "redacted",
        "rate-limited",
        "expired",
    ] {
        assert!(errors.contains(error), "missing typed error {error}");
    }
    assert!(WIT.contains("minor below the server minor is accepted"));
    assert!(WIT.contains("must match exactly"));
}

#[test]
fn every_request_is_explicit_and_authority_scoped() {
    let iface = body_after("interface companion-export").to_ascii_lowercase();
    for function in [
        "describe: func",
        "list-projects: func",
        "list-progress: func",
        "get-daily-root: func",
        "get-health-adapter: func",
        "list-worker-memory: func",
        "submit-task-intent: func",
    ] {
        assert!(iface.contains(function), "missing request {function}");
    }
    assert!(iface.contains("epoch: u64"));
    assert!(iface.contains("intent: task-intent"));
    assert!(iface.contains("result<session, export-error>"));
    assert!(iface.contains("result<project-page, export-error>"));
    assert!(iface.contains("result<progress-page, export-error>"));
    assert!(iface.contains("result<daily-root, export-error>"));
    assert!(iface.contains("result<health-adapter, export-error>"));
    assert!(iface.contains("result<worker-memory-page, export-error>"));
    assert!(iface.contains("result<task-intent-receipt, export-error>"));
}

#[test]
fn forbidden_data_has_no_export_field() {
    let canonical = [
        "record project",
        "record progress",
        "record daily-root",
        "record health-adapter",
        "record worker-memory",
        "record task-intent",
    ]
    .iter()
    .map(|record| uncomment(body_after(record)))
    .collect::<Vec<_>>()
    .join("\n");
    for forbidden_field in [
        "credential:",
        "secret:",
        "password:",
        "personal-record:",
        "calendar-body:",
        "message-body:",
        "medical-body:",
        "shell-command:",
        "arguments:",
        "filesystem-path:",
        "path:",
        "promotion:",
        "rank:",
    ] {
        assert!(!canonical.contains(forbidden_field), "forbidden export field {forbidden_field}");
    }
    assert!(WIT.contains("source-handle"));
    assert!(WIT.contains("provenance: object-id"));
}

#[test]
fn c_abi_has_matching_opcodes_bounds_and_validation_helpers() {
    for opcode in [
        "MSG_COMPANION_DESCRIBE",
        "MSG_COMPANION_LIST_PROJECTS",
        "MSG_COMPANION_LIST_PROGRESS",
        "MSG_COMPANION_GET_DAILY_ROOT",
        "MSG_COMPANION_GET_HEALTH_ADAPTER",
        "MSG_COMPANION_LIST_WORKER_MEMORY",
        "MSG_COMPANION_SUBMIT_TASK_INTENT",
    ] {
        assert!(HEADER.contains(opcode), "C ABI missing {opcode}");
    }
    for symbol in [
        "COMPANION_OBJECT_ID_BYTES",
        "COMPANION_MAX_RESULT_BYTES",
        "COMPANION_MAX_PAGE_ITEMS",
        "companion_schema_compatible",
        "companion_cursor_stale",
        "COMPANION_EXPORT_ERR_DENIED",
        "COMPANION_EXPORT_ERR_STALE_CURSOR",
        "COMPANION_EXPORT_ERR_RESULT_TOO_LARGE",
    ] {
        assert!(HEADER.contains(symbol), "C ABI missing {symbol}");
    }
}
