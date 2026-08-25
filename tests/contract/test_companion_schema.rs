#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const WIT: &str = include_str!("../../interfaces/wit/fractal-companion-v1/companion.wit");
const ABI_SPEC: &str = include_str!("../../tools/abi_spec.toml");
const SYSTEM: &str = include_str!("../../kernel/fractalos-root-task/fractalos.system");
const SYSTEM_AARCH64: &str =
    include_str!("../../kernel/fractalos-root-task/fractalos-aarch64.system");
const FRACTALOS_H: &str = include_str!("../../kernel/fractalos-root-task/include/fractalos.h");
const COMPANION_H: &str =
    include_str!("../../kernel/fractalos-root-task/include/contracts/companion_export_contract.h");

fn source_without_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| line.split("//").next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
}

fn named_block(source: &str, kind: &str, name: &str) -> String {
    let clean = source_without_comments(source);
    let declaration = format!("{kind} {name} {{");
    let start = clean
        .find(&declaration)
        .unwrap_or_else(|| panic!("missing {kind} {name}"));
    let open = clean[start..]
        .find('{')
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("missing opening brace for {kind} {name}"));
    let mut depth = 0usize;
    let mut close = None;
    for (offset, ch) in clean[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + offset);
                    break;
                }
            }
            _ => {}
        }
    }
    clean[open + 1..close.expect("balanced WIT block")].to_owned()
}

fn record_fields(name: &str) -> Vec<(String, String)> {
    named_block(WIT, "record", name)
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with(','))
        .map(|line| {
            let (field, ty) = line[..line.len() - 1]
                .split_once(':')
                .unwrap_or_else(|| panic!("malformed field in {name}: {line}"));
            (field.trim().to_owned(), ty.trim().to_owned())
        })
        .collect()
}

fn enum_variants(name: &str) -> Vec<String> {
    named_block(WIT, "enum", name)
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with(','))
        .map(|line| line.trim_end_matches(',').to_owned())
        .collect()
}

fn interface_functions(name: &str) -> BTreeMap<String, String> {
    let body = named_block(WIT, "interface", name);
    let mut functions = BTreeMap::new();
    let mut statement = String::new();
    for line in body.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if statement.is_empty() {
            if !line.contains(": func") {
                continue;
            }
            statement.push_str(line);
            statement.push(' ');
        } else {
            statement.push_str(line);
            statement.push(' ');
        }
        if line.ends_with(';') {
            let operation = statement
                .split_once(':')
                .expect("operation declaration")
                .0
                .trim()
                .to_owned();
            functions.insert(
                operation,
                statement.split_whitespace().collect::<Vec<_>>().join(" "),
            );
            statement.clear();
        }
    }
    functions
}

fn c_struct_fields(typedef_name: &str) -> Vec<String> {
    let end_marker = format!("}} {typedef_name};");
    let end = COMPANION_H
        .find(&end_marker)
        .unwrap_or_else(|| panic!("missing C typedef {typedef_name}"));
    let start = COMPANION_H[..end]
        .rfind("typedef struct")
        .expect("typedef start");
    let open = start + COMPANION_H[start..end].find('{').expect("typedef brace");
    COMPANION_H[open + 1..end]
        .lines()
        .map(|line| line.split("/*").next().unwrap_or_default().trim())
        .filter(|line| line.ends_with(';'))
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
        .collect()
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives below repository root")
        .to_path_buf()
}

#[test]
fn package_has_an_additive_minor_and_retains_v1_0_shapes() {
    let clean = source_without_comments(WIT);
    let package = clean
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("package "))
        .expect("WIT package declaration");
    assert_eq!(package, "package fractalos:fractal-companion@1.1.0;");

    let session = record_fields("session");
    assert!(session.contains(&("min-schema-minor".into(), "u32".into())));
    for legacy in ["project-snapshot", "progress-node"] {
        assert!(
            !record_fields(legacy).is_empty(),
            "v1.0 record {legacy} removed"
        );
    }
}

#[test]
fn cursor_ast_binds_every_resume_dimension_in_wire_order() {
    assert_eq!(
        record_fields("event-cursor"),
        vec![
            ("event-seq".into(), "u64".into()),
            ("authority-epoch".into(), "u64".into()),
            ("stream-id".into(), "u32".into()),
            ("schema-major".into(), "u32".into()),
            ("schema-minor".into(), "u32".into()),
            ("projection".into(), "projection-kind".into()),
            ("position".into(), "u64".into()),
            ("root".into(), "object-id".into()),
        ]
    );
    assert_eq!(
        enum_variants("projection-kind"),
        [
            "project",
            "progress",
            "daily-root",
            "health",
            "worker-memory",
            "task-intent"
        ]
    );
}

#[test]
fn every_variable_field_family_has_an_explicit_aligned_limit() {
    let actual: BTreeMap<_, _> = record_fields("limits").into_iter().collect();
    let expected = [
        "max-page-items",
        "max-result-bytes",
        "max-label-bytes",
        "max-ref-bytes",
        "max-note-bytes",
        "max-date-bytes",
        "max-timezone-bytes",
        "max-worker-kind-bytes",
        "max-ordering-key-bytes",
        "max-daily-items",
        "max-conflict-heads",
        "max-health-signals",
        "max-progress-dependencies",
        "max-consent-scopes",
    ];
    assert_eq!(actual.len(), expected.len());
    for field in expected {
        assert_eq!(
            actual.get(field).map(String::as_str),
            Some("u32"),
            "{field}"
        );
    }
}

#[test]
fn operations_parse_to_typed_bounded_results() {
    let operations = interface_functions("companion-export");
    let expected = BTreeMap::from([
        ("describe", "result<session, export-error>"),
        ("list-projects", "result<project-page, export-error>"),
        ("list-progress", "result<progress-page, export-error>"),
        ("get-daily-root", "result<daily-root, export-error>"),
        (
            "get-health-adapter",
            "result<health-adapter-summary, export-error>",
        ),
        (
            "list-worker-memory",
            "result<worker-memory-page, export-error>",
        ),
        (
            "submit-task-intent",
            "result<task-intent-receipt, export-error>",
        ),
    ]);
    assert_eq!(operations.len(), expected.len());
    for (operation, result) in expected {
        let signature = operations
            .get(operation)
            .unwrap_or_else(|| panic!("missing {operation}"));
        assert!(signature.contains(result), "{operation}: {signature}");
    }
}

#[test]
fn canonical_registry_structurally_owns_all_opcodes_and_unique_channel() {
    let spec: toml::Value = toml::from_str(ABI_SPEC).expect("valid ABI spec TOML");
    let companion = spec["pd"]
        .as_array()
        .expect("pd array")
        .iter()
        .find(|pd| pd["name"].as_str() == Some("companion_export"))
        .expect("companion_export registry entry");
    let opcodes = companion["opcode"].as_array().expect("opcode array");
    assert_eq!(opcodes.len(), 7);
    let values: BTreeSet<_> = opcodes
        .iter()
        .map(|op| op["value"].as_integer().expect("numeric opcode"))
        .collect();
    assert_eq!(values.len(), opcodes.len(), "duplicate companion opcode");
    assert_eq!(values, (0x2f01i64..=0x2f07).collect());

    let channels = companion["channel"].as_array().expect("channel array");
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0]["id"].as_integer(), Some(77));
    assert_eq!(channels[0]["legacy"].as_str(), Some("CH_COMPANION_EXPORT"));
}

fn controller_channel_ids(system: &str) -> Vec<u32> {
    system
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("<end ") && line.contains("pd=\"controller\""))
        .map(|line| {
            let id = line.split("id=\"").nth(1).expect("controller end id");
            id.split('"')
                .next()
                .expect("closing quote")
                .parse()
                .expect("numeric id")
        })
        .collect()
}

#[test]
fn reserved_channel_is_collision_free_in_both_system_descriptions() {
    for (name, system) in [("generic", SYSTEM), ("aarch64", SYSTEM_AARCH64)] {
        let ids = controller_channel_ids(system);
        let unique: BTreeSet<_> = ids.iter().copied().collect();
        assert_eq!(
            unique.len(),
            ids.len(),
            "pre-existing {name} controller collision"
        );
        assert!(
            !unique.contains(&77),
            "{name} already allocates reserved channel 77"
        );
    }

    let owners = FRACTALOS_H
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("#define CH_"))
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let value = fields.get(2)?.trim_end_matches('u').parse::<u32>().ok()?;
            (value == 77).then(|| fields[1].to_owned())
        })
        .collect::<Vec<_>>();
    assert_eq!(owners, ["CH_COMPANION_EXPORT"]);
}

#[test]
fn generated_c_layout_matches_wit_ast_and_arena_lowering() {
    let cursor = record_fields("event-cursor");
    let c_type = |wit: &str| match wit {
        "u64" => "uint64_t",
        "u32" | "projection-kind" => "uint32_t",
        "object-id" => "companion_object_id_t",
        other => panic!("no C lowering for {other}"),
    };
    let mut generated_fields = String::new();
    for (name, ty) in cursor {
        generated_fields.push_str(&format!(
            "    {} {};\n",
            c_type(&ty),
            name.replace('-', "_")
        ));
    }
    let mut generated_limits = String::new();
    let mut limit_asserts = String::new();
    for (name, ty) in record_fields("limits") {
        assert_eq!(ty, "u32");
        let c_name = name.replace('-', "_");
        generated_limits.push_str(&format!("    uint32_t {c_name};\n"));
        limit_asserts.push_str(&format!(
            "_Static_assert(offsetof(generated_limits_t, {c_name}) == offsetof(companion_limits_t, {c_name}), \"limit {c_name} offset\");\n"
        ));
    }

    let source = format!(
        r#"
#include <stddef.h>
#include <stdint.h>
#include "contracts/companion_export_contract.h"
typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {{
{generated_fields}}} generated_cursor_t;
typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {{
{generated_limits}}} generated_limits_t;
_Static_assert(sizeof(generated_cursor_t) == sizeof(companion_event_cursor_t), "cursor size");
_Static_assert(offsetof(generated_cursor_t, schema_minor) == offsetof(companion_event_cursor_t, schema_minor), "schema minor offset");
_Static_assert(offsetof(generated_cursor_t, projection) == offsetof(companion_event_cursor_t, projection), "projection offset");
_Static_assert(offsetof(generated_cursor_t, position) == offsetof(companion_event_cursor_t, position), "position offset");
_Static_assert(offsetof(generated_cursor_t, root) == offsetof(companion_event_cursor_t, root), "root offset");
_Static_assert(sizeof(generated_limits_t) == sizeof(companion_limits_t), "limits size");
{limit_asserts}
_Static_assert(sizeof(companion_wire_list_t) == 16u, "list lowering");
_Static_assert(sizeof(companion_wire_bytes_t) == 8u, "string lowering");
_Static_assert(sizeof(struct companion_req_describe_v1_0) == 8u, "v1.0 decode");
_Static_assert(sizeof(struct companion_req_describe) == 32u, "v1.1 envelope");
int main(void) {{
    companion_result_arena_t valid = {{8u, COMPANION_MAX_RESULT_BYTES}};
    companion_result_arena_t unaligned = {{3u, 8u}};
    return companion_arena_valid(&valid, 16u)
        && companion_request_transport_valid(32768u, 128u, &valid)
        && !companion_request_transport_valid(8u, 128u, &valid)
        && !companion_arena_valid(&unaligned, 8u) ? 0 : 1;
}}
"#
    );

    let temp = tempfile::tempdir().expect("tempdir");
    let probe = temp.path().join("companion_codegen_probe.c");
    let binary = temp.path().join("companion_codegen_probe");
    fs::write(&probe, source).expect("write generated C probe");
    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    let root = repo_root();
    let compile = Command::new(compiler)
        .current_dir(&root)
        .args([
            "-DFRACTALOS_TEST_HOST",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
        ])
        .arg(format!(
            "-I{}",
            root.join("kernel/fractalos-root-task/include").display()
        ))
        .arg(&probe)
        .arg("-o")
        .arg(&binary)
        .output()
        .expect("run C compiler");
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    assert!(Command::new(binary).status().expect("run probe").success());
}

#[test]
fn every_v1_1_result_record_has_the_same_c_and_wit_semantic_fields() {
    for (wit_name, c_name) in [
        ("blocker-evidence", "companion_wire_blocker_evidence_t"),
        ("worker-assignment", "companion_wire_worker_assignment_t"),
        ("project", "companion_wire_project_t"),
        ("progress", "companion_wire_progress_t"),
        (
            "task-intent-reference",
            "companion_wire_task_intent_reference_t",
        ),
        ("daily-item", "companion_wire_daily_item_t"),
        ("daily-root", "companion_wire_daily_root_t"),
        ("health-signal", "companion_wire_health_signal_t"),
        (
            "health-adapter-summary",
            "companion_wire_health_adapter_summary_t",
        ),
        ("worker-memory", "companion_wire_worker_memory_t"),
        ("session", "companion_wire_session_t"),
        (
            "task-intent-receipt",
            "companion_wire_task_intent_receipt_t",
        ),
        ("task-intent", "companion_wire_task_intent_t"),
        ("page-info", "companion_wire_page_info_t"),
        ("project-page", "companion_wire_project_page_t"),
        ("progress-page", "companion_wire_progress_page_t"),
        ("worker-memory-page", "companion_wire_worker_memory_page_t"),
    ] {
        let wit_fields = record_fields(wit_name)
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>();
        let c_fields = c_struct_fields(c_name)
            .into_iter()
            .filter(|name| !name.starts_with("reserved"))
            .filter(|name| name != "merge_reserved")
            .filter(|name| name != "has_merge_schema")
            .filter(|name| name != "note_len")
            .map(|name| match name.as_str() {
                "timezone_key" => "tz-key".to_owned(),
                "flags" => "more".to_owned(),
                other => other.replace('_', "-"),
            })
            .collect::<Vec<_>>();
        assert_eq!(c_fields, wit_fields, "semantic field drift for {wit_name}");
    }
}

#[test]
fn forbidden_payload_fields_are_absent_from_parsed_export_records() {
    let mut fields = BTreeSet::new();
    for record in [
        "project",
        "progress",
        "daily-root",
        "health-adapter-summary",
        "worker-memory",
        "task-intent",
    ] {
        fields.extend(record_fields(record).into_iter().map(|(name, _)| name));
    }
    for forbidden in [
        "credential",
        "secret",
        "password",
        "calendar-body",
        "message-body",
        "medical-body",
        "shell-command",
        "arguments",
        "filesystem-path",
        "path",
        "promotion",
        "rank",
    ] {
        assert!(!fields.contains(forbidden), "forbidden field {forbidden}");
    }
}
