//! Deterministic Agent IR → capability-scoped WASM lowering and RUN_PROGRAM host.
//!
//! fos-gz0.14.6.3: pinned IR → byte-identical WASM, AOT cache, fail-closed validation.
//! fos-gz0.14.6.4: trusted host executes validated WASM/IR with structured concurrency,
//! budgets, canonical events, and independent nested-call authorization.

#![forbid(unsafe_code)]

mod cache;
mod encode;
mod events;
mod host;
mod ir;
mod run;
mod validate;

pub use cache::{ArtifactCache, CacheError, CacheKey};
pub use encode::{compile_ir_to_wasm, COMPILER_ID, WASM_INTERFACE_VERSION};
pub use events::{Event, EventKind, EventLog};
pub use host::{HostConfig, HostError, HostState};
pub use ir::{
    sample_parallel_verify_program, AgentIrNode, IrProgram, ObjectId, AGENT_IR_INTERFACE_VERSION,
    AGENT_ISA_CAP_ACT, AGENT_ISA_CAP_COMMIT, AGENT_ISA_CAP_CONTROL, AGENT_ISA_CAP_EVENT,
    AGENT_ISA_CAP_INFER, AGENT_ISA_CAP_OBJECT, AGENT_ISA_CAP_TRACE, AGENT_ISA_CAP_VERIFY,
    AGENT_ISA_FLAG_ASYNC, AGENT_ISA_OP_ACT, AGENT_ISA_OP_BUDGET, AGENT_ISA_OP_CAP_GRANT,
    AGENT_ISA_OP_CAP_REVOKE, AGENT_ISA_OP_CHECKPOINT, AGENT_ISA_OP_COMMIT, AGENT_ISA_OP_DELEGATE,
    AGENT_ISA_OP_EMIT, AGENT_ISA_OP_INFER, AGENT_ISA_OP_OBJECT_GET, AGENT_ISA_OP_OBJECT_PUT,
    AGENT_ISA_OP_OBJECT_QUERY, AGENT_ISA_OP_RESTORE, AGENT_ISA_OP_SPAWN, AGENT_ISA_OP_TERMINATE,
    AGENT_ISA_OP_TRACE, AGENT_ISA_OP_VERIFY, AGENT_ISA_OP_WAIT, MAX_BUDGET_UNITS, MAX_IR_NODES,
};
pub use run::{
    adversarial_hidden_call, adversarial_raw_opcode, adversarial_stale_epoch, run_program_ir,
    run_program_ir_with_forced_child_failure, run_program_wasm, RunError, RunResult,
};
pub use validate::{validate_program, validate_wasm_imports, CompileError};

use sha2::{Digest, Sha256};

/// Full compile pipeline: validate → cache lookup → encode → store.
pub fn compile_cached(
    program: &IrProgram,
    cache: &mut ArtifactCache,
) -> Result<CompileOutput, CompileError> {
    validate_program(program)?;
    let ir_bytes = program.canonical_bytes();
    let key = CacheKey::from_ir(&ir_bytes);
    if let Some(hit) = cache.get(&key) {
        let wasm_digest = digest(&hit);
        return Ok(CompileOutput {
            wasm: hit,
            cache_hit: true,
            key,
            ir_digest: digest(&ir_bytes),
            wasm_digest,
        });
    }
    let wasm = compile_ir_to_wasm(program)?;
    let wasm_digest = digest(&wasm);
    cache.put(&key, &wasm)?;
    Ok(CompileOutput {
        wasm,
        cache_hit: false,
        key,
        ir_digest: digest(&ir_bytes),
        wasm_digest,
    })
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileOutput {
    pub wasm: Vec<u8>,
    pub cache_hit: bool,
    pub key: CacheKey,
    pub ir_digest: [u8; 32],
    pub wasm_digest: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::sample_delegate_program;

    #[test]
    fn pinned_ir_yields_byte_identical_wasm() {
        let program = sample_delegate_program();
        let a = compile_ir_to_wasm(&program).expect("compile a");
        let b = compile_ir_to_wasm(&program).expect("compile b");
        assert_eq!(a, b, "deterministic encoding");
        assert!(a.starts_with(&[0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn cache_hit_avoids_recompilation_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let mut cache = ArtifactCache::open(dir.path()).unwrap();
        let program = sample_delegate_program();
        let first = compile_cached(&program, &mut cache).unwrap();
        assert!(!first.cache_hit);
        let second = compile_cached(&program, &mut cache).unwrap();
        assert!(second.cache_hit);
        assert_eq!(first.wasm, second.wasm);
        assert_eq!(first.wasm_digest, second.wasm_digest);
        assert_eq!(first.ir_digest, second.ir_digest);
    }

    #[test]
    fn undeclared_effect_fails_closed() {
        let mut program = sample_delegate_program();
        program.declared_effects = 0;
        let err = validate_program(&program).unwrap_err();
        assert!(matches!(err, CompileError::EffectViolation { .. }));
    }

    #[test]
    fn excess_budget_fails_closed() {
        let mut program = sample_delegate_program();
        program.nodes[0].budget_units = MAX_BUDGET_UNITS + 1;
        let err = validate_program(&program).unwrap_err();
        assert!(matches!(err, CompileError::ResourceLimit { .. }));
    }

    #[test]
    fn forged_import_in_module_is_rejected_on_validate_roundtrip() {
        let program = sample_delegate_program();
        let mut wasm = compile_ir_to_wasm(&program).unwrap();
        if let Some(pos) = wasm.windows(7).position(|w| w == b"fractal") {
            wasm[pos..pos + 7].copy_from_slice(b"ambient");
        } else {
            panic!("expected fractal import module name");
        }
        let err = validate_wasm_imports(&wasm, &program).unwrap_err();
        assert!(matches!(err, CompileError::UndeclaredImport { .. }));
    }

    #[test]
    fn parallel_read_edit_verify_commit_flow() {
        let program = sample_parallel_verify_program();
        let caps = AGENT_ISA_CAP_OBJECT | AGENT_ISA_CAP_VERIFY | AGENT_ISA_CAP_COMMIT;
        let result = run_program_ir(&program, caps, 256).expect("parallel flow");
        assert_eq!(
            result.call_trace,
            vec![
                "object_get",
                "object_get",
                "object_put",
                "task_verify",
                "commit"
            ]
        );
        assert_eq!(result.compact_result, "verified");
        assert!(result.event_count >= 10);
        assert!(result
            .event_head
            .iter()
            .any(|b| *b != 0));
        // Nested trace is fully retained even though compact result is selected.
        let wasm = run_program_wasm(&program, caps, 256).expect("wasm flow");
        assert!(wasm.wasm_executed);
        assert_eq!(wasm.call_trace, result.call_trace);
    }

    #[test]
    fn nested_trace_replays_deterministically() {
        let program = sample_parallel_verify_program();
        let caps = AGENT_ISA_CAP_OBJECT | AGENT_ISA_CAP_VERIFY | AGENT_ISA_CAP_COMMIT;
        let a = run_program_ir(&program, caps, 256).unwrap();
        let b = run_program_ir(&program, caps, 256).unwrap();
        assert_eq!(a.call_trace, b.call_trace);
        assert_eq!(a.event_head, b.event_head);
        assert_eq!(a.compact_result, b.compact_result);
    }

    #[test]
    fn adversarial_hidden_raw_stale_overrun_cancel_child_failure() {
        let program = sample_parallel_verify_program();
        let caps = AGENT_ISA_CAP_OBJECT | AGENT_ISA_CAP_VERIFY | AGENT_ISA_CAP_COMMIT;
        let mut host = HostState::new(HostConfig {
            installed_caps: caps,
            authority_epoch: 1,
            budget_limit: 10,
            max_children: 8,
            allowed_imports: vec![
                "object_get".into(),
                "object_put".into(),
                "task_verify".into(),
                "commit".into(),
            ],
        });

        assert!(matches!(
            adversarial_hidden_call(&mut host),
            Err(HostError::HiddenCall(_))
        ));
        assert!(matches!(
            adversarial_raw_opcode(&mut host),
            Err(HostError::RawOpcode(_))
        ));
        assert!(matches!(
            adversarial_stale_epoch(&mut host),
            Err(HostError::StaleEpoch)
        ));

        // Budget overrun
        let err = run_program_ir(&program, caps, 5).unwrap_err();
        assert!(matches!(err, RunError::Host(HostError::BudgetExhausted)));

        // Cancellation
        let mut host = HostState::new(HostConfig {
            installed_caps: caps,
            allowed_imports: vec!["object_get".into()],
            budget_limit: 100,
            ..HostConfig::default()
        });
        host.cancel();
        assert!(matches!(
            host.dispatch("object_get", AGENT_ISA_OP_OBJECT_GET, 0, 1, 1),
            Err(HostError::Cancelled)
        ));

        // Child failure closes parallel scope
        let err = run_program_ir_with_forced_child_failure(&program, caps, 256, 1).unwrap_err();
        assert!(matches!(err, RunError::Host(HostError::ChildFailed(1))));
    }
}
