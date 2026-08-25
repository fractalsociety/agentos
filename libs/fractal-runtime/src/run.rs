//! RUN_PROGRAM host: structured-concurrency IR schedule + WASM import fence.

use crate::encode::compile_ir_to_wasm;
use crate::events::EventKind;
use crate::host::{HostConfig, HostError, HostState};
use crate::ir::{import_name_for_op, IrProgram};
use crate::validate::{validate_program, validate_wasm_imports, CompileError};
use wasmi::{Caller, Engine, Linker, Module, Store};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    pub compact_result: String,
    pub call_trace: Vec<String>,
    pub event_count: usize,
    pub event_head: [u8; 32],
    pub budget_used: u64,
    pub wasm_executed: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error(transparent)]
    Compile(#[from] CompileError),
    #[error(transparent)]
    Host(#[from] HostError),
    #[error("wasm: {0}")]
    Wasm(String),
}

fn allowed_imports(program: &IrProgram) -> Vec<String> {
    let mut out = Vec::new();
    for node in &program.nodes {
        if let Some(name) = import_name_for_op(node.operation) {
            if !out.iter().any(|a| a == name) {
                out.push(name.to_string());
            }
        }
    }
    out
}

fn host_config_for(program: &IrProgram, installed_caps: u32, budget: u64) -> HostConfig {
    HostConfig {
        installed_caps,
        authority_epoch: 1,
        budget_limit: budget,
        max_children: 8,
        allowed_imports: allowed_imports(program),
    }
}

/// Execute the IR schedule with structured concurrency (primary host path).
pub fn run_program_ir(
    program: &IrProgram,
    installed_caps: u32,
    budget: u64,
) -> Result<RunResult, RunError> {
    validate_program(program)?;
    let mut host = HostState::new(host_config_for(program, installed_caps, budget));
    host.events.emit(
        EventKind::ProgramSubmit,
        host.config.authority_epoch,
        0,
        0,
        0,
        "run_program_ir",
    );

    let mut i = 0usize;
    while i < program.nodes.len() {
        if host.cancelled {
            return Err(RunError::Host(HostError::Cancelled));
        }
        let group = program.parallel_groups[i];
        if group == 0 {
            dispatch_node(&mut host, program, i)?;
            i += 1;
            continue;
        }
        let start = i;
        while i < program.nodes.len() && program.parallel_groups[i] == group {
            i += 1;
        }
        let end = i;
        let children = (end - start) as u32;
        host.begin_parallel(group, children)?;
        for idx in start..end {
            if let Err(err) = dispatch_node(&mut host, program, idx) {
                let name = import_name_for_op(program.nodes[idx].operation).unwrap_or("op");
                let _ = host.fail_child(group, name);
                return Err(RunError::Host(err));
            }
        }
        host.end_parallel(group);
    }

    let compact = host
        .compact_result
        .clone()
        .unwrap_or_else(|| "ok".into());
    host.events.emit(
        EventKind::ProgramResult,
        host.config.authority_epoch,
        0,
        0,
        0,
        &compact,
    );
    Ok(RunResult {
        compact_result: compact,
        call_trace: host.call_trace,
        event_count: host.events.events.len(),
        event_head: host.events.head(),
        budget_used: host.budget_used,
        wasm_executed: false,
    })
}

fn dispatch_node(host: &mut HostState, program: &IrProgram, idx: usize) -> Result<(), HostError> {
    let node = &program.nodes[idx];
    let name = import_name_for_op(node.operation).ok_or(HostError::RawOpcode(node.operation))?;
    let group = program.parallel_groups[idx];
    let epoch = host.config.authority_epoch;
    host.dispatch(name, node.operation, group, epoch, u64::from(node.budget_units))
}

/// Compile IR → WASM, validate imports, instantiate with wasmi, run `_start`.
pub fn run_program_wasm(
    program: &IrProgram,
    installed_caps: u32,
    budget: u64,
) -> Result<RunResult, RunError> {
    validate_program(program)?;
    let wasm = compile_ir_to_wasm(program)?;
    validate_wasm_imports(&wasm, program)?;

    let mut host = HostState::new(host_config_for(program, installed_caps, budget));
    host.events.emit(
        EventKind::ProgramSubmit,
        host.config.authority_epoch,
        0,
        0,
        0,
        "run_program_wasm",
    );

    // Map import name → (operation, next parallel group index cursor via schedule).
    // WASM calls are sequential; attach parallel_group 0 for import fence (authorization
    // still independent per call). Structured-concurrency proof is run_program_ir.
    let op_by_name: Vec<(String, u16)> = allowed_imports(program)
        .into_iter()
        .filter_map(|name| {
            program
                .nodes
                .iter()
                .find(|n| import_name_for_op(n.operation) == Some(name.as_str()))
                .map(|n| (name, n.operation))
        })
        .collect();

    let engine = Engine::default();
    let module = Module::new(&engine, &wasm[..]).map_err(|e| RunError::Wasm(e.to_string()))?;
    let mut store = Store::new(&engine, host);
    let mut linker = Linker::new(&engine);

    for (name, operation) in op_by_name {
        let import_name = name.clone();
        linker
            .func_wrap(
                "fractal",
                name.as_str(),
                move |mut caller: Caller<'_, HostState>| {
                    let epoch = caller.data().config.authority_epoch;
                    let cost = 1u64;
                    if let Err(err) =
                        caller
                            .data_mut()
                            .dispatch(&import_name, operation, 0, epoch, cost)
                    {
                        caller.data_mut().trap = Some(err);
                    }
                },
            )
            .map_err(|e| RunError::Wasm(e.to_string()))?;
    }

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| RunError::Wasm(e.to_string()))?
        .ensure_no_start(&mut store)
        .map_err(|e| RunError::Wasm(e.to_string()))?;

    let start = instance
        .get_typed_func::<(), ()>(&store, "_start")
        .map_err(|e| RunError::Wasm(e.to_string()))?;
    start
        .call(&mut store, ())
        .map_err(|e| RunError::Wasm(e.to_string()))?;

    let host = store.into_data();
    if let Some(err) = host.trap {
        return Err(RunError::Host(err));
    }
    let compact = host
        .compact_result
        .clone()
        .unwrap_or_else(|| "ok".into());
    Ok(RunResult {
        compact_result: compact,
        call_trace: host.call_trace,
        event_count: host.events.events.len(),
        event_head: host.events.head(),
        budget_used: host.budget_used,
        wasm_executed: true,
    })
}

/// Adversarial: attempt a hidden/raw call against a live host.
pub fn adversarial_hidden_call(host: &mut HostState) -> Result<(), HostError> {
    host.dispatch("shell", 0xFFFF, 0, host.config.authority_epoch, 1)
}

pub fn adversarial_raw_opcode(host: &mut HostState) -> Result<(), HostError> {
    // Use an allowlisted import name with a fabricated opcode so the raw-opcode
    // fence fires after the import-name allowlist check.
    host.dispatch("object_get", 99, 0, host.config.authority_epoch, 1)
}

pub fn adversarial_stale_epoch(host: &mut HostState) -> Result<(), HostError> {
    let stale = host.config.authority_epoch;
    host.bump_epoch();
    host.dispatch("delegate", crate::ir::AGENT_ISA_OP_DELEGATE, 0, stale, 1)
}

/// Force a parallel child failure mid-scope.
pub fn run_program_ir_with_forced_child_failure(
    program: &IrProgram,
    installed_caps: u32,
    budget: u64,
    fail_at_index: usize,
) -> Result<RunResult, RunError> {
    validate_program(program)?;
    let mut host = HostState::new(host_config_for(program, installed_caps, budget));
    let mut i = 0usize;
    while i < program.nodes.len() {
        let group = program.parallel_groups[i];
        if group == 0 {
            if i == fail_at_index {
                let name = import_name_for_op(program.nodes[i].operation).unwrap_or("op");
                return Err(RunError::Host(host.fail_child(group, name)));
            }
            dispatch_node(&mut host, program, i)?;
            i += 1;
            continue;
        }
        let start = i;
        while i < program.nodes.len() && program.parallel_groups[i] == group {
            i += 1;
        }
        let end = i;
        host.begin_parallel(group, (end - start) as u32)?;
        for idx in start..end {
            if idx == fail_at_index {
                let name = import_name_for_op(program.nodes[idx].operation).unwrap_or("op");
                return Err(RunError::Host(host.fail_child(group, name)));
            }
            dispatch_node(&mut host, program, idx)?;
        }
        host.end_parallel(group);
    }
    Ok(RunResult {
        compact_result: host.compact_result.unwrap_or_else(|| "ok".into()),
        call_trace: host.call_trace,
        event_count: host.events.events.len(),
        event_head: host.events.head(),
        budget_used: host.budget_used,
        wasm_executed: false,
    })
}
