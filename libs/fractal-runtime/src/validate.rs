//! Fail-closed validation of IR programs and emitted WASM imports.

use crate::ir::{
    import_name_for_op, operation_is_async, operation_required_caps, IrProgram, MAX_BUDGET_UNITS,
    MAX_IR_NODES, AGENT_IR_INTERFACE_VERSION, AGENT_ISA_FLAG_ASYNC,
};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CompileError {
    #[error("invalid program: {0}")]
    Invalid(&'static str),
    #[error("unsupported IR interface version {0}")]
    Version(u16),
    #[error("unknown or unsupported operation {0}")]
    Operation(u16),
    #[error("capability/effect violation for op {operation}")]
    EffectViolation { operation: u16 },
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
    #[error("undeclared or ambient WASM import `{module}::{field}`")]
    UndeclaredImport { module: String, field: String },
    #[error("cache error: {0}")]
    Cache(String),
}

pub fn validate_program(program: &IrProgram) -> Result<(), CompileError> {
    if program.interface_version != AGENT_IR_INTERFACE_VERSION {
        return Err(CompileError::Version(program.interface_version));
    }
    if program.nodes.is_empty() {
        return Err(CompileError::Invalid("program has no nodes"));
    }
    if program.parallel_groups.len() != program.nodes.len() {
        return Err(CompileError::Invalid("parallel_groups length mismatch"));
    }
    if program.nodes.len() > MAX_IR_NODES || program.nodes.len() as u16 > program.max_nodes {
        return Err(CompileError::ResourceLimit("too many IR nodes"));
    }
    if program.max_budget_units == 0 || program.max_budget_units > MAX_BUDGET_UNITS {
        return Err(CompileError::ResourceLimit("invalid max budget"));
    }

    let mut total_budget: u64 = 0;
    for node in &program.nodes {
        if node.interface_version != AGENT_IR_INTERFACE_VERSION {
            return Err(CompileError::Version(node.interface_version));
        }
        let required = operation_required_caps(node.operation)
            .ok_or(CompileError::Operation(node.operation))?;
        if node.declared_caps != required {
            return Err(CompileError::EffectViolation {
                operation: node.operation,
            });
        }
        if (program.declared_effects & required) != required {
            return Err(CompileError::EffectViolation {
                operation: node.operation,
            });
        }
        let async_flag = (node.execution_flags & AGENT_ISA_FLAG_ASYNC) != 0;
        if async_flag != operation_is_async(node.operation)
            || (node.execution_flags & !AGENT_ISA_FLAG_ASYNC) != 0
        {
            return Err(CompileError::Invalid("execution flags mismatch"));
        }
        if node.budget_units == 0 || node.budget_units > MAX_BUDGET_UNITS {
            return Err(CompileError::ResourceLimit("node budget"));
        }
        total_budget = total_budget.saturating_add(u64::from(node.budget_units));
        if total_budget > u64::from(program.max_budget_units) {
            return Err(CompileError::ResourceLimit("aggregate budget"));
        }
        if import_name_for_op(node.operation).is_none() {
            return Err(CompileError::Operation(node.operation));
        }
    }
    Ok(())
}

/// Parse the import section of a WASM module and ensure every import is an
/// allowlisted `fractal::<op>` corresponding to the program's operations.
pub fn validate_wasm_imports(wasm: &[u8], program: &IrProgram) -> Result<(), CompileError> {
    if wasm.len() < 8 || &wasm[0..4] != b"\0asm" || wasm[4..8] != [1, 0, 0, 0] {
        return Err(CompileError::Invalid("not a WASM module"));
    }
    let allowed: Vec<&str> = program
        .nodes
        .iter()
        .filter_map(|n| import_name_for_op(n.operation))
        .collect();

    let mut offset = 8usize;
    while offset < wasm.len() {
        let section_id = wasm[offset];
        offset += 1;
        let (size, size_len) = read_u32_leb(&wasm[offset..])
            .ok_or(CompileError::Invalid("bad section size"))?;
        offset += size_len;
        let end = offset
            .checked_add(size as usize)
            .ok_or(CompileError::Invalid("section overflow"))?;
        if end > wasm.len() {
            return Err(CompileError::Invalid("truncated section"));
        }
        if section_id == 2 {
            // Import section.
            let body = &wasm[offset..end];
            let mut i = 0usize;
            let (count, nlen) =
                read_u32_leb(&body[i..]).ok_or(CompileError::Invalid("import count"))?;
            i += nlen;
            for _ in 0..count {
                let (module, mlen) =
                    read_name(&body[i..]).ok_or(CompileError::Invalid("import module"))?;
                i += mlen;
                let (field, flen) =
                    read_name(&body[i..]).ok_or(CompileError::Invalid("import field"))?;
                i += flen;
                if i >= body.len() {
                    return Err(CompileError::Invalid("import kind missing"));
                }
                let kind = body[i];
                i += 1;
                if kind != 0 {
                    return Err(CompileError::UndeclaredImport {
                        module: module.to_string(),
                        field: field.to_string(),
                    });
                }
                let (_typeidx, tlen) =
                    read_u32_leb(&body[i..]).ok_or(CompileError::Invalid("import type"))?;
                i += tlen;
                if module != "fractal" || !allowed.iter().any(|a| *a == field) {
                    return Err(CompileError::UndeclaredImport {
                        module: module.to_string(),
                        field: field.to_string(),
                    });
                }
            }
        }
        offset = end;
    }
    Ok(())
}

fn read_u32_leb(bytes: &[u8]) -> Option<(u32, usize)> {
    let mut result = 0u32;
    let mut shift = 0u32;
    for (i, b) in bytes.iter().copied().enumerate() {
        if i > 4 {
            return None;
        }
        result |= u32::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

fn read_name(bytes: &[u8]) -> Option<(&str, usize)> {
    let (len, nlen) = read_u32_leb(bytes)?;
    let start = nlen;
    let end = start.checked_add(len as usize)?;
    let name = std::str::from_utf8(bytes.get(start..end)?).ok()?;
    Some((name, end))
}
