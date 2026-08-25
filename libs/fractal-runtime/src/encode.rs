//! Deterministic WASM encoder for validated Agent IR programs.

use crate::ir::{import_name_for_op, IrProgram};
use crate::validate::{validate_program, validate_wasm_imports, CompileError};

pub const COMPILER_ID: &[u8] = b"fractal-ir-wasm/1";
pub const WASM_INTERFACE_VERSION: u16 = 1;

pub fn compile_ir_to_wasm(program: &IrProgram) -> Result<Vec<u8>, CompileError> {
    validate_program(program)?;

    // Deduplicate imports while preserving first-seen order (deterministic).
    let mut imports: Vec<(u16, &'static str)> = Vec::new();
    for node in &program.nodes {
        let name = import_name_for_op(node.operation).ok_or(CompileError::Operation(node.operation))?;
        if !imports.iter().any(|(op, _)| *op == node.operation) {
            imports.push((node.operation, name));
        }
    }

    let mut module = Vec::new();
    module.extend_from_slice(b"\0asm");
    module.extend_from_slice(&1u32.to_le_bytes());

    // Type section: (0) host op ()->(), (1) start ()->()
    let mut types = Vec::new();
    write_u32_leb(&mut types, 2);
    // type 0
    types.push(0x60);
    write_u32_leb(&mut types, 0);
    write_u32_leb(&mut types, 0);
    // type 1
    types.push(0x60);
    write_u32_leb(&mut types, 0);
    write_u32_leb(&mut types, 0);
    write_section(&mut module, 1, &types);

    // Import section
    let mut import_body = Vec::new();
    write_u32_leb(&mut import_body, imports.len() as u32);
    for (_op, name) in &imports {
        write_name(&mut import_body, "fractal");
        write_name(&mut import_body, name);
        import_body.push(0x00); // func
        write_u32_leb(&mut import_body, 0); // type 0
    }
    write_section(&mut module, 2, &import_body);

    // Function section: one local function (start) with type 1
    let mut funcs = Vec::new();
    write_u32_leb(&mut funcs, 1);
    write_u32_leb(&mut funcs, 1);
    write_section(&mut module, 3, &funcs);

    // Export section: export "_start" -> func (imports.len())
    let mut exports = Vec::new();
    write_u32_leb(&mut exports, 1);
    write_name(&mut exports, "_start");
    exports.push(0x00); // func
    write_u32_leb(&mut exports, imports.len() as u32);
    write_section(&mut module, 7, &exports);

    // Code section
    let mut code_fn = Vec::new();
    write_u32_leb(&mut code_fn, 0); // locals
    for node in &program.nodes {
        let idx = imports
            .iter()
            .position(|(op, _)| *op == node.operation)
            .ok_or(CompileError::Operation(node.operation))? as u32;
        code_fn.push(0x10); // call
        write_u32_leb(&mut code_fn, idx);
    }
    code_fn.push(0x0b); // end
    let mut code_body = Vec::new();
    write_u32_leb(&mut code_body, 1);
    write_u32_leb(&mut code_body, code_fn.len() as u32);
    code_body.extend_from_slice(&code_fn);
    write_section(&mut module, 10, &code_body);

    // Custom section with canonical IR (not executed; pins content identity).
    let mut custom = Vec::new();
    write_name(&mut custom, "fractal.agent-ir/1");
    custom.extend_from_slice(COMPILER_ID);
    custom.extend_from_slice(&WASM_INTERFACE_VERSION.to_le_bytes());
    custom.extend_from_slice(&program.canonical_bytes());
    write_section(&mut module, 0, &custom);

    validate_wasm_imports(&module, program)?;
    Ok(module)
}

fn write_section(module: &mut Vec<u8>, id: u8, body: &[u8]) {
    module.push(id);
    write_u32_leb(module, body.len() as u32);
    module.extend_from_slice(body);
}

fn write_u32_leb(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
            out.push(byte);
        } else {
            out.push(byte);
            break;
        }
    }
}

fn write_name(out: &mut Vec<u8>, name: &str) {
    write_u32_leb(out, name.len() as u32);
    out.extend_from_slice(name.as_bytes());
}
