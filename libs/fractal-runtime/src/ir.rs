//! Canonical Agent IR program layout for WASM lowering.

use sha2::{Digest, Sha256};

pub const AGENT_IR_INTERFACE_VERSION: u16 = 1;
pub const MAX_IR_NODES: usize = 32;
pub const MAX_BUDGET_UNITS: u32 = 0x7fff_ffff;

pub const AGENT_ISA_OP_SPAWN: u16 = 1;
pub const AGENT_ISA_OP_DELEGATE: u16 = 2;
pub const AGENT_ISA_OP_CAP_GRANT: u16 = 3;
pub const AGENT_ISA_OP_CAP_REVOKE: u16 = 4;
pub const AGENT_ISA_OP_OBJECT_GET: u16 = 5;
pub const AGENT_ISA_OP_OBJECT_PUT: u16 = 6;
pub const AGENT_ISA_OP_OBJECT_QUERY: u16 = 7;
pub const AGENT_ISA_OP_INFER: u16 = 8;
pub const AGENT_ISA_OP_ACT: u16 = 9;
pub const AGENT_ISA_OP_WAIT: u16 = 10;
pub const AGENT_ISA_OP_EMIT: u16 = 11;
pub const AGENT_ISA_OP_CHECKPOINT: u16 = 12;
pub const AGENT_ISA_OP_RESTORE: u16 = 13;
pub const AGENT_ISA_OP_VERIFY: u16 = 14;
pub const AGENT_ISA_OP_COMMIT: u16 = 15;
pub const AGENT_ISA_OP_TRACE: u16 = 16;
pub const AGENT_ISA_OP_BUDGET: u16 = 17;
pub const AGENT_ISA_OP_TERMINATE: u16 = 18;

pub const AGENT_ISA_CAP_CONTROL: u32 = 1 << 0;
pub const AGENT_ISA_CAP_ADMIN: u32 = 1 << 1;
pub const AGENT_ISA_CAP_OBJECT: u32 = 1 << 2;
pub const AGENT_ISA_CAP_INFER: u32 = 1 << 3;
pub const AGENT_ISA_CAP_ACT: u32 = 1 << 4;
pub const AGENT_ISA_CAP_EVENT: u32 = 1 << 5;
pub const AGENT_ISA_CAP_VERIFY: u32 = 1 << 6;
pub const AGENT_ISA_CAP_COMMIT: u32 = 1 << 7;
pub const AGENT_ISA_CAP_TRACE: u32 = 1 << 8;
pub const AGENT_ISA_CAP_BUDGET: u32 = 1 << 9;

pub const AGENT_ISA_FLAG_ASYNC: u32 = 1 << 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectId {
    pub word: [u32; 4],
}

impl ObjectId {
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();
        let mut word = [0u32; 4];
        for i in 0..4 {
            let o = i * 4;
            word[i] = u32::from_le_bytes(digest[o..o + 4].try_into().unwrap());
        }
        Self { word }
    }

    pub const ZERO: Self = Self { word: [0; 4] };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIrNode {
    pub interface_version: u16,
    pub operation: u16,
    pub execution_flags: u32,
    pub declared_caps: u32,
    pub budget_units: u32,
    pub subject_root: ObjectId,
    pub context_root: ObjectId,
    pub success_continuation_root: ObjectId,
    pub failure_continuation_root: ObjectId,
}

impl AgentIrNode {
    pub fn canonical_bytes(&self) -> [u8; 80] {
        let mut out = [0u8; 80];
        let mut o = 0usize;
        put16(&mut out, &mut o, self.interface_version);
        put16(&mut out, &mut o, self.operation);
        put32(&mut out, &mut o, self.execution_flags);
        put32(&mut out, &mut o, self.declared_caps);
        put32(&mut out, &mut o, self.budget_units);
        put_id(&mut out, &mut o, &self.subject_root);
        put_id(&mut out, &mut o, &self.context_root);
        put_id(&mut out, &mut o, &self.success_continuation_root);
        put_id(&mut out, &mut o, &self.failure_continuation_root);
        debug_assert_eq!(o, 80);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrProgram {
    pub interface_version: u16,
    /// Effect row the program may exercise (capability-class bits).
    pub declared_effects: u32,
    pub max_nodes: u16,
    pub max_budget_units: u32,
    pub nodes: Vec<AgentIrNode>,
    /// Structured-concurrency group per node; 0 = sequential singleton.
    /// Equal nonzero values are siblings in one parallel scope.
    pub parallel_groups: Vec<u16>,
}

impl IrProgram {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.nodes.len() * 82);
        out.extend_from_slice(&self.interface_version.to_le_bytes());
        out.extend_from_slice(&self.declared_effects.to_le_bytes());
        out.extend_from_slice(&self.max_nodes.to_le_bytes());
        out.extend_from_slice(&self.max_budget_units.to_le_bytes());
        out.extend_from_slice(&(self.nodes.len() as u32).to_le_bytes());
        for (idx, node) in self.nodes.iter().enumerate() {
            out.extend_from_slice(&node.canonical_bytes());
            let group = self.parallel_groups.get(idx).copied().unwrap_or(0);
            out.extend_from_slice(&group.to_le_bytes());
        }
        out
    }
}

pub fn operation_required_caps(operation: u16) -> Option<u32> {
    Some(match operation {
        AGENT_ISA_OP_SPAWN | AGENT_ISA_OP_DELEGATE => AGENT_ISA_CAP_CONTROL,
        AGENT_ISA_OP_CAP_GRANT | AGENT_ISA_OP_CAP_REVOKE => AGENT_ISA_CAP_ADMIN,
        AGENT_ISA_OP_OBJECT_GET | AGENT_ISA_OP_OBJECT_PUT | AGENT_ISA_OP_OBJECT_QUERY => {
            AGENT_ISA_CAP_OBJECT
        }
        AGENT_ISA_OP_INFER => AGENT_ISA_CAP_INFER,
        AGENT_ISA_OP_ACT => AGENT_ISA_CAP_ACT,
        AGENT_ISA_OP_WAIT => AGENT_ISA_CAP_CONTROL,
        AGENT_ISA_OP_EMIT => AGENT_ISA_CAP_EVENT,
        AGENT_ISA_OP_CHECKPOINT | AGENT_ISA_OP_RESTORE => AGENT_ISA_CAP_OBJECT,
        AGENT_ISA_OP_VERIFY => AGENT_ISA_CAP_VERIFY,
        AGENT_ISA_OP_COMMIT => AGENT_ISA_CAP_COMMIT,
        AGENT_ISA_OP_TRACE => AGENT_ISA_CAP_TRACE,
        AGENT_ISA_OP_BUDGET => AGENT_ISA_CAP_BUDGET,
        AGENT_ISA_OP_TERMINATE => AGENT_ISA_CAP_CONTROL,
        _ => return None,
    })
}

pub fn operation_is_async(operation: u16) -> bool {
    matches!(
        operation,
        AGENT_ISA_OP_SPAWN
            | AGENT_ISA_OP_DELEGATE
            | AGENT_ISA_OP_OBJECT_GET
            | AGENT_ISA_OP_OBJECT_PUT
            | AGENT_ISA_OP_OBJECT_QUERY
            | AGENT_ISA_OP_INFER
            | AGENT_ISA_OP_ACT
            | AGENT_ISA_OP_EMIT
            | AGENT_ISA_OP_VERIFY
    )
}

pub fn import_name_for_op(operation: u16) -> Option<&'static str> {
    Some(match operation {
        AGENT_ISA_OP_SPAWN => "spawn",
        AGENT_ISA_OP_DELEGATE => "delegate",
        AGENT_ISA_OP_CAP_GRANT => "cap_grant",
        AGENT_ISA_OP_CAP_REVOKE => "cap_revoke",
        AGENT_ISA_OP_OBJECT_GET => "object_get",
        AGENT_ISA_OP_OBJECT_PUT => "object_put",
        AGENT_ISA_OP_OBJECT_QUERY => "object_query",
        AGENT_ISA_OP_INFER => "infer",
        AGENT_ISA_OP_ACT => "act",
        AGENT_ISA_OP_WAIT => "wait",
        AGENT_ISA_OP_EMIT => "emit",
        AGENT_ISA_OP_CHECKPOINT => "checkpoint",
        AGENT_ISA_OP_RESTORE => "restore",
        AGENT_ISA_OP_VERIFY => "task_verify",
        AGENT_ISA_OP_COMMIT => "commit",
        AGENT_ISA_OP_TRACE => "trace",
        AGENT_ISA_OP_BUDGET => "budget",
        AGENT_ISA_OP_TERMINATE => "terminate",
        _ => return None,
    })
}

#[cfg(test)]
pub fn sample_delegate_program() -> IrProgram {
    let objective = ObjectId::from_bytes(b"fix(issue)");
    let workspace = ObjectId::from_bytes(b"workspace");
    let success = ObjectId::from_bytes(b"verify-next");
    let failure = ObjectId::from_bytes(b"restore-next");
    IrProgram {
        interface_version: AGENT_IR_INTERFACE_VERSION,
        declared_effects: AGENT_ISA_CAP_CONTROL,
        max_nodes: MAX_IR_NODES as u16,
        max_budget_units: 1024,
        nodes: vec![AgentIrNode {
            interface_version: AGENT_IR_INTERFACE_VERSION,
            operation: AGENT_ISA_OP_DELEGATE,
            execution_flags: AGENT_ISA_FLAG_ASYNC,
            declared_caps: AGENT_ISA_CAP_CONTROL,
            budget_units: 8,
            subject_root: objective,
            context_root: workspace,
            success_continuation_root: success,
            failure_continuation_root: failure,
        }],
        parallel_groups: vec![0],
    }
}

/// Parallel read → edit → TASK_VERIFY → commit fixture for RUN_PROGRAM gates.
pub fn sample_parallel_verify_program() -> IrProgram {
    let mk = |op: u16, caps: u32, flags: u32, budget: u32| AgentIrNode {
        interface_version: AGENT_IR_INTERFACE_VERSION,
        operation: op,
        execution_flags: flags,
        declared_caps: caps,
        budget_units: budget,
        subject_root: ObjectId::from_bytes(b"subject"),
        context_root: ObjectId::from_bytes(b"context"),
        success_continuation_root: ObjectId::from_bytes(b"ok"),
        failure_continuation_root: ObjectId::from_bytes(b"err"),
    };
    IrProgram {
        interface_version: AGENT_IR_INTERFACE_VERSION,
        declared_effects: AGENT_ISA_CAP_OBJECT
            | AGENT_ISA_CAP_VERIFY
            | AGENT_ISA_CAP_COMMIT,
        max_nodes: MAX_IR_NODES as u16,
        max_budget_units: 256,
        nodes: vec![
            mk(
                AGENT_ISA_OP_OBJECT_GET,
                AGENT_ISA_CAP_OBJECT,
                AGENT_ISA_FLAG_ASYNC,
                4,
            ),
            mk(
                AGENT_ISA_OP_OBJECT_GET,
                AGENT_ISA_CAP_OBJECT,
                AGENT_ISA_FLAG_ASYNC,
                4,
            ),
            mk(AGENT_ISA_OP_OBJECT_PUT, AGENT_ISA_CAP_OBJECT, AGENT_ISA_FLAG_ASYNC, 8),
            mk(AGENT_ISA_OP_VERIFY, AGENT_ISA_CAP_VERIFY, AGENT_ISA_FLAG_ASYNC, 8),
            mk(AGENT_ISA_OP_COMMIT, AGENT_ISA_CAP_COMMIT, 0, 4),
        ],
        // Two concurrent reads in group 1, then sequential edit/verify/commit.
        parallel_groups: vec![1, 1, 0, 0, 0],
    }
}

fn put16(out: &mut [u8], o: &mut usize, value: u16) {
    out[*o] = value as u8;
    out[*o + 1] = (value >> 8) as u8;
    *o += 2;
}

fn put32(out: &mut [u8], o: &mut usize, value: u32) {
    out[*o..*o + 4].copy_from_slice(&value.to_le_bytes());
    *o += 4;
}

fn put_id(out: &mut [u8], o: &mut usize, id: &ObjectId) {
    for word in id.word {
        put32(out, o, word);
    }
}
