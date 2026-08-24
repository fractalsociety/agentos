//! Generated bindings for `interfaces/wit/fractalos-capabilities-v1/capabilities.wit`.
//!
//! This checked-in no-std representation is produced from the WIT records and
//! keeps the wire model usable by seL4 PDs without importing a runtime.  The
//! optional `wit-bindings` feature enables the upstream generator in consumers
//! that need a component-model adapter.

use alloc::vec::Vec;

pub const PACKAGE: &str = "fractalos:capabilities@1.0.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectId {
    pub word0: u32,
    pub word1: u32,
    pub word2: u32,
    pub word3: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramHandle {
    pub id: u64,
    pub authority_epoch: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskHandle {
    pub id: u64,
    pub authority_epoch: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscriptionHandle {
    pub id: u64,
    pub authority_epoch: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerKind {
    Native,
    Agentlang,
    Wasm,
    Guest,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerIdentity {
    pub kind: WorkerKind,
    pub slot: u32,
    pub generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramRef {
    pub digest: [u8; 32],
    pub program_version: u32,
    pub interface_version: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    pub cpu_quanta: u64,
    pub memory_bytes: u64,
    pub max_steps: u32,
    pub max_result_bytes: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Accepted,
    Running,
    Complete,
    Failed,
    Cancelled,
    Revoked,
    BudgetExhausted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgramState {
    Loading,
    Ready,
    Rejected,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyStatus {
    Unverified,
    Accepted,
    Rejected,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofLevel {
    None,
    HostContract,
    TargetContract,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyEvidence {
    pub evidence_version: u32,
    pub proof_level: ProofLevel,
    pub test_count: u32,
    pub commit_digest: Vec<u8>,
    pub test_digest: Vec<u8>,
    pub evidence_digest: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskError {
    Invalid,
    Version,
    Denied,
    NotFound,
    StaleHandle,
    Revoked,
    Cancelled,
    BudgetExhausted,
    NotReady,
    WouldBlock,
    Terminal,
    Authority,
    VerifyRequired,
    EvidenceMismatch,
    PromotionForbidden,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Submission {
    pub program: ProgramHandle,
    pub task: TaskHandle,
    pub state: State,
    pub authority_epoch: u32,
    pub worker: WorkerIdentity,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalResult {
    pub state: State,
    pub result_kind: u32,
    pub terminal_code: u32,
    pub result_bytes: u32,
    pub verify_status: VerifyStatus,
    pub worker: WorkerIdentity,
    pub result_digest: Vec<u8>,
}

/// Generated operation surface. Implementations may use the native IPC
/// adapter or a component-model transport; every call remains nonblocking.
pub trait TaskControlPlane {
    fn open_program(
        &mut self,
        reference: ProgramRef,
        authority_epoch: u32,
    ) -> Result<ProgramHandle, TaskError>;
    fn poll_program(
        &mut self,
        program: ProgramHandle,
        authority_epoch: u32,
    ) -> Result<ProgramState, TaskError>;
    fn submit(
        &mut self,
        program: ProgramHandle,
        budget: Budget,
        authority_epoch: u32,
    ) -> Result<Submission, TaskError>;
    fn poll(&mut self, task: TaskHandle, authority_epoch: u32) -> Result<State, TaskError>;
    fn cancel(&mut self, task: TaskHandle, authority_epoch: u32) -> Result<State, TaskError>;
    fn set_budget(
        &mut self,
        task: TaskHandle,
        budget: Budget,
        authority_epoch: u32,
    ) -> Result<Budget, TaskError>;
    fn task_verify(
        &mut self,
        task: TaskHandle,
        evidence: VerifyEvidence,
        authority_epoch: u32,
    ) -> Result<VerifyStatus, TaskError>;
    fn get_terminal_result(
        &mut self,
        task: TaskHandle,
        authority_epoch: u32,
    ) -> Result<TerminalResult, TaskError>;
}
