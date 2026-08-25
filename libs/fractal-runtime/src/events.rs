//! Canonical execution events for RUN_PROGRAM (host L2 projection).

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EventKind {
    ProgramSubmit = 1,
    ProgramResult = 2,
    CapabilityCall = 3,
    CapabilityResult = 4,
    CapabilityDenied = 5,
    TaskVerification = 6,
    Checkpoint = 7,
    Commit = 8,
    Restore = 9,
    BudgetChange = 10,
    Cancelled = 11,
    ChildFailed = 12,
    ParallelEnter = 13,
    ParallelExit = 14,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub kind: EventKind,
    pub sequence: u64,
    pub authority_epoch: u32,
    pub operation: u16,
    pub parallel_group: u16,
    pub budget_delta: i64,
    pub summary: String,
    pub previous_hash: [u8; 32],
    pub event_hash: [u8; 32],
}

#[derive(Debug, Default)]
pub struct EventLog {
    pub events: Vec<Event>,
    head: [u8; 32],
}

impl EventLog {
    pub fn emit(
        &mut self,
        kind: EventKind,
        authority_epoch: u32,
        operation: u16,
        parallel_group: u16,
        budget_delta: i64,
        summary: impl Into<String>,
    ) -> &Event {
        let sequence = self.events.len() as u64 + 1;
        let summary = summary.into();
        let previous_hash = self.head;
        let mut hasher = Sha256::new();
        hasher.update(previous_hash);
        hasher.update((kind as u16).to_le_bytes());
        hasher.update(sequence.to_le_bytes());
        hasher.update(authority_epoch.to_le_bytes());
        hasher.update(operation.to_le_bytes());
        hasher.update(parallel_group.to_le_bytes());
        hasher.update(budget_delta.to_le_bytes());
        hasher.update(summary.as_bytes());
        let event_hash = hasher.finalize().into();
        self.head = event_hash;
        self.events.push(Event {
            kind,
            sequence,
            authority_epoch,
            operation,
            parallel_group,
            budget_delta,
            summary,
            previous_hash,
            event_hash,
        });
        self.events.last().unwrap()
    }

    pub fn head(&self) -> [u8; 32] {
        self.head
    }
}
