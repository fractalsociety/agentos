//! Trusted RUN_PROGRAM host authority and nested-call fence.

use crate::events::{EventKind, EventLog};
use crate::ir::{import_name_for_op, operation_required_caps};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HostError {
    #[error("denied: {0}")]
    Denied(&'static str),
    #[error("stale authority epoch")]
    StaleEpoch,
    #[error("budget exhausted")]
    BudgetExhausted,
    #[error("cancelled")]
    Cancelled,
    #[error("child failure in parallel group {0}")]
    ChildFailed(u16),
    #[error("undeclared or hidden call `{0}`")]
    HiddenCall(String),
    #[error("raw opcode {0} is not an installed import")]
    RawOpcode(u16),
    #[error("{0}")]
    Message(String),
}

#[derive(Debug, Clone)]
pub struct HostConfig {
    pub installed_caps: u32,
    pub authority_epoch: u32,
    pub budget_limit: u64,
    pub max_children: u32,
    /// Import names the module may invoke (from validated IR).
    pub allowed_imports: Vec<String>,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            installed_caps: u32::MAX,
            authority_epoch: 1,
            budget_limit: 10_000,
            max_children: 8,
            allowed_imports: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct HostState {
    pub config: HostConfig,
    pub budget_used: u64,
    pub cancelled: bool,
    pub active_children: u32,
    pub events: EventLog,
    pub call_trace: Vec<String>,
    /// Compact model-facing result (selected only).
    pub compact_result: Option<String>,
    /// Set when a host import fails; inspected after WASM returns/traps.
    pub trap: Option<HostError>,
}

impl HostState {
    pub fn new(config: HostConfig) -> Self {
        Self {
            config,
            budget_used: 0,
            cancelled: false,
            active_children: 0,
            events: EventLog::default(),
            call_trace: Vec::new(),
            compact_result: None,
            trap: None,
        }
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.events.emit(
            EventKind::Cancelled,
            self.config.authority_epoch,
            0,
            0,
            0,
            "host cancelled",
        );
    }

    pub fn bump_epoch(&mut self) {
        self.config.authority_epoch = self.config.authority_epoch.saturating_add(1);
        self.events.emit(
            EventKind::CapabilityDenied,
            self.config.authority_epoch,
            0,
            0,
            0,
            "authority epoch bumped",
        );
    }

    /// Independent nested-call authorization fence.
    pub fn authorize_call(
        &mut self,
        import_name: &str,
        operation: u16,
        parallel_group: u16,
        caller_epoch: u32,
        cost: u64,
    ) -> Result<(), HostError> {
        if self.cancelled {
            return Err(HostError::Cancelled);
        }
        if caller_epoch != self.config.authority_epoch {
            self.events.emit(
                EventKind::CapabilityDenied,
                self.config.authority_epoch,
                operation,
                parallel_group,
                0,
                format!("stale epoch {caller_epoch}"),
            );
            return Err(HostError::StaleEpoch);
        }
        if !self
            .config
            .allowed_imports
            .iter()
            .any(|a| a == import_name)
        {
            self.events.emit(
                EventKind::CapabilityDenied,
                self.config.authority_epoch,
                operation,
                parallel_group,
                0,
                format!("hidden/undeclared `{import_name}`"),
            );
            return Err(HostError::HiddenCall(import_name.into()));
        }
        let Some(expected_name) = import_name_for_op(operation) else {
            self.events.emit(
                EventKind::CapabilityDenied,
                self.config.authority_epoch,
                operation,
                parallel_group,
                0,
                "raw opcode",
            );
            return Err(HostError::RawOpcode(operation));
        };
        if expected_name != import_name {
            return Err(HostError::HiddenCall(import_name.into()));
        }
        let required = operation_required_caps(operation).ok_or(HostError::RawOpcode(operation))?;
        if (self.config.installed_caps & required) != required {
            self.events.emit(
                EventKind::CapabilityDenied,
                self.config.authority_epoch,
                operation,
                parallel_group,
                0,
                "missing capability",
            );
            return Err(HostError::Denied("missing capability"));
        }
        if self.budget_used.saturating_add(cost) > self.config.budget_limit {
            self.events.emit(
                EventKind::BudgetChange,
                self.config.authority_epoch,
                operation,
                parallel_group,
                -(cost as i64),
                "budget exhausted",
            );
            return Err(HostError::BudgetExhausted);
        }
        Ok(())
    }

    pub fn dispatch(
        &mut self,
        import_name: &str,
        operation: u16,
        parallel_group: u16,
        caller_epoch: u32,
        cost: u64,
    ) -> Result<(), HostError> {
        self.authorize_call(import_name, operation, parallel_group, caller_epoch, cost)?;
        self.budget_used += cost;
        self.call_trace.push(import_name.to_string());
        self.events.emit(
            EventKind::CapabilityCall,
            self.config.authority_epoch,
            operation,
            parallel_group,
            -(cost as i64),
            import_name,
        );

        // Domain semantics for compact result / failure injection hooks.
        match import_name {
            "object_get" | "checkpoint" => {
                self.events.emit(
                    EventKind::Checkpoint,
                    self.config.authority_epoch,
                    operation,
                    parallel_group,
                    0,
                    import_name,
                );
            }
            "task_verify" => {
                self.events.emit(
                    EventKind::TaskVerification,
                    self.config.authority_epoch,
                    operation,
                    parallel_group,
                    0,
                    "verify ok",
                );
                self.compact_result = Some("verified".into());
            }
            "commit" => {
                self.events.emit(
                    EventKind::Commit,
                    self.config.authority_epoch,
                    operation,
                    parallel_group,
                    0,
                    "commit",
                );
                if self.compact_result.is_none() {
                    self.compact_result = Some("committed".into());
                }
            }
            "restore" => {
                self.events.emit(
                    EventKind::Restore,
                    self.config.authority_epoch,
                    operation,
                    parallel_group,
                    0,
                    "restore",
                );
            }
            _ => {}
        }

        self.events.emit(
            EventKind::CapabilityResult,
            self.config.authority_epoch,
            operation,
            parallel_group,
            0,
            format!("{import_name} ok"),
        );
        Ok(())
    }

    pub fn begin_parallel(&mut self, group: u16, children: u32) -> Result<(), HostError> {
        if children > self.config.max_children {
            return Err(HostError::Denied("too many parallel children"));
        }
        self.active_children = children;
        self.events.emit(
            EventKind::ParallelEnter,
            self.config.authority_epoch,
            0,
            group,
            0,
            format!("parallel group {group} children={children}"),
        );
        Ok(())
    }

    pub fn end_parallel(&mut self, group: u16) {
        self.active_children = 0;
        self.events.emit(
            EventKind::ParallelExit,
            self.config.authority_epoch,
            0,
            group,
            0,
            format!("parallel group {group} closed"),
        );
    }

    pub fn fail_child(&mut self, group: u16, name: &str) -> HostError {
        self.events.emit(
            EventKind::ChildFailed,
            self.config.authority_epoch,
            0,
            group,
            0,
            format!("child `{name}` failed"),
        );
        self.cancel();
        HostError::ChildFailed(group)
    }
}
