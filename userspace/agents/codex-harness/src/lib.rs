//! Capability-native Codex-style agent loop.
//!
//! This crate contains no network, filesystem, process, or model client. Every
//! effect crosses a [`Backend`] method after an independent authority check.
//! A seL4 PD adapter supplies those methods using only installed capabilities.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use serde::Deserialize;

pub const CAP_MODEL: u32 = 1 << 0;
pub const CAP_TOOL: u32 = 1 << 1;
pub const CAP_MEMORY: u32 = 1 << 2;
pub const CAP_EXEC: u32 = 1 << 3;
pub const CAP_NETWORK: u32 = 1 << 4;
pub const CAP_KNOWN_MASK: u32 = CAP_MODEL | CAP_TOOL | CAP_MEMORY | CAP_EXEC | CAP_NETWORK;

const SYSTEM_PROMPT: &str = r#"You are an AgentOS coding harness planner. Return exactly one JSON object per turn.
Allowed actions:
{"action":"tool","name":"<granted tool>","arguments":<json>}
{"action":"memory_read","object":"<capability-scoped object>"}
{"action":"memory_write","object":"<capability-scoped object>","content":"<text>"}
{"action":"verify","command":"<command>"}
{"action":"final","summary":"<result>"}
There is no direct network action. Use only capabilities visible in the supplied context. Never claim success before required verification passes."#;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Authority(u32);

impl Authority {
    pub fn from_installed(mask: u32) -> Result<Self, HarnessError> {
        if mask & !CAP_KNOWN_MASK != 0 {
            return Err(HarnessError::UnknownCapability);
        }
        Ok(Self(mask))
    }

    pub const fn mask(self) -> u32 {
        self.0
    }

    pub const fn contains(self, capability: u32) -> bool {
        self.0 & capability == capability
    }

    fn require(self, capability: u32) -> Result<(), HarnessError> {
        if self.contains(capability) {
            Ok(())
        } else {
            Err(HarnessError::CapabilityDenied(capability))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Task {
    pub id: u32,
    pub instruction: String,
    pub required_caps: u32,
    pub max_steps: u32,
    pub require_verification: bool,
    pub max_context_bytes: usize,
}

impl Task {
    pub fn coding(id: u32, instruction: impl Into<String>, required_caps: u32) -> Self {
        Self {
            id,
            instruction: instruction.into(),
            required_caps,
            max_steps: 32,
            require_verification: true,
            max_context_bytes: 256 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelReply {
    pub text: String,
    pub tokens_in: u32,
    pub tokens_out: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendError {
    Denied,
    NotFound,
    Failed(String),
}

/// Effects available to the harness. The seL4 adapter must map each method to
/// a different minted endpoint/frame capability; it must not implement an
/// ambient catch-all RPC channel.
pub trait Backend {
    fn model(&mut self, request: &str) -> Result<ModelReply, BackendError>;
    fn invoke_tool(&mut self, name: &str, arguments_json: &str) -> Result<String, BackendError>;
    fn read_memory(&mut self, object: &str) -> Result<String, BackendError>;
    fn write_memory(&mut self, object: &str, content: &str) -> Result<(), BackendError>;
    fn verify(&mut self, command: &str) -> Result<(i32, String), BackendError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HarnessError {
    InvalidTask,
    UnknownCapability,
    CapabilityDenied(u32),
    BackendDenied,
    BackendNotFound,
    BackendFailed(String),
    Protocol(String),
    ContextLimit,
    StepLimit,
    VerificationRequired,
}

impl From<BackendError> for HarnessError {
    fn from(error: BackendError) -> Self {
        match error {
            BackendError::Denied => Self::BackendDenied,
            BackendError::NotFound => Self::BackendNotFound,
            BackendError::Failed(message) => Self::BackendFailed(message),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RunMetrics {
    pub steps: u32,
    pub model_calls: u32,
    pub tool_calls: u32,
    pub memory_ops: u32,
    pub exec_calls: u32,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub used_caps: u32,
    pub denied_attempts: u32,
    pub verification_exit_code: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunResult {
    pub task_id: u32,
    pub summary: String,
    pub metrics: RunMetrics,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Tool {
        name: String,
        arguments: serde_json::Value,
    },
    MemoryRead {
        object: String,
    },
    MemoryWrite {
        object: String,
        content: String,
    },
    Verify {
        command: String,
    },
    Final {
        summary: String,
    },
}

pub struct Harness<B> {
    authority: Authority,
    backend: B,
}

impl<B: Backend> Harness<B> {
    pub const fn new(authority: Authority, backend: B) -> Self {
        Self { authority, backend }
    }

    pub fn into_backend(self) -> B {
        self.backend
    }

    pub fn run(&mut self, task: &Task) -> Result<RunResult, HarnessError> {
        validate_task(task, self.authority)?;
        // Every planner turn requires ModelCap, even if the task descriptor did
        // not declare it. Task data cannot weaken the harness's own contract.
        self.authority.require(CAP_MODEL)?;

        let mut context = format!(
            "{SYSTEM_PROMPT}\n\nTask {}:\n{}\n\nInstalled capability classes: {}\n",
            task.id,
            task.instruction,
            capability_names(self.authority)
        );
        let mut metrics = RunMetrics::default();
        let mut verification_passed = false;

        for step in 1..=task.max_steps {
            metrics.steps = step;
            metrics.model_calls += 1;
            metrics.used_caps |= CAP_MODEL;
            let reply = self.backend.model(&context).map_err(HarnessError::from)?;
            metrics.tokens_in = metrics.tokens_in.saturating_add(reply.tokens_in as u64);
            metrics.tokens_out = metrics.tokens_out.saturating_add(reply.tokens_out as u64);
            let action: Action = serde_json::from_str(reply.text.trim())
                .map_err(|error| HarnessError::Protocol(error.to_string()))?;

            let observation = match action {
                Action::Tool { name, arguments } => {
                    require_counted(self.authority, CAP_TOOL, &mut metrics)?;
                    metrics.tool_calls += 1;
                    let encoded = serde_json::to_string(&arguments)
                        .map_err(|error| HarnessError::Protocol(error.to_string()))?;
                    let output = self
                        .backend
                        .invoke_tool(&name, &encoded)
                        .map_err(HarnessError::from)?;
                    format!("tool {name} returned: {output}")
                }
                Action::MemoryRead { object } => {
                    require_counted(self.authority, CAP_MEMORY, &mut metrics)?;
                    metrics.memory_ops += 1;
                    let output = self
                        .backend
                        .read_memory(&object)
                        .map_err(HarnessError::from)?;
                    format!("memory {object}: {output}")
                }
                Action::MemoryWrite { object, content } => {
                    require_counted(self.authority, CAP_MEMORY, &mut metrics)?;
                    metrics.memory_ops += 1;
                    self.backend
                        .write_memory(&object, &content)
                        .map_err(HarnessError::from)?;
                    format!("memory {object} updated")
                }
                Action::Verify { command } => {
                    require_counted(self.authority, CAP_EXEC, &mut metrics)?;
                    metrics.exec_calls += 1;
                    let (exit_code, output) =
                        self.backend.verify(&command).map_err(HarnessError::from)?;
                    metrics.verification_exit_code = Some(exit_code);
                    verification_passed = exit_code == 0;
                    format!("verification exit={exit_code}: {output}")
                }
                Action::Final { summary } => {
                    if task.require_verification && !verification_passed {
                        return Err(HarnessError::VerificationRequired);
                    }
                    return Ok(RunResult {
                        task_id: task.id,
                        summary,
                        metrics,
                    });
                }
            };

            context.push_str("\nPlanner response: ");
            context.push_str(reply.text.trim());
            context.push_str("\nObservation: ");
            context.push_str(&observation);
            context.push('\n');
            if context.len() > task.max_context_bytes {
                return Err(HarnessError::ContextLimit);
            }
        }
        Err(HarnessError::StepLimit)
    }
}

fn validate_task(task: &Task, authority: Authority) -> Result<(), HarnessError> {
    if task.id == 0 || task.instruction.is_empty() || task.max_steps == 0 {
        return Err(HarnessError::InvalidTask);
    }
    if task.required_caps & !CAP_KNOWN_MASK != 0 {
        return Err(HarnessError::UnknownCapability);
    }
    let missing = task.required_caps & !authority.mask();
    if missing != 0 {
        return Err(HarnessError::CapabilityDenied(missing));
    }
    Ok(())
}

fn require_counted(
    authority: Authority,
    capability: u32,
    metrics: &mut RunMetrics,
) -> Result<(), HarnessError> {
    if let Err(error) = authority.require(capability) {
        metrics.denied_attempts += 1;
        return Err(error);
    }
    metrics.used_caps |= capability;
    Ok(())
}

fn capability_names(authority: Authority) -> String {
    let mut value = String::new();
    for (bit, name) in [
        (CAP_MODEL, "model"),
        (CAP_TOOL, "tool"),
        (CAP_MEMORY, "memory"),
        (CAP_EXEC, "exec"),
        (CAP_NETWORK, "network"),
    ] {
        if authority.contains(bit) {
            if !value.is_empty() {
                value.push(',');
            }
            value.push_str(name);
        }
    }
    if value.is_empty() {
        value.push_str("none");
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct ScriptedBackend {
        replies: VecDeque<&'static str>,
        model_calls: u32,
        tool_calls: u32,
        memory_calls: u32,
        exec_calls: u32,
        deny_tool: bool,
    }

    impl ScriptedBackend {
        fn with_replies(replies: &[&'static str]) -> Self {
            Self {
                replies: replies.iter().copied().collect(),
                ..Self::default()
            }
        }
    }

    impl Backend for ScriptedBackend {
        fn model(&mut self, _request: &str) -> Result<ModelReply, BackendError> {
            self.model_calls += 1;
            Ok(ModelReply {
                text: self.replies.pop_front().unwrap_or("{}").to_string(),
                tokens_in: 10,
                tokens_out: 3,
            })
        }

        fn invoke_tool(&mut self, _name: &str, _arguments: &str) -> Result<String, BackendError> {
            self.tool_calls += 1;
            if self.deny_tool {
                Err(BackendError::Denied)
            } else {
                Ok("patch applied".to_string())
            }
        }

        fn read_memory(&mut self, _object: &str) -> Result<String, BackendError> {
            self.memory_calls += 1;
            Ok("content".to_string())
        }

        fn write_memory(&mut self, _object: &str, _content: &str) -> Result<(), BackendError> {
            self.memory_calls += 1;
            Ok(())
        }

        fn verify(&mut self, _command: &str) -> Result<(i32, String), BackendError> {
            self.exec_calls += 1;
            Ok((0, "PASS".to_string()))
        }
    }

    #[test]
    fn no_model_cap_means_no_model_call() {
        let backend = ScriptedBackend::with_replies(&[]);
        let mut harness = Harness::new(Authority::from_installed(0).unwrap(), backend);
        let task = Task::coding(1, "fix it", 0);
        assert_eq!(
            harness.run(&task),
            Err(HarnessError::CapabilityDenied(CAP_MODEL))
        );
        assert_eq!(harness.into_backend().model_calls, 0);
    }

    #[test]
    fn model_cap_does_not_allow_tools() {
        let backend = ScriptedBackend::with_replies(&[
            r#"{"action":"tool","name":"workspace.apply_patch","arguments":{}}"#,
        ]);
        let mut harness = Harness::new(Authority::from_installed(CAP_MODEL).unwrap(), backend);
        let task = Task::coding(1, "fix it", CAP_MODEL);
        assert_eq!(
            harness.run(&task),
            Err(HarnessError::CapabilityDenied(CAP_TOOL))
        );
        assert_eq!(harness.into_backend().tool_calls, 0);
    }

    #[test]
    fn tool_service_can_still_deny_a_specific_tool() {
        let mut backend = ScriptedBackend::with_replies(&[
            r#"{"action":"tool","name":"admin.erase","arguments":{}}"#,
        ]);
        backend.deny_tool = true;
        let authority = Authority::from_installed(CAP_MODEL | CAP_TOOL).unwrap();
        let mut harness = Harness::new(authority, backend);
        let task = Task::coding(1, "fix it", CAP_MODEL | CAP_TOOL);
        assert_eq!(harness.run(&task), Err(HarnessError::BackendDenied));
        assert_eq!(harness.into_backend().tool_calls, 1);
    }

    #[test]
    fn direct_network_action_is_not_part_of_the_protocol() {
        let backend =
            ScriptedBackend::with_replies(&[r#"{"action":"network","url":"https://example.com"}"#]);
        let authority = Authority::from_installed(CAP_MODEL | CAP_NETWORK).unwrap();
        let mut harness = Harness::new(authority, backend);
        let task = Task::coding(1, "fetch", CAP_MODEL | CAP_NETWORK);
        assert!(matches!(harness.run(&task), Err(HarnessError::Protocol(_))));
    }

    #[test]
    fn final_is_rejected_until_verification_passes() {
        let backend = ScriptedBackend::with_replies(&[r#"{"action":"final","summary":"done"}"#]);
        let mut harness = Harness::new(Authority::from_installed(CAP_MODEL).unwrap(), backend);
        let task = Task::coding(1, "fix it", CAP_MODEL);
        assert_eq!(harness.run(&task), Err(HarnessError::VerificationRequired));
    }

    #[test]
    fn coding_loop_tools_verifies_and_finishes() {
        let backend = ScriptedBackend::with_replies(&[
            r#"{"action":"tool","name":"workspace.apply_patch","arguments":{"patch":"x"}}"#,
            r#"{"action":"verify","command":"./test.sh"}"#,
            r#"{"action":"final","summary":"fixed and tested"}"#,
        ]);
        let caps = CAP_MODEL | CAP_TOOL | CAP_EXEC;
        let mut harness = Harness::new(Authority::from_installed(caps).unwrap(), backend);
        let task = Task::coding(7, "repair health check", caps);
        let result = harness.run(&task).unwrap();
        assert_eq!(result.summary, "fixed and tested");
        assert_eq!(result.metrics.steps, 3);
        assert_eq!(result.metrics.model_calls, 3);
        assert_eq!(result.metrics.tool_calls, 1);
        assert_eq!(result.metrics.exec_calls, 1);
        assert_eq!(result.metrics.verification_exit_code, Some(0));
        assert_eq!(result.metrics.used_caps, caps);
    }

    #[test]
    fn declared_requirements_cannot_exceed_installed_authority() {
        let backend = ScriptedBackend::default();
        let mut harness = Harness::new(Authority::from_installed(CAP_MODEL).unwrap(), backend);
        let task = Task::coding(1, "fix", CAP_MODEL | CAP_MEMORY);
        assert_eq!(
            harness.run(&task),
            Err(HarnessError::CapabilityDenied(CAP_MEMORY))
        );
        assert_eq!(harness.into_backend().model_calls, 0);
    }
}
