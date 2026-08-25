//! Narrow Model Context Protocol bridge for the FractalOS control plane.
//!
//! The server deliberately exposes a small allowlist instead of a generic
//! `agentctl raw` escape hatch. Three operations are read-only; the explicitly
//! mutating native-task operation reaches only the audited `agentctl agent-run`
//! command. Codex talks JSON-RPC over stdio; this process alone connects to
//! CC-PD's Unix socket.

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::Command;

const SERVER_NAME: &str = "fractalos-control";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";

#[derive(Parser, Debug)]
#[command(name = "fractalos-mcp", version, about)]
struct Args {
    /// Path to the compiled agentctl reference client.
    #[arg(long, default_value = "tools/agentctl/agentctl")]
    agentctl: PathBuf,

    /// CC-PD Unix socket path.
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[derive(Debug)]
struct AgentCtlRunner {
    binary: PathBuf,
    socket: PathBuf,
}

impl AgentCtlRunner {
    fn invoke(&self, command: &str, args: &[String]) -> std::result::Result<Value, String> {
        let mut child = Command::new(&self.binary);
        child
            .arg("--socket")
            .arg(&self.socket)
            .arg("--batch")
            .arg(command)
            .args(args);
        let output = child
            .output()
            .map_err(|err| format!("failed to start agentctl: {err}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "agentctl {command} failed with {}: {}",
                output.status,
                stderr.trim()
            ));
        }
        let stdout = String::from_utf8(output.stdout)
            .map_err(|_| "agentctl emitted non-UTF-8 output".to_string())?;
        serde_json::from_str(stdout.trim())
            .map_err(|err| format!("agentctl emitted invalid JSON: {err}"))
    }
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message.into()}
    })
}

fn tool_descriptor(name: &str, title: &str, description: &str, input: Value) -> Value {
    json!({
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": input,
        "annotations": {
            "readOnlyHint": true,
            "destructiveHint": false,
            "openWorldHint": false
        }
    })
}

fn native_task_descriptor() -> Value {
    json!({
        "name": "fractalos_run_native_task",
        "title": "Run an FractalOS-native coding task",
        "description": "Submit one bounded task to the capability-native FractalOS harness and return its final result and structured metrics.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string", "minLength": 1, "maxLength": 4076},
                "required_caps": {"type": "integer", "minimum": 0, "maximum": 31, "default": 13},
                "max_steps": {"type": "integer", "minimum": 1, "maximum": 128, "default": 16},
                "require_test": {"type": "boolean", "default": false}
            },
            "required": ["prompt"],
            "additionalProperties": false
        },
        "annotations": {
            "readOnlyHint": false,
            "destructiveHint": true,
            "openWorldHint": false
        }
    })
}

fn tools_list() -> Value {
    json!({"tools": [
        tool_descriptor(
            "fractalos_pool_status",
            "Get FractalOS agent pool status",
            "Read the live worker-pool capacity from a booted FractalOS CC-PD.",
            json!({"type": "object", "properties": {}, "additionalProperties": false})
        ),
        tool_descriptor(
            "fractalos_list_guests",
            "List FractalOS guests",
            "List guest VMs known to the live FractalOS control plane.",
            json!({"type": "object", "properties": {}, "additionalProperties": false})
        ),
        tool_descriptor(
            "fractalos_guest_status",
            "Get FractalOS guest status",
            "Read one guest VM's live state by guest handle.",
            json!({
                "type": "object",
                "properties": {
                    "guest_handle": {"type": "integer", "minimum": 0, "maximum": 4294967295_u64}
                },
                "required": ["guest_handle"],
                "additionalProperties": false
            })
        ),
        native_task_descriptor()
    ]})
}

fn pool_status(raw: Value) -> std::result::Result<Value, String> {
    let mr = raw
        .get("mr")
        .and_then(Value::as_array)
        .ok_or_else(|| "pool response is missing mr array".to_string())?;
    if mr.len() != 4 {
        return Err("pool response must contain four message registers".to_string());
    }
    let values: Vec<u64> = mr
        .iter()
        .map(|item| {
            item.as_u64()
                .ok_or_else(|| "pool register is not an integer".to_string())
        })
        .collect::<std::result::Result<_, _>>()?;
    let (status, total, busy, idle) = (values[0], values[1], values[2], values[3]);
    if status != 0 {
        return Err(format!("FractalOS returned pool status error {status}"));
    }
    let accounted = busy
        .checked_add(idle)
        .ok_or_else(|| "pool accounting overflow".to_string())?;
    let faulted = total
        .checked_sub(accounted)
        .ok_or_else(|| "pool accounting exceeds total capacity".to_string())?;
    Ok(json!({
        "ok": true,
        "total": total,
        "busy": busy,
        "idle": idle,
        "faulted": faulted
    }))
}

fn tool_success(structured: Value) -> Value {
    let text = serde_json::to_string(&structured).expect("serializable tool result");
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
        "isError": false
    })
}

fn tool_failure(message: impl Into<String>) -> Value {
    json!({
        "content": [{"type": "text", "text": message.into()}],
        "isError": true
    })
}

fn call_tool<F>(params: &Value, invoke: &F) -> Value
where
    F: Fn(&str, &[String]) -> std::result::Result<Value, String>,
{
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return tool_failure("tools/call is missing a tool name");
    };
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let result = match name {
        "fractalos_pool_status" => invoke("list-polecats", &[]).and_then(pool_status),
        "fractalos_list_guests" => invoke("list-guests", &[]),
        "fractalos_guest_status" => {
            let handle = arguments
                .get("guest_handle")
                .and_then(Value::as_u64)
                .filter(|value| *value <= u32::MAX as u64)
                .ok_or_else(|| "guest_handle must be a uint32".to_string());
            handle.and_then(|value| invoke("guest-status", &[value.to_string()]))
        }
        "fractalos_run_native_task" => {
            let prompt = arguments
                .get("prompt")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 4076)
                .ok_or_else(|| "prompt must be a 1..4076 byte string".to_string());
            let caps = arguments
                .get("required_caps")
                .and_then(Value::as_u64)
                .unwrap_or(13);
            let max_steps = arguments
                .get("max_steps")
                .and_then(Value::as_u64)
                .unwrap_or(16);
            let require_test = arguments
                .get("require_test")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if caps > 31 {
                Err("required_caps must be a known uint5 capability mask".to_string())
            } else if !(1..=128).contains(&max_steps) {
                Err("max_steps must be in 1..128".to_string())
            } else {
                prompt.and_then(|prompt| {
                    let mut args = vec![
                        "--caps".to_string(),
                        caps.to_string(),
                        "--max-steps".to_string(),
                        max_steps.to_string(),
                    ];
                    if require_test {
                        args.push("--require-test".to_string());
                    }
                    args.push(prompt.to_string());
                    invoke("agent-run", &args)
                })
            }
        }
        _ => Err(format!("unknown FractalOS tool: {name}")),
    };
    match result {
        Ok(value) => tool_success(value),
        Err(message) => tool_failure(message),
    }
}

fn handle_request<F>(request: &Value, invoke: &F) -> Option<Value>
where
    F: Fn(&str, &[String]) -> std::result::Result<Value, String>,
{
    let method = request.get("method")?.as_str()?;
    let id = request.get("id")?.clone();
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    Some(match method {
        "initialize" => {
            let protocol = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_PROTOCOL_VERSION);
            rpc_result(
                id,
                json!({
                    "protocolVersion": protocol,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    "instructions": "Use these read-only tools for live FractalOS state. Never infer capacity or guest state from source files when a live tool result is available."
                }),
            )
        }
        "tools/list" => rpc_result(id, tools_list()),
        "tools/call" => rpc_result(id, call_tool(&params, invoke)),
        "ping" => rpc_result(id, json!({})),
        _ => rpc_error(id, -32601, format!("method not found: {method}")),
    })
}

fn main() -> Result<()> {
    let args = Args::parse();
    let socket = args
        .socket
        .or_else(|| std::env::var_os("CC_PD_SOCK").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("build/cc_pd.sock"));
    let runner = AgentCtlRunner {
        binary: args.agentctl,
        socket,
    };
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.context("failed to read MCP request")?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = serde_json::from_str(&line).context("invalid MCP JSON-RPC request")?;
        if let Some(response) = handle_request(&request, &|command, arguments| {
            runner.invoke(command, arguments)
        }) {
            serde_json::to_writer(&mut stdout, &response)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(id: u64, method: &str, params: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
    }

    #[test]
    fn initialize_advertises_read_only_tools() {
        let response = handle_request(
            &request(1, "initialize", json!({"protocolVersion": "2025-06-18"})),
            &|_, _| unreachable!(),
        )
        .unwrap();
        assert_eq!(response["result"]["serverInfo"]["name"], SERVER_NAME);
        assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
    }

    #[test]
    fn lists_only_named_read_only_tools() {
        let response =
            handle_request(&request(2, "tools/list", json!({})), &|_, _| unreachable!()).unwrap();
        let tools = response["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 4);
        assert!(tools[..3]
            .iter()
            .all(|tool| tool["annotations"]["readOnlyHint"] == true));
        assert!(tools
            .iter()
            .all(|tool| !tool["name"].as_str().unwrap().contains("raw")));
        assert_eq!(tools[3]["name"], "fractalos_run_native_task");
        assert_eq!(tools[3]["annotations"]["readOnlyHint"], false);
        assert_eq!(tools[3]["annotations"]["destructiveHint"], true);
    }

    #[test]
    fn pool_tool_names_registers_and_derives_faulted_count() {
        let response = handle_request(
            &request(
                3,
                "tools/call",
                json!({"name": "fractalos_pool_status", "arguments": {}}),
            ),
            &|command, args| {
                assert_eq!(command, "list-polecats");
                assert!(args.is_empty());
                Ok(json!({"mr": [0, 8, 1, 6]}))
            },
        )
        .unwrap();
        assert_eq!(response["result"]["structuredContent"]["total"], 8);
        assert_eq!(response["result"]["structuredContent"]["faulted"], 1);
        assert_eq!(response["result"]["isError"], false);
    }

    #[test]
    fn malformed_pool_accounting_is_a_tool_error() {
        let response = handle_request(
            &request(
                4,
                "tools/call",
                json!({"name": "fractalos_pool_status", "arguments": {}}),
            ),
            &|_, _| Ok(json!({"mr": [0, 8, 7, 2]})),
        )
        .unwrap();
        assert_eq!(response["result"]["isError"], true);
    }

    #[test]
    fn native_task_tool_uses_only_the_named_agentctl_command() {
        let response = handle_request(
            &request(
                5,
                "tools/call",
                json!({"name": "fractalos_run_native_task", "arguments": {
                    "prompt": "repair the fixture", "required_caps": 13,
                    "max_steps": 20, "require_test": true
                }}),
            ),
            &|command, args| {
                assert_eq!(command, "agent-run");
                assert_eq!(
                    args,
                    &[
                        "--caps",
                        "13",
                        "--max-steps",
                        "20",
                        "--require-test",
                        "repair the fixture"
                    ]
                );
                Ok(json!({"ok": 0, "task_id": 9, "result": "done"}))
            },
        )
        .unwrap();
        assert_eq!(response["result"]["structuredContent"]["task_id"], 9);
        assert_eq!(response["result"]["isError"], false);
    }

    #[test]
    fn guest_handle_is_validated_before_agentctl() {
        let response = handle_request(
            &request(
                5,
                "tools/call",
                json!({"name": "fractalos_guest_status", "arguments": {"guest_handle": -1}}),
            ),
            &|_, _| unreachable!(),
        )
        .unwrap();
        assert_eq!(response["result"]["isError"], true);
    }
}
