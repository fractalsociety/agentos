# ToolSvc — Tool Registry and Dispatch Service Contract

## Overview

ToolSvc is the central registry and dispatcher for all callable tools in
FractalOS.  It provides:

- Built-in and administrator-configured external tool registration
- MCP-compatible tool discovery (JSON format matching Model Context Protocol)
- Capability-gated invocation: callers must hold `CAPSTORE_CAP_TOOL`
- Routing of external invocations through a private MCP transport capability
- Per-tool usage statistics (call count, latency)

External tools are namespaced as `mcp.*`. Holding a generic ToolCap does not
authorize them: the immutable endpoint badge must contain
`TOOLSVC_RIGHT_MCP_EXTERNAL`. `mcp.tools.list` discovers the bounded catalog
registered by the administrator-selected provider.

## Protection Domain

ToolSvc is a singleton seL4 protection domain. Each worker maps only its own
48 KiB request window. The external MCP transport maps only ToolSvc's private
arena and owns a dedicated VirtIO console; neither mapping nor endpoint is
installed in a worker CSpace.

The Rust userspace server in `userspace/servers/tool-registry/src/lib.rs`
mirrors this contract for the higher-level agent runtime.

## IPC Endpoint

Agents reach ToolSvc through badged, call-only endpoint capabilities. External
registration is administrator-owned and boot-time; agent-supplied
`REGISTER`/`UNREGISTER` requests remain denied.

## Operations

| Opcode | Value | Description |
|--------|-------|-------------|
| `TOOLSVC_OP_REGISTER`   | 0x400 | Register a tool with name/schema/provider |
| `TOOLSVC_OP_UNREGISTER` | 0x401 | Remove a tool (provider only) |
| `TOOLSVC_OP_INVOKE`     | 0x402 | Invoke a tool by name |
| `TOOLSVC_OP_LIST`       | 0x403 | List all tools in MCP JSON format |
| `TOOLSVC_OP_INFO`       | 0x404 | Fetch metadata for one tool |
| `TOOLSVC_OP_STATS`      | 0x405 | Per-tool usage statistics |
| `TOOLSVC_OP_HEALTH`     | 0x406 | Liveness probe |

## Error Codes

| Code | Value | Meaning |
|------|-------|---------|
| `TOOLSVC_ERR_OK`           | 0  | Success |
| `TOOLSVC_ERR_INVALID_ARG`  | 1  | Bad opcode or name too long |
| `TOOLSVC_ERR_NOT_FOUND`    | 2  | Tool not registered |
| `TOOLSVC_ERR_EXISTS`       | 3  | Tool already registered by provider |
| `TOOLSVC_ERR_DENIED`       | 4  | Caller lacks CAPSTORE_CAP_TOOL |
| `TOOLSVC_ERR_NOMEM`        | 5  | Tool table full (512 max) |
| `TOOLSVC_ERR_PROVIDER_DOWN`| 6  | Provider agent not responding |
| `TOOLSVC_ERR_INTERNAL`     | 99 | Unexpected server error |

## MCP Compatibility

The `TOOLSVC_OP_LIST` response format is JSON-compatible with MCP tool
listings:

```json
{
  "tools": [
    {
      "name": "tool-name",
      "description": "...",
      "inputSchema": { ... },
      "calls": 42
    }
  ]
}
```

Agent LLMs can call `TOOLSVC_OP_LIST` to discover available tools and
`TOOLSVC_OP_INVOKE` to execute them. A caller with external MCP authority first
invokes `mcp.tools.list`, then invokes one of the returned `mcp.*` names.

The host adapter uses newline-delimited JSON-RPC over stdio. It implements the
MCP 2026-07-28 `server/discover` probe and per-request metadata, with a tested
fallback to the legacy initialize/initialized lifecycle. Server commands are
exact JSON argv arrays and credentials are supplied through an explicit JSON
environment map; no shell is involved and ambient host credentials are not
inherited.

## Source Files

- `services/toolsvc/tool_svc.c` — target implementation
- `kernel/fractalos-root-task/src/mcp_transport.c` — isolated native transport
- `tools/mcp_transport_proxy.py` — shared MCP stdio adapter
- `userspace/servers/tool-registry/src/lib.rs` — Rust userspace server
