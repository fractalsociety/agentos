# ModelSvc — Model Inference Proxy Service Contract

## Overview

ModelSvc is the capability-gated inference proxy for FractalOS.  All LLM
inference requests from agents flow through this service, which:

- Maintains a registry of up to 32 named model endpoints
- Validates that callers hold `CAPSTORE_CAP_MODEL` before forwarding requests
- Routes HTTP POST requests through NetServer (`OP_NET_HTTP_POST = 0x500`)
  so agents never hold network capabilities directly
- Collects per-model usage statistics (requests, tokens in/out, latency)
- Supports OpenAI-compatible chat completions endpoints by default
- Streams bounded response chunks, supports cancellation, and caches exact
  results on the native fast path

Default models registered at boot:
- `default` — NVIDIA inference API (`NVIDIA_API_KEY`)
- `code-gen` — NVIDIA inference API, higher token limit
- `fast` — OpenAI API (`OPENAI_API_KEY`), smaller context window
- `fractalos-echo` — dependency-free native diagnostic backend

The implementation is intentionally vibe-swappable: an agent can register
a replacement that performs local inference, quantization, model routing,
or ensemble voting.

## Protection Domain

ModelSvc is a dedicated native protection domain (`model_svc.elf`). The root
task maps a 4 MiB large-page arena at `MODELSVC_SHMEM_VADDR` into ModelSvc and
NetServer, while agents receive only a badged ModelSvc endpoint capability.
HTTP transport is delegated to NetServer via `OP_NET_HTTP_POST`; its bridge
connection is persistent and reused across inference requests.

The Rust userspace model proxy is at `userspace/servers/model-proxy/`.

## IPC Endpoint

Controller, InitAgent, and authorized agent PDs call the dedicated ModelSvc
endpoint. Caller identity comes from the root-minted badge, never shared data.
Compact 48-byte wire records carry validated offsets into the shared arena.

## Operations

| Opcode | Value | Description |
|--------|-------|-------------|
| `MODELSVC_OP_QUERY`      | 0x500 | Submit inference request |
| `MODELSVC_OP_REGISTER`   | 0x501 | Register model endpoint |
| `MODELSVC_OP_UNREGISTER` | 0x502 | Remove model endpoint |
| `MODELSVC_OP_LIST`       | 0x503 | Enumerate registered models |
| `MODELSVC_OP_STATS`      | 0x504 | Per-model usage statistics |
| `MODELSVC_OP_HEALTH`     | 0x505 | Liveness probe |
| `MODELSVC_OP_STREAM_BEGIN` | 0x506 | Begin streaming inference |
| `MODELSVC_OP_STREAM_POLL` | 0x507 | Copy the next bounded chunk |
| `MODELSVC_OP_CANCEL` | 0x508 | Cancel an owned request |

## Error Codes

| Code | Value | Meaning |
|------|-------|---------|
| `MODELSVC_ERR_OK`           | 0  | Success |
| `MODELSVC_ERR_INVALID_ARG`  | 1  | Null prompt or bad opcode |
| `MODELSVC_ERR_NOT_FOUND`    | 2  | model_id not registered |
| `MODELSVC_ERR_DENIED`       | 3  | Caller lacks CAPSTORE_CAP_MODEL |
| `MODELSVC_ERR_NOMEM`        | 4  | Model table full (32 max) |
| `MODELSVC_ERR_NET`          | 5  | HTTP request to endpoint failed |
| `MODELSVC_ERR_RATE_LIMIT`   | 6  | HTTP 429 from upstream |
| `MODELSVC_ERR_CONTEXT_FULL` | 7  | Prompt exceeds context window |
| `MODELSVC_ERR_STUB`         | 8  | Feature not yet implemented |
| `MODELSVC_ERR_INTERNAL`     | 99 | Unexpected server error |

## Temperature Encoding

The `temperature_milli` field encodes a floating-point temperature as an
integer: `temperature_milli = (uint32_t)(temperature * 1000)`.  For example:
- 0.7 → 700
- 1.0 → 1000
- 0.0 → 0 (greedy)

## Security Notes

API-key names are registry metadata; secret values remain in the trusted host
bridge and are never put in message registers or the shared arena. Registry
mutation is limited to Controller/InitAgent badges. Stream ownership is also
checked against the caller badge, and every offset/length pair is validated
without overflow before dereference.

## Source Files

- `services/modelsvc/model_svc.c` — native C protection-domain implementation
- `userspace/servers/model-proxy/src/lib.rs` — Rust userspace proxy
- `kernel/fractalos-root-task/include/net_server.h` — OP_NET_HTTP_POST
