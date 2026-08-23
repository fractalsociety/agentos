/*
 * agentOS ModelSvc IPC Contract — interface.h
 *
 * Formal seL4 IPC API contract for the ModelSvc model inference proxy.
 * ModelSvc abstracts all LLM inference behind a capability-gated interface.
 * The reference implementation proxies to HTTP APIs (OpenAI-compatible);
 * agents may vibe-code replacements for local inference, quantization,
 * model routing, ensemble voting, or any other strategy.
 *
 * HTTP transport is performed via the NetServer using the OP_NET_HTTP_POST
 * opcode; ModelSvc holds the network capability and isolates inference
 * traffic from agent address spaces.
 *
 * IPC mechanism: seL4_Call / seL4_Reply.
 * MR0 carries the opcode on request; MR0 carries the status on reply.
 * Prompt text and responses pass through a shared memory region.
 *
 * Copyright (c) 2026 The agentOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

/* ── Version ─────────────────────────────────────────────────────────────── */

#define MODELSVC_INTERFACE_VERSION  1

/* ── Limits ──────────────────────────────────────────────────────────────── */

#define MODELSVC_MAX_MODELS         32
#define MODELSVC_MODEL_ID_MAX       128
#define MODELSVC_ENDPOINT_MAX       512
#define MODELSVC_AGENT_ID_BYTES     32
#define MODELSVC_SHMEM_SIZE          (4u * 1024u * 1024u)
#define MODELSVC_SHMEM_VADDR         0x60000000u
#define MODELSVC_MAX_INFLIGHT        16u
#define MODELSVC_CACHE_ENTRIES       64u
#define MODELSVC_STREAM_CHUNK_MAX    (64u * 1024u)

/* ── Model flags ─────────────────────────────────────────────────────────── */

#define MODELSVC_FLAG_DEFAULT       (1u << 0)  /* selected when model_id is empty */
#define MODELSVC_FLAG_STREAMING     (1u << 1)  /* supports bounded response chunks */
#define MODELSVC_FLAG_LOCAL         (1u << 2)  /* runs in-process (no HTTP) */

/* ── Opcodes ─────────────────────────────────────────────────────────────── */

#define MODELSVC_OP_QUERY           0x500u  /* inference request */
#define MODELSVC_OP_REGISTER        0x501u  /* register a model endpoint */
#define MODELSVC_OP_UNREGISTER      0x502u  /* remove a model endpoint */
#define MODELSVC_OP_LIST            0x503u  /* enumerate registered models */
#define MODELSVC_OP_STATS           0x504u  /* per-model usage statistics */
#define MODELSVC_OP_HEALTH          0x505u  /* liveness probe */
#define MODELSVC_OP_STREAM_BEGIN    0x506u  /* enqueue streaming inference */
#define MODELSVC_OP_STREAM_POLL     0x507u  /* retrieve next response chunk */
#define MODELSVC_OP_CANCEL          0x508u  /* cancel queued/in-flight request */

/* ── Error codes ─────────────────────────────────────────────────────────── */

#define MODELSVC_ERR_OK             0u
#define MODELSVC_ERR_INVALID_ARG    1u   /* bad opcode, null prompt, etc. */
#define MODELSVC_ERR_NOT_FOUND      2u   /* model_id not registered */
#define MODELSVC_ERR_DENIED         3u   /* caller lacks CAPSTORE_CAP_MODEL */
#define MODELSVC_ERR_NOMEM          4u   /* model table full */
#define MODELSVC_ERR_NET            5u   /* HTTP request to endpoint failed */
#define MODELSVC_ERR_RATE_LIMIT     6u   /* upstream rate limit (HTTP 429) */
#define MODELSVC_ERR_CONTEXT_FULL   7u   /* prompt exceeds model context window */
#define MODELSVC_ERR_STUB           8u   /* feature not yet implemented */
#define MODELSVC_ERR_INTERNAL       99u

/* ── Compact seL4 wire records ──────────────────────────────────────────── */

/*
 * The descriptive request objects below live in shared memory; they are too
 * large for sel4_msg_t.data[48].  These compact records are the authoritative
 * on-wire payloads.  All offsets are relative to MODELSVC_SHMEM_VADDR and are
 * validated with overflow-safe bounds checks by the service.
 *
 * Caller identity is derived from the minted endpoint badge, never trusted
 * from shared memory.  model_id_offset/model_id_len select the requested model
 * (length zero selects the registered default).
 */
typedef struct modelsvc_query_wire {
    uint32_t max_tokens;
    uint32_t temperature_milli;
    uint32_t system_prompt_offset;
    uint32_t system_prompt_len;
    uint32_t user_prompt_offset;
    uint32_t user_prompt_len;
    uint32_t response_offset;
    uint32_t response_buf_len;
    uint32_t model_id_offset;
    uint32_t model_id_len;
    uint32_t flags;
    uint32_t request_tag;
} __attribute__((packed)) modelsvc_query_wire_t;

_Static_assert(sizeof(modelsvc_query_wire_t) == 48u,
               "modelsvc_query_wire_t must fit one seL4 payload");

/* REGISTER points at one modelsvc_register_req_t stored in shared memory. */
typedef struct modelsvc_shmem_object_wire {
    uint32_t offset;
    uint32_t length;
} __attribute__((packed)) modelsvc_shmem_object_wire_t;

/* LIST writes modelsvc_model_info_t entries to the requested shared buffer. */
typedef struct modelsvc_list_wire {
    uint32_t buf_offset;
    uint32_t max_count;
} __attribute__((packed)) modelsvc_list_wire_t;

/* STREAM_BEGIN uses modelsvc_query_wire_t and returns this reply payload. */
typedef struct modelsvc_stream_begin_rep {
    uint32_t status;
    uint32_t request_id;
    uint32_t state;
    uint32_t cache_hit;
} __attribute__((packed)) modelsvc_stream_begin_rep_t;

typedef struct modelsvc_stream_poll_wire {
    uint32_t request_id;
    uint32_t max_bytes;
} __attribute__((packed)) modelsvc_stream_poll_wire_t;

typedef struct modelsvc_stream_poll_rep {
    uint32_t status;
    uint32_t state;
    uint32_t chunk_len;
    uint32_t total_response_len;
    uint32_t tokens_in;
    uint32_t tokens_out;
} __attribute__((packed)) modelsvc_stream_poll_rep_t;

typedef struct modelsvc_cancel_wire {
    uint32_t request_id;
} __attribute__((packed)) modelsvc_cancel_wire_t;

#define MODELSVC_STREAM_QUEUED      1u
#define MODELSVC_STREAM_RUNNING     2u
#define MODELSVC_STREAM_READY       3u
#define MODELSVC_STREAM_COMPLETE    4u
#define MODELSVC_STREAM_CANCELLED   5u
#define MODELSVC_STREAM_FAILED      6u

/* ── Model info structure (returned by MODELSVC_OP_LIST / STATS) ─────────── */

typedef struct modelsvc_model_info {
    char     model_id[MODELSVC_MODEL_ID_MAX];
    char     endpoint_url[MODELSVC_ENDPOINT_MAX];
    uint32_t context_window;            /* maximum context tokens */
    uint32_t max_tokens;                /* maximum tokens per response */
    uint32_t flags;                     /* MODELSVC_FLAG_* */
    uint64_t total_requests;
    uint64_t total_tokens_in;
    uint64_t total_tokens_out;
    uint64_t total_latency_us;
} __attribute__((packed)) modelsvc_model_info_t;

/* ── Request / reply structs ─────────────────────────────────────────────── */

/*
 * MODELSVC_OP_QUERY
 *
 * Submit an inference request.  Caller must hold CAPSTORE_CAP_MODEL.
 *
 * system_prompt and user_prompt are NUL-terminated strings read from the
 * caller's shmem MR at the given offsets.  Pass 0 for system_prompt_offset
 * if no system prompt.
 *
 * The response text is written NUL-terminated into the caller's shmem MR
 * at response_shmem_offset.
 *
 * temperature: encoded as uint32_t = (float_value * 1000); e.g. 700 = 0.700
 * max_tokens:  0 means use model default.
 *
 * Request:  opcode, max_tokens, temperature_milli, system_prompt_offset,
 *           system_prompt_len, user_prompt_offset, user_prompt_len,
 *           response_shmem_offset, response_buf_len,
 *           caller (32 bytes), model_id
 * Reply:    status, tokens_in, tokens_out, latency_us
 */
typedef struct modelsvc_query_req {
    uint32_t opcode;                            /* MODELSVC_OP_QUERY */
    uint32_t max_tokens;
    uint32_t temperature_milli;                 /* temperature * 1000 */
    uint32_t system_prompt_shmem_offset;        /* 0 = no system prompt */
    uint32_t system_prompt_len;
    uint32_t user_prompt_shmem_offset;
    uint32_t user_prompt_len;
    uint32_t response_shmem_offset;
    uint32_t response_buf_len;
    uint32_t _pad;
    uint8_t  caller[MODELSVC_AGENT_ID_BYTES];
    char     model_id[MODELSVC_MODEL_ID_MAX];   /* empty = use default */
} __attribute__((packed)) modelsvc_query_req_t;

typedef struct modelsvc_query_rep {
    uint32_t status;                            /* MODELSVC_ERR_* */
    uint32_t response_len;                      /* bytes written */
    uint32_t tokens_in;
    uint32_t tokens_out;
    uint64_t latency_us;
} __attribute__((packed)) modelsvc_query_rep_t;

/*
 * MODELSVC_OP_REGISTER
 *
 * Register a model endpoint.  Only the init task or controller may call this.
 * The api_key_env field is the name of the environment variable that holds
 * the API key (e.g. "NVIDIA_API_KEY"); the key itself never crosses the IPC.
 *
 * Request:  opcode, flags, context_window, max_tokens,
 *           model_id, endpoint_url, api_key_env
 * Reply:    status
 */
typedef struct modelsvc_register_req {
    uint32_t opcode;                            /* MODELSVC_OP_REGISTER */
    uint32_t flags;                             /* MODELSVC_FLAG_* */
    uint32_t context_window;
    uint32_t max_tokens;
    char     model_id[MODELSVC_MODEL_ID_MAX];
    char     endpoint_url[MODELSVC_ENDPOINT_MAX];
    char     api_key_env[64];
} __attribute__((packed)) modelsvc_register_req_t;

typedef struct modelsvc_register_rep {
    uint32_t status;
} __attribute__((packed)) modelsvc_register_rep_t;

/*
 * MODELSVC_OP_UNREGISTER
 *
 * Remove a model endpoint (init task or controller only).
 *
 * Request:  opcode, model_id
 * Reply:    status
 */
typedef struct modelsvc_unregister_req {
    uint32_t opcode;                            /* MODELSVC_OP_UNREGISTER */
    uint32_t _pad;
    char     model_id[MODELSVC_MODEL_ID_MAX];
} __attribute__((packed)) modelsvc_unregister_req_t;

typedef struct modelsvc_unregister_rep {
    uint32_t status;
} __attribute__((packed)) modelsvc_unregister_rep_t;

/*
 * MODELSVC_OP_LIST
 *
 * Enumerate registered models.  The array of modelsvc_model_info_t structs
 * is written into the caller's shmem MR at buf_shmem_offset.
 *
 * Request:  opcode, buf_shmem_offset, max_count
 * Reply:    status, model_count, bytes_written
 */
typedef struct modelsvc_list_req {
    uint32_t opcode;                            /* MODELSVC_OP_LIST */
    uint32_t buf_shmem_offset;
    uint32_t max_count;
} __attribute__((packed)) modelsvc_list_req_t;

typedef struct modelsvc_list_rep {
    uint32_t status;
    uint32_t model_count;
    uint32_t bytes_written;
} __attribute__((packed)) modelsvc_list_rep_t;

/*
 * MODELSVC_OP_STATS
 *
 * Retrieve usage statistics for a single model.
 *
 * Request:  opcode, model_id
 * Reply:    status, total_requests, total_tokens_in, total_tokens_out,
 *           avg_latency_us
 */
typedef struct modelsvc_stats_req {
    uint32_t opcode;                            /* MODELSVC_OP_STATS */
    uint32_t _pad;
    char     model_id[MODELSVC_MODEL_ID_MAX];
} __attribute__((packed)) modelsvc_stats_req_t;

typedef struct modelsvc_stats_rep {
    uint32_t status;
    uint32_t _pad;
    uint64_t total_requests;
    uint64_t total_tokens_in;
    uint64_t total_tokens_out;
    uint64_t avg_latency_us;
} __attribute__((packed)) modelsvc_stats_rep_t;

/*
 * MODELSVC_OP_HEALTH
 *
 * Liveness probe.
 *
 * Request:  opcode
 * Reply:    status, model_count, version
 */
typedef struct modelsvc_health_req {
    uint32_t opcode;                            /* MODELSVC_OP_HEALTH */
} __attribute__((packed)) modelsvc_health_req_t;

typedef struct modelsvc_health_rep {
    uint32_t status;
    uint32_t model_count;
    uint32_t version;                           /* MODELSVC_INTERFACE_VERSION */
} __attribute__((packed)) modelsvc_health_rep_t;
