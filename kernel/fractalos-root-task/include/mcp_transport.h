/* Shared external MCP transport owned by ToolSvc, never by a worker. */
#pragma once

#include <stdint.h>

#define MCP_TRANSPORT_OP_REQUEST          0x2d01u
#define MCP_TRANSPORT_INTERFACE_VERSION   1u
#define MCP_TRANSPORT_WIRE_MAGIC          0x504d4741u /* "AGMP" */
#define MCP_TRANSPORT_WIRE_VERSION        1u

#define MCP_TRANSPORT_REQUEST_LIST        1u
#define MCP_TRANSPORT_REQUEST_INVOKE      2u

typedef struct __attribute__((packed)) {
    uint32_t operation;
    uint32_t name_offset;
    uint32_t name_len;
    uint32_t input_offset;
    uint32_t input_len;
    uint32_t output_offset;
    uint32_t output_capacity;
    uint32_t request_tag;
} mcp_transport_wire_t;

typedef struct __attribute__((packed)) {
    uint32_t status;
    uint32_t output_len;
    uint32_t request_tag;
} mcp_transport_reply_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t version;
    uint32_t operation;
    uint32_t name_len;
    uint32_t input_len;
    uint32_t output_capacity;
    uint32_t request_tag;
} mcp_transport_request_header_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t status;
    uint32_t output_len;
    uint32_t request_tag;
} mcp_transport_response_header_t;

_Static_assert(sizeof(mcp_transport_wire_t) == 32u,
               "MCP transport request must fit one seL4 payload");
_Static_assert(sizeof(mcp_transport_reply_t) == 12u,
               "MCP transport reply ABI drift");
_Static_assert(sizeof(mcp_transport_request_header_t) == 28u,
               "MCP host request header ABI drift");
_Static_assert(sizeof(mcp_transport_response_header_t) == 16u,
               "MCP host response header ABI drift");
