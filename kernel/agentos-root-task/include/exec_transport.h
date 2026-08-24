/* Capability-scoped host execution transport shared by ExecSvc clients. */
#pragma once

#include <stdint.h>

#define EXEC_TRANSPORT_OP_RUN             0x2c01u
#define EXEC_TRANSPORT_INTERFACE_VERSION  1u
#define EXEC_TRANSPORT_WIRE_MAGIC         0x45584741u /* "AGXE" little-endian */
#define EXEC_TRANSPORT_WIRE_VERSION       1u

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t version;
    uint32_t profile_id;
    uint32_t source_len;
    uint32_t output_capacity;
    uint32_t request_tag;
} exec_transport_request_header_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t status;
    int32_t exit_code;
    uint32_t output_len;
    uint32_t request_tag;
} exec_transport_response_header_t;

_Static_assert(sizeof(exec_transport_request_header_t) == 24u,
               "exec transport request header ABI drift");
_Static_assert(sizeof(exec_transport_response_header_t) == 20u,
               "exec transport response header ABI drift");
