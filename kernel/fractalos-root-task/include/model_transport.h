/*
 * model_transport.h — capability-scoped native model transport contract
 *
 * NetServer calls this service through a real seL4 endpoint capability.  The
 * service owns a dedicated VirtIO console connected to a host-side model
 * bridge; agents and ModelSvc never receive that device capability.
 */
#pragma once

#include <stdint.h>

#define MODEL_TRANSPORT_OP_POST          0x2b01u
#define MODEL_TRANSPORT_INTERFACE_VERSION 1u

#define MODEL_TRANSPORT_WIRE_MAGIC       0x4d544741u /* "AGTM" little-endian */
#define MODEL_TRANSPORT_WIRE_VERSION     1u
#define MODEL_TRANSPORT_MAX_BODY         (1024u * 1024u)

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t version;
    uint32_t body_len;
    uint32_t response_cap;
} model_transport_request_header_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t http_status;
    uint32_t body_len;
    uint32_t transport_status;
} model_transport_response_header_t;

_Static_assert(sizeof(model_transport_request_header_t) == 16u,
               "model transport request header ABI drift");
_Static_assert(sizeof(model_transport_response_header_t) == 16u,
               "model transport response header ABI drift");
