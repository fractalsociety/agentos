/*
 * Fractal Companion Gateway boundary (fos-gz0.14.17).
 *
 * Host-side projection dispatcher in front of Local Gateway sessions.
 * No HTTP/TLS/UI. Sibling companion consumes the typed client separately.
 */

#pragma once

#include "local_gateway.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COMPANION_GATEWAY_MAX_PROGRESS     16u
#define COMPANION_GATEWAY_MAX_WORKER_MEM   16u
#define COMPANION_GATEWAY_MAX_HEALTH_SIG   8u
#define COMPANION_GATEWAY_LABEL_BYTES      64u

enum companion_gateway_error {
    COMPANION_GATEWAY_OK                  = 0u,
    COMPANION_GATEWAY_ERR_INVALID         = 1u,
    COMPANION_GATEWAY_ERR_DENIED          = 2u,
    COMPANION_GATEWAY_ERR_NOT_FOUND       = 3u,
    COMPANION_GATEWAY_ERR_WRONG_AUDIENCE  = 4u,
    COMPANION_GATEWAY_ERR_CREDENTIAL      = 5u,
    COMPANION_GATEWAY_ERR_STALE_ROOT      = 6u,
    COMPANION_GATEWAY_ERR_NO_GRANT        = 7u,
    COMPANION_GATEWAY_ERR_REVOKED         = 8u,
    COMPANION_GATEWAY_ERR_EXPIRED         = 9u,
    COMPANION_GATEWAY_ERR_STALE_EPOCH     = 10u,
    COMPANION_GATEWAY_ERR_AMBIENT_DENIED  = 11u,
};

struct companion_gateway_progress_item {
    local_gateway_object_id_t project_id;
    uint32_t proof_level; /* 1=L1 .. never inferred upward */
    uint32_t state;       /* 1 open 2 blocked 3 closed */
    uint32_t label_len;
    uint8_t label[COMPANION_GATEWAY_LABEL_BYTES];
};

struct companion_gateway_worker_memory {
    local_gateway_object_id_t worker_id;
    uint64_t active_private_bytes;
    uint64_t dormant_private_bytes;
};

struct companion_gateway_health_signal {
    uint32_t family; /* opaque family id */
    uint32_t confidence_bp; /* 0..10000 */
    uint8_t freshness; /* 1 fresh 2 stale 3 offline */
    uint8_t reserved[3];
};

struct companion_gateway_health_summary {
    local_gateway_object_id_t provenance_root;
    struct local_gateway_event_range event_range;
    uint64_t authority_epoch;
    uint32_t signal_count;
    uint32_t revoked; /* 1 if consent revoked */
    struct companion_gateway_health_signal signals[COMPANION_GATEWAY_MAX_HEALTH_SIG];
};

void companion_gateway_reset(void);

/* Service fence — delegates to local_gateway with same wire structs. */
uint32_t companion_gateway_publish_service(
    const struct local_gateway_req_publish_service *req,
    struct local_gateway_reply_publish_service *reply);

uint32_t companion_gateway_revoke_service(
    const struct local_gateway_req_revoke_service *req,
    struct local_gateway_reply_revoke_service *reply);

uint32_t companion_gateway_open_session(
    const struct local_gateway_req_open_session *req,
    const local_gateway_audience_t *presented_audience,
    struct local_gateway_reply_open_session *reply);

uint32_t companion_gateway_get_daily(
    const struct local_gateway_req_get_daily *req,
    const local_gateway_audience_t *presented_audience,
    struct local_gateway_daily_item *out_items, uint32_t out_cap,
    struct local_gateway_reply_get_daily *reply);

uint32_t companion_gateway_get_health(
    const local_gateway_session_id_t *session_id,
    const local_gateway_audience_t *presented_audience,
    uint64_t authority_epoch, uint64_t now_unix_ms,
    struct companion_gateway_health_summary *out);

uint32_t companion_gateway_list_progress(
    const local_gateway_session_id_t *session_id,
    const local_gateway_audience_t *presented_audience,
    uint64_t authority_epoch, uint64_t now_unix_ms,
    struct companion_gateway_progress_item *out_items, uint32_t out_cap,
    uint32_t *out_count, local_gateway_root_id_t *out_root,
    struct local_gateway_event_range *out_range);

uint32_t companion_gateway_list_worker_memory(
    const local_gateway_session_id_t *session_id,
    const local_gateway_audience_t *presented_audience,
    uint64_t authority_epoch, uint64_t now_unix_ms,
    struct companion_gateway_worker_memory *out_items, uint32_t out_cap,
    uint32_t *out_count, local_gateway_root_id_t *out_root,
    struct local_gateway_event_range *out_range);

uint32_t companion_gateway_submit_intent(
    const struct local_gateway_req_submit_intent *req,
    const local_gateway_audience_t *presented_audience,
    struct local_gateway_reply_submit_intent *reply);

#ifdef __cplusplus
}
#endif
