/*
 * Host-side Fractal Local Gateway fence (fos-gz0.14.10.5).
 *
 * L2 freestanding runtime: expiring service capabilities, pinned-root sessions,
 * daily workspace reads, narrow task intents, and revoke/derive fail-closed.
 * No HTTP/UI.
 */

#pragma once

#include "contracts/local_gateway_contract.h"

#ifdef __cplusplus
extern "C" {
#endif

void local_gateway_reset(void);

uint32_t local_gateway_publish_service(
    const struct local_gateway_req_publish_service *req,
    struct local_gateway_reply_publish_service *reply);

uint32_t local_gateway_revoke_service(
    const struct local_gateway_req_revoke_service *req,
    struct local_gateway_reply_revoke_service *reply);

uint32_t local_gateway_open_session(
    const struct local_gateway_req_open_session *req,
    struct local_gateway_reply_open_session *reply);

uint32_t local_gateway_get_daily(
    const struct local_gateway_req_get_daily *req,
    struct local_gateway_daily_item *out_items, uint32_t out_cap,
    struct local_gateway_reply_get_daily *reply);

uint32_t local_gateway_submit_intent(
    const struct local_gateway_req_submit_intent *req,
    struct local_gateway_reply_submit_intent *reply);

uint32_t local_gateway_status(const struct local_gateway_req_status *req,
                              struct local_gateway_reply_status *reply);

uint32_t local_gateway_service_count(void);
uint32_t local_gateway_session_count(void);

#ifdef __cplusplus
}
#endif
