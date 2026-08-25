/*
 * Host continual-harness E1 runtime (fos-gz0.14.8).
 */

#pragma once

#include "contracts/continual_harness_contract.h"

#ifdef __cplusplus
extern "C" {
#endif

void continual_harness_reset(void);

uint32_t continual_harness_snapshot(const struct continual_req_snapshot *req,
                                    struct continual_reply_snapshot *reply);
uint32_t continual_harness_evaluate(const struct continual_req_evaluate *req,
                                    struct continual_reply_evaluate *reply);
uint32_t continual_harness_promote(const struct continual_req_promote *req,
                                   struct continual_reply_promote *reply);
uint32_t continual_harness_rollback(const struct continual_req_rollback *req,
                                    struct continual_reply_rollback *reply);
uint32_t continual_harness_status(const struct continual_req_status *req,
                                  struct continual_reply_status *reply);
uint32_t continual_harness_query_held_out(
    const struct continual_req_query_held_out *req,
    struct continual_reply_query_held_out *reply);

#ifdef __cplusplus
}
#endif
