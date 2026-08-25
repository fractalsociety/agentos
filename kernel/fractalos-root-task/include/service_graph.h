/*
 * Host-side immutable capability service graph (fos-gz0.14.9).
 *
 * Freestanding C runtime for host contract tests. Consumers bind by
 * interface hash/version only; provider names never appear in the bind path.
 * Swaps mint a new graph ObjectID and preserve prior-root lineage.
 */

#pragma once

#include "contracts/service_graph_contract.h"

#ifdef __cplusplus
extern "C" {
#endif

void service_graph_reset(void);

/* Register a known provider artifact hash (anti-fabrication). */
uint32_t service_graph_register_artifact(
    const struct service_graph_digest *provider_id);

uint32_t service_graph_validate(
    const struct service_graph_req_validate *req,
    const struct service_graph_provider *providers,
    const struct service_graph_edge *edges,
    struct service_graph_reply_validate *reply);

uint32_t service_graph_publish(
    const struct service_graph_req_publish *req,
    struct service_graph_reply_publish *reply);

uint32_t service_graph_bind(
    const struct service_graph_req_bind *req,
    struct service_graph_reply_bind *reply);

uint32_t service_graph_swap(
    const struct service_graph_req_swap *req,
    struct service_graph_reply_swap *reply);

uint32_t service_graph_rollback(
    const struct service_graph_req_rollback *req,
    struct service_graph_reply_rollback *reply);

uint32_t service_graph_resolve(
    const struct service_graph_req_resolve *req,
    struct service_graph_reply_resolve *reply);

uint32_t service_graph_stored_count(void);
uint32_t service_graph_artifact_count(void);

#ifdef __cplusplus
}
#endif
