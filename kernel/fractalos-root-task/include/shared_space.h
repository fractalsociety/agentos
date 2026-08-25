/*
 * Host-side immutable shared-space replication (fos-gz0.14.10.3).
 *
 * Freestanding C runtime for L2 host tests. Models content-addressed objects,
 * per-device have/want views, CAS roots, offline branches, dual-head conflicts,
 * and verified merge. Never CRDT-merges authority state.
 */

#pragma once

#include "contracts/shared_space_contract.h"

#ifdef __cplusplus
extern "C" {
#endif

void shared_space_reset(void);

uint32_t shared_space_create(const struct shared_space_req_create *req,
                             struct shared_space_reply_create *reply);

uint32_t shared_space_put_object(const struct shared_space_req_put_object *req,
                                 const uint8_t *payload,
                                 struct shared_space_reply_put_object *reply);

uint32_t shared_space_get_object(const struct shared_space_req_get_object *req,
                                 uint8_t *out_payload, uint32_t out_cap,
                                 struct shared_space_reply_get_object *reply);

/* have[] / want[] are caller arrays; missing objects (in want, not local to
 * from_device) are counted. Duplicates already present on device are counted. */
uint32_t shared_space_have_want(const struct shared_space_req_have_want *req,
                                const shared_object_id_t *have,
                                const shared_object_id_t *want,
                                struct shared_space_reply_have_want *reply);

/* After have/want, copy an object from the global store into a device view. */
uint32_t shared_space_device_ingest(const shared_device_id_t *device,
                                    const shared_object_id_t *object_id);

uint32_t shared_space_cas_root(const struct shared_space_req_cas_root *req,
                               struct shared_space_reply_cas_root *reply);

uint32_t shared_space_branch(const struct shared_space_req_branch *req,
                             struct shared_space_reply_branch *reply);

uint32_t shared_space_merge(const struct shared_space_req_merge *req,
                            struct shared_space_reply_merge *reply);

uint32_t shared_space_status(const struct shared_space_req_status *req,
                             struct shared_space_reply_status *reply);

uint32_t shared_space_object_count(void);
uint32_t shared_space_space_count(void);

#ifdef __cplusplus
}
#endif
