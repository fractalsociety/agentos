/*
 * Host-side scoped actor + persistent mailbox runtime
 * (fos-gz0.14.7.1 / fos-gz0.14.7.2).
 *
 * Freestanding C implementation used by host contract tests. Target PD
 * wiring lands with the dispatcher topology work; this module is the
 * authoritative enforcement of handle/scope/mailbox/passivation invariants.
 */

#pragma once

#include "contracts/actor_mailbox_contract.h"

#ifdef __cplusplus
extern "C" {
#endif

void actor_mailbox_reset(void);

/* SPAWN / DELEGATE return immediately (no completion wait). */
uint32_t actor_mailbox_spawn(const struct actor_req_spawn *req,
                             struct actor_reply_spawn *reply);
uint32_t actor_mailbox_delegate(const struct actor_req_delegate *req,
                                struct actor_reply_delegate *reply);

uint32_t actor_mailbox_deliver(const struct actor_req_mailbox_deliver *req,
                               struct actor_reply_mailbox_deliver *reply);
uint32_t actor_mailbox_poll(const struct actor_req_mailbox_poll *req,
                            struct actor_reply_mailbox_poll *reply);

uint32_t actor_mailbox_resolve(const struct actor_req_handle_resolve *req,
                               struct actor_reply_handle_resolve *reply);

/* fos-gz0.14.7.2 */
uint32_t actor_mailbox_passivate(const struct actor_req_passivate *req,
                                 struct actor_reply_passivate *reply);
uint32_t actor_mailbox_reactivate(const struct actor_req_reactivate *req,
                                  struct actor_reply_reactivate *reply);
uint32_t actor_mailbox_memory_stats(const struct actor_req_memory_stats *req,
                                    struct actor_reply_memory_stats *reply);

/* Advance authority epoch for an agent (marks prior handles stale). */
uint32_t actor_mailbox_bump_epoch(uint64_t agent_id);

uint32_t actor_mailbox_agent_count(void);
uint32_t actor_mailbox_task_count(void);

#ifdef __cplusplus
}
#endif
