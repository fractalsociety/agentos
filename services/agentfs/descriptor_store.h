/* Bounded AgentFS event-descriptor persistence / resolution. */
#pragma once

#include <stdint.h>

#include "../../kernel/fractalos-root-task/include/contracts/eventbus_contract.h"

#define AGENTFS_DESC_MAX_ENTRIES 64u
#define AGENTFS_DESC_MAX_BYTES   256u

struct agentfs_desc_entry {
    int used;
    eventbus_event_hash_t payload_root;
    uint32_t length;
    uint8_t bytes[AGENTFS_DESC_MAX_BYTES];
};

void agentfs_desc_store_init(void);

/* Persist descriptor bytes under payload_root. Returns 0 on success. */
uint32_t agentfs_desc_persist(const eventbus_event_hash_t *payload_root,
                              const uint8_t *bytes, uint32_t length);

/* Resolve previously persisted descriptor. Writes up to capacity bytes.
 * *out_length receives stored length. Returns 0 on success. */
uint32_t agentfs_desc_resolve(const eventbus_event_hash_t *payload_root,
                              uint8_t *out, uint32_t capacity,
                              uint32_t *out_length);

uint32_t agentfs_desc_count(void);
