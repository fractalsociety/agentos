#pragma once

#include <stdint.h>

void agentfs_workspace_init(void *arena, uint32_t arena_size);
uint32_t agentfs_workspace_dispatch(uint64_t badge, uint32_t opcode,
                                    const void *payload, uint32_t payload_len,
                                    uint8_t *reply, uint32_t *reply_len);
