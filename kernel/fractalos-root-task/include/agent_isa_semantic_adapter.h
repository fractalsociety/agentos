/*
 * Host semantic adapter registry (fos-gz0.14.1.2).
 */

#pragma once

#include "contracts/agent_isa_semantic_adapter_contract.h"

#ifdef __cplusplus
extern "C" {
#endif

void agent_isa_adapter_reset(void);

uint32_t agent_isa_adapter_install(
    const struct agent_isa_adapter_req_install *req,
    struct agent_isa_adapter_reply_install *reply);

uint32_t agent_isa_adapter_invoke(
    const struct agent_isa_adapter_req_invoke *req,
    struct agent_isa_adapter_reply_invoke *reply);

uint32_t agent_isa_adapter_status(
    const struct agent_isa_adapter_req_status *req,
    struct agent_isa_adapter_reply_status *reply);

#ifdef __cplusplus
}
#endif
