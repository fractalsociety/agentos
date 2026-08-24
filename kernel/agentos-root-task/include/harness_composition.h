/* Freestanding validator for launcher-owned AgentHarness component graphs. */
#pragma once

#include <stdint.h>

#include "contracts/init_agent_contract.h"

struct harness_component_catalog_entry {
    uint16_t component_id;
    uint16_t version;
    uint32_t flags;
    uint32_t requires_components;
    uint32_t conflicts_components;
    uint32_t required_caps;
    uint32_t private_bytes;
    uint32_t shared_mapped_bytes;
    uint32_t endpoint_mask;
    uint32_t mapping_mask;
    uint32_t shared_components;
};

uint32_t harness_compose_validate(
    const struct harness_component_catalog_entry *catalog,
    uint32_t catalog_count,
    const struct initagent_req_compose_validate *req,
    struct initagent_reply_compose *reply);

uint32_t harness_compose_validate_builtin(
    const struct initagent_req_compose_validate *req,
    struct initagent_reply_compose *reply);

uint32_t harness_compose_profile(
    const struct initagent_req_compose_profile *req,
    struct initagent_reply_compose *reply);

const struct harness_component_catalog_entry *
harness_compose_builtin_catalog(uint32_t *count);
