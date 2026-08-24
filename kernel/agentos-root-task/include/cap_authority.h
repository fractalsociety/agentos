/*
 * Restricted runtime capability authority delegated by the root task.
 *
 * These slots live only in the controller CSpace.  Callers of CapBroker name
 * a semantic harness capability class; they never supply a source CPtr,
 * destination CNode, or destination slot.
 */
#pragma once

#include <stdint.h>

#define CONTROLLER_RIGHT_CAP_ADMIN       (1u << 0)
#define CONTROLLER_RIGHT_AGENT_TASK      (1u << 1)

#define CAPBROKER_AUTH_SELF_CNODE_SLOT   224u
#define CAPBROKER_AUTH_HARNESS_CNODE_SLOT 225u
#define CAPBROKER_AUTH_MODEL_SOURCE_SLOT 240u
#define CAPBROKER_AUTH_TOOL_SOURCE_SLOT  241u
#define CAPBROKER_AUTH_MEMORY_SOURCE_SLOT 242u
#define CAPBROKER_AUTH_EXEC_SOURCE_SLOT  243u
#define CAPBROKER_AUTH_NETWORK_SOURCE_SLOT 244u

#define CAPBROKER_CONTROLLER_CNODE_BITS  10u
#define CAPBROKER_HARNESS_CNODE_BITS      8u
#define CAPBROKER_CONTROLLER_PD_ID        4u
#define CAPBROKER_HARNESS_PD_ID          11u
#define CAPBROKER_HARNESS_SERVICE_ID      26u

/* Initial CSpace state before any runtime grants. ToolCap and NetCap are
 * intentionally absent and must be installed by CapBroker. */
#define CAPBROKER_HARNESS_INITIAL_CAPS \
    (HARNESS_CAP_MODEL | HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC)

struct cap_broker_reply_runtime {
    uint32_t status;
    uint32_t installed_caps;
    uint32_t authority_epoch;
    uint32_t changed;
};
