/*
 * eventbus_test.c — contract tests for the EventBus PD
 *
 * Covered opcodes:
 *   MSG_EVENTBUS_INIT        (0x0001) — initialise the event bus
 *   MSG_EVENTBUS_SUBSCRIBE   (0x0002) — subscribe a channel to events
 *   MSG_EVENTBUS_UNSUBSCRIBE (0x0003) — unsubscribe a channel
 *   MSG_EVENTBUS_STATUS      (0x0004) — query ring buffer status
 *
 * Channel: MONITOR_CH_EVENTBUS (1) from the controller's perspective.
 *
 * Copyright (c) 2026 The agentOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "../harness/test_framework.h"
#include "../../kernel/agentos-root-task/include/agentos.h"
#include "../../kernel/agentos-root-task/include/contracts/eventbus_contract.h"

#define ASSERT_EVENT_CONTRACT(condition, name)                         \
    do {                                                               \
        if (condition) _tf_ok(name);                                   \
        else _tf_fail_point(name, "canonical event contract assertion"); \
    } while (0)

void run_eventbus_tests(microkit_channel ch)
{
    TEST_SECTION("eventbus");

    /* STATUS — must succeed; the root task maps the ring on target (agentos-gom)
     * and event_bus_main initialises it before entering its server loop. */
    ASSERT_IPC_OK(ch, MSG_EVENTBUS_STATUS, "eventbus: STATUS returns ok");

    /* SUBSCRIBE — subscribe the monitor channel (badge 0 = self). */
    microkit_mr_set(0, (uint64_t)MSG_EVENTBUS_SUBSCRIBE);
    microkit_mr_set(1, 0);  /* subscriber channel id */
    (void)microkit_ppcall(ch, microkit_msginfo_new(MSG_EVENTBUS_SUBSCRIBE, 2));
    {
        uint64_t rc = microkit_mr_get(0);
        if (rc == AOS_OK || rc == AOS_ERR_EXISTS) {
            _tf_ok("eventbus: SUBSCRIBE returns ok or already-subscribed");
        } else {
            _tf_fail_point("eventbus: SUBSCRIBE returns ok or already-subscribed",
                           "unexpected error code");
        }
    }

    /* UNSUBSCRIBE — should succeed (or return not-found if not subscribed). */
    microkit_mr_set(0, (uint64_t)MSG_EVENTBUS_UNSUBSCRIBE);
    microkit_mr_set(1, 0);
    (void)microkit_ppcall(ch, microkit_msginfo_new(MSG_EVENTBUS_UNSUBSCRIBE, 2));
    {
        uint64_t rc = microkit_mr_get(0);
        if (rc == AOS_OK || rc == AOS_ERR_NOT_FOUND) {
            _tf_ok("eventbus: UNSUBSCRIBE returns ok or not-found");
        } else {
            _tf_fail_point("eventbus: UNSUBSCRIBE returns ok or not-found",
                           "unexpected error code");
        }
    }

    /* INIT — reinitialise (idempotent on a running system). */
    ASSERT_IPC_OK_OR_ERR(ch, MSG_EVENTBUS_INIT, AOS_ERR_BUSY,
                         "eventbus: INIT returns ok or busy");

    /* STATUS again — confirm bus is still responsive after subscribe/unsubscribe. */
    ASSERT_IPC_OK(ch, MSG_EVENTBUS_STATUS, "eventbus: STATUS still ok after ops");

    /* Canonical Agent event schema checks.  EventBus transports these records;
     * the durable stream contract authenticates and replays them above it. */
    ASSERT_EVENT_CONTRACT(EVENTBUS_AGENT_EVENT_SCHEMA_VERSION == 2u,
                          "eventbus: canonical event schema is version 2");
    ASSERT_EVENT_CONTRACT(EVENTBUS_EVENT_TASK < EVENTBUS_EVENT_RECONNECT
                              && EVENTBUS_EVENT_TASK_VERIFY
                                  != EVENTBUS_EVENT_COMMIT,
                          "eventbus: lifecycle and TASK_VERIFY event types are distinct");
    ASSERT_EVENT_CONTRACT(EVENTBUS_EVENT_FLAG_KNOWN_MASK
                    == (EVENTBUS_EVENT_FLAG_TASK_VERIFY_SUCCESS
                        | EVENTBUS_EVENT_FLAG_EXTERNAL_EFFECT
                        | EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE
                        | EVENTBUS_EVENT_FLAG_PROMOTION_INTERNAL),
                          "eventbus: event flags fail closed");
    ASSERT_EVENT_CONTRACT(EVENTBUS_AGENT_EVENT_ERR_TAMPER
                    != EVENTBUS_AGENT_EVENT_ERR_TRUNCATED
                    && EVENTBUS_AGENT_EVENT_ERR_REORDERED
                        != EVENTBUS_AGENT_EVENT_ERR_SCOPE
                    && EVENTBUS_AGENT_EVENT_ERR_COMMIT_EVIDENCE
                        != EVENTBUS_AGENT_EVENT_ERR_PROMOTION_FORBIDDEN,
                          "eventbus: replay failures are distinguishable");
}
