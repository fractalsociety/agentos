/*
 * log_drain_test.c — contract tests for the LogDrain PD
 *
 * Covered opcodes:
 *   OP_LOG_WRITE  (0x01) — register ring slot and flush buffered output
 *   OP_LOG_STATUS (0x02) — query: slot_count, bytes_drained
 *
 * Channel: CH_LOG_DRAIN (55 on qemu-virt-aarch64, 60 otherwise).
 *
 * Copyright (c) 2026 The agentOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "../harness/test_framework.h"
#include "../../kernel/agentos-root-task/include/agentos.h"
#include "../../kernel/agentos-root-task/include/system_desc.h"

/* The production image installs LogDrain at its native well-known capability
 * slot. Host contract tests retain the Microkit channel shim. */
static microkit_msginfo log_drain_call(microkit_channel ch,
                                       microkit_msginfo request)
{
#ifdef AGENTOS_TEST_HOST
    return microkit_ppcall(ch, request);
#else
    (void)ch;
    return seL4_Call((seL4_CPtr)PD_CNODE_SLOT_LOG_DRAIN_EP, request);
#endif
}

/* Raw seL4 servers return transport status in the reply label and keep the
 * payload free for operation data. The host Microkit shim predates that
 * migration and still places its synthetic status in MR0. */
static uint64_t log_drain_reply_status(microkit_msginfo reply)
{
#ifdef AGENTOS_TEST_HOST
    (void)reply;
    return microkit_mr_get(0);
#else
    return microkit_msginfo_get_label(reply);
#endif
}

static void assert_log_status(microkit_channel ch, const char *name)
{
    microkit_mr_set(0, (uint64_t)OP_LOG_STATUS);
    microkit_msginfo reply = log_drain_call(
        ch, microkit_msginfo_new((uint64_t)OP_LOG_STATUS, 1));
    if (log_drain_reply_status(reply) == AOS_OK) _tf_ok(name);
    else {
        _tf_puts("  # log_drain status=");
        _tf_put_hex(log_drain_reply_status(reply));
        _tf_puts("\n");
        _tf_fail_point(name, "reply label reported an error");
    }
}

void run_log_drain_tests(microkit_channel ch)
{
    TEST_SECTION("log_drain");

    /* STATUS — must return slot_count and bytes_drained. */
    assert_log_status(ch, "log_drain: STATUS returns ok");

    /*
     * WRITE — register slot 0 with pd_id=0.
     * Expect ok or INVAL (if slot 0 is already in use by a real PD).
     */
    microkit_mr_set(0, (uint64_t)OP_LOG_WRITE);
    microkit_mr_set(1, 0);  /* slot */
    microkit_mr_set(2, 0);  /* pd_id */
    microkit_msginfo write_reply =
        log_drain_call(ch, microkit_msginfo_new(OP_LOG_WRITE, 3));
    {
        uint64_t rc = log_drain_reply_status(write_reply);
        if (rc == AOS_OK || rc == AOS_ERR_INVAL || rc == AOS_ERR_EXISTS) {
            _tf_ok("log_drain: WRITE returns ok, inval, or exists");
        } else {
            _tf_puts("  # log_drain write status=");
            _tf_put_hex(rc);
            _tf_puts("\n");
            _tf_fail_point("log_drain: WRITE returns ok, inval, or exists",
                           "unexpected error code");
        }
    }

    /* STATUS again — confirm log_drain still responds after WRITE. */
    assert_log_status(ch, "log_drain: STATUS still ok after WRITE");
}
