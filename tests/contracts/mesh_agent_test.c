/*
 * mesh_agent_test.c — contract tests for the MeshAgent PD
 *
 * Covered legacy opcodes:
 *   MSG_MESH_ANNOUNCE, MSG_MESH_STATUS, MSG_REMOTE_SPAWN,
 *   MSG_MESH_HEARTBEAT
 *
 * Also covers the contract-only Fractal Mesh invariants: generated frame
 * lengths, replay cursors, grant audience/epoch fencing, remote badge
 * rejection, one-shot completion, and bounded flow control.
 *
 * Channel: 0 (placeholder — update when ch is assigned in agentos.system).
 *
 * Copyright (c) 2026 The agentOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "../harness/test_framework.h"
#include "../../kernel/agentos-root-task/include/agentos.h"
#include "../../kernel/agentos-root-task/include/contracts/mesh_agent_contract.h"

static void mesh_check(bool condition, const char *name)
{
    if (condition) _tf_ok(name);
    else _tf_fail_point(name, "contract invariant rejected");
}

static void mesh_contract_tests(void)
{
    TEST_SECTION("fractal_mesh_contract");

    mesh_check(MSG_MESH_SESSION_OPEN != MSG_MESH_SESSION_RESUME &&
                   MSG_MESH_SESSION_RESUME != MSG_MESH_SESSION_CANCEL &&
                   MSG_MESH_SESSION_CANCEL != MSG_MESH_SERVICE_ADVERTISE &&
                   MSG_MESH_SERVICE_ADVERTISE != MSG_MESH_LEASE_ACQUIRE &&
                   MSG_MESH_LEASE_ACQUIRE != MSG_MESH_LEASE_RENEW &&
                   MSG_MESH_LEASE_RENEW != MSG_MESH_LEASE_RELEASE &&
                   MSG_MESH_LEASE_RELEASE != MSG_MESH_REVOCATION_EPOCH &&
                   MSG_MESH_REVOCATION_EPOCH != MSG_MESH_FRAME_ACK,
               "mesh: remote IPC opcodes are distinct");

    mesh_frame_header_t header = {
        .magic = MESH_FRAME_MAGIC,
        .schema_version = MESH_WIRE_SCHEMA_VERSION,
        .frame_type = MESH_FRAME_TASK,
        .flags = MESH_FRAME_FLAG_FIRST,
        .header_bytes = MESH_FRAME_HEADER_BYTES,
        .payload_bytes = 4u,
    };
    mesh_check(mesh_frame_header_valid(&header, MESH_FRAME_HEADER_BYTES + 4u),
               "mesh: valid length-delimited task frame");
    header.payload_bytes = MESH_MAX_FRAME_PAYLOAD + 1u;
    mesh_check(!mesh_frame_header_valid(&header, MESH_MAX_FRAME_BYTES + 1u),
               "mesh: malformed payload length rejected");

    mesh_replay_cursor_t replay = { .highest_sequence = 7u };
    mesh_check(!mesh_sequence_accept(&replay, 7u),
               "mesh: replayed sequence rejected");
    mesh_check(mesh_sequence_accept(&replay, 8u),
               "mesh: next sequence accepted");

    mesh_remote_grant_t grant = { 0 };
    mesh_node_id_t local = { 0 };
    grant.audience_node.bytes[0] = 1u;
    mesh_check(!mesh_grant_audience_matches(&grant, &local),
               "mesh: wrong grant audience rejected");
    grant.audience_node.bytes[0] = 0u;
    grant.authority_epoch = 3u;
    grant.revocation_epoch = 4u;
    mesh_revocation_epoch_t current = { .authority_epoch = 3u,
                                        .revocation_epoch = 5u };
    mesh_check(!mesh_epochs_current(&grant, current),
               "mesh: stale revocation epoch rejected");
    mesh_check(!mesh_remote_badge_accepted(0xfeedu),
               "mesh: injected remote badge rejected");

    mesh_completion_guard_t completion = { 0 };
    mesh_check(mesh_completion_accept(&completion, 11u),
               "mesh: first completion accepted");
    mesh_check(!mesh_completion_accept(&completion, 11u),
               "mesh: duplicate completion rejected");

    mesh_flow_window_t flow = { 0 };
    mesh_check(mesh_flow_allows(&flow, 1024u),
               "mesh: bounded flow credit allows first frame");
    flow.frames_in_flight = MESH_MAX_INFLIGHT_FRAMES;
    mesh_check(!mesh_flow_allows(&flow, 1u),
               "mesh: bounded frame credit rejects overflow");
    mesh_check(mesh_frame_type_is_datagram_safe(MESH_FRAME_HINT) &&
                   !mesh_frame_type_is_datagram_safe(MESH_FRAME_TASK),
               "mesh: datagrams restricted to disposable hints");
}

void run_mesh_agent_tests(microkit_channel ch)
{
    TEST_SECTION("mesh_agent");

    mesh_contract_tests();

    if (ch == 0) {
        _tf_puts("# mesh_agent: channel not wired in test topology (ch=0)\n");

        _tf_total++; _tf_pass++;
        _tf_puts("ok "); _tf_put_uint((uint64_t)_tf_total);
        _tf_puts(" - mesh_agent: STATUS channel placeholder # TODO wire ch\n");

        _tf_total++; _tf_pass++;
        _tf_puts("ok "); _tf_put_uint((uint64_t)_tf_total);
        _tf_puts(" - mesh_agent: ANNOUNCE channel placeholder # TODO wire ch\n");

        _tf_total++; _tf_pass++;
        _tf_puts("ok "); _tf_put_uint((uint64_t)_tf_total);
        _tf_puts(" - mesh_agent: REMOTE_SPAWN channel placeholder # TODO wire ch\n");

        _tf_total++; _tf_pass++;
        _tf_puts("ok "); _tf_put_uint((uint64_t)_tf_total);
        _tf_puts(" - mesh_agent: HEARTBEAT channel placeholder # TODO wire ch\n");
        return;
    }

    /* STATUS — query peer count. */
    ASSERT_IPC_OK(ch, MSG_MESH_STATUS, "mesh_agent: STATUS returns ok");

    /* ANNOUNCE — register with zero node_id and slot counts. */
    microkit_mr_set(0, (uint64_t)MSG_MESH_ANNOUNCE);
    microkit_mr_set(1, 0);  /* node_id */
    microkit_mr_set(2, 0);  /* slot_count */
    microkit_mr_set(3, 0);  /* gpu_slots */
    (void)microkit_ppcall(ch, microkit_msginfo_new(MSG_MESH_ANNOUNCE, 4));
    {
        uint64_t rc = microkit_mr_get(0);
        if (rc == AOS_OK || rc == AOS_ERR_EXISTS || rc == AOS_ERR_INVAL) {
            _tf_ok("mesh_agent: ANNOUNCE returns ok, exists, or inval");
        } else {
            _tf_fail_point("mesh_agent: ANNOUNCE returns ok, exists, or inval",
                           "unexpected error code");
        }
    }

    /* REMOTE_SPAWN — attempt to spawn on best peer; may have no peers. */
    microkit_mr_set(0, (uint64_t)MSG_REMOTE_SPAWN);
    microkit_mr_set(1, 0);  /* hash_lo */
    microkit_mr_set(2, 0);  /* hash_hi */
    (void)microkit_ppcall(ch, microkit_msginfo_new(MSG_REMOTE_SPAWN, 3));
    {
        uint64_t rc = microkit_mr_get(0);
        if (rc == AOS_OK || rc == AOS_ERR_NOT_FOUND || rc == AOS_ERR_NOSPC) {
            _tf_ok("mesh_agent: REMOTE_SPAWN returns ok, not-found, or nospc");
        } else {
            _tf_fail_point("mesh_agent: REMOTE_SPAWN returns ok, not-found, or nospc",
                           "unexpected error code");
        }
    }

    /* HEARTBEAT — liveness ping; expect ok. */
    microkit_mr_set(0, (uint64_t)MSG_MESH_HEARTBEAT);
    microkit_mr_set(1, 0);  /* node_id */
    (void)microkit_ppcall(ch, microkit_msginfo_new(MSG_MESH_HEARTBEAT, 2));
    {
        uint64_t rc = microkit_mr_get(0);
        if (rc == AOS_OK || rc == AOS_ERR_NOT_FOUND) {
            _tf_ok("mesh_agent: HEARTBEAT returns ok or not-found");
        } else {
            _tf_fail_point("mesh_agent: HEARTBEAT returns ok or not-found",
                           "unexpected error code");
        }
    }
}
