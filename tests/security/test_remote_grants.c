/*
 * RemoteGrant contract/security tests.
 *
 * These are host-side contract tests.  They exercise the rejection boundary
 * before any remote request can reach a service and deliberately model a
 * peer-supplied badge as untrusted data.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../kernel/agentos-root-task/include/contracts/auth_server_contract.h"
#include "../../kernel/agentos-root-task/include/contracts/cap_broker_contract.h"

#define CALLER_BADGE UINT64_C(0x4d45534800000001)

struct fixture {
    auth_remote_authority_t auth;
    cap_broker_remote_state_t cap;
    mesh_remote_authority_state_t mesh;
    mesh_remote_authority_context_t ctx;
    uint32_t events;
};

static void fill_id(uint8_t bytes[MESH_ID_BYTES], uint8_t seed)
{
    for (uint32_t i = 0u; i < MESH_ID_BYTES; i++) bytes[i] = (uint8_t)(seed + i);
}

static int verify_signature(const uint8_t signature[MESH_SIGNATURE_BYTES],
                            const uint8_t *message, uint32_t message_len,
                            const uint8_t public_key[MESH_ID_BYTES], void *ctx)
{
    (void)ctx;
    assert(message != NULL &&
           message_len == (uint32_t)(sizeof(MESH_REMOTE_GRANT_SIGNATURE_DOMAIN) - 1u) +
                              MESH_REMOTE_GRANT_SIGNING_BYTES);
    assert(public_key[0] == 0x42u);
    return signature[0] == 0xA5u ? 0 : -1;
}

static uint32_t verify_grant(const mesh_remote_grant_t *grant, void *ctx)
{
    struct fixture *fixture = (struct fixture *)ctx;
    return auth_server_verify_remote_grant(grant, &fixture->auth);
}

static uint64_t derive_badge(const mesh_remote_grant_t *grant,
                             uint64_t operations, uint32_t effect,
                             uint64_t budget, void *ctx)
{
    struct fixture *fixture = (struct fixture *)ctx;
    uint64_t badge = 0u;
    if (cap_broker_derive_remote_endpoint_badge(
            &fixture->cap, CALLER_BADGE, grant, operations, effect, budget,
            &badge) != CAP_BROKER_OK)
        return 0u;
    return badge;
}

static uint32_t emit_event(uint32_t event_type, uint32_t decision,
                           uint32_t status, const mesh_remote_grant_t *grant,
                           const mesh_execution_lease_t *lease,
                           uint64_t local_badge, void *ctx)
{
    (void)event_type; (void)decision; (void)grant; (void)lease;
    (void)local_badge;
    struct fixture *fixture = (struct fixture *)ctx;
    fixture->events++;
    return status;
}

static mesh_remote_grant_t valid_grant(struct fixture *fixture)
{
    mesh_remote_grant_t grant;
    memset(&grant, 0, sizeof(grant));
    fill_id(grant.issuer.bytes, 0x70u);
    grant.subject_node = fixture->ctx.authenticated_tailnet_peer;
    grant.subject_agent = fixture->ctx.expected_agent;
    grant.audience_node = fixture->ctx.local_node;
    grant.space_id = fixture->ctx.expected_space;
    grant.interface_hash = fixture->ctx.expected_interface;
    grant.object_scope = fixture->ctx.expected_object_scope;
    grant.operation_mask = 1u;
    grant.scope_flags = MESH_GRANT_SCOPE_OBJECTS;
    grant.effect_class = MESH_EFFECT_LOCAL;
    grant.budget_units = 10u;
    grant.expiry_unix_ms = 2000u;
    grant.authority_epoch = 4u;
    grant.revocation_epoch = 9u;
    grant.nonce[0] = 0x91u;
    grant.signature[0] = 0xA5u;
    return grant;
}

static void fixture_init(struct fixture *fixture)
{
    uint8_t key[MESH_ID_BYTES] = {0};
    mesh_node_id_t issuer = {0};
    memset(fixture, 0, sizeof(*fixture));
    fill_id(issuer.bytes, 0x70u);
    key[0] = 0x42u;
    auth_server_remote_authority_init(&fixture->auth, verify_signature, NULL);
    assert(auth_server_remote_trust_issuer(&fixture->auth, &issuer, key)
           == AUTH_REMOTE_OK);
    cap_broker_remote_init(&fixture->cap, CALLER_BADGE);
    mesh_agent_remote_authority_init(&fixture->mesh);

    fill_id(fixture->ctx.authenticated_tailnet_peer.bytes, 0x10u);
    fill_id(fixture->ctx.local_node.bytes, 0x20u);
    fill_id(fixture->ctx.expected_agent.bytes, 0x30u);
    fill_id(fixture->ctx.expected_space.bytes, 0x40u);
    fill_id(fixture->ctx.expected_interface.bytes, 0x50u);
    fill_id(fixture->ctx.expected_object_scope.bytes, 0x60u);
    fixture->ctx.requested_operations = 1u;
    fixture->ctx.required_scope_flags = MESH_GRANT_SCOPE_OBJECTS;
    fixture->ctx.requested_effect_class = MESH_EFFECT_LOCAL;
    fixture->ctx.max_effect_class = MESH_EFFECT_LOCAL;
    fixture->ctx.requested_budget_units = 1u;
    fixture->ctx.now_unix_ms = 1000u;
    fixture->ctx.authority_epoch = 4u;
    fixture->ctx.revocation_epoch = 9u;
    fixture->ctx.verify_grant = verify_grant;
    fixture->ctx.derive_local_badge = derive_badge;
    fixture->ctx.emit_event = emit_event;
    fixture->ctx.callback_ctx = fixture;
}

static void check(bool condition, const char *name)
{
    if (!condition) {
        fprintf(stderr, "not ok - %s\n", name);
        assert(condition);
    }
    printf("ok - %s\n", name);
}

int main(void)
{
    struct fixture fixture;
    fixture_init(&fixture);
    mesh_remote_grant_t grant = valid_grant(&fixture);

    mesh_frame_header_t header = {
        .magic = MESH_FRAME_MAGIC,
        .schema_version = MESH_WIRE_SCHEMA_VERSION,
        .frame_type = MESH_FRAME_TASK,
        .header_bytes = MESH_FRAME_HEADER_BYTES,
        .payload_bytes = 1u,
    };
    check(mesh_frame_header_valid(&header, MESH_FRAME_HEADER_BYTES + 1u),
          "valid frame length is accepted");
    header.header_bytes = MESH_FRAME_HEADER_BYTES - 1u;
    check(!mesh_frame_header_valid(&header, MESH_FRAME_HEADER_BYTES + 1u),
          "malformed header length is rejected");
    header.header_bytes = MESH_FRAME_HEADER_BYTES;
    header.payload_bytes = MESH_MAX_FRAME_PAYLOAD + 1u;
    check(!mesh_frame_header_valid(&header, MESH_MAX_FRAME_BYTES + 1u),
          "malformed payload length is rejected");

    check(auth_server_verify_remote_grant(&grant, &fixture.auth)
              == AUTH_REMOTE_OK,
          "signed RemoteGrant is accepted by the trusted issuer");

    uint64_t badge = 0u;
    check(mesh_agent_admit_remote_grant(&fixture.mesh, &grant, &fixture.ctx,
                                        0u, &badge) == MESH_AUTHZ_OK,
          "valid RemoteGrant is admitted and locally narrowed");
    check(!mesh_grant_audience_matches(&grant, &fixture.ctx.authenticated_tailnet_peer),
          "wrong audience is rejected");

    mesh_remote_grant_t wrong_audience = grant;
    wrong_audience.audience_node.bytes[0] ^= 1u;
    check(!mesh_grant_audience_matches(&wrong_audience, &fixture.ctx.local_node),
          "tampered audience cannot match the local node");

    mesh_revocation_epoch_t current = {
        .authority_epoch = grant.authority_epoch,
        .revocation_epoch = grant.revocation_epoch + 1u,
    };
    check(!mesh_epochs_current(&grant, current),
          "stale revocation epoch is rejected");
    check(!mesh_remote_badge_accepted(CAP_BROKER_REMOTE_BADGE_PREFIX | 1u),
          "remote-badge injection is never accepted as authority");

    mesh_replay_cursor_t cursor = { .highest_sequence = 12u };
    check(!mesh_sequence_accept(&cursor, 12u), "replayed frame is rejected");
    check(mesh_sequence_accept(&cursor, 13u), "new frame sequence is accepted");

    mesh_completion_guard_t completion = {0};
    check(mesh_completion_accept(&completion, 13u),
          "first completion is accepted");
    check(!mesh_completion_accept(&completion, 13u),
          "duplicate completion is rejected");

    mesh_flow_window_t flow = {0};
    check(mesh_flow_allows(&flow, 1024u), "bounded flow window accepts credit");
    flow.frames_in_flight = MESH_MAX_INFLIGHT_FRAMES;
    check(!mesh_flow_allows(&flow, 1u), "bounded flow window rejects overflow");
    check(mesh_frame_type_is_datagram_safe(MESH_FRAME_HINT) &&
              !mesh_frame_type_is_datagram_safe(MESH_FRAME_CONTROL),
          "datagrams are restricted to disposable hints");

    puts("remote grants contract/security suite: ok");
    return 0;
}
