#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../kernel/agentos-root-task/include/agent_task_gateway.h"
#include "../../kernel/agentos-root-task/include/contracts/auth_server_contract.h"
#include "../../kernel/agentos-root-task/include/contracts/cap_broker_contract.h"

#define OP_READ  (UINT64_C(1) << 0)
#define OP_WRITE (UINT64_C(1) << 1)
#define MESH_CALLER_BADGE UINT64_C(0x4d45534800000001)

struct audit_state {
    uint32_t allowed;
    uint32_t denied;
    uint32_t last_event_type;
    uint32_t last_decision;
    uint32_t last_status;
    uint64_t last_badge;
    uint32_t verify_calls;
};

struct fixture {
    struct audit_state audit;
    auth_remote_authority_t auth;
    cap_broker_remote_state_t cap_broker;
    mesh_remote_authority_state_t mesh;
};

static void ok(const char *name)
{
    printf("ok - %s\n", name);
}

static void fill_id(uint8_t bytes[MESH_ID_BYTES], uint8_t seed)
{
    for (uint32_t i = 0u; i < MESH_ID_BYTES; i++)
        bytes[i] = (uint8_t)(seed + i);
}

static int fake_signature_verify(
    const uint8_t signature[MESH_SIGNATURE_BYTES], const uint8_t *message,
    uint32_t message_len, const uint8_t public_key[MESH_ID_BYTES], void *ctx)
{
    struct audit_state *audit = (struct audit_state *)ctx;
    audit->verify_calls++;
    assert(message != NULL);
    assert(message_len > (uint32_t)sizeof(MESH_REMOTE_GRANT_SIGNATURE_DOMAIN));
    assert(public_key[0] == 0x42u);
    return signature[0] == 0xA5u ? 0 : -1;
}

static uint32_t fixture_verify_grant(const mesh_remote_grant_t *grant, void *ctx)
{
    struct fixture *fixture = (struct fixture *)ctx;
    return auth_server_verify_remote_grant(grant, &fixture->auth);
}

static uint32_t fixture_verify_lease(const mesh_execution_lease_t *lease,
                                     const mesh_remote_grant_t *grant, void *ctx)
{
    struct fixture *fixture = (struct fixture *)ctx;
    return auth_server_verify_execution_lease(lease, grant, &fixture->auth);
}

static uint64_t fixture_derive_badge(
    const mesh_remote_grant_t *grant, uint64_t operations,
    uint32_t effect_class, uint64_t budget_units, void *ctx)
{
    struct fixture *fixture = (struct fixture *)ctx;
    uint64_t badge = 0u;
    uint32_t status = cap_broker_derive_remote_endpoint_badge(
        &fixture->cap_broker, MESH_CALLER_BADGE, grant, operations,
        effect_class, budget_units, &badge);
    return status == CAP_BROKER_OK ? badge : 0u;
}

static uint32_t fixture_emit(uint32_t event_type, uint32_t decision,
                             uint32_t status,
                             const mesh_remote_grant_t *grant,
                             const mesh_execution_lease_t *lease,
                             uint64_t local_badge, void *ctx)
{
    (void)grant;
    (void)lease;
    struct fixture *fixture = (struct fixture *)ctx;
    struct audit_state *audit = &fixture->audit;
    audit->last_event_type = event_type;
    audit->last_decision = decision;
    audit->last_status = status;
    audit->last_badge = local_badge;
    if (decision == MESH_AUTHZ_DECISION_ALLOW) audit->allowed++;
    else audit->denied++;
    return EVENTBUS_AGENT_EVENT_OK;
}

static mesh_remote_authority_context_t valid_context(struct fixture *fixture)
{
    mesh_remote_authority_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    fill_id(ctx.authenticated_tailnet_peer.bytes, 0x10u);
    fill_id(ctx.local_node.bytes, 0x20u);
    fill_id(ctx.expected_agent.bytes, 0x30u);
    fill_id(ctx.expected_space.bytes, 0x40u);
    fill_id(ctx.expected_interface.bytes, 0x50u);
    fill_id(ctx.expected_object_scope.bytes, 0x60u);
    ctx.requested_operations = OP_READ;
    ctx.required_scope_flags = MESH_GRANT_SCOPE_OBJECTS;
    ctx.requested_effect_class = MESH_EFFECT_LOCAL;
    ctx.max_effect_class = MESH_EFFECT_SHARED;
    ctx.requested_budget_units = 10u;
    ctx.now_unix_ms = 1000u;
    ctx.authority_epoch = 7u;
    ctx.revocation_epoch = 3u;
    ctx.expected_lease_fence_epoch = 99u;
    ctx.verify_grant = fixture_verify_grant;
    ctx.verify_lease = fixture_verify_lease;
    ctx.derive_local_badge = fixture_derive_badge;
    ctx.emit_event = fixture_emit;
    ctx.callback_ctx = fixture;
    return ctx;
}

static mesh_remote_grant_t valid_grant(
    const mesh_remote_authority_context_t *ctx)
{
    mesh_remote_grant_t grant;
    memset(&grant, 0, sizeof(grant));
    fill_id(grant.issuer.bytes, 0x70u);
    grant.subject_node = ctx->authenticated_tailnet_peer;
    grant.subject_agent = ctx->expected_agent;
    grant.audience_node = ctx->local_node;
    grant.space_id = ctx->expected_space;
    grant.interface_hash = ctx->expected_interface;
    grant.object_scope = ctx->expected_object_scope;
    grant.operation_mask = OP_READ | OP_WRITE;
    grant.scope_flags = MESH_GRANT_SCOPE_OBJECTS;
    grant.effect_class = MESH_EFFECT_SHARED;
    grant.budget_units = 100u;
    grant.expiry_unix_ms = 2000u;
    grant.authority_epoch = ctx->authority_epoch;
    grant.revocation_epoch = ctx->revocation_epoch;
    grant.nonce[0] = 0x91u;
    grant.signature[0] = 0xA5u;
    return grant;
}

static mesh_execution_lease_t valid_lease(
    const mesh_remote_grant_t *grant,
    const mesh_remote_authority_context_t *ctx)
{
    mesh_execution_lease_t lease;
    memset(&lease, 0, sizeof(lease));
    lease.lease_id = 123u;
    lease.fence_epoch = ctx->expected_lease_fence_epoch;
    lease.expires_unix_ms = 1900u;
    lease.authority_epoch = ctx->authority_epoch;
    lease.revocation_epoch = ctx->revocation_epoch;
    lease.holder_node = grant->subject_node;
    lease.subject_agent = grant->subject_agent;
    lease.space_id = grant->space_id;
    lease.nonce[0] = 0x33u;
    lease.signature[0] = 0xA5u;
    return lease;
}

static void fixture_init(struct fixture *fixture,
                         mesh_node_id_t issuer)
{
    uint8_t key[MESH_ID_BYTES] = {0};
    memset(fixture, 0, sizeof(*fixture));
    key[0] = 0x42u;
    auth_server_remote_authority_init(&fixture->auth,
                                      fake_signature_verify,
                                      &fixture->audit);
    assert(auth_server_remote_trust_issuer(&fixture->auth, &issuer, key)
           == AUTH_REMOTE_OK);
    cap_broker_remote_init(&fixture->cap_broker, MESH_CALLER_BADGE);
    mesh_agent_remote_authority_init(&fixture->mesh);
}

static void expect_admit(const char *name, struct fixture *fixture,
                         mesh_remote_grant_t grant,
                         mesh_remote_authority_context_t ctx,
                         uint64_t serialized_badge, uint32_t expected)
{
    uint64_t badge = UINT64_C(0xfeed);
    uint32_t status = mesh_agent_admit_remote_grant(
        &fixture->mesh, &grant, &ctx, serialized_badge, &badge);
    assert(status == expected);
    assert(fixture->audit.last_event_type == EVENTBUS_EVENT_AUTHORITY_CHANGE);
    assert(fixture->audit.last_status == expected);
    if (expected == MESH_AUTHZ_OK) {
        assert(badge != 0u);
        assert((badge & UINT64_C(0xff00000000000000))
               == CAP_BROKER_REMOTE_BADGE_PREFIX);
        assert(fixture->audit.last_decision == MESH_AUTHZ_DECISION_ALLOW);
    } else {
        assert(badge == 0u);
        assert(fixture->audit.last_decision == MESH_AUTHZ_DECISION_DENY);
    }
    ok(name);
}

int main(void)
{
    struct fixture fixture;
    mesh_remote_authority_context_t ctx;
    mesh_remote_grant_t grant;
    mesh_execution_lease_t lease;
    uint64_t badge = 0u;

    ctx = valid_context(&fixture);
    grant = valid_grant(&ctx);
    fixture_init(&fixture, grant.issuer);
    ctx.callback_ctx = &fixture;

    assert(MSG_MESH_REMOTE_AUTHORIZE != MSG_MESH_REMOTE_DISPATCH);
    assert(MSG_MESH_REMOTE_DISPATCH != MSG_MESH_REMOTE_COMPLETE);
    assert(MSG_CAP_REMOTE_DERIVE != MSG_CAP_LIST);
    assert(OP_AUTH_REMOTE_VERIFY != OP_AUTH_STATUS);
    ok("remote authority IPC opcodes are registered and distinct");

    expect_admit("valid grant derives a narrow local CapBroker badge",
                 &fixture, grant, ctx, 0u, MESH_AUTHZ_OK);
    badge = fixture.audit.last_badge;

    expect_admit("replayed grant nonce is denied", &fixture, grant, ctx, 0u,
                 MESH_AUTHZ_ERR_REPLAY);

    fixture_init(&fixture, grant.issuer);
    mesh_remote_grant_t bad = grant;
    bad.signature[0] = 0u;
    expect_admit("fabricated signature is denied", &fixture, bad, ctx, 0u,
                 MESH_AUTHZ_ERR_SIGNATURE);

    fixture_init(&fixture, grant.issuer);
    bad = grant;
    bad.issuer.bytes[0] ^= 1u;
    expect_admit("untrusted issuer is denied", &fixture, bad, ctx, 0u,
                 MESH_AUTHZ_ERR_ISSUER);

    fixture_init(&fixture, grant.issuer);
    assert(auth_server_remote_revoke_issuer(&fixture.auth, &grant.issuer)
           == AUTH_REMOTE_OK);
    expect_admit("locally revoked issuer is denied", &fixture, grant, ctx, 0u,
                 MESH_AUTHZ_ERR_REVOKED);

    fixture_init(&fixture, grant.issuer);
    bad = grant;
    bad.subject_node.bytes[0] ^= 1u;
    expect_admit("tailnet peer is bound to subject node", &fixture, bad, ctx,
                 0u, MESH_AUTHZ_ERR_PEER_SUBJECT);

    fixture_init(&fixture, grant.issuer);
    bad = grant;
    bad.audience_node.bytes[0] ^= 1u;
    expect_admit("wrong audience is denied", &fixture, bad, ctx, 0u,
                 MESH_AUTHZ_ERR_AUDIENCE);

    fixture_init(&fixture, grant.issuer);
    bad = grant;
    bad.subject_agent.bytes[0] ^= 1u;
    expect_admit("wrong agent binding is denied", &fixture, bad, ctx, 0u,
                 MESH_AUTHZ_ERR_AGENT);

    fixture_init(&fixture, grant.issuer);
    bad = grant;
    bad.space_id.bytes[0] ^= 1u;
    expect_admit("wrong space binding is denied", &fixture, bad, ctx, 0u,
                 MESH_AUTHZ_ERR_SPACE);

    fixture_init(&fixture, grant.issuer);
    bad = grant;
    bad.interface_hash.bytes[0] ^= 1u;
    expect_admit("wrong interface binding is denied", &fixture, bad, ctx, 0u,
                 MESH_AUTHZ_ERR_INTERFACE);

    fixture_init(&fixture, grant.issuer);
    bad = grant;
    bad.operation_mask = OP_WRITE;
    expect_admit("operation escalation is denied", &fixture, bad, ctx, 0u,
                 MESH_AUTHZ_ERR_OPERATION);

    fixture_init(&fixture, grant.issuer);
    bad = grant;
    bad.object_scope.bytes[0] ^= 1u;
    expect_admit("object scope escalation is denied", &fixture, bad, ctx, 0u,
                 MESH_AUTHZ_ERR_OBJECT_SCOPE);

    fixture_init(&fixture, grant.issuer);
    bad = grant;
    bad.effect_class = MESH_EFFECT_EXTERNAL;
    expect_admit("effect ceiling escalation is denied", &fixture, bad, ctx,
                 0u, MESH_AUTHZ_ERR_EFFECT);

    fixture_init(&fixture, grant.issuer);
    bad = grant;
    bad.budget_units = ctx.requested_budget_units - 1u;
    expect_admit("over-budget request is denied", &fixture, bad, ctx, 0u,
                 MESH_AUTHZ_ERR_BUDGET);

    fixture_init(&fixture, grant.issuer);
    bad = grant;
    bad.expiry_unix_ms = ctx.now_unix_ms;
    expect_admit("expired grant is denied", &fixture, bad, ctx, 0u,
                 MESH_AUTHZ_ERR_EXPIRED);

    fixture_init(&fixture, grant.issuer);
    bad = grant;
    memset(bad.nonce, 0, sizeof(bad.nonce));
    expect_admit("zero nonce is denied", &fixture, bad, ctx, 0u,
                 MESH_AUTHZ_ERR_NONCE);

    fixture_init(&fixture, grant.issuer);
    bad = grant;
    bad.authority_epoch--;
    expect_admit("stale authority epoch is denied", &fixture, bad, ctx, 0u,
                 MESH_AUTHZ_ERR_STALE_AUTHORITY);

    fixture_init(&fixture, grant.issuer);
    bad = grant;
    bad.revocation_epoch--;
    expect_admit("revoked grant epoch is denied", &fixture, bad, ctx, 0u,
                 MESH_AUTHZ_ERR_REVOKED);

    fixture_init(&fixture, grant.issuer);
    expect_admit("serialized endpoint badges are denied", &fixture, grant,
                 ctx, CAP_BROKER_REMOTE_BADGE_PREFIX | 1u,
                 MESH_AUTHZ_ERR_REMOTE_BADGE);

    fixture_init(&fixture, grant.issuer);
    expect_admit("fresh grant admitted for dispatch checks", &fixture, grant,
                 ctx, 0u, MESH_AUTHZ_OK);
    badge = fixture.audit.last_badge;
    lease = valid_lease(&grant, &ctx);
    uint64_t dispatch_badge = 0u;
    assert(agent_task_gateway_remote_dispatch_recheck(
               &fixture.mesh, &grant, &lease, &ctx, badge, &dispatch_badge)
           == MESH_AUTHZ_OK);
    assert(dispatch_badge == badge);
    ok("dispatch rechecks grant, local badge, and signed lease");

    lease.fence_epoch++;
    dispatch_badge = UINT64_C(0xfeed);
    assert(agent_task_gateway_remote_dispatch_recheck(
               &fixture.mesh, &grant, &lease, &ctx, badge, &dispatch_badge)
           == MESH_AUTHZ_ERR_LEASE_PARTITIONED);
    assert(dispatch_badge == 0u);
    ok("partitioned execution lease is fenced at dispatch");

    lease = valid_lease(&grant, &ctx);
    lease.signature[0] = 0u;
    assert(agent_task_gateway_remote_dispatch_recheck(
               &fixture.mesh, &grant, &lease, &ctx, badge, &dispatch_badge)
           == MESH_AUTHZ_ERR_LEASE_SIGNATURE);
    ok("fabricated execution lease is denied");

    lease = valid_lease(&grant, &ctx);
    lease.subject_agent.bytes[0] ^= 1u;
    assert(agent_task_gateway_remote_dispatch_recheck(
               &fixture.mesh, &grant, &lease, &ctx, badge, &dispatch_badge)
           == MESH_AUTHZ_ERR_LEASE_SUBJECT);
    ok("execution lease is bound to the admitted subject and space");

    lease = valid_lease(&grant, &ctx);
    mesh_completion_guard_t completion = {0};
    assert(agent_task_gateway_remote_completion_recheck(
               &fixture.mesh, &grant, &lease, &ctx, badge, &completion, 8u)
           == MESH_AUTHZ_OK);
    assert(agent_task_gateway_remote_completion_recheck(
               &fixture.mesh, &grant, &lease, &ctx, badge, &completion, 8u)
           == MESH_AUTHZ_ERR_DUPLICATE_COMPLETION);
    ok("completion rechecks authority and is accepted exactly once");

    mesh_completion_guard_t revoked_completion = {0};
    mesh_remote_authority_context_t revoked_ctx = ctx;
    revoked_ctx.revocation_epoch++;
    assert(agent_task_gateway_remote_completion_recheck(
               &fixture.mesh, &grant, &lease, &revoked_ctx, badge,
               &revoked_completion, 9u) == MESH_AUTHZ_ERR_REVOKED);
    assert(revoked_completion.completed == 0u);
    ok("completion after revocation is fenced before state mutation");

    assert(cap_broker_remote_badge_recheck(
               &fixture.cap_broker, badge, &grant, OP_READ | OP_WRITE,
               MESH_EFFECT_LOCAL, 10u, ctx.now_unix_ms,
               ctx.authority_epoch, ctx.revocation_epoch)
           == CAP_BROKER_ERR_REMOTE_SCOPE);
    assert(cap_broker_remote_badge_recheck(
               &fixture.cap_broker, badge, &grant, OP_READ,
               MESH_EFFECT_SHARED, 10u, ctx.now_unix_ms,
               ctx.authority_epoch, ctx.revocation_epoch)
           == CAP_BROKER_ERR_REMOTE_SCOPE);
    ok("local badge cannot be widened after CapBroker derivation");

    uint64_t unauthorized_badge = UINT64_C(0xfeed);
    assert(cap_broker_derive_remote_endpoint_badge(
               &fixture.cap_broker, MESH_CALLER_BADGE ^ 1u, &grant, OP_READ,
               MESH_EFFECT_LOCAL, 1u, &unauthorized_badge)
           == CAP_BROKER_ERR_REMOTE_CALLER);
    assert(unauthorized_badge == 0u);
    ok("only the locally badged MeshAgent may ask CapBroker to derive");

    assert(fixture.audit.allowed > 0u && fixture.audit.denied > 0u);
    assert(fixture.audit.last_event_type == EVENTBUS_EVENT_AUTHORITY_CHANGE);
    ok("authorization and denial use canonical authority events");

    puts("remote authority security suite: ok");
    return 0;
}
