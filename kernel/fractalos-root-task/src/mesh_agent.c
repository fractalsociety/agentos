/*
 * FractalOS Mesh Agent Protection Domain
 *
 * Priority 110 (between init_agent=100 and gpu_sched=120).
 *
 * The mesh_agent PD implements the distributed agent mesh layer.
 * It allows FractalOS nodes to discover each other via SquirrelBus
 * and route SPAWN_AGENT requests to the least-loaded peer.
 *
 * Architecture (multi-board FractalOS mesh):
 *   ┌─────────────────────────────────────────────────────────┐
 *   │  Sparky GB10 (primary compute, 4 GPU slots)              │
 *   │   mesh_agent ←→ SquirrelBus ←→ mesh_agent on do-host1   │
 *   └─────────────────────────────────────────────────────────┘
 *   ┌─────────────────────────────────────────────────────────┐
 *   │  do-host1 (orchestrator, CPU-only)                       │
 *   │   mesh_agent routes GPU work → Sparky                    │
 *   └─────────────────────────────────────────────────────────┘
 *
 * IPC:
 *   MSG_MESH_ANNOUNCE: peer node registers (node_id, slot_count, gpu_slots)
 *   MSG_MESH_STATUS:   query peer table (peer_count, total_slots, gpu_slots)
 *   MSG_REMOTE_SPAWN:  spawn on best-fit peer (returns node_id + ticket_id)
 *   MSG_MESH_HEARTBEAT: liveness ping from a peer
 *
 * Peer selection for MSG_REMOTE_SPAWN:
 *   1. If wasm_flags & SPAWN_FLAG_GPU and a peer has free GPU slots → route there
 *   2. Else pick the peer with the most free worker slots (least loaded)
 *   3. If no peers or all saturated → fallback to local pool
 *
 * SquirrelBus integration (userspace, not seL4):
 *   The mesh_agent PD communicates with the SquirrelBus HTTP API via the
 *   controller's outbound notification path. In production, a thin userspace
 *   daemon (mesh_bridge) relays between the seL4 PD and the bus REST endpoint.
 *   Within the seL4 domain we model the bus as a notification channel pair:
 *     CH_SQUIRRELBUS_TX (notify): mesh_agent → bridge → SquirrelBus POST
 *     CH_SQUIRRELBUS_RX (notified): SquirrelBus → bridge → mesh_agent
 *
 * Copyright (c) 2026 The FractalOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "contracts/mesh_agent_contract.h"
#include <stdint.h>
#include <stdbool.h>

static bool mesh_remote_bytes_equal(const uint8_t *a, const uint8_t *b,
                                    uint32_t length)
{
    uint8_t difference = 0u;
    for (uint32_t i = 0u; i < length; i++) difference |= (uint8_t)(a[i] ^ b[i]);
    return difference == 0u;
}

static bool mesh_remote_bytes_zero(const uint8_t *bytes, uint32_t length)
{
    uint8_t combined = 0u;
    for (uint32_t i = 0u; i < length; i++) combined |= bytes[i];
    return combined == 0u;
}

bool mesh_grant_audience_matches(const mesh_remote_grant_t *grant,
                                 const mesh_node_id_t *local_node)
{
    return grant != NULL && local_node != NULL &&
        mesh_remote_bytes_equal(grant->audience_node.bytes,
                                local_node->bytes, MESH_ID_BYTES);
}

bool mesh_epochs_current(const mesh_remote_grant_t *grant,
                         mesh_revocation_epoch_t current)
{
    return grant != NULL && grant->authority_epoch == current.authority_epoch &&
        grant->revocation_epoch == current.revocation_epoch;
}

bool mesh_remote_badge_accepted(uint64_t remote_badge)
{
    (void)remote_badge;
    return false;
}

static uint32_t mesh_remote_emit(
    const mesh_remote_authority_context_t *ctx, uint32_t status,
    const mesh_remote_grant_t *grant, const mesh_execution_lease_t *lease,
    uint64_t local_badge)
{
    if (ctx == NULL || ctx->emit_event == NULL) return MESH_AUTHZ_ERR_EVENT;
    uint32_t event_status = ctx->emit_event(
        EVENTBUS_EVENT_AUTHORITY_CHANGE,
        status == MESH_AUTHZ_OK ? MESH_AUTHZ_DECISION_ALLOW
                                : MESH_AUTHZ_DECISION_DENY,
        status, grant, lease, local_badge, ctx->callback_ctx);
    return event_status == EVENTBUS_AGENT_EVENT_OK ? status
                                                    : MESH_AUTHZ_ERR_EVENT;
}

void mesh_agent_remote_authority_init(mesh_remote_authority_state_t *state)
{
    if (state == NULL) return;
    uint8_t *bytes = (uint8_t *)state;
    for (uint32_t i = 0u; i < (uint32_t)sizeof(*state); i++) bytes[i] = 0u;
}

static uint32_t mesh_remote_authn_status(uint32_t authn)
{
    switch (authn) {
    case MESH_REMOTE_AUTHN_OK: return MESH_AUTHZ_OK;
    case MESH_REMOTE_AUTHN_UNTRUSTED_ISSUER: return MESH_AUTHZ_ERR_ISSUER;
    case MESH_REMOTE_AUTHN_REVOKED_ISSUER: return MESH_AUTHZ_ERR_REVOKED;
    default: return MESH_AUTHZ_ERR_SIGNATURE;
    }
}

static uint32_t mesh_remote_grant_fields_validate(
    const mesh_remote_grant_t *grant,
    const mesh_remote_authority_context_t *ctx)
{
    if (grant == NULL || ctx == NULL || ctx->verify_grant == NULL ||
        ctx->derive_local_badge == NULL || ctx->emit_event == NULL)
        return MESH_AUTHZ_ERR_BAD_ARG;
    if (!mesh_remote_bytes_equal(grant->subject_node.bytes,
                                 ctx->authenticated_tailnet_peer.bytes,
                                 MESH_ID_BYTES))
        return MESH_AUTHZ_ERR_PEER_SUBJECT;
    uint32_t authn = mesh_remote_authn_status(
        ctx->verify_grant(grant, ctx->callback_ctx));
    if (authn != MESH_AUTHZ_OK) return authn;
    if (!mesh_remote_bytes_equal(grant->audience_node.bytes,
                                 ctx->local_node.bytes, MESH_ID_BYTES))
        return MESH_AUTHZ_ERR_AUDIENCE;
    if (!mesh_remote_bytes_equal(grant->subject_agent.bytes,
                                 ctx->expected_agent.bytes, MESH_ID_BYTES))
        return MESH_AUTHZ_ERR_AGENT;
    if (!mesh_remote_bytes_equal(grant->space_id.bytes,
                                 ctx->expected_space.bytes, MESH_ID_BYTES))
        return MESH_AUTHZ_ERR_SPACE;
    if (!mesh_remote_bytes_equal(grant->interface_hash.bytes,
                                 ctx->expected_interface.bytes, MESH_ID_BYTES))
        return MESH_AUTHZ_ERR_INTERFACE;
    if (ctx->requested_operations == 0u ||
        (ctx->requested_operations & ~grant->operation_mask) != 0u)
        return MESH_AUTHZ_ERR_OPERATION;
    if ((ctx->required_scope_flags & ~grant->scope_flags) != 0u ||
        !mesh_remote_bytes_equal(grant->object_scope.bytes,
                                 ctx->expected_object_scope.bytes,
                                 MESH_ID_BYTES))
        return MESH_AUTHZ_ERR_OBJECT_SCOPE;
    if (ctx->requested_effect_class > grant->effect_class ||
        grant->effect_class > ctx->max_effect_class ||
        ctx->max_effect_class > MESH_EFFECT_EXTERNAL)
        return MESH_AUTHZ_ERR_EFFECT;
    if (ctx->requested_budget_units == 0u ||
        ctx->requested_budget_units > grant->budget_units)
        return MESH_AUTHZ_ERR_BUDGET;
    if (grant->expiry_unix_ms <= ctx->now_unix_ms)
        return MESH_AUTHZ_ERR_EXPIRED;
    if (mesh_remote_bytes_zero(grant->nonce, MESH_NONCE_BYTES))
        return MESH_AUTHZ_ERR_NONCE;
    if (grant->authority_epoch != ctx->authority_epoch)
        return MESH_AUTHZ_ERR_STALE_AUTHORITY;
    if (grant->revocation_epoch != ctx->revocation_epoch)
        return MESH_AUTHZ_ERR_REVOKED;
    return MESH_AUTHZ_OK;
}

static int32_t mesh_remote_nonce_find(
    const mesh_remote_authority_state_t *state,
    const mesh_remote_grant_t *grant, uint64_t now_unix_ms)
{
    if (state == NULL || grant == NULL) return -1;
    for (uint32_t i = 0u; i < MESH_REMOTE_NONCE_CACHE_CAP; i++) {
        const struct mesh_remote_nonce_entry *entry = &state->nonces[i];
        if (entry->active != 0u && entry->expiry_unix_ms > now_unix_ms &&
            mesh_remote_bytes_equal(entry->issuer.bytes, grant->issuer.bytes,
                                    MESH_ID_BYTES) &&
            mesh_remote_bytes_equal(entry->nonce, grant->nonce,
                                    MESH_NONCE_BYTES))
            return (int32_t)i;
    }
    return -1;
}

static void mesh_remote_nonce_remember(mesh_remote_authority_state_t *state,
                                       const mesh_remote_grant_t *grant)
{
    uint32_t slot = state->next_nonce++ % MESH_REMOTE_NONCE_CACHE_CAP;
    struct mesh_remote_nonce_entry *entry = &state->nonces[slot];
    *entry = (struct mesh_remote_nonce_entry){0};
    entry->issuer = grant->issuer;
    for (uint32_t i = 0u; i < MESH_NONCE_BYTES; i++)
        entry->nonce[i] = grant->nonce[i];
    entry->expiry_unix_ms = grant->expiry_unix_ms;
    entry->authority_epoch = grant->authority_epoch;
    entry->revocation_epoch = grant->revocation_epoch;
    entry->active = 1u;
}

uint32_t mesh_agent_admit_remote_grant(
    mesh_remote_authority_state_t *state, const mesh_remote_grant_t *grant,
    const mesh_remote_authority_context_t *ctx, uint64_t serialized_badge,
    uint64_t *out_local_badge)
{
    if (out_local_badge != NULL) *out_local_badge = 0u;
    uint32_t status = mesh_remote_grant_fields_validate(grant, ctx);
    if (status == MESH_AUTHZ_OK && (state == NULL || out_local_badge == NULL))
        status = MESH_AUTHZ_ERR_BAD_ARG;
    if (status == MESH_AUTHZ_OK && serialized_badge != 0u)
        status = MESH_AUTHZ_ERR_REMOTE_BADGE;
    if (status == MESH_AUTHZ_OK &&
        mesh_remote_nonce_find(state, grant, ctx->now_unix_ms) >= 0)
        status = MESH_AUTHZ_ERR_REPLAY;
    uint64_t badge = 0u;
    if (status == MESH_AUTHZ_OK) {
        badge = ctx->derive_local_badge(
            grant, ctx->requested_operations, ctx->requested_effect_class,
            ctx->requested_budget_units, ctx->callback_ctx);
        if (badge == 0u) status = MESH_AUTHZ_ERR_CAPBROKER;
    }
    uint32_t emitted = mesh_remote_emit(ctx, status, grant, NULL,
                                        status == MESH_AUTHZ_OK ? badge : 0u);
    if (emitted != status) status = emitted;
    if (status == MESH_AUTHZ_OK) {
        mesh_remote_nonce_remember(state, grant);
        *out_local_badge = badge;
    }
    return status;
}

uint32_t mesh_agent_recheck_remote_grant(
    const mesh_remote_authority_state_t *state,
    const mesh_remote_grant_t *grant,
    const mesh_remote_authority_context_t *ctx, uint64_t *out_local_badge)
{
    if (out_local_badge != NULL) *out_local_badge = 0u;
    uint32_t status = mesh_remote_grant_fields_validate(grant, ctx);
    if (status == MESH_AUTHZ_OK && (state == NULL || out_local_badge == NULL))
        status = MESH_AUTHZ_ERR_BAD_ARG;
    if (status == MESH_AUTHZ_OK &&
        mesh_remote_nonce_find(state, grant, ctx->now_unix_ms) < 0)
        status = MESH_AUTHZ_ERR_NOT_ADMITTED;
    uint64_t badge = 0u;
    if (status == MESH_AUTHZ_OK) {
        badge = ctx->derive_local_badge(
            grant, ctx->requested_operations, ctx->requested_effect_class,
            ctx->requested_budget_units, ctx->callback_ctx);
        if (badge == 0u) status = MESH_AUTHZ_ERR_CAPBROKER;
    }
    uint32_t emitted = mesh_remote_emit(ctx, status, grant, NULL,
                                        status == MESH_AUTHZ_OK ? badge : 0u);
    if (emitted != status) status = emitted;
    if (status == MESH_AUTHZ_OK) *out_local_badge = badge;
    return status;
}

uint32_t mesh_agent_validate_execution_lease(
    const mesh_execution_lease_t *lease, const mesh_remote_grant_t *grant,
    const mesh_remote_authority_context_t *ctx)
{
    uint32_t status = MESH_AUTHZ_OK;
    if (lease == NULL || grant == NULL || ctx == NULL ||
        ctx->verify_lease == NULL || ctx->emit_event == NULL) {
        status = MESH_AUTHZ_ERR_BAD_ARG;
    } else {
        uint32_t authn = mesh_remote_authn_status(
            ctx->verify_lease(lease, grant, ctx->callback_ctx));
        if (authn == MESH_AUTHZ_ERR_SIGNATURE)
            status = MESH_AUTHZ_ERR_LEASE_SIGNATURE;
        else if (authn != MESH_AUTHZ_OK)
            status = authn;
        else if (mesh_remote_bytes_zero(lease->nonce, MESH_NONCE_BYTES))
            status = MESH_AUTHZ_ERR_NONCE;
        else if (lease->expires_unix_ms <= ctx->now_unix_ms ||
                 lease->expires_unix_ms > grant->expiry_unix_ms)
            status = MESH_AUTHZ_ERR_EXPIRED;
        else if (lease->authority_epoch != ctx->authority_epoch ||
                 lease->authority_epoch != grant->authority_epoch)
            status = MESH_AUTHZ_ERR_STALE_AUTHORITY;
        else if (lease->revocation_epoch != ctx->revocation_epoch ||
                 lease->revocation_epoch != grant->revocation_epoch)
            status = MESH_AUTHZ_ERR_REVOKED;
        else if (lease->fence_epoch != ctx->expected_lease_fence_epoch)
            status = MESH_AUTHZ_ERR_LEASE_PARTITIONED;
        else if (!mesh_remote_bytes_equal(
                     lease->holder_node.bytes, grant->subject_node.bytes,
                     MESH_ID_BYTES) ||
                 !mesh_remote_bytes_equal(
                     lease->holder_node.bytes,
                     ctx->authenticated_tailnet_peer.bytes, MESH_ID_BYTES) ||
                 !mesh_remote_bytes_equal(
                     lease->subject_agent.bytes, grant->subject_agent.bytes,
                     MESH_ID_BYTES) ||
                 !mesh_remote_bytes_equal(
                     lease->space_id.bytes, grant->space_id.bytes,
                     MESH_ID_BYTES))
            status = MESH_AUTHZ_ERR_LEASE_SUBJECT;
    }
    return mesh_remote_emit(ctx, status, grant, lease, 0u);
}

#if !defined(FRACTALOS_REMOTE_AUTHORITY_HOST_TEST) && \
    !defined(FRACTALOS_REMOTE_AUTHORITY_ONLY)
#include "sel4_server.h"
#include <string.h>

/* ── Channel IDs ───────────────────────────────────────────────────────────── */
#define CH_CONTROLLER        1   /* controller <-> mesh_agent */
#define CH_EVENTBUS          2   /* eventbus <-> mesh_agent (pp=true) */
#define CH_SQUIRRELBUS_TX    3   /* mesh_agent → SquirrelBus bridge */
#define CH_SQUIRRELBUS_RX    4   /* SquirrelBus bridge → mesh_agent */
#define CH_GPUSCHED          5   /* mesh_agent → gpu_sched for remote GPU tasks */

/* ── Peer registry ─────────────────────────────────────────────────────────── */
#define MAX_PEERS          8
#define NODE_ID_LEN        16   /* up to 15 chars + null */
#define PEER_TIMEOUT_TICKS 30   /* heartbeats missed before marking offline */

/* Spawn flags for MSG_REMOTE_SPAWN */
#define SPAWN_FLAG_GPU     0x01   /* prefer GPU-capable node */
#define SPAWN_FLAG_STRICT  0x02   /* fail if no suitable peer (don't fallback to local) */

typedef struct {
    char     node_id[NODE_ID_LEN];  /* e.g. "sparky", "do-host1" */
    uint32_t worker_slots_total;
    uint32_t worker_slots_free;
    uint32_t gpu_slots_total;
    uint32_t gpu_slots_free;
    uint32_t last_heartbeat;   /* tick counter */
    bool     online;
} peer_entry_t;

/* ── Local node identity ───────────────────────────────────────────────────── */
/* Compiled in at build time via -DFRACTALOS_NODE_ID="\"sparky\"" etc.
 * Falls back to "unknown" if not defined. */
#ifndef FRACTALOS_NODE_ID
#define FRACTALOS_NODE_ID "FractalOS-node"
#endif

/* ── Mesh state ────────────────────────────────────────────────────────────── */
static struct {
    peer_entry_t peers[MAX_PEERS];
    uint32_t     peer_count;
    uint32_t     tick;           /* incremented on each heartbeat notification */
    uint32_t     spawns_local;   /* total spawns routed to local pool */
    uint32_t     spawns_remote;  /* total spawns routed to a peer */
    uint32_t     spawns_failed;  /* total spawn attempts with no available node */
    bool         eventbus_ready;
    bool         squirrelbus_ready;
} mesh;

/* ── Helpers ───────────────────────────────────────────────────────────────── */

static void put_dec(uint32_t v) {
    log_drain_write(15, 15, "0");
    char buf[12]; int i = 11; buf[i] = '\0';
    while (v > 0 && i > 0) { buf[--i] = '0' + (v % 10); v /= 10; }
    log_drain_write(15, 15, &buf[i]);
}

static void puts_safe(const char *s) {
    log_drain_write(15, 15, s);
}

/* Find a peer by node_id string */
static int peer_find(const char *node_id) {
    for (int i = 0; i < MAX_PEERS; i++) {
        if (mesh.peers[i].online &&
            strncmp(mesh.peers[i].node_id, node_id, NODE_ID_LEN - 1) == 0) {
            return i;
        }
    }
    return -1;
}

/* Allocate a new peer slot */
static int peer_alloc(void) {
    for (int i = 0; i < MAX_PEERS; i++) {
        if (!mesh.peers[i].online) return i;
    }
    return -1;
}

/* ── Peer discovery via SquirrelBus ────────────────────────────────────────── */

/*
 * Announce this node to the SquirrelBus mesh channel.
 * Packs announcement into MRs and notifies the bridge.
 *
 * Bridge message format (MRs):
 *   MR0: MSG_MESH_ANNOUNCE
 *   MR1: worker_slots_total (4 bits: local pool)
 *   MR2: worker_slots_free
 *   MR3: gpu_slots_total
 *   MR4: gpu_slots_free
 *   MR5-6: node_id as two packed u32 (8 chars each, LE)
 */
static void mesh_announce_self(uint32_t worker_total, uint32_t worker_free,
                                uint32_t gpu_total, uint32_t gpu_free) {
    IPC_STUB_LOCALS
    if (!mesh.squirrelbus_ready) return;

    /* Pack node_id into two u32s */
    const char *nid = FRACTALOS_NODE_ID;
    uint32_t nid_lo = 0, nid_hi = 0;
    for (int i = 0; i < 4 && nid[i]; i++) nid_lo |= ((uint32_t)(uint8_t)nid[i] << (i * 8));
    for (int i = 0; i < 4 && nid[4 + i]; i++) nid_hi |= ((uint32_t)(uint8_t)nid[4 + i] << (i * 8));

    rep_u32(rep, 0, MSG_MESH_ANNOUNCE);
    rep_u32(rep, 4, worker_total);
    rep_u32(rep, 8, worker_free);
    rep_u32(rep, 12, gpu_total);
    rep_u32(rep, 16, gpu_free);
    rep_u32(rep, 20, nid_lo);
    rep_u32(rep, 24, nid_hi);
    sel4_dbg_puts("[E5-S8] notify-stub\n");

    log_drain_write(15, 15, "[mesh_agent] Announced self to SquirrelBus mesh channel\n");
}

/* ── Peer selection ────────────────────────────────────────────────────────── */

/*
 * Select best peer for a spawn request.
 * Returns peer index (0..MAX_PEERS-1) or -1 for local fallback.
 */
static int select_peer(uint32_t flags) {
    int best = -1;
    uint32_t best_free = 0;
    bool need_gpu = (flags & SPAWN_FLAG_GPU) != 0;

    for (int i = 0; i < MAX_PEERS; i++) {
        peer_entry_t *p = &mesh.peers[i];
        if (!p->online) continue;
        /* Skip if GPU required but peer has no GPU slots */
        if (need_gpu && p->gpu_slots_free == 0) continue;
        uint32_t free_slots = need_gpu ? p->gpu_slots_free : p->worker_slots_free;
        if (free_slots > best_free) {
            best_free = free_slots;
            best = i;
        }
    }
    return best;
}

/* ── EventBus publish ──────────────────────────────────────────────────────── */

static void publish_peer_down(const char *node_id) {
    IPC_STUB_LOCALS
    if (!mesh.eventbus_ready) return;
    /* Pack node_id for event payload */
    uint32_t nid_lo = 0, nid_hi = 0;
    for (int i = 0; i < 4 && node_id[i]; i++) nid_lo |= ((uint32_t)(uint8_t)node_id[i] << (i*8));
    for (int i = 0; i < 4 && node_id[4+i]; i++) nid_hi |= ((uint32_t)(uint8_t)node_id[4+i] << (i*8));
    rep_u32(rep, 0, MSG_EVENT_PUBLISH);
    rep_u32(rep, 4, MSG_MESH_PEER_DOWN);
    rep_u32(rep, 8, nid_lo);
    rep_u32(rep, 12, nid_hi);
    /* E5-S8: ppcall stubbed */
}

/* ── Timeout sweep: mark stale peers offline ───────────────────────────────── */

static void sweep_stale_peers(void) {
    for (int i = 0; i < MAX_PEERS; i++) {
        peer_entry_t *p = &mesh.peers[i];
        if (!p->online) continue;
        if (mesh.tick > p->last_heartbeat + PEER_TIMEOUT_TICKS) {
            log_drain_write(15, 15, "[mesh_agent] Peer offline (timeout): ");
            puts_safe(p->node_id);
            log_drain_write(15, 15, "\n");
            publish_peer_down(p->node_id);
            p->online = false;
            if (mesh.peer_count > 0) mesh.peer_count--;
        }
    }
}

/* ── protected() — synchronous PPC handler ─────────────────────────────────── */

static uint32_t mesh_agent_pd_dispatch(sel4_badge_t b, const sel4_msg_t *req, sel4_msg_t *rep, void *ctx) {
    (void)b; (void)ctx;
    uint64_t tag = msg_u32(req, 0);

    switch ((uint32_t)tag) {

    case MSG_MESH_ANNOUNCE: {
        /*
         * A peer node is registering itself.
         * MR0/1: worker_total/free, MR2/3: gpu_total/free
         * MR4/5: node_id packed as two u32 (LE bytes)
         */
        uint32_t w_total  = (uint32_t)msg_u32(req, 0);
        uint32_t w_free   = (uint32_t)msg_u32(req, 4);
        uint32_t g_total  = (uint32_t)msg_u32(req, 8);
        uint32_t g_free   = (uint32_t)msg_u32(req, 12);
        uint32_t nid_lo   = (uint32_t)msg_u32(req, 16);
        uint32_t nid_hi   = (uint32_t)msg_u32(req, 20);

        /* Unpack node_id */
        char node_id[NODE_ID_LEN] = {0};
        for (int i = 0; i < 4; i++) node_id[i]     = (char)((nid_lo >> (i * 8)) & 0xFF);
        for (int i = 0; i < 4; i++) node_id[4 + i] = (char)((nid_hi >> (i * 8)) & 0xFF);
        node_id[NODE_ID_LEN - 1] = '\0';

        int pi = peer_find(node_id);
        if (pi < 0) {
            pi = peer_alloc();
            if (pi < 0) {
                log_drain_write(15, 15, "[mesh_agent] ANNOUNCE: peer table full\n");
                rep_u32(rep, 0, 0xE1);
                rep->length = 4;
        return SEL4_ERR_OK;
            }
            mesh.peer_count++;
        }

        peer_entry_t *p = &mesh.peers[pi];
        strncpy(p->node_id, node_id, NODE_ID_LEN - 1);
        p->worker_slots_total = w_total;
        p->worker_slots_free  = w_free;
        p->gpu_slots_total    = g_total;
        p->gpu_slots_free     = g_free;
        p->last_heartbeat     = mesh.tick;
        p->online             = true;

        log_drain_write(15, 15, "[mesh_agent] Peer registered: ");
        puts_safe(node_id);
        log_drain_write(15, 15, " workers=");
        put_dec(w_free);
        log_drain_write(15, 15, "/");
        put_dec(w_total);
        log_drain_write(15, 15, " gpu=");
        put_dec(g_free);
        log_drain_write(15, 15, "/");
        put_dec(g_total);
        log_drain_write(15, 15, "\n");

        rep_u32(rep, 0, 0);  /* ok */
        rep->length = 4;
        return SEL4_ERR_OK;
    }

    case MSG_MESH_STATUS: {
        /* Return aggregate mesh state */
        uint32_t total_workers = 0, free_workers = 0;
        uint32_t total_gpu = 0, free_gpu = 0;
        uint32_t online = 0;
        for (int i = 0; i < MAX_PEERS; i++) {
            if (!mesh.peers[i].online) continue;
            online++;
            total_workers += mesh.peers[i].worker_slots_total;
            free_workers  += mesh.peers[i].worker_slots_free;
            total_gpu     += mesh.peers[i].gpu_slots_total;
            free_gpu      += mesh.peers[i].gpu_slots_free;
        }
        rep_u32(rep, 0, online);
        rep_u32(rep, 4, total_workers);
        rep_u32(rep, 8, free_workers);
        rep_u32(rep, 12, total_gpu);
        rep_u32(rep, 16, free_gpu);
        rep_u32(rep, 20, mesh.spawns_local);
        rep_u32(rep, 24, mesh.spawns_remote);
        rep->length = 28;
        return SEL4_ERR_OK;
    }

    case MSG_REMOTE_SPAWN: {
        /*
         * Route a spawn request to the best peer.
         * MR0/1: wasm_hash_lo, MR2/3: wasm_hash_hi
         * MR4: priority, MR5: flags (SPAWN_FLAG_GPU etc.)
         */
        uint64_t hash_lo = (uint64_t)msg_u32(req, 0) | ((uint64_t)msg_u32(req, 4) << 32);
        uint64_t hash_hi = (uint64_t)msg_u32(req, 8) | ((uint64_t)msg_u32(req, 12) << 32);
        uint32_t priority = (uint32_t)msg_u32(req, 16);
        uint32_t flags    = (uint32_t)msg_u32(req, 20);
        (void)hash_lo; (void)hash_hi; (void)priority;

        int peer = select_peer(flags);
        if (peer < 0) {
            if (flags & SPAWN_FLAG_STRICT) {
                mesh.spawns_failed++;
                rep_u32(rep, 0, 0);
                rep_u32(rep, 4, 0xE2);  /* ERR_NO_PEER */
                rep->length = 8;
        return SEL4_ERR_OK;
            }
            /* Fallback: route to local init_agent (MSG_SPAWN_AGENT) */
            log_drain_write(15, 15, "[mesh_agent] REMOTE_SPAWN: no peer available, routing locally\n");
            mesh.spawns_local++;
            rep_u32(rep, 0, 0);        /* node_id = 0 (local) */
            rep_u32(rep, 4, 0);        /* ticket = pending from local pool */
            rep_u32(rep, 8, 0);        /* status: local fallback */
            rep->length = 12;
        return SEL4_ERR_OK;
        }

        peer_entry_t *p = &mesh.peers[peer];
        log_drain_write(15, 15, "[mesh_agent] REMOTE_SPAWN → peer: ");
        puts_safe(p->node_id);
        log_drain_write(15, 15, "\n");

        /* Forward via SquirrelBus bridge */
        if (mesh.squirrelbus_ready) {
            uint32_t nid_lo = 0, nid_hi = 0;
            for (int i = 0; i < 4; i++) nid_lo |= ((uint32_t)(uint8_t)p->node_id[i] << (i*8));
            for (int i = 0; i < 4; i++) nid_hi |= ((uint32_t)(uint8_t)p->node_id[4+i] << (i*8));
            rep_u32(rep, 0, MSG_REMOTE_SPAWN);
            rep_u32(rep, 4, (uint32_t)(hash_lo & 0xFFFFFFFF));
            rep_u32(rep, 8, (uint32_t)((hash_lo >> 32) & 0xFFFFFFFF));
            rep_u32(rep, 12, priority);
            rep_u32(rep, 16, flags);
            rep_u32(rep, 20, nid_lo);
            rep_u32(rep, 24, nid_hi);
            sel4_dbg_puts("[E5-S8] notify-stub\n");
        }

        /* Decrement peer's free slot count optimistically */
        if (flags & SPAWN_FLAG_GPU) {
            if (p->gpu_slots_free > 0) p->gpu_slots_free--;
        } else {
            if (p->worker_slots_free > 0) p->worker_slots_free--;
        }
        mesh.spawns_remote++;

        /* Return peer's packed node_id as confirmation */
        uint32_t nid_r_lo = 0, nid_r_hi = 0;
        for (int i = 0; i < 4; i++) nid_r_lo |= ((uint32_t)(uint8_t)p->node_id[i] << (i*8));
        for (int i = 0; i < 4; i++) nid_r_hi |= ((uint32_t)(uint8_t)p->node_id[4+i] << (i*8));
        rep_u32(rep, 0, nid_r_lo);
        rep_u32(rep, 4, nid_r_hi);
        rep_u32(rep, 8, 0);  /* ticket_id TBD — bridge assigns on delivery */
        rep_u32(rep, 12, 1);  /* status: routed to peer */
        rep->length = 16;
        return SEL4_ERR_OK;
    }

    default:
        rep_u32(rep, 0, 0xFFFF);
        rep->length = 4;
        return SEL4_ERR_OK;
    }
}

/* ── notified() ─────────────────────────────────────────────────────────────── */

static void mesh_agent_pd_notified(uint32_t ch) {
    IPC_STUB_LOCALS
    switch (ch) {
    case CH_CONTROLLER:
        /* Controller signals mesh_agent ready */
        log_drain_write(15, 15, "[mesh_agent] Ready — entering mesh mode\n");
        /* Announce self to the mesh */
        /* worker_total=8 (AGENT_POOL_SIZE), gpu_total=4 (GPU_SLOT_COUNT from gpu_sched.h) */
        mesh_announce_self(8, 8, 4, 4);
        break;

    case CH_SQUIRRELBUS_RX: {
        /*
         * Incoming SquirrelBus message routed to us.
         * MR0 = message tag.
         */
        uint32_t rx_tag = (uint32_t)msg_u32(req, 0);
        switch (rx_tag) {
        case (uint32_t)MSG_MESH_ANNOUNCE: {
            /* Peer announcing itself via the bus — register */
            uint32_t w_total = (uint32_t)msg_u32(req, 4);
            uint32_t w_free  = (uint32_t)msg_u32(req, 8);
            uint32_t g_total = (uint32_t)msg_u32(req, 12);
            uint32_t g_free  = (uint32_t)msg_u32(req, 16);
            uint32_t nid_lo  = (uint32_t)msg_u32(req, 20);
            uint32_t nid_hi  = (uint32_t)msg_u32(req, 24);
            char node_id[NODE_ID_LEN] = {0};
            for (int i = 0; i < 4; i++) node_id[i]     = (char)((nid_lo >> (i*8)) & 0xFF);
            for (int i = 0; i < 4; i++) node_id[4+i]   = (char)((nid_hi >> (i*8)) & 0xFF);

            /* Reuse PPC handler logic via direct struct update */
            int pi = peer_find(node_id);
            if (pi < 0) { pi = peer_alloc(); if (pi >= 0) mesh.peer_count++; }
            if (pi >= 0) {
                peer_entry_t *p = &mesh.peers[pi];
                strncpy(p->node_id, node_id, NODE_ID_LEN - 1);
                p->worker_slots_total = w_total;
                p->worker_slots_free  = w_free;
                p->gpu_slots_total    = g_total;
                p->gpu_slots_free     = g_free;
                p->last_heartbeat     = mesh.tick;
                p->online             = true;
                {
                    char _cl_buf[256] = {};
                    char *_cl_p = _cl_buf;
                    for (const char *_s = "[mesh_agent] Peer joined via bus: "; *_s; _s++) *_cl_p++ = *_s;
                    for (const char *_s = node_id; *_s; _s++) *_cl_p++ = *_s;
                    for (const char *_s = "\n"; *_s; _s++) *_cl_p++ = *_s;
                    *_cl_p = 0;
                    log_drain_write(15, 15, _cl_buf);
                }
            }
            break;
        }
        case (uint32_t)MSG_MESH_HEARTBEAT: {
            uint32_t nid_lo = (uint32_t)msg_u32(req, 4);
            uint32_t nid_hi = (uint32_t)msg_u32(req, 8);
            char node_id[NODE_ID_LEN] = {0};
            for (int i = 0; i < 4; i++) node_id[i]   = (char)((nid_lo >> (i*8)) & 0xFF);
            for (int i = 0; i < 4; i++) node_id[4+i] = (char)((nid_hi >> (i*8)) & 0xFF);
            int pi = peer_find(node_id);
            if (pi >= 0) mesh.peers[pi].last_heartbeat = mesh.tick;
            break;
        }
        default:
            break;
        }
        break;
    }

    case CH_EVENTBUS:
        mesh.eventbus_ready = true;
        /* Subscribe to EventBus for peer-down events */
        rep_u32(rep, 0, CH_EVENTBUS);
        rep_u32(rep, 4, 0);
        /* E5-S8: ppcall stubbed */
        break;

    default:
        break;
    }

    /* Tick-based operations */
    mesh.tick++;
    if ((mesh.tick % 10) == 0) {
        sweep_stale_peers();
    }
}

/* ── init() ─────────────────────────────────────────────────────────────────── */

static void mesh_agent_pd_init(void) {
    /* Zero the mesh state */
    for (int i = 0; i < MAX_PEERS; i++) {
        mesh.peers[i].online = false;
        mesh.peers[i].last_heartbeat = 0;
    }
    mesh.peer_count = 0;
    mesh.tick = 0;
    mesh.spawns_local = 0;
    mesh.spawns_remote = 0;
    mesh.spawns_failed = 0;
    mesh.eventbus_ready = false;
    mesh.squirrelbus_ready = true;  /* bridge assumed ready at boot */

    log_drain_write(15, 15, "[mesh_agent] Distributed Agent Mesh PD online\n[mesh_agent]   node_id=" FRACTALOS_NODE_ID "\n[mesh_agent]   max_peers=8, timeout=30 ticks\n[mesh_agent]   spawn_policy=least-loaded, GPU-affinity\n");

    /* Signal controller: mesh_agent ready */
    sel4_dbg_puts("[E5-S8] notify-stub\n");
}

#endif /* full legacy MeshAgent PD body */
