/*
 * auth_server.c — Authentication server for FractalOS
 *
 * HURD-equivalent: auth server
 * Priority: 170 (passive, above most services)
 *
 * Provides user/group identity mapped to capability tokens.
 * Analogous to GNU HURD's auth server but using FractalOS capability model.
 *
 * Pre-created users at init:
 *   uid=0 "root"  cap_mask=0xFF (all capabilities)
 *   uid=1 "admin" cap_mask=0x3F (no SWAP_WRITE/SWAP_READ caps)
 *
 * E5-S8: migrated from Microkit to raw seL4 IPC.
 *
 * Copyright (c) 2026 The FractalOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#define FRACTALOS_DEBUG 1
#include "fractalos.h"
#include "contracts/auth_server_contract.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

static bool auth_remote_bytes_equal(const uint8_t *a, const uint8_t *b,
                                    uint32_t length)
{
    uint8_t difference = 0u;
    for (uint32_t i = 0u; i < length; i++) difference |= (uint8_t)(a[i] ^ b[i]);
    return difference == 0u;
}

static bool auth_remote_bytes_zero(const uint8_t *bytes, uint32_t length)
{
    uint8_t combined = 0u;
    for (uint32_t i = 0u; i < length; i++) combined |= bytes[i];
    return combined == 0u;
}

static void auth_remote_put_u32(uint8_t *out, uint32_t value)
{
    for (uint32_t i = 0u; i < 4u; i++) out[i] = (uint8_t)(value >> (i * 8u));
}

static void auth_remote_put_u64(uint8_t *out, uint64_t value)
{
    for (uint32_t i = 0u; i < 8u; i++) out[i] = (uint8_t)(value >> (i * 8u));
}

static void auth_remote_copy(uint8_t *out, const uint8_t *in, uint32_t length)
{
    for (uint32_t i = 0u; i < length; i++) out[i] = in[i];
}

static uint32_t auth_remote_encode_grant(const mesh_remote_grant_t *grant,
                                         uint8_t *out)
{
    uint32_t cursor = 0u;
#define AUTH_GRANT_ID(field) do { \
    auth_remote_copy(out + cursor, (field).bytes, MESH_ID_BYTES); \
    cursor += MESH_ID_BYTES; \
} while (0)
    AUTH_GRANT_ID(grant->issuer);
    AUTH_GRANT_ID(grant->subject_node);
    AUTH_GRANT_ID(grant->subject_agent);
    AUTH_GRANT_ID(grant->audience_node);
    AUTH_GRANT_ID(grant->space_id);
    AUTH_GRANT_ID(grant->interface_hash);
    AUTH_GRANT_ID(grant->object_scope);
#undef AUTH_GRANT_ID
    auth_remote_put_u64(out + cursor, grant->operation_mask); cursor += 8u;
    auth_remote_put_u32(out + cursor, grant->scope_flags); cursor += 4u;
    auth_remote_put_u32(out + cursor, grant->effect_class); cursor += 4u;
    auth_remote_put_u64(out + cursor, grant->budget_units); cursor += 8u;
    auth_remote_put_u64(out + cursor, grant->expiry_unix_ms); cursor += 8u;
    auth_remote_put_u64(out + cursor, grant->authority_epoch); cursor += 8u;
    auth_remote_put_u64(out + cursor, grant->revocation_epoch); cursor += 8u;
    auth_remote_copy(out + cursor, grant->nonce, MESH_NONCE_BYTES);
    cursor += MESH_NONCE_BYTES;
    return cursor;
}

static uint32_t auth_remote_encode_lease(
    const mesh_execution_lease_t *lease, uint8_t *out)
{
    uint32_t cursor = 0u;
    auth_remote_put_u64(out + cursor, lease->lease_id); cursor += 8u;
    auth_remote_put_u64(out + cursor, lease->fence_epoch); cursor += 8u;
    auth_remote_put_u64(out + cursor, lease->expires_unix_ms); cursor += 8u;
    auth_remote_put_u64(out + cursor, lease->authority_epoch); cursor += 8u;
    auth_remote_put_u64(out + cursor, lease->revocation_epoch); cursor += 8u;
    auth_remote_copy(out + cursor, lease->holder_node.bytes, MESH_ID_BYTES);
    cursor += MESH_ID_BYTES;
    auth_remote_copy(out + cursor, lease->subject_agent.bytes, MESH_ID_BYTES);
    cursor += MESH_ID_BYTES;
    auth_remote_copy(out + cursor, lease->space_id.bytes, MESH_ID_BYTES);
    cursor += MESH_ID_BYTES;
    auth_remote_copy(out + cursor, lease->nonce, MESH_NONCE_BYTES);
    cursor += MESH_NONCE_BYTES;
    return cursor;
}

void auth_server_remote_authority_init(
    auth_remote_authority_t *authority,
    auth_server_signature_verify_fn verify_signature, void *verify_ctx)
{
    if (authority == NULL) return;
    uint8_t *bytes = (uint8_t *)authority;
    for (uint32_t i = 0u; i < (uint32_t)sizeof(*authority); i++) bytes[i] = 0u;
    authority->verify_signature = verify_signature;
    authority->verify_ctx = verify_ctx;
}

uint32_t auth_server_remote_trust_issuer(
    auth_remote_authority_t *authority, const mesh_node_id_t *issuer,
    const uint8_t public_key[MESH_ID_BYTES])
{
    if (authority == NULL || issuer == NULL || public_key == NULL ||
        auth_remote_bytes_zero(issuer->bytes, MESH_ID_BYTES) ||
        auth_remote_bytes_zero(public_key, MESH_ID_BYTES))
        return AUTH_REMOTE_ERR_BAD_ARG;

    struct auth_remote_issuer *free_entry = NULL;
    for (uint32_t i = 0u; i < AUTH_REMOTE_MAX_ISSUERS; i++) {
        struct auth_remote_issuer *entry = &authority->issuers[i];
        if (entry->active != 0u &&
            auth_remote_bytes_equal(entry->issuer.bytes, issuer->bytes,
                                    MESH_ID_BYTES)) {
            for (uint32_t j = 0u; j < MESH_ID_BYTES; j++)
                entry->public_key[j] = public_key[j];
            entry->revoked = 0u;
            return AUTH_REMOTE_OK;
        }
        if (entry->active == 0u && free_entry == NULL) free_entry = entry;
    }
    if (free_entry == NULL) return AUTH_REMOTE_ERR_TABLE_FULL;
    free_entry->issuer = *issuer;
    for (uint32_t i = 0u; i < MESH_ID_BYTES; i++)
        free_entry->public_key[i] = public_key[i];
    free_entry->active = 1u;
    free_entry->revoked = 0u;
    return AUTH_REMOTE_OK;
}

uint32_t auth_server_remote_revoke_issuer(
    auth_remote_authority_t *authority, const mesh_node_id_t *issuer)
{
    if (authority == NULL || issuer == NULL) return AUTH_REMOTE_ERR_BAD_ARG;
    for (uint32_t i = 0u; i < AUTH_REMOTE_MAX_ISSUERS; i++) {
        struct auth_remote_issuer *entry = &authority->issuers[i];
        if (entry->active != 0u &&
            auth_remote_bytes_equal(entry->issuer.bytes, issuer->bytes,
                                    MESH_ID_BYTES)) {
            entry->revoked = 1u;
            return AUTH_REMOTE_OK;
        }
    }
    return AUTH_REMOTE_ERR_UNTRUSTED_ISSUER;
}

static const struct auth_remote_issuer *auth_remote_find_issuer(
    const auth_remote_authority_t *authority, const mesh_node_id_t *issuer)
{
    if (authority == NULL || issuer == NULL) return NULL;
    for (uint32_t i = 0u; i < AUTH_REMOTE_MAX_ISSUERS; i++) {
        const struct auth_remote_issuer *entry = &authority->issuers[i];
        if (entry->active != 0u &&
            auth_remote_bytes_equal(entry->issuer.bytes, issuer->bytes,
                                    MESH_ID_BYTES))
            return entry;
    }
    return NULL;
}

uint32_t auth_server_verify_remote_grant(const mesh_remote_grant_t *grant,
                                         void *authority_ptr)
{
    auth_remote_authority_t *authority =
        (auth_remote_authority_t *)authority_ptr;
    if (grant == NULL || authority == NULL || authority->verify_signature == NULL)
        return MESH_REMOTE_AUTHN_BAD_SIGNATURE;
    const struct auth_remote_issuer *issuer =
        auth_remote_find_issuer(authority, &grant->issuer);
    if (issuer == NULL) return MESH_REMOTE_AUTHN_UNTRUSTED_ISSUER;
    if (issuer->revoked != 0u) return MESH_REMOTE_AUTHN_REVOKED_ISSUER;

    static const uint8_t domain[] = MESH_REMOTE_GRANT_SIGNATURE_DOMAIN;
    uint8_t message[(sizeof(domain) - 1u) + MESH_REMOTE_GRANT_SIGNING_BYTES];
    uint32_t cursor = 0u;
    for (uint32_t i = 0u; i < (uint32_t)sizeof(domain) - 1u; i++)
        message[cursor++] = domain[i];
    cursor += auth_remote_encode_grant(grant, message + cursor);
    return authority->verify_signature(
               grant->signature, message, cursor, issuer->public_key,
               authority->verify_ctx) == 0
        ? MESH_REMOTE_AUTHN_OK : MESH_REMOTE_AUTHN_BAD_SIGNATURE;
}

uint32_t auth_server_verify_execution_lease(
    const mesh_execution_lease_t *lease, const mesh_remote_grant_t *grant,
    void *authority_ptr)
{
    auth_remote_authority_t *authority =
        (auth_remote_authority_t *)authority_ptr;
    if (lease == NULL || grant == NULL || authority == NULL ||
        authority->verify_signature == NULL)
        return MESH_REMOTE_AUTHN_BAD_SIGNATURE;
    const struct auth_remote_issuer *issuer =
        auth_remote_find_issuer(authority, &grant->issuer);
    if (issuer == NULL) return MESH_REMOTE_AUTHN_UNTRUSTED_ISSUER;
    if (issuer->revoked != 0u) return MESH_REMOTE_AUTHN_REVOKED_ISSUER;

    static const uint8_t domain[] = MESH_EXECUTION_LEASE_SIGNATURE_DOMAIN;
    uint8_t message[(sizeof(domain) - 1u) + MESH_ID_BYTES +
                    MESH_EXECUTION_LEASE_SIGNING_BYTES];
    uint32_t cursor = 0u;
    for (uint32_t i = 0u; i < (uint32_t)sizeof(domain) - 1u; i++)
        message[cursor++] = domain[i];
    for (uint32_t i = 0u; i < MESH_ID_BYTES; i++)
        message[cursor++] = grant->issuer.bytes[i];
    cursor += auth_remote_encode_lease(lease, message + cursor);
    return authority->verify_signature(
               lease->signature, message, cursor, issuer->public_key,
               authority->verify_ctx) == 0
        ? MESH_REMOTE_AUTHN_OK : MESH_REMOTE_AUTHN_BAD_SIGNATURE;
}

static uint32_t auth_remote_encode_service_ad(
    const mesh_service_advertisement_t *advertisement, uint8_t *out)
{
    uint32_t cursor = 0u;
    auth_remote_copy(out + cursor, advertisement->service_id.bytes, MESH_ID_BYTES);
    cursor += MESH_ID_BYTES;
    auth_remote_copy(out + cursor, advertisement->provider_node.bytes,
                     MESH_ID_BYTES);
    cursor += MESH_ID_BYTES;
    auth_remote_copy(out + cursor, advertisement->interface_hash.bytes,
                     MESH_ID_BYTES);
    cursor += MESH_ID_BYTES;
    auth_remote_copy(out + cursor, advertisement->endpoint, MESH_ENDPOINT_BYTES);
    cursor += MESH_ENDPOINT_BYTES;
    auth_remote_put_u64(out + cursor, advertisement->required_capability);
    cursor += 8u;
    auth_remote_put_u64(out + cursor, advertisement->health_epoch);
    cursor += 8u;
    auth_remote_put_u64(out + cursor, advertisement->expiry_unix_ms);
    cursor += 8u;
    return cursor;
}

uint32_t auth_server_verify_service_advertisement(
    const mesh_service_advertisement_t *advertisement, void *authority_ptr)
{
    auth_remote_authority_t *authority =
        (auth_remote_authority_t *)authority_ptr;
    if (advertisement == NULL || authority == NULL ||
        authority->verify_signature == NULL)
        return MESH_REMOTE_AUTHN_BAD_SIGNATURE;
    const struct auth_remote_issuer *issuer =
        auth_remote_find_issuer(authority, &advertisement->provider_node);
    if (issuer == NULL) return MESH_REMOTE_AUTHN_UNTRUSTED_ISSUER;
    if (issuer->revoked != 0u) return MESH_REMOTE_AUTHN_REVOKED_ISSUER;

    static const uint8_t domain[] = MESH_ADVERTISEMENT_SIGNATURE_DOMAIN;
    uint8_t message[(sizeof(domain) - 1u) + MESH_SERVICE_ADVERTISEMENT_SIGNING_BYTES];
    uint32_t cursor = 0u;
    for (uint32_t i = 0u; i < (uint32_t)sizeof(domain) - 1u; i++)
        message[cursor++] = domain[i];
    cursor += auth_remote_encode_service_ad(advertisement, message + cursor);
    return authority->verify_signature(
               advertisement->signature, message, cursor, issuer->public_key,
               authority->verify_ctx) == 0
        ? MESH_REMOTE_AUTHN_OK : MESH_REMOTE_AUTHN_BAD_SIGNATURE;
}

#ifndef FRACTALOS_REMOTE_AUTHORITY_HOST_TEST
#include "sel4_server.h"
#include "ed25519_verify.h"

static int auth_remote_ed25519_verify(
    const uint8_t signature[MESH_SIGNATURE_BYTES], const uint8_t *message,
    uint32_t message_len, const uint8_t public_key[MESH_ID_BYTES], void *ctx)
{
    (void)ctx;
    return ed25519_verify(signature, message, message_len, public_key);
}

/* ── Configuration ─────────────────────────────────────────────────────── */
#define AUTH_MAX_USERS   16
#define AUTH_MAX_TOKENS  64
#define AUTH_TOKEN_MAGIC 0xA0710001u

/* ── Shared memory region for user name reads ─────────────────────────── */
uintptr_t auth_shmem_vaddr;

/* ── Data structures ───────────────────────────────────────────────────── */
typedef struct {
    uint32_t uid;
    char     name[16];
    uint32_t cap_mask;
    bool     active;
} auth_user_t;

typedef struct {
    uint32_t  token_id;
    uint32_t  uid;
    uint32_t  cap_mask;
    uint64_t  issued_tick;
    bool      valid;
} auth_token_t;

static auth_user_t  users[AUTH_MAX_USERS];
static auth_token_t tokens[AUTH_MAX_TOKENS];
static uint32_t     next_token_id = 1;
static uint64_t     tick_counter  = 0;
static auth_remote_authority_t remote_authority;

/* ── Helpers ───────────────────────────────────────────────────────────── */
static auth_user_t *find_user(uint32_t uid) {
    for (int i = 0; i < AUTH_MAX_USERS; i++)
        if (users[i].active && users[i].uid == uid) return &users[i];
    return (void *)0;
}

static auth_token_t *find_token(uint32_t token_id) {
    for (int i = 0; i < AUTH_MAX_TOKENS; i++)
        if (tokens[i].valid && tokens[i].token_id == token_id) return &tokens[i];
    return (void *)0;
}

static auth_token_t *alloc_token(void) {
    for (int i = 0; i < AUTH_MAX_TOKENS; i++)
        if (!tokens[i].valid) return &tokens[i];
    return (void *)0;
}

/* ── Helpers to read/write msg data fields ─────────────────────────────── */
#ifndef FRACTALOS_IPC_HELPERS_DEFINED
#define FRACTALOS_IPC_HELPERS_DEFINED
static inline uint32_t msg_u32(const sel4_msg_t *m, uint32_t off) {
    uint32_t v = 0;
    if (off + 4u <= SEL4_MSG_DATA_BYTES) {
        v  = (uint32_t)m->data[off];
        v |= (uint32_t)m->data[off+1] << 8;
        v |= (uint32_t)m->data[off+2] << 16;
        v |= (uint32_t)m->data[off+3] << 24;
    }
    return v;
}

static inline void rep_u32(sel4_msg_t *m, uint32_t off, uint32_t v) {
    if (off + 4u <= SEL4_MSG_DATA_BYTES) {
        m->data[off]   = (uint8_t)(v);
        m->data[off+1] = (uint8_t)(v >> 8);
        m->data[off+2] = (uint8_t)(v >> 16);
        m->data[off+3] = (uint8_t)(v >> 24);
    }
}
#endif /* FRACTALOS_IPC_HELPERS_DEFINED */

/* ── Opcode handlers ───────────────────────────────────────────────────── */

static uint32_t handle_login(sel4_badge_t b, const sel4_msg_t *req,
                              sel4_msg_t *rep, void *ctx)
{
    (void)b; (void)ctx;
    uint32_t uid = msg_u32(req, 0);
    auth_user_t *u = find_user(uid);
    if (!u) { rep_u32(rep, 0, 0xFFu); rep->length = 4; return 0xFFu; }
    auth_token_t *t = alloc_token();
    if (!t) { rep_u32(rep, 0, 0xFEu); rep->length = 4; return 0xFEu; }
    t->token_id    = next_token_id++;
    t->uid         = uid;
    t->cap_mask    = u->cap_mask;
    t->issued_tick = tick_counter;
    t->valid       = true;
    rep_u32(rep, 0, 0u);
    rep_u32(rep, 4, t->token_id);
    rep->length = 8;
    return SEL4_ERR_OK;
}

static uint32_t handle_verify(sel4_badge_t b, const sel4_msg_t *req,
                               sel4_msg_t *rep, void *ctx)
{
    (void)b; (void)ctx;
    uint32_t token_id = msg_u32(req, 0);
    auth_token_t *t = find_token(token_id);
    if (!t) { rep_u32(rep, 0, 0xFFu); rep->length = 4; return 0xFFu; }
    rep_u32(rep, 0, 0u);
    rep_u32(rep, 4, t->uid);
    rep_u32(rep, 8, t->cap_mask);
    rep->length = 12;
    return SEL4_ERR_OK;
}

static uint32_t handle_revoke(sel4_badge_t b, const sel4_msg_t *req,
                               sel4_msg_t *rep, void *ctx)
{
    (void)b; (void)ctx;
    uint32_t token_id = msg_u32(req, 0);
    auth_token_t *t = find_token(token_id);
    if (t) t->valid = false;
    rep_u32(rep, 0, 0u);
    rep->length = 4;
    return SEL4_ERR_OK;
}

static uint32_t handle_adduser(sel4_badge_t b, const sel4_msg_t *req,
                                sel4_msg_t *rep, void *ctx)
{
    (void)b; (void)ctx;
    uint32_t uid      = msg_u32(req, 0);
    uint32_t cap_mask = msg_u32(req, 4);
    if (find_user(uid)) { rep_u32(rep, 0, 0xFDu); rep->length = 4; return 0xFDu; }
    auth_user_t *slot = (void *)0;
    for (int i = 0; i < AUTH_MAX_USERS; i++)
        if (!users[i].active) { slot = &users[i]; break; }
    if (!slot) { rep_u32(rep, 0, 0xFCu); rep->length = 4; return 0xFCu; }
    slot->uid      = uid;
    slot->cap_mask = cap_mask;
    slot->active   = true;
    if (auth_shmem_vaddr) {
        const char *name = (const char *)(uintptr_t)auth_shmem_vaddr;
        for (int i = 0; i < 15; i++) {
            slot->name[i] = name[i];
            if (!name[i]) break;
        }
        slot->name[15] = '\0';
    } else {
        slot->name[0] = 'u'; slot->name[1] = '\0';
    }
    rep_u32(rep, 0, 0u);
    rep->length = 4;
    return SEL4_ERR_OK;
}

static uint32_t handle_status(sel4_badge_t b, const sel4_msg_t *req,
                               sel4_msg_t *rep, void *ctx)
{
    (void)b; (void)req; (void)ctx;
    uint32_t atokens = 0, ausers = 0;
    for (int i = 0; i < AUTH_MAX_TOKENS; i++) if (tokens[i].valid)  atokens++;
    for (int i = 0; i < AUTH_MAX_USERS;  i++) if (users[i].active)  ausers++;
    rep_u32(rep, 0, 0u);
    rep_u32(rep, 4, atokens);
    rep_u32(rep, 8, ausers);
    rep->length = 12;
    return SEL4_ERR_OK;
}

static uint32_t handle_remote_verify(sel4_badge_t b, const sel4_msg_t *req,
                                     sel4_msg_t *rep, void *ctx)
{
    (void)b; (void)ctx;
    uint32_t kind = msg_u32(req, 0);
    uint32_t offset = msg_u32(req, 4);
    uint32_t length = msg_u32(req, 8);
    uint32_t result = MESH_REMOTE_AUTHN_BAD_SIGNATURE;
    if (auth_shmem_vaddr != 0u && offset <= 4096u && length <= 4096u - offset) {
        const uint8_t *record =
            (const uint8_t *)(uintptr_t)(auth_shmem_vaddr + offset);
        if (kind == AUTH_REMOTE_RECORD_GRANT &&
            length == sizeof(mesh_remote_grant_t)) {
            result = auth_server_verify_remote_grant(
                (const mesh_remote_grant_t *)record, &remote_authority);
        } else if (kind == AUTH_REMOTE_RECORD_LEASE &&
                   length == sizeof(mesh_remote_grant_t) +
                             sizeof(mesh_execution_lease_t)) {
            result = auth_server_verify_execution_lease(
                (const mesh_execution_lease_t *)(record +
                    sizeof(mesh_remote_grant_t)),
                (const mesh_remote_grant_t *)record, &remote_authority);
        }
    }
    rep_u32(rep, 0, result);
    rep->length = 4u;
    return result == MESH_REMOTE_AUTHN_OK ? SEL4_ERR_OK : result;
}

/* ── Main entry point ──────────────────────────────────────────────────── */

void auth_server_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    (void)ns_ep;

    /* Initialise state */
    for (int i = 0; i < AUTH_MAX_USERS;  i++) users[i].active  = false;
    for (int i = 0; i < AUTH_MAX_TOKENS; i++) tokens[i].valid  = false;
    /* Trust anchors are provisioned locally by the root task. Tailnet peer
     * identity is deliberately not copied into this Agent ISA trust store. */
    auth_server_remote_authority_init(&remote_authority,
                                      auth_remote_ed25519_verify, NULL);

    /* Pre-create root (uid=0) */
    users[0].uid      = 0;
    users[0].cap_mask = 0xFFu;
    users[0].active   = true;
    users[0].name[0]  = 'r'; users[0].name[1] = 'o';
    users[0].name[2]  = 'o'; users[0].name[3] = 't'; users[0].name[4] = '\0';

    /* Pre-create admin (uid=1) */
    users[1].uid      = 1;
    users[1].cap_mask = 0x3Fu;
    users[1].active   = true;
    users[1].name[0]  = 'a'; users[1].name[1] = 'd';
    users[1].name[2]  = 'm'; users[1].name[3] = 'i';
    users[1].name[4]  = 'n'; users[1].name[5] = '\0';

    sel4_dbg_puts("[auth_server] READY: 2 users, root+admin\n");

    static sel4_server_t srv;
    sel4_server_init(&srv, my_ep);
    sel4_server_register(&srv, OP_AUTH_LOGIN,   handle_login,   (void *)0);
    sel4_server_register(&srv, OP_AUTH_VERIFY,  handle_verify,  (void *)0);
    sel4_server_register(&srv, OP_AUTH_REVOKE,  handle_revoke,  (void *)0);
    sel4_server_register(&srv, OP_AUTH_ADDUSER, handle_adduser, (void *)0);
    sel4_server_register(&srv, OP_AUTH_STATUS,  handle_status,  (void *)0);
    sel4_server_register(&srv, OP_AUTH_REMOTE_VERIFY,
                         handle_remote_verify, (void *)0);
    sel4_server_run(&srv);
}

void pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep) { auth_server_main(my_ep, ns_ep); }

/* suppress tick_counter unused warning */
static void _tick(void) { tick_counter++; }
static void (*_tick_fn)(void) __attribute__((unused)) = _tick;
#endif /* !FRACTALOS_REMOTE_AUTHORITY_HOST_TEST */
