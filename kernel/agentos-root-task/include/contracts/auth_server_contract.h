/*
 * AuthServer IPC Contract
 *
 * The AuthServer PD is the single authentication authority for agentOS.
 * It issues opaque token IDs on successful login, which other PDs present
 * when invoking capability-guarded operations.  Token-to-capability mappings
 * are authoritative: every system service that checks caller identity must
 * call OP_AUTH_VERIFY rather than cache tokens locally.
 *
 * Channel: CH_AUTH_SERVER = 29 (from controller perspective)
 * Opcodes: OP_AUTH_LOGIN, OP_AUTH_VERIFY, OP_AUTH_REVOKE,
 *          OP_AUTH_ADDUSER, OP_AUTH_STATUS, OP_AUTH_REMOTE_VERIFY,
 *          OP_AUTH_REMOTE_ADVERTISEMENT_VERIFY, OP_AUTH_REMOTE_EPOCH
 *
 * Invariants:
 *   - User name for ADDUSER is a NUL-terminated string placed in shared
 *     memory before the IPC call.
 *   - Tokens are opaque uint32_t values; the AuthServer owns the namespace.
 *   - A token is valid until explicitly revoked or the AuthServer reboots.
 *   - ADDUSER requires the caller to hold AGENTOS_CAP_ADMIN.
 *   - There is no persistent credential store in this revision; user records
 *     are RAM-only and lost on reboot.
 */

#pragma once
#include "../agentos.h"
#include "mesh_agent_contract.h"

/* ─── Channel IDs ────────────────────────────────────────────────────────── */
#ifndef CH_AUTH_SERVER
#define CH_AUTH_SERVER   29u     /* controller → auth_server */
#endif

/* ─── Opcodes ─────────────────────────────────────────────────────────────── */
#define OP_AUTH_LOGIN    0xF0u
#define OP_AUTH_VERIFY   0xF1u
#define OP_AUTH_REVOKE   0xF2u
#define OP_AUTH_ADDUSER  0xF3u
#define OP_AUTH_STATUS   0xF4u
#define OP_AUTH_REMOTE_VERIFY 0xF5u
#define OP_AUTH_REMOTE_ADVERTISEMENT_VERIFY 0xF6u
#define OP_AUTH_REMOTE_EPOCH 0xF7u

/* ─── Request structs ────────────────────────────────────────────────────── */

struct auth_server_req_login {
    uint32_t op;                 /* OP_AUTH_LOGIN */
    uint32_t uid;                /* numeric user identifier */
};

struct auth_server_req_verify {
    uint32_t op;                 /* OP_AUTH_VERIFY */
    uint32_t token_id;           /* token to verify */
};

struct auth_server_req_revoke {
    uint32_t op;                 /* OP_AUTH_REVOKE */
    uint32_t token_id;           /* token to invalidate */
};

struct auth_server_req_adduser {
    uint32_t op;                 /* OP_AUTH_ADDUSER */
    uint32_t uid;                /* numeric user identifier */
    uint32_t cap_mask;           /* AGENTOS_CAP_* bitmask for new user */
    /* NUL-terminated name string in shmem */
};

struct auth_server_req_status {
    uint32_t op;                 /* OP_AUTH_STATUS */
};

struct auth_server_req_remote_verify {
    uint32_t op;                 /* OP_AUTH_REMOTE_VERIFY */
    uint32_t record_kind;        /* AUTH_REMOTE_RECORD_* */
    uint32_t record_offset;      /* byte offset in auth shmem */
    uint32_t record_length;
};

struct auth_server_req_remote_epoch {
    uint32_t op;                 /* OP_AUTH_REMOTE_EPOCH */
};

struct auth_server_req_remote_advertisement {
    uint32_t op;                 /* OP_AUTH_REMOTE_ADVERTISEMENT_VERIFY */
    uint32_t reserved;
    mesh_service_advertisement_t advertisement;
};

/* ─── Reply structs ──────────────────────────────────────────────────────── */

struct auth_server_reply_login {
    uint32_t ok;                 /* AUTH_OK or error code */
    uint32_t token_id;           /* issued token; 0 on error */
};

struct auth_server_reply_verify {
    uint32_t ok;                 /* AUTH_OK or error code */
    uint32_t uid;                /* uid the token belongs to */
    uint32_t cap_mask;           /* AGENTOS_CAP_* bitmask for this token */
};

struct auth_server_reply_revoke {
    uint32_t ok;                 /* AUTH_OK or error code */
};

struct auth_server_reply_adduser {
    uint32_t ok;                 /* AUTH_OK or error code */
};

struct auth_server_reply_status {
    uint32_t ok;                 /* AUTH_OK or error code */
    uint32_t active_tokens;      /* number of live tokens */
    uint32_t active_users;       /* number of registered users */
};

struct auth_server_reply_remote_verify {
    uint32_t ok;                 /* AUTH_OK or AUTH_REMOTE_ERR_* */
    uint32_t issuer_slot;        /* local trust-store slot; never wire authority */
    uint64_t authority_epoch;    /* current trust authority generation */
    uint64_t revocation_epoch;   /* current remote revocation fence */
};

struct auth_server_reply_remote_epoch {
    uint32_t ok;
    uint32_t reserved;
    mesh_revocation_epoch_t epoch;
};

struct auth_server_reply_remote_advertisement {
    uint32_t ok;                 /* AUTH_OK or AUTH_REMOTE_ERR_* */
    uint32_t issuer_slot;
    uint64_t health_epoch;
};

/* ─── Error codes ────────────────────────────────────────────────────────── */

enum auth_server_error {
    AUTH_OK             = 0x00,
    AUTH_ERR_FULL       = 0xFC,  /* token or user table is full */
    AUTH_ERR_EXISTS     = 0xFD,  /* user already registered */
    AUTH_ERR_NOTOKENS   = 0xFE,  /* token not found / invalid */
    AUTH_ERR_NOUSER     = 0xFF,  /* uid not found */
};

enum auth_remote_record_kind {
    AUTH_REMOTE_RECORD_GRANT = 1u,
    AUTH_REMOTE_RECORD_LEASE = 2u,
    AUTH_REMOTE_RECORD_ADVERTISEMENT = 3u,
};

enum auth_remote_error {
    AUTH_REMOTE_OK = 0u,
    AUTH_REMOTE_ERR_BAD_ARG = 1u,
    AUTH_REMOTE_ERR_UNTRUSTED_ISSUER = 2u,
    AUTH_REMOTE_ERR_SIGNATURE = 3u,
    AUTH_REMOTE_ERR_REVOKED_ISSUER = 4u,
    AUTH_REMOTE_ERR_TABLE_FULL = 5u,
    AUTH_REMOTE_ERR_MALFORMED = 6u,
    AUTH_REMOTE_ERR_STALE_EPOCH = 7u,
};

#define AUTH_REMOTE_MAX_ISSUERS 16u

typedef int (*auth_server_signature_verify_fn)(
    const uint8_t signature[MESH_SIGNATURE_BYTES], const uint8_t *message,
    uint32_t message_len, const uint8_t public_key[MESH_ID_BYTES], void *ctx);

struct auth_remote_issuer {
    mesh_node_id_t issuer;
    uint8_t public_key[MESH_ID_BYTES];
    uint8_t active;
    uint8_t revoked;
    uint16_t reserved;
};

struct auth_remote_authority {
    struct auth_remote_issuer issuers[AUTH_REMOTE_MAX_ISSUERS];
    auth_server_signature_verify_fn verify_signature;
    void *verify_ctx;
};
typedef struct auth_remote_authority auth_remote_authority_t;

void auth_server_remote_authority_init(
    auth_remote_authority_t *authority,
    auth_server_signature_verify_fn verify_signature, void *verify_ctx);
uint32_t auth_server_remote_trust_issuer(
    auth_remote_authority_t *authority, const mesh_node_id_t *issuer,
    const uint8_t public_key[MESH_ID_BYTES]);
uint32_t auth_server_remote_revoke_issuer(
    auth_remote_authority_t *authority, const mesh_node_id_t *issuer);
uint32_t auth_server_verify_remote_grant(
    const mesh_remote_grant_t *grant, void *authority);
uint32_t auth_server_verify_execution_lease(
    const mesh_execution_lease_t *lease,
    const mesh_remote_grant_t *grant, void *authority);
uint32_t auth_server_verify_service_advertisement(
    const mesh_service_advertisement_t *advertisement, void *authority);
