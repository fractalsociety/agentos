/*
 * agentOS WireGuard Overlay Network Protection Domain — E5-S4: raw seL4 IPC
 *
 * Implements an encrypted agent-to-agent overlay network using the
 * WireGuard protocol (Noise_IKpsk2 with Curve25519, ChaCha20-Poly1305).
 *
 * Migration notes (E5-S4):
 *   - Priority ordering constraint ELIMINATED.  wg_net_main() uses a
 *     sel4_server_t receive loop; callers block on endpoint IPC.
 *   - CH_NET_SERVER_NET_ISOLATOR (id=11) channel replaced with nameserver
 *     lookup for "net".  The resolved cap is stored in g_net_ep and used
 *     for all outbound sel4_call() to net_server.
 *   - Microkit timer notification replaced with seL4 notification on
 *     timer_ntfn_cap (passed to wg_net_main).  The keepalive timer is
 *     driven by a dedicated OP_WG_TIMER_TICK opcode in the server loop or
 *     a separate notification endpoint — no PPC ordering requirement.
 *   - microkit_notify(CH_CONTROLLER) at init() replaced with seL4_Signal().
 *   - wg_net registers itself as "wg_net" with the nameserver at startup.
 *
 * Crypto:
 *   Transport encryption uses RFC 8439 ChaCha20-Poly1305. Handshake messages
 *   use the canonical WireGuard Noise_IKpsk2 transcript and BLAKE2s KDF.
 *
 * Copyright (c) 2026 The agentOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* ── Conditional compilation ─────────────────────────────────────────────── */

#ifdef AGENTOS_TEST_HOST
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef unsigned long      seL4_CPtr;
typedef unsigned long long sel4_badge_t;

typedef struct {
    uint32_t opcode;
    uint32_t length;
    uint8_t  data[48];
} sel4_msg_t;

#define SEL4_ERR_OK          0u
#define SEL4_ERR_INVALID_OP  1u
#define SEL4_ERR_NOT_FOUND   2u
#define SEL4_ERR_PERM        3u
#define SEL4_ERR_BAD_ARG     4u
#define SEL4_ERR_NO_MEM      5u
#define SEL4_ERR_INTERNAL    6u

typedef uint32_t (*sel4_handler_fn)(sel4_badge_t badge,
                                     const sel4_msg_t *req,
                                     sel4_msg_t *rep,
                                     void *ctx);
#define SEL4_SERVER_MAX_HANDLERS 32u
typedef struct {
    struct {
        uint32_t        opcode;
        sel4_handler_fn fn;
        void           *ctx;
    } handlers[SEL4_SERVER_MAX_HANDLERS];
    uint32_t  handler_count;
    seL4_CPtr ep;
} sel4_server_t;

static inline void sel4_server_init(sel4_server_t *srv, seL4_CPtr ep)
{
    srv->handler_count = 0;
    srv->ep            = ep;
    for (uint32_t i = 0; i < SEL4_SERVER_MAX_HANDLERS; i++) {
        srv->handlers[i].opcode = 0;
        srv->handlers[i].fn     = (sel4_handler_fn)0;
        srv->handlers[i].ctx    = (void *)0;
    }
}
static inline int sel4_server_register(sel4_server_t *srv, uint32_t opcode,
                                        sel4_handler_fn fn, void *ctx)
{
    if (srv->handler_count >= SEL4_SERVER_MAX_HANDLERS) return -1;
    srv->handlers[srv->handler_count].opcode = opcode;
    srv->handlers[srv->handler_count].fn     = fn;
    srv->handlers[srv->handler_count].ctx    = ctx;
    srv->handler_count++;
    return 0;
}
static inline uint32_t sel4_server_dispatch(sel4_server_t *srv,
                                             sel4_badge_t badge,
                                             const sel4_msg_t *req,
                                             sel4_msg_t *rep)
{
    for (uint32_t i = 0; i < srv->handler_count; i++) {
        if (srv->handlers[i].opcode == req->opcode) {
            uint32_t rc = srv->handlers[i].fn(badge, req, rep,
                                               srv->handlers[i].ctx);
            rep->opcode = rc;
            return rc;
        }
    }
    rep->opcode = SEL4_ERR_INVALID_OP;
    rep->length = 0;
    return SEL4_ERR_INVALID_OP;
}

static inline uint32_t data_rd32(const uint8_t *d, int off)
{
    return (uint32_t)d[off]
         | ((uint32_t)d[off+1] <<  8)
         | ((uint32_t)d[off+2] << 16)
         | ((uint32_t)d[off+3] << 24);
}
static inline void data_wr32(uint8_t *d, int off, uint32_t v)
{
    d[off  ] = (uint8_t)(v      );
    d[off+1] = (uint8_t)(v >>  8);
    d[off+2] = (uint8_t)(v >> 16);
    d[off+3] = (uint8_t)(v >> 24);
}

/* Most host API tests use deterministic stand-ins. Session integration tests
 * define AGENTOS_TEST_REAL_CRYPTO and link the production implementation. */
#ifdef AGENTOS_TEST_REAL_CRYPTO
#include "monocypher.h"
#else
static inline void crypto_chacha20_poly1305_lock(
                                     uint8_t *ct, uint8_t *mac,
                                     const uint8_t *key, const uint8_t *n,
                                     const uint8_t *ad, size_t ad_sz,
                                     const uint8_t *pt, size_t pt_sz)
{
    (void)key;(void)n;(void)ad;(void)ad_sz;
    for (size_t i = 0; i < pt_sz; i++) ct[i] = pt ? pt[i] : 0;
    for (size_t i = 0; i < 16u; i++) mac[i] = 0;
}
static inline int crypto_chacha20_poly1305_unlock(
                                      uint8_t *pt, const uint8_t *mac,
                                      const uint8_t *key, const uint8_t *n,
                                      const uint8_t *ad, size_t ad_sz,
                                      const uint8_t *ct, size_t ct_sz)
{
    (void)mac;(void)key;(void)n;(void)ad;(void)ad_sz;
    for (size_t i = 0; i < ct_sz; i++) pt[i] = ct[i];
    return 0;
}
static inline void crypto_x25519(uint8_t *out, const uint8_t *sk, const uint8_t *pk)
{
    for (int i = 0; i < 32; i++) out[i] = sk[i] ^ pk[i] ^ 0x42u;
}
#endif

static inline void log_drain_write(int a, int b, const char *s) { (void)a;(void)b;(void)s; }
static inline void agentos_log_boot(const char *s) { (void)s; }
static inline void seL4_Signal(seL4_CPtr cap) { (void)cap; }

/* sel4_call stub — in test mode, outbound calls to net_server are no-ops */
static inline void sel4_call(seL4_CPtr ep, const sel4_msg_t *req, sel4_msg_t *rep)
{
    (void)ep; (void)req;
    rep->opcode = 0; /* NET_OK */
    rep->length = 8;
    /* MR1 = bytes_sent=0 */
    for (int i = 0; i < 48; i++) rep->data[i] = 0;
}

/* OP_NS_REGISTER stub */
#ifndef OP_NS_REGISTER
#define OP_NS_REGISTER 0xD0u
#endif

#else /* !AGENTOS_TEST_HOST */

#define AGENTOS_DEBUG 1
#include "agentos.h"
#include "system_desc.h"
#include "monocypher.h"
#include "sel4_ipc.h"
#include "sel4_server.h"
#include "sel4_client.h"
#include "nameserver.h"
#include "pd_startup_record.h"

static inline uint32_t data_rd32(const uint8_t *d, int off)
{
    return (uint32_t)d[off]
         | ((uint32_t)d[off+1] <<  8)
         | ((uint32_t)d[off+2] << 16)
         | ((uint32_t)d[off+3] << 24);
}
static inline void data_wr32(uint8_t *d, int off, uint32_t v)
{
    d[off  ] = (uint8_t)(v      );
    d[off+1] = (uint8_t)(v >>  8);
    d[off+2] = (uint8_t)(v >> 16);
    d[off+3] = (uint8_t)(v >> 24);
}

#endif /* AGENTOS_TEST_HOST */

/* Host and production builds both take staging geometry, opcodes, and
 * peer layout from wg_net.h so session tests stay aligned with the
 * packet-only NetServer handoff (keys below WG_STAGING_TX_OFF). */
#include "wg_net.h"
#include "wireguard_counter.h"
#include "wireguard_noise.h"
#include "net_server.h"

/* ── Staging region virtual address ──────────────────────────────────────── */
uintptr_t wg_staging_vaddr;
#define WG_STAGING ((volatile uint8_t *)wg_staging_vaddr)

#define WG_AEAD_TAG_LEN      16u
#define WG_TRANSPORT_HDR_LEN 16u

/* ── Module state ────────────────────────────────────────────────────────── */
static wg_peer_t   peers[WG_MAX_PEERS];
static uint32_t    active_peer_count = 0;

static uint8_t     wg_privkey[WG_KEY_LEN];
static uint8_t     wg_pubkey[WG_KEY_LEN];
static bool        wg_privkey_set = false;

static uint32_t    timer_tick    = 0;
static uint32_t    keepalive_due = 0;

static uint32_t    rx_peer_id  = 0;
static uint32_t    rx_data_len = 0;
static bool        rx_pending  = false;

/*
 * g_net_ep — resolved endpoint cap for "net" (net_server) service.
 * Replaces the old CH_NET_SERVER_NET_ISOLATOR (id=11) channel.
 * Set once at startup by register_with_nameserver(); outbound calls use it.
 */
static seL4_CPtr   g_net_ep = 0;

/* sel4_server_t instance */
static sel4_server_t g_srv;

/* ── Logging helpers ─────────────────────────────────────────────────────── */
static void wg_log_dec(uint32_t v) {
    char buf[12];
    int  i = 11;
    buf[i] = '\0';
    if (v == 0) { buf[--i] = '0'; }
    else { while (v > 0 && i > 0) { buf[--i] = '0' + (char)(v % 10); v /= 10; } }
    log_drain_write(16, 16, &buf[i]);
}

static void wg_log_hex(uint32_t v) {
    static const char hex[] = "0123456789abcdef";
    char buf[11];
    buf[0]  = '0'; buf[1]  = 'x';
    buf[2]  = hex[(v >> 28) & 0xf]; buf[3]  = hex[(v >> 24) & 0xf];
    buf[4]  = hex[(v >> 20) & 0xf]; buf[5]  = hex[(v >> 16) & 0xf];
    buf[6]  = hex[(v >> 12) & 0xf]; buf[7]  = hex[(v >>  8) & 0xf];
    buf[8]  = hex[(v >>  4) & 0xf]; buf[9]  = hex[ v        & 0xf];
    buf[10] = '\0';
    log_drain_write(16, 16, buf);
}

/* ── Memory helpers ──────────────────────────────────────────────────────── */
static void wg_copy_from_staging(uint8_t *dst, volatile const uint8_t *src, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) dst[i] = src[i];
}
static void wg_copy_to_staging(volatile uint8_t *dst, const uint8_t *src, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) dst[i] = src[i];
}
static void wg_zero(uint8_t *dst, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) dst[i] = 0;
}

static uint64_t wg_read64_le(const volatile uint8_t *src) {
    uint64_t value = 0u;
    for (uint32_t i = 0u; i < 8u; i++) value |= (uint64_t)src[i] << (8u * i);
    return value;
}

static bool wg_timestamp_after(const uint8_t candidate[WG_NOISE_TIMESTAMP_LEN],
                               const uint8_t previous[WG_NOISE_TIMESTAMP_LEN]) {
    for (uint32_t i = 0u; i < WG_NOISE_TIMESTAMP_LEN; i++) {
        if (candidate[i] > previous[i]) return true;
        if (candidate[i] < previous[i]) return false;
    }
    return false;
}

static bool wg_staging_range(uint32_t offset, uint32_t length,
                             uint32_t start, uint32_t end)
{
    return wg_staging_vaddr != 0u && offset >= start
        && offset + length >= offset && offset + length <= end;
}

static uint32_t wg_message_type(const volatile uint8_t *message)
{
    return (uint32_t)message[0] | ((uint32_t)message[1] << 8u)
        | ((uint32_t)message[2] << 16u) | ((uint32_t)message[3] << 24u);
}

static void wg_session_install(wg_peer_t *peer)
{
    peer->receive_index = peer->handshake.local_index;
    peer->send_index = peer->handshake.remote_index;
    peer->session_established = true;
    peer->tx_counter = 0u;
    wg_replay_window_reset(&peer->rx_replay);
    peer->last_handshake = timer_tick;
}

/* ── Peer table helpers ───────────────────────────────────────────────────── */
static wg_peer_t *find_peer(uint8_t peer_id) {
    for (int i = 0; i < (int)WG_MAX_PEERS; i++) {
        if (peers[i].active && peers[i].peer_id == peer_id)
            return &peers[i];
    }
    return NULL;
}
static wg_peer_t *find_peer_by_handshake_index(uint32_t receiver) {
    for (int i = 0; i < (int)WG_MAX_PEERS; i++) {
        if (peers[i].active && peers[i].handshake.local_index == receiver)
            return &peers[i];
    }
    return NULL;
}
static wg_peer_t *find_peer_by_session_index(uint32_t receiver) {
    for (int i = 0; i < (int)WG_MAX_PEERS; i++) {
        if (peers[i].active && peers[i].session_established
            && peers[i].receive_index == receiver)
            return &peers[i];
    }
    return NULL;
}
static bool wg_index_in_use(uint32_t index, const wg_peer_t *except) {
    if (index == 0u) return true;
    for (int i = 0; i < (int)WG_MAX_PEERS; i++) {
        const wg_peer_t *peer = &peers[i];
        if (!peer->active || peer == except) continue;
        if (peer->handshake.local_index == index
            || (peer->session_established && peer->receive_index == index))
            return true;
    }
    return false;
}
static int alloc_peer_slot(void) {
    for (int i = 0; i < (int)WG_MAX_PEERS; i++) {
        if (!peers[i].active) return i;
    }
    return -1;
}

/* ── ChaCha20-Poly1305 AEAD ──────────────────────────────────────────────── */
static int wg_encrypt(const uint8_t *key, const uint8_t *nonce,
                       const uint8_t *plain, uint32_t plain_len,
                       uint8_t *cipher, uint32_t *cipher_len)
{
    if (plain_len + WG_AEAD_TAG_LEN < plain_len)
        return -1;

    uint8_t mac[WG_AEAD_TAG_LEN];
    crypto_chacha20_poly1305_lock(
        cipher, mac, key, nonce, NULL, 0u,
        plain ? plain : (const uint8_t *)"", (size_t)plain_len);

    for (uint32_t i = 0; i < WG_AEAD_TAG_LEN; i++)
        cipher[plain_len + i] = mac[i];

    *cipher_len = plain_len + WG_AEAD_TAG_LEN;
    return 0;
}

static int wg_decrypt(const uint8_t *key, const uint8_t *nonce,
                       const uint8_t *cipher, uint32_t cipher_len,
                       uint8_t *plain, uint32_t *plain_len)
{
    if (cipher_len < WG_AEAD_TAG_LEN)
        return -1;

    uint32_t ct_len = cipher_len - WG_AEAD_TAG_LEN;
    const uint8_t *mac = cipher + ct_len;

    int rc = crypto_chacha20_poly1305_unlock(
        plain, mac, key, nonce, NULL, 0u, cipher, (size_t)ct_len);
    if (rc != 0) return -1;

    *plain_len = ct_len;
    return 0;
}

static void wg_derive_pubkey(const uint8_t *privkey, uint8_t *pubkey) {
    /* CRYPTO_INTEGRATION_POINT: Curve25519 scalar mult */
    static const uint8_t basepoint[32] = { 9u };
    crypto_x25519(pubkey, privkey, basepoint);
}

/* ── Outbound call to net_server via sel4_call ───────────────────────────── */

/*
 * Forward an encrypted WireGuard packet through NetServer's dedicated,
 * capability-scoped UDP path (OP_NET_WG_UDP_SEND). NetServer maps packet
 * pages only, wraps the ciphertext in an Ethernet/IPv4/UDP envelope that
 * preserves Headscale/netmap peer endpoints, and submits via net_pd's
 * net_device fastpath. Keys never leave this PD.
 *
 * E5-S4: g_net_ep is the nameserver-resolved endpoint for "net".
 */
static void wg_forward_to_net(uint32_t tx_offset, uint32_t pkt_len,
                               wg_peer_t *p)
{
    if (!g_net_ep) return;

    sel4_msg_t req = {0}, rep = {0};
    req.opcode = OP_NET_WG_UDP_SEND;
    data_wr32(req.data, 0, tx_offset);
    data_wr32(req.data, 4, pkt_len);
    data_wr32(req.data, 8, p ? p->endpoint_ip : 0u);
    data_wr32(req.data, 12, p ? (uint32_t)p->endpoint_port : 0u);
    req.length = 16;
    sel4_call(g_net_ep, &req, &rep);

    if (p && rep.opcode == SEL4_ERR_OK && rep.length >= 8u
        && data_rd32(rep.data, 0) == NET_OK)
        p->tx_bytes += data_rd32(rep.data, 4);
}

/* ── Keepalive sender ─────────────────────────────────────────────────────── */
static void send_keepalives(void) {
    if (!wg_privkey_set) return;

    for (int i = 0; i < (int)WG_MAX_PEERS; i++) {
        wg_peer_t *p = &peers[i];
        if (!p->active || !p->session_established) continue;

        if (!wg_staging_vaddr) {
            log_drain_write(16, 16, "[wg_net] keepalive: staging not mapped\n");
            return;
        }

        volatile uint8_t *tx = WG_STAGING + WG_STAGING_TX_OFF;
        tx[0] = 4; tx[1] = 0; tx[2] = 0; tx[3] = 0;
        uint32_t receiver = p->send_index;
        tx[4] = (uint8_t)receiver; tx[5] = (uint8_t)(receiver >> 8u);
        tx[6] = (uint8_t)(receiver >> 16u); tx[7] = (uint8_t)(receiver >> 24u);
        uint8_t nonce[12];
        if (!wg_transport_next_counter(&p->tx_counter, nonce)) continue;
        for (int b = 0; b < 8; b++) tx[8 + b] = nonce[4 + b];

        uint8_t  cipher[WG_AEAD_TAG_LEN];
        uint32_t cipher_len = 0;
        int rc = wg_encrypt(p->send_key, nonce, NULL, 0, cipher, &cipher_len);
        if (rc != 0) continue;

        for (uint32_t b = 0; b < cipher_len; b++)
            tx[WG_TRANSPORT_HDR_LEN + b] = cipher[b];

        uint32_t pkt_len = WG_TRANSPORT_HDR_LEN + cipher_len;
        wg_forward_to_net((uint32_t)WG_STAGING_TX_OFF, pkt_len, p);

        log_drain_write(16, 16, "[wg_net] keepalive -> peer=");
        wg_log_dec(p->peer_id);
        log_drain_write(16, 16, " ep=");
        wg_log_hex(p->endpoint_ip);
        log_drain_write(16, 16, ":");
        wg_log_dec(p->endpoint_port);
        log_drain_write(16, 16, "\n");
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Handler: OP_WG_ADD_PEER
 *   req.data[0..3]   = peer_id
 *   req.data[4..7]   = pubkey_off
 *   req.data[8..11]  = endpoint_ip
 *   req.data[12..15] = endpoint_port
 *   req.data[16..19] = allowed_ip
 *   req.data[20..23] = allowed_mask
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_add_peer(sel4_badge_t badge __attribute__((unused)),
                                  const sel4_msg_t *req,
                                  sel4_msg_t *rep,
                                  void *ctx __attribute__((unused)))
{
    uint32_t peer_id      = data_rd32(req->data,  0);
    uint32_t pubkey_off   = data_rd32(req->data,  4);
    uint32_t endpoint_ip  = data_rd32(req->data,  8);
    uint32_t endpoint_port= data_rd32(req->data, 12);
    uint32_t allowed_ip   = data_rd32(req->data, 16);
    uint32_t allowed_mask = data_rd32(req->data, 20);

    if (peer_id >= WG_MAX_PEERS) {
        log_drain_write(16, 16, "[wg_net] ADD_PEER: invalid peer_id=");
        wg_log_dec(peer_id);
        log_drain_write(16, 16, "\n");
        data_wr32(rep->data, 0, WG_ERR_NOPEER);
        rep->length = 4;
        return SEL4_ERR_BAD_ARG;
    }

    if (active_peer_count >= WG_MAX_PEERS && find_peer((uint8_t)peer_id) == NULL) {
        log_drain_write(16, 16, "[wg_net] ADD_PEER: peer table full\n");
        data_wr32(rep->data, 0, WG_ERR_FULL);
        rep->length = 4;
        return SEL4_ERR_NO_MEM;
    }

    if (!wg_staging_vaddr || pubkey_off + WG_KEY_LEN > 0x20000u) {
        log_drain_write(16, 16, "[wg_net] ADD_PEER: staging not mapped or bad offset\n");
        data_wr32(rep->data, 0, WG_ERR_CRYPTO);
        rep->length = 4;
        return SEL4_ERR_BAD_ARG;
    }

    wg_peer_t *p = find_peer((uint8_t)peer_id);
    if (!p) {
        int slot = alloc_peer_slot();
        if (slot < 0) {
            data_wr32(rep->data, 0, WG_ERR_FULL);
            rep->length = 4;
            return SEL4_ERR_NO_MEM;
        }
        p = &peers[slot];
        active_peer_count++;
    }

    p->peer_id       = (uint8_t)peer_id;
    p->active        = true;
    p->endpoint_ip   = endpoint_ip;
    p->endpoint_port = (uint16_t)(endpoint_port & 0xFFFFu);
    p->allowed_ip    = allowed_ip;
    p->allowed_mask  = allowed_mask;
    p->tx_bytes      = 0;
    p->rx_bytes      = 0;
    p->tx_counter    = 0u;
    wg_replay_window_reset(&p->rx_replay);
    p->last_handshake= 0;
    wg_zero(p->preshared_key, WG_KEY_LEN);

    wg_copy_from_staging(p->pubkey, WG_STAGING + pubkey_off, WG_KEY_LEN);
    wg_noise_handshake_init(&p->handshake, p->pubkey, p->preshared_key);
    wg_zero(p->send_key, WG_KEY_LEN);
    wg_zero(p->receive_key, WG_KEY_LEN);
    p->send_index = 0u;
    p->receive_index = 0u;
    wg_zero(p->last_timestamp, WG_NOISE_TIMESTAMP_LEN);
    p->session_established = false;

    log_drain_write(16, 16, "[wg_net] ADD_PEER: id=");
    wg_log_dec(peer_id);
    log_drain_write(16, 16, " ep=");
    wg_log_hex(endpoint_ip);
    log_drain_write(16, 16, ":");
    wg_log_dec(endpoint_port);
    log_drain_write(16, 16, " allowed=");
    wg_log_hex(allowed_ip);
    log_drain_write(16, 16, "/");
    wg_log_hex(allowed_mask);
    log_drain_write(16, 16, "\n");

    data_wr32(rep->data, 0, WG_OK);
    rep->length = 4;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Handler: OP_WG_REMOVE_PEER
 *   req.data[0..3] = peer_id
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_remove_peer(sel4_badge_t badge __attribute__((unused)),
                                    const sel4_msg_t *req,
                                    sel4_msg_t *rep,
                                    void *ctx __attribute__((unused)))
{
    uint32_t peer_id = data_rd32(req->data, 0);
    wg_peer_t *p = find_peer((uint8_t)peer_id);
    if (!p) {
        log_drain_write(16, 16, "[wg_net] REMOVE_PEER: not found id=");
        wg_log_dec(peer_id);
        log_drain_write(16, 16, "\n");
        data_wr32(rep->data, 0, WG_ERR_NOPEER);
        rep->length = 4;
        return SEL4_ERR_NOT_FOUND;
    }

    log_drain_write(16, 16, "[wg_net] REMOVE_PEER: id=");
    wg_log_dec(peer_id);
    log_drain_write(16, 16, " tx_bytes=");
    wg_log_dec((uint32_t)(p->tx_bytes & 0xFFFFFFFFu));
    log_drain_write(16, 16, " rx_bytes=");
    wg_log_dec((uint32_t)(p->rx_bytes & 0xFFFFFFFFu));
    log_drain_write(16, 16, "\n");

    wg_zero(p->pubkey, WG_KEY_LEN);
    wg_zero(p->preshared_key, WG_KEY_LEN);
    wg_zero(p->send_key, WG_KEY_LEN);
    wg_zero(p->receive_key, WG_KEY_LEN);
    p->send_index = 0u;
    p->receive_index = 0u;
    wg_zero((uint8_t *)&p->handshake, (uint32_t)sizeof(p->handshake));
    wg_zero(p->last_timestamp, WG_NOISE_TIMESTAMP_LEN);
    p->session_established = false;
    p->active  = false;
    p->peer_id = 0;

    if (active_peer_count > 0) active_peer_count--;

    data_wr32(rep->data, 0, WG_OK);
    rep->length = 4;
    return SEL4_ERR_OK;
}

/* Create an initiation without exposing the resident static private key. */
static uint32_t handle_handshake_start(
    sel4_badge_t badge __attribute__((unused)), const sel4_msg_t *req,
    sel4_msg_t *rep, void *ctx __attribute__((unused)))
{
    uint32_t peer_id = data_rd32(req->data, 0);
    uint32_t ephemeral_off = data_rd32(req->data, 4);
    uint32_t timestamp_off = data_rd32(req->data, 8);
    uint32_t sender_index = data_rd32(req->data, 12);
    wg_peer_t *peer = find_peer((uint8_t)peer_id);
    uint8_t ephemeral[WG_NOISE_KEY_LEN], timestamp[WG_NOISE_TIMESTAMP_LEN];
    uint8_t message[WG_NOISE_INITIATION_LEN];

    if (!wg_privkey_set) {
        data_wr32(rep->data, 0, WG_ERR_NOKEY);
        rep->length = 4;
        return SEL4_ERR_PERM;
    }
    if (peer_id >= WG_MAX_PEERS || peer == NULL) {
        data_wr32(rep->data, 0, WG_ERR_NOPEER);
        rep->length = 4;
        return SEL4_ERR_NOT_FOUND;
    }
    if (wg_index_in_use(sender_index, peer)
        || !wg_staging_range(ephemeral_off, WG_NOISE_KEY_LEN, 0u,
                             (uint32_t)WG_STAGING_TX_OFF)
        || !wg_staging_range(timestamp_off, WG_NOISE_TIMESTAMP_LEN, 0u,
                             (uint32_t)WG_STAGING_TX_OFF)) {
        data_wr32(rep->data, 0, WG_ERR_CRYPTO);
        rep->length = 4;
        return SEL4_ERR_BAD_ARG;
    }

    wg_copy_from_staging(ephemeral, WG_STAGING + ephemeral_off,
                         WG_NOISE_KEY_LEN);
    wg_copy_from_staging(timestamp, WG_STAGING + timestamp_off,
                         WG_NOISE_TIMESTAMP_LEN);
    wg_noise_handshake_init(&peer->handshake, peer->pubkey,
                            peer->preshared_key);
    if (wg_noise_create_initiation(&peer->handshake, wg_privkey, wg_pubkey,
                                   ephemeral, timestamp, sender_index,
                                   message) != 0) {
        wg_zero(ephemeral, sizeof(ephemeral));
        wg_zero(timestamp, sizeof(timestamp));
        data_wr32(rep->data, 0, WG_ERR_CRYPTO);
        rep->length = 4;
        return SEL4_ERR_INTERNAL;
    }
    wg_zero(ephemeral, sizeof(ephemeral));
    wg_zero(timestamp, sizeof(timestamp));
    wg_copy_to_staging(WG_STAGING + WG_STAGING_TX_OFF, message,
                       WG_NOISE_INITIATION_LEN);
    wg_zero(message, sizeof(message));
    wg_forward_to_net((uint32_t)WG_STAGING_TX_OFF,
                      WG_NOISE_INITIATION_LEN, peer);

    data_wr32(rep->data, 0, WG_OK);
    data_wr32(rep->data, 4, (uint32_t)WG_STAGING_TX_OFF);
    data_wr32(rep->data, 8, WG_NOISE_INITIATION_LEN);
    rep->length = 12;
    return SEL4_ERR_OK;
}

/* Authenticate handshake/transport messages before changing peer state. */
static uint32_t handle_ingest(sel4_badge_t badge __attribute__((unused)),
                              const sel4_msg_t *req, sel4_msg_t *rep,
                              void *ctx __attribute__((unused)))
{
    uint32_t packet_off = data_rd32(req->data, 0);
    uint32_t packet_len = data_rd32(req->data, 4);
    uint32_t ephemeral_off = data_rd32(req->data, 8);
    uint32_t sender_index = data_rd32(req->data, 12);
    uint32_t ingress_end = (uint32_t)(WG_STAGING_RX_OFF + WG_STAGING_RX_MAX);

    if (!wg_privkey_set) {
        data_wr32(rep->data, 0, WG_ERR_NOKEY);
        rep->length = 4;
        return SEL4_ERR_PERM;
    }
    if (!wg_staging_range(packet_off, packet_len,
                          (uint32_t)WG_STAGING_INGRESS_OFF, ingress_end)
        || packet_len < 4u) {
        data_wr32(rep->data, 0, WG_ERR_CRYPTO);
        rep->length = 4;
        return SEL4_ERR_BAD_ARG;
    }

    volatile const uint8_t *packet = WG_STAGING + packet_off;
    uint32_t type = wg_message_type(packet);
    if (type == 1u) {
        uint8_t initiation[WG_NOISE_INITIATION_LEN];
        uint8_t response[WG_NOISE_RESPONSE_LEN];
        uint8_t ephemeral[WG_NOISE_KEY_LEN];
        uint8_t timestamp[WG_NOISE_TIMESTAMP_LEN];
        wg_peer_t *matched = NULL;
        wg_noise_handshake_t candidate;

        if (packet_len != WG_NOISE_INITIATION_LEN || sender_index == 0u
            || !wg_staging_range(ephemeral_off, WG_NOISE_KEY_LEN, 0u,
                                 (uint32_t)WG_STAGING_TX_OFF)
            || wg_index_in_use(sender_index, NULL)) {
            data_wr32(rep->data, 0, WG_ERR_CRYPTO);
            rep->length = 4;
            return SEL4_ERR_BAD_ARG;
        }
        wg_copy_from_staging(initiation, packet, sizeof(initiation));
        for (uint32_t i = 0u; i < WG_MAX_PEERS; i++) {
            if (!peers[i].active) continue;
            wg_noise_handshake_init(&candidate, peers[i].pubkey,
                                    peers[i].preshared_key);
            if (wg_noise_consume_initiation(
                    &candidate, wg_privkey, wg_pubkey, peers[i].pubkey,
                    initiation, timestamp) == 0
                && wg_timestamp_after(timestamp, peers[i].last_timestamp)) {
                matched = &peers[i];
                break;
            }
        }
        if (matched == NULL) {
            wg_zero(initiation, sizeof(initiation));
            wg_zero(timestamp, sizeof(timestamp));
            data_wr32(rep->data, 0, WG_ERR_CRYPTO);
            rep->length = 4;
            return SEL4_ERR_PERM;
        }

        wg_copy_from_staging(ephemeral, WG_STAGING + ephemeral_off,
                             sizeof(ephemeral));
        matched->handshake = candidate;
        if (wg_noise_create_response(&matched->handshake, ephemeral,
                                     sender_index, response) != 0
            || wg_noise_begin_session(&matched->handshake, matched->send_key,
                                      matched->receive_key) != 0) {
            wg_zero(ephemeral, sizeof(ephemeral));
            wg_zero(initiation, sizeof(initiation));
            wg_zero(timestamp, sizeof(timestamp));
            data_wr32(rep->data, 0, WG_ERR_CRYPTO);
            rep->length = 4;
            return SEL4_ERR_INTERNAL;
        }
        wg_zero(ephemeral, sizeof(ephemeral));
        wg_zero(initiation, sizeof(initiation));
        wg_copy_to_staging(WG_STAGING + WG_STAGING_TX_OFF, response,
                           sizeof(response));
        wg_zero(response, sizeof(response));
        for (uint32_t i = 0u; i < WG_NOISE_TIMESTAMP_LEN; i++)
            matched->last_timestamp[i] = timestamp[i];
        wg_zero(timestamp, sizeof(timestamp));
        wg_session_install(matched);
        wg_forward_to_net((uint32_t)WG_STAGING_TX_OFF,
                          WG_NOISE_RESPONSE_LEN, matched);

        data_wr32(rep->data, 0, WG_OK);
        data_wr32(rep->data, 4, (uint32_t)WG_STAGING_TX_OFF);
        data_wr32(rep->data, 8, WG_NOISE_RESPONSE_LEN);
        rep->length = 12;
        return SEL4_ERR_OK;
    }

    if (type == 2u) {
        uint8_t response[WG_NOISE_RESPONSE_LEN];
        uint32_t receiver;
        wg_peer_t *peer;
        if (packet_len != WG_NOISE_RESPONSE_LEN) {
            data_wr32(rep->data, 0, WG_ERR_CRYPTO);
            rep->length = 4;
            return SEL4_ERR_BAD_ARG;
        }
        wg_copy_from_staging(response, packet, sizeof(response));
        receiver = data_rd32(response, 8);
        peer = find_peer_by_handshake_index(receiver);
        if (peer == NULL
            || wg_noise_consume_response(&peer->handshake, wg_privkey,
                                         wg_pubkey, response) != 0
            || wg_noise_begin_session(&peer->handshake, peer->send_key,
                                      peer->receive_key) != 0) {
            wg_zero(response, sizeof(response));
            data_wr32(rep->data, 0, WG_ERR_CRYPTO);
            rep->length = 4;
            return SEL4_ERR_PERM;
        }
        wg_zero(response, sizeof(response));
        wg_session_install(peer);
        data_wr32(rep->data, 0, WG_OK);
        data_wr32(rep->data, 4, peer->peer_id);
        data_wr32(rep->data, 8, 0u);
        rep->length = 12;
        return SEL4_ERR_OK;
    }

    if (type == 4u) {
        uint32_t receiver, plain_len = 0u;
        uint64_t counter;
        uint8_t nonce[12];
        wg_peer_t *peer;
        wg_replay_window_t proposed;
        if (packet_len < WG_TRANSPORT_HDR_LEN + WG_AEAD_TAG_LEN) {
            data_wr32(rep->data, 0, WG_ERR_CRYPTO);
            rep->length = 4;
            return SEL4_ERR_BAD_ARG;
        }
        receiver = data_rd32((const uint8_t *)packet, 4);
        peer = find_peer_by_session_index(receiver);
        counter = wg_read64_le(packet + 8u);
        if (peer == NULL) {
            data_wr32(rep->data, 0, WG_ERR_NOSESSION);
            rep->length = 4;
            return SEL4_ERR_PERM;
        }
        proposed = peer->rx_replay;
        if (!wg_replay_window_accept(&proposed, counter)) {
            data_wr32(rep->data, 0, WG_ERR_CRYPTO);
            rep->length = 4;
            return SEL4_ERR_PERM;
        }
        wg_transport_counter_nonce(counter, nonce);
        if (wg_decrypt(peer->receive_key, nonce,
                       (const uint8_t *)packet + WG_TRANSPORT_HDR_LEN,
                       packet_len - WG_TRANSPORT_HDR_LEN,
                       (uint8_t *)(wg_staging_vaddr + WG_STAGING_RX_OFF),
                       &plain_len) != 0) {
            data_wr32(rep->data, 0, WG_ERR_CRYPTO);
            rep->length = 4;
            return SEL4_ERR_PERM;
        }
        peer->rx_replay = proposed;
        peer->rx_bytes += plain_len;
        if (plain_len != 0u) {
            rx_pending = true;
            rx_peer_id = peer->peer_id;
            rx_data_len = plain_len;
        }
        data_wr32(rep->data, 0, WG_OK);
        data_wr32(rep->data, 4, peer->peer_id);
        data_wr32(rep->data, 8, plain_len);
        rep->length = 12;
        return SEL4_ERR_OK;
    }

    data_wr32(rep->data, 0, WG_ERR_CRYPTO);
    rep->length = 4;
    return SEL4_ERR_BAD_ARG;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Handler: OP_WG_SEND
 *   req.data[0..3]  = peer_id
 *   req.data[4..7]  = data_off  (offset into wg_staging TX region)
 *   req.data[8..11] = data_len
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_send(sel4_badge_t badge __attribute__((unused)),
                              const sel4_msg_t *req,
                              sel4_msg_t *rep,
                              void *ctx __attribute__((unused)))
{
    uint32_t peer_id  = data_rd32(req->data, 0);
    uint32_t data_off = data_rd32(req->data, 4);
    uint32_t data_len = data_rd32(req->data, 8);

    if (!wg_privkey_set) {
        log_drain_write(16, 16, "[wg_net] SEND: no private key set\n");
        data_wr32(rep->data, 0, WG_ERR_NOKEY);
        data_wr32(rep->data, 4, 0);
        rep->length = 8;
        return SEL4_ERR_PERM;
    }

    wg_peer_t *p = find_peer((uint8_t)peer_id);
    if (!p) {
        log_drain_write(16, 16, "[wg_net] SEND: peer not found id=");
        wg_log_dec(peer_id);
        log_drain_write(16, 16, "\n");
        data_wr32(rep->data, 0, WG_ERR_NOPEER);
        data_wr32(rep->data, 4, 0);
        rep->length = 8;
        return SEL4_ERR_NOT_FOUND;
    }

    if (!p->session_established) {
        data_wr32(rep->data, 0, WG_ERR_NOSESSION);
        data_wr32(rep->data, 4, 0u);
        rep->length = 8;
        return SEL4_ERR_PERM;
    }

    if (!wg_staging_vaddr
            || data_off + data_len < data_off
            || data_off < WG_TRANSPORT_HDR_LEN + WG_AEAD_TAG_LEN
            || data_off + data_len > WG_STAGING_TX_MAX) {
        data_wr32(rep->data, 0, WG_ERR_CRYPTO);
        data_wr32(rep->data, 4, 0);
        rep->length = 8;
        return SEL4_ERR_BAD_ARG;
    }

    uint8_t nonce[12];
    if (!wg_transport_next_counter(&p->tx_counter, nonce)) {
        data_wr32(rep->data, 0, WG_ERR_CRYPTO);
        data_wr32(rep->data, 4, 0u);
        rep->length = 8;
        return SEL4_ERR_INTERNAL;
    }
    const uint8_t *plain = (const uint8_t *)(wg_staging_vaddr
                                              + WG_STAGING_TX_OFF + data_off);

    volatile uint8_t *out = WG_STAGING + WG_STAGING_TX_OFF;
    out[0] = 4; out[1] = 0; out[2] = 0; out[3] = 0;
    uint32_t receiver = p->send_index;
    out[4] = (uint8_t)receiver; out[5] = (uint8_t)(receiver >> 8u);
    out[6] = (uint8_t)(receiver >> 16u); out[7] = (uint8_t)(receiver >> 24u);
    for (int b = 0; b < 8; b++) out[8 + b] = nonce[4 + b];

    uint8_t *cipher_dst = (uint8_t *)(wg_staging_vaddr
                                       + WG_STAGING_TX_OFF
                                       + WG_TRANSPORT_HDR_LEN);
    uint32_t cipher_len = 0;

    int rc = wg_encrypt(p->send_key, nonce, plain, data_len,
                        cipher_dst, &cipher_len);
    if (rc != 0) {
        log_drain_write(16, 16, "[wg_net] SEND: encrypt failed for peer=");
        wg_log_dec(peer_id);
        log_drain_write(16, 16, "\n");
        data_wr32(rep->data, 0, WG_ERR_CRYPTO);
        data_wr32(rep->data, 4, 0);
        rep->length = 8;
        return SEL4_ERR_INTERNAL;
    }

    uint32_t pkt_len = WG_TRANSPORT_HDR_LEN + cipher_len;

    /*
     * Forward to net_server via sel4_call.
     * E5-S4: replaces microkit_ppcall(WG_CH_NET_SERVER, ...).
     * g_net_ep was resolved from nameserver at startup.
     */
    wg_forward_to_net((uint32_t)WG_STAGING_TX_OFF, pkt_len, p);

    log_drain_write(16, 16, "[wg_net] SEND: peer=");
    wg_log_dec(peer_id);
    log_drain_write(16, 16, " plain_len=");
    wg_log_dec(data_len);
    log_drain_write(16, 16, " cipher_len=");
    wg_log_dec(cipher_len);
    log_drain_write(16, 16, "\n");

    data_wr32(rep->data, 0, WG_OK);
    data_wr32(rep->data, 4, cipher_len);
    rep->length = 8;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Handler: OP_WG_RECV
 *   req.data[0..3] = req_peer  (0xFF = any peer)
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_recv(sel4_badge_t badge __attribute__((unused)),
                              const sel4_msg_t *req,
                              sel4_msg_t *rep,
                              void *ctx __attribute__((unused)))
{
    uint32_t req_peer = data_rd32(req->data, 0);

    if (!rx_pending) {
        data_wr32(rep->data,  0, WG_OK);
        data_wr32(rep->data,  4, 0u);
        data_wr32(rep->data,  8, 0u);
        data_wr32(rep->data, 12, 0u);
        rep->length = 16;
        return SEL4_ERR_OK;
    }

    if (req_peer != 0xFFu && rx_peer_id != (uint8_t)req_peer) {
        data_wr32(rep->data,  0, WG_OK);
        data_wr32(rep->data,  4, 0u);
        data_wr32(rep->data,  8, 0u);
        data_wr32(rep->data, 12, 0u);
        rep->length = 16;
        return SEL4_ERR_OK;
    }

    uint32_t peer_out = rx_peer_id;
    uint32_t len_out  = rx_data_len;
    rx_pending  = false;
    rx_data_len = 0;
    rx_peer_id  = 0;

    log_drain_write(16, 16, "[wg_net] RECV: peer=");
    wg_log_dec(peer_out);
    log_drain_write(16, 16, " len=");
    wg_log_dec(len_out);
    log_drain_write(16, 16, "\n");

    data_wr32(rep->data,  0, WG_OK);
    data_wr32(rep->data,  4, peer_out);
    data_wr32(rep->data,  8, (uint32_t)WG_STAGING_RX_OFF);
    data_wr32(rep->data, 12, len_out);
    rep->length = 16;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Handler: OP_WG_STATUS
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_status(sel4_badge_t badge __attribute__((unused)),
                               const sel4_msg_t *req __attribute__((unused)),
                               sel4_msg_t *rep,
                               void *ctx __attribute__((unused)))
{
    uint64_t total_tx = 0, total_rx = 0;
    uint32_t last_hs  = 0;
    for (int i = 0; i < (int)WG_MAX_PEERS; i++) {
        if (!peers[i].active) continue;
        total_tx += peers[i].tx_bytes;
        total_rx += peers[i].rx_bytes;
        if (peers[i].last_handshake > last_hs)
            last_hs = peers[i].last_handshake;
    }

    data_wr32(rep->data,  0, WG_OK);
    data_wr32(rep->data,  4, active_peer_count);
    data_wr32(rep->data,  8, (uint32_t)(total_tx & 0xFFFFFFFFu));
    data_wr32(rep->data, 12, (uint32_t)(total_rx & 0xFFFFFFFFu));
    data_wr32(rep->data, 16, last_hs);
    rep->length = 20;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Handler: OP_WG_SET_PRIVKEY
 *   req.data[0..3] = key_off (offset into wg_staging)
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_set_privkey(sel4_badge_t badge __attribute__((unused)),
                                    const sel4_msg_t *req,
                                    sel4_msg_t *rep,
                                    void *ctx __attribute__((unused)))
{
    uint32_t key_off = data_rd32(req->data, 0);

    if (!wg_staging_vaddr || key_off + WG_KEY_LEN > 0x20000u) {
        log_drain_write(16, 16, "[wg_net] SET_PRIVKEY: staging not mapped or bad offset\n");
        data_wr32(rep->data, 0, WG_ERR_CRYPTO);
        rep->length = 4;
        return SEL4_ERR_BAD_ARG;
    }

    wg_copy_from_staging(wg_privkey, WG_STAGING + key_off, WG_KEY_LEN);
    wg_zero((uint8_t *)(wg_staging_vaddr + key_off), WG_KEY_LEN);

    wg_derive_pubkey(wg_privkey, wg_pubkey);

    wg_copy_to_staging(WG_STAGING + WG_STAGING_PUBKEY_OFF, wg_pubkey, WG_KEY_LEN);

    wg_privkey_set = true;
    for (uint32_t i = 0u; i < WG_MAX_PEERS; i++) {
        if (!peers[i].active) continue;
        wg_noise_handshake_init(&peers[i].handshake, peers[i].pubkey,
                                peers[i].preshared_key);
        wg_zero(peers[i].send_key, WG_KEY_LEN);
        wg_zero(peers[i].receive_key, WG_KEY_LEN);
        peers[i].send_index = 0u;
        peers[i].receive_index = 0u;
        peers[i].session_established = false;
        peers[i].tx_counter = 0u;
        wg_replay_window_reset(&peers[i].rx_replay);
    }

    log_drain_write(16, 16, "[wg_net] SET_PRIVKEY: key loaded, pubkey[0..3]=");
    wg_log_hex((uint32_t)(wg_pubkey[0])
                | ((uint32_t)wg_pubkey[1] << 8)
                | ((uint32_t)wg_pubkey[2] << 16)
                | ((uint32_t)wg_pubkey[3] << 24));
    log_drain_write(16, 16, "\n");

    data_wr32(rep->data, 0, WG_OK);
    rep->length = 4;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Handler: OP_WG_HEALTH
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_health(sel4_badge_t badge __attribute__((unused)),
                               const sel4_msg_t *req __attribute__((unused)),
                               sel4_msg_t *rep,
                               void *ctx __attribute__((unused)))
{
    uint32_t sessions = 0u;
    for (uint32_t i = 0u; i < WG_MAX_PEERS; i++)
        if (peers[i].active && peers[i].session_established) sessions++;
    data_wr32(rep->data, 0, WG_OK);
    data_wr32(rep->data, 4, active_peer_count);
    data_wr32(rep->data, 8, wg_privkey_set ? 1u : 0u);
    data_wr32(rep->data, 12, sessions);
    rep->length = 16;
    return SEL4_ERR_OK;
}

/* ── Nameserver registration + "net" lookup ──────────────────────────────── */
static void register_with_nameserver(seL4_CPtr ns_ep,
                                      seL4_CPtr controller_ntfn)
{
    if (!ns_ep) return;

    /* Register wg_net */
    sel4_msg_t req = {0}, rep = {0};
    req.opcode = (uint32_t)OP_NS_REGISTER;
    data_wr32(req.data,  0, 0u);
    data_wr32(req.data,  4, 0u);
    data_wr32(req.data,  8, 0u);
    data_wr32(req.data, 12, 1u);
    /* Name "wg_net" */
    req.data[16] = 'w'; req.data[17] = 'g'; req.data[18] = '_';
    req.data[19] = 'n'; req.data[20] = 'e'; req.data[21] = 't'; req.data[22] = '\0';
    req.length = 23;
#ifndef AGENTOS_TEST_HOST
    sel4_call(ns_ep, &req, &rep);

#else
    (void)rep;
    g_net_ep = 0;  /* no outbound calls in test mode */
#endif

    /* Notify controller that wg_net is ready.
     * E5-S4: replaces microkit_notify(CH_CONTROLLER).
     */
    if (controller_ntfn)
        seL4_Signal(controller_ntfn);

    log_drain_write(16, 16, "[wg_net] registered as 'wg_net'; net_ep=");
    wg_log_hex((uint32_t)g_net_ep);
    log_drain_write(16, 16, "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * wg_net_test_init() — set up dispatch table for host-side tests
 * ═══════════════════════════════════════════════════════════════════════════ */
static void wg_net_test_init(void)
{
    for (int i = 0; i < (int)WG_MAX_PEERS; i++) {
        peers[i].active  = false;
        peers[i].peer_id = 0;
        wg_zero(peers[i].pubkey, WG_KEY_LEN);
        wg_zero(peers[i].preshared_key, WG_KEY_LEN);
        wg_zero(peers[i].send_key, WG_KEY_LEN);
        wg_zero(peers[i].receive_key, WG_KEY_LEN);
        peers[i].send_index = 0u;
        peers[i].receive_index = 0u;
        wg_zero((uint8_t *)&peers[i].handshake,
                (uint32_t)sizeof(peers[i].handshake));
        wg_zero(peers[i].last_timestamp, WG_NOISE_TIMESTAMP_LEN);
        peers[i].session_established = false;
        peers[i].tx_bytes       = 0;
        peers[i].rx_bytes       = 0;
        peers[i].tx_counter     = 0u;
        wg_replay_window_reset(&peers[i].rx_replay);
        peers[i].last_handshake = 0;
    }
    active_peer_count = 0;

    wg_zero(wg_privkey, WG_KEY_LEN);
    wg_zero(wg_pubkey, WG_KEY_LEN);
    wg_privkey_set = false;

    timer_tick    = 0;
    keepalive_due = WG_KEEPALIVE_SECS;

    rx_pending  = false;
    rx_data_len = 0;
    rx_peer_id  = 0;

    g_net_ep = 0;

    sel4_server_init(&g_srv, 0u);
    sel4_server_register(&g_srv, OP_WG_ADD_PEER,    handle_add_peer,    NULL);
    sel4_server_register(&g_srv, OP_WG_REMOVE_PEER, handle_remove_peer, NULL);
    sel4_server_register(&g_srv, OP_WG_SEND,        handle_send,        NULL);
    sel4_server_register(&g_srv, OP_WG_RECV,        handle_recv,        NULL);
    sel4_server_register(&g_srv, OP_WG_STATUS,      handle_status,      NULL);
    sel4_server_register(&g_srv, OP_WG_SET_PRIVKEY, handle_set_privkey, NULL);
    sel4_server_register(&g_srv, OP_WG_HEALTH,      handle_health,      NULL);
    sel4_server_register(&g_srv, OP_WG_HANDSHAKE_START,
                         handle_handshake_start, NULL);
    sel4_server_register(&g_srv, OP_WG_INGEST,      handle_ingest,      NULL);
}

/* ── dispatch helper for tests ───────────────────────────────────────────── */
static uint32_t wg_net_dispatch_one(sel4_badge_t badge,
                                     const sel4_msg_t *req,
                                     sel4_msg_t *rep)
{
    return sel4_server_dispatch(&g_srv, badge, req, rep);
}

/*
 * wg_net_timer_tick() — advance keepalive timer.
 *
 * E5-S4: called when a seL4 notification arrives on timer_ntfn_cap.
 * Replaces the old notified(CH_TIMER) path.  No Microkit, no PPC ordering.
 */
static void wg_net_timer_tick(void) {
    timer_tick++;
    if (timer_tick >= keepalive_due) {
        send_keepalives();
        keepalive_due = timer_tick + WG_KEEPALIVE_SECS;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * wg_net_main() — raw seL4 IPC entry point
 *
 * Parameters:
 *   my_ep            — this PD's listen endpoint
 *   ns_ep            — nameserver endpoint (for "wg_net" registration and
 *                      "net" lookup)
 *   controller_ntfn  — seL4 notification cap to signal controller at boot
 *
 * E5-S4: CH_NET_SERVER_NET_ISOLATOR (id=11) is gone.  We look up "net" via
 * the nameserver and store the resolved cap in g_net_ep for all outbound
 * OP_NET_VNIC_SEND calls.  No priority constraint.
 * ═══════════════════════════════════════════════════════════════════════════ */
#ifndef AGENTOS_TEST_HOST
void wg_net_main(seL4_CPtr my_ep, seL4_CPtr ns_ep,
                  seL4_CPtr controller_ntfn)
{
    wg_staging_vaddr = (uintptr_t)0x08000000u;
    agentos_log_boot("wg_net");
    log_drain_write(16, 16, "[wg_net] Initialising WireGuard PD (raw seL4 IPC)\n");
    log_drain_write(16, 16, "[wg_net]   priority ordering constraint ELIMINATED\n");
    log_drain_write(16, 16, "[wg_net]   transport_aead=rfc8439-chacha20-poly1305\n");

    wg_net_test_init();
    /* Authority comes from the endpoint installed by root, never from a
     * nameserver channel number or task-controlled metadata. Install it after
     * state initialization so the common host reset cannot erase it. */
    g_net_ep = (seL4_CPtr)PD_CNODE_SLOT_NET_SERVER_EP;

    if (wg_staging_vaddr) {
        volatile uint8_t *s = WG_STAGING;
        for (uint32_t i = 0; i < WG_KEY_LEN * 2; i++) s[i] = 0;
    }

    register_with_nameserver(ns_ep, controller_ntfn);

    log_drain_write(16, 16, "[wg_net] READY — max_peers=");
    wg_log_dec(WG_MAX_PEERS);
    log_drain_write(16, 16, " keepalive_secs=");
    wg_log_dec(WG_KEEPALIVE_SECS);
    log_drain_write(16, 16, "\n");

    g_srv.ep = my_ep;
    sel4_server_run(&g_srv);   /* NEVER RETURNS */
}

void pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    /*
     * The controller-notification cap is supplied by the root task in the
     * per-instance startup record at PD_STARTUP_RECORD_VA (agentos-3ev).  An
     * absent/invalid record yields PD_STARTUP_CAP_NONE, matching the legacy
     * "no direct controller cap" behaviour without hard-coding it.
     */
    const pd_startup_record_t *rec =
        (const pd_startup_record_t *)PD_STARTUP_RECORD_VA;
    seL4_CPtr controller_ntfn =
        (seL4_CPtr)pd_startup_record_controller_ntfn(rec);

    wg_net_main(my_ep, ns_ep, controller_ntfn);
}
#endif /* !AGENTOS_TEST_HOST */
