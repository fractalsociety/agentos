/*
 * fos-gz0.5 — WireGuard cookie reply + under-load mac2 (L2 host).
 */
#define FRACTALOS_TEST_REAL_CRYPTO 1
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/src/wg_net.c"

static int test_no;
static int failed;

#define CHECK(cond, desc) do {                                                 \
    test_no++;                                                                 \
    if (cond) printf("ok %d - %s\n", test_no, desc);                           \
    else { printf("not ok %d - %s\n", test_no, desc); failed++; }              \
} while (0)

static uint8_t staging[0x20000];

static uint32_t dispatch6(uint32_t opcode, uint32_t a, uint32_t b, uint32_t c,
                          uint32_t d, uint32_t e, uint32_t f, sel4_msg_t *reply)
{
    sel4_msg_t request = {0};
    request.opcode = opcode;
    request.length = 24u;
    data_wr32(request.data, 0, a);
    data_wr32(request.data, 4, b);
    data_wr32(request.data, 8, c);
    data_wr32(request.data, 12, d);
    data_wr32(request.data, 16, e);
    data_wr32(request.data, 20, f);
    *reply = (sel4_msg_t){0};
    return wg_net_dispatch_one(0u, &request, reply);
}

static uint32_t dispatch(uint32_t opcode, uint32_t a, uint32_t b,
                         uint32_t c, uint32_t d, sel4_msg_t *reply)
{
    return dispatch6(opcode, a, b, c, d, 0u, 0u, reply);
}

static int bytes_equal(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    uint8_t d = 0u;
    for (uint32_t i = 0u; i < n; i++) d |= a[i] ^ b[i];
    return d == 0u;
}

int main(void)
{
    static const uint8_t basepoint[32] = {9u};
    uint8_t local_priv[32], remote_priv[32], remote_pub[32], local_pub[32];
    uint8_t local_eph[32], remote_eph[32], secret[32], nonce[24];
    uint8_t timestamp[12] = {0x40, 0, 0, 0, 0, 0, 0, 0x25, 0, 0, 0, 2};
    uint8_t initiation[WG_NOISE_INITIATION_LEN], cookie_reply[64];
    uint8_t cookie[16], decoded[16], addr[6];
    uint8_t response[WG_NOISE_RESPONSE_LEN];
    wg_noise_handshake_t remote_hs;
    sel4_msg_t reply;
    uint32_t src_ip = 0x0A000001u; /* 10.0.0.1 octets LE-packed */
    uint16_t src_port = 51820u;
    uint32_t i;

    printf("1..24\n");
    for (i = 0u; i < 32u; i++) {
        local_priv[i] = (uint8_t)(i + 1u);
        remote_priv[i] = (uint8_t)(i + 65u);
        local_eph[i] = (uint8_t)(i + 101u);
        remote_eph[i] = (uint8_t)(i + 151u);
        secret[i] = (uint8_t)(0xC0u + i);
    }
    for (i = 0u; i < 24u; i++) nonce[i] = (uint8_t)(0xA0u + i);

    crypto_x25519(remote_pub, remote_priv, basepoint);
    memset(staging, 0, sizeof(staging));
    memcpy(staging, local_priv, 32u);
    memcpy(staging + 0x40u, remote_eph, 32u);
    memcpy(staging + 0x60u, timestamp, sizeof(timestamp));
    memcpy(staging + WG_STAGING_COOKIE_NONCE_OFF, nonce, sizeof(nonce));
    memcpy(staging + 0xA0u, secret, sizeof(secret));
    memcpy(staging + WG_STAGING_PEER_KEY_OFF, remote_pub, 32u);
    wg_staging_vaddr = (uintptr_t)staging;
    wg_net_test_init();

    CHECK(dispatch(OP_WG_SET_PRIVKEY, 0u, 0u, 0u, 0u, &reply) == SEL4_ERR_OK,
          "local static key installed");
    memcpy(local_pub, staging + WG_STAGING_PUBKEY_OFF, 32u);
    CHECK(dispatch(OP_WG_ADD_PEER, 0u, WG_STAGING_PEER_KEY_OFF, src_ip, src_port,
                   &reply) == SEL4_ERR_OK, "remote peer registered");
    CHECK(dispatch(OP_WG_SET_COOKIE_SECRET, 0xA0u, 0u, 0u, 0u, &reply)
              == SEL4_ERR_OK,
          "cookie secret installed");
    CHECK(dispatch(OP_WG_SET_UNDER_LOAD, 1u, 0u, 0u, 0u, &reply) == SEL4_ERR_OK,
          "under-load gate enabled");

    /* Independent initiator builds type-1 without mac2. */
    wg_noise_handshake_init(&remote_hs, local_pub, NULL);
    CHECK(wg_noise_create_initiation(&remote_hs, remote_priv, remote_pub,
                                     local_eph, timestamp, 0x11111111u,
                                     initiation) == 0,
          "independent initiation created");
    CHECK(initiation[132] == 0 && initiation[147] == 0,
          "initiation mac2 is zero before cookie");

    memcpy(staging + WG_STAGING_INGRESS_OFF, initiation, sizeof(initiation));
    CHECK(dispatch6(OP_WG_INGEST, WG_STAGING_INGRESS_OFF,
                    WG_NOISE_INITIATION_LEN, 0x40u, 0x22222222u, src_ip,
                    src_port, &reply) == SEL4_ERR_OK,
          "under-load ingest emits cookie reply");
    CHECK(data_rd32(reply.data, 8) == WG_NOISE_COOKIE_REPLY_LEN,
          "cookie reply is 64 bytes");
    CHECK(data_rd32(staging + WG_STAGING_TX_OFF, 0) == 3u,
          "cookie reply has WireGuard type 3");
    memcpy(cookie_reply, staging + WG_STAGING_TX_OFF, sizeof(cookie_reply));

    addr[0] = (uint8_t)src_ip;
    addr[1] = (uint8_t)(src_ip >> 8);
    addr[2] = (uint8_t)(src_ip >> 16);
    addr[3] = (uint8_t)(src_ip >> 24);
    addr[4] = (uint8_t)(src_port >> 8);
    addr[5] = (uint8_t)src_port;
    wg_noise_compute_cookie(cookie, secret, addr, sizeof(addr));
    CHECK(wg_noise_consume_cookie_reply(decoded, cookie_reply,
                                        initiation + 116u, local_pub) == 0,
          "initiator decrypts cookie with responder static");
    CHECK(bytes_equal(decoded, cookie, 16u),
          "decrypted cookie matches secret/IP MAC");

    /* Retry initiation with mac2; responder must complete Noise. */
    wg_noise_handshake_init(&remote_hs, local_pub, NULL);
    CHECK(wg_noise_create_initiation(&remote_hs, remote_priv, remote_pub,
                                     local_eph, timestamp, 0x11111111u,
                                     initiation) == 0,
          "retry initiation after cookie");
    wg_noise_write_mac2(initiation + 132u, initiation, 132u, decoded);
    memcpy(staging + WG_STAGING_INGRESS_OFF, initiation, sizeof(initiation));
    CHECK(dispatch6(OP_WG_INGEST, WG_STAGING_INGRESS_OFF,
                    WG_NOISE_INITIATION_LEN, 0x40u, 0x22222222u, src_ip,
                    src_port, &reply) == SEL4_ERR_OK,
          "under-load ingest accepts mac2 and completes handshake");
    CHECK(data_rd32(reply.data, 8) == WG_NOISE_RESPONSE_LEN,
          "mac2 path returns Noise response");
    CHECK(peers[0].session_established,
          "responder session established after cookie retry");

    /* Initiator-side: HANDSHAKE_START remembers mac1; ingest type 3 stores cookie;
     * next start attaches mac2. */
    wg_net_test_init();
    memset(staging, 0, sizeof(staging));
    memcpy(staging, local_priv, 32u);
    memcpy(staging + 0x40u, local_eph, 32u);
    memcpy(staging + 0x60u, timestamp, sizeof(timestamp));
    memcpy(staging + WG_STAGING_PEER_KEY_OFF, remote_pub, 32u);
    for (i = 0u; i < 24u; i++) staging[WG_STAGING_COOKIE_NONCE_OFF + i] =
                                    (uint8_t)(0xB0u + i);
    wg_staging_vaddr = (uintptr_t)staging;
    CHECK(dispatch(OP_WG_SET_PRIVKEY, 0u, 0u, 0u, 0u, &reply) == SEL4_ERR_OK,
          "re-init local key for initiator cookie path");
    memcpy(local_pub, staging + WG_STAGING_PUBKEY_OFF, 32u);
    CHECK(dispatch(OP_WG_ADD_PEER, 0u, WG_STAGING_PEER_KEY_OFF, src_ip, src_port,
                   &reply) == SEL4_ERR_OK, "peer re-registered");
    CHECK(dispatch(OP_WG_HANDSHAKE_START, 0u, 0x40u, 0x60u, 0x33333333u,
                   &reply) == SEL4_ERR_OK,
          "initiator creates first initiation");
    memcpy(initiation, staging + WG_STAGING_TX_OFF, sizeof(initiation));
    CHECK(peers[0].have_sent_mac1, "initiator retained mac1 for cookie AAD");

    wg_noise_compute_cookie(cookie, secret, addr, sizeof(addr));
    CHECK(wg_noise_create_cookie_reply(cookie_reply, 0x33333333u,
                                       staging + WG_STAGING_COOKIE_NONCE_OFF,
                                       cookie, initiation + 116u,
                                       remote_pub) == 0,
          "peer builds cookie reply for our initiation");
    memcpy(staging + WG_STAGING_INGRESS_OFF, cookie_reply, sizeof(cookie_reply));
    CHECK(dispatch(OP_WG_INGEST, WG_STAGING_INGRESS_OFF,
                   WG_NOISE_COOKIE_REPLY_LEN, 0u, 0u, &reply) == SEL4_ERR_OK,
          "initiator ingests type-3 cookie reply");
    CHECK(peers[0].cookie_valid, "peer cookie marked valid");

    CHECK(dispatch(OP_WG_HANDSHAKE_START, 0u, 0x40u, 0x60u, 0x44444444u,
                   &reply) == SEL4_ERR_OK,
          "second initiation after cookie");
    memcpy(initiation, staging + WG_STAGING_TX_OFF, sizeof(initiation));
    {
        uint8_t expected_mac2[16];
        wg_noise_write_mac2(expected_mac2, initiation, 132u,
                            peers[0].latest_cookie);
        CHECK(bytes_equal(initiation + 132u, expected_mac2, 16u),
              "second initiation carries mac2 from cookie");
    }

    (void)response;
    return failed ? 1 : 0;
}
