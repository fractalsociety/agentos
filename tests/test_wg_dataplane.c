/*
 * fos-gz0.5 — multi-peer dataplane host proof:
 *   netmap apply → sessions → UDP forward → DERP fallback → roam → rekey.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FRACTALOS_TEST_REAL_CRYPTO 1
#include "../kernel/fractalos-root-task/src/wireguard_derp.c"
#include "../kernel/fractalos-root-task/src/wg_net.c"

static int test_no;
static int failed;
#define CHECK(condition, description) do {                                      \
    test_no++;                                                                  \
    if (condition) printf("ok %d - %s\n", test_no, description);              \
    else { printf("not ok %d - %s\n", test_no, description); failed++; }       \
} while (0)

static uint8_t staging[0x20000];

static uint32_t dispatch(uint32_t opcode, uint32_t a, uint32_t b,
                         uint32_t c, uint32_t d, sel4_msg_t *reply)
{
    sel4_msg_t request = {0};
    request.opcode = opcode;
    request.length = 16u;
    data_wr32(request.data, 0, a);
    data_wr32(request.data, 4, b);
    data_wr32(request.data, 8, c);
    data_wr32(request.data, 12, d);
    *reply = (sel4_msg_t){0};
    return wg_net_dispatch_one(0u, &request, reply);
}

static void write_netmap_peer(uint8_t *dst, const uint8_t pubkey[32],
                              uint32_t ip, uint16_t port, uint32_t allowed,
                              uint32_t mask)
{
    struct wg_netmap_peer pe;
    memset(&pe, 0, sizeof(pe));
    memcpy(pe.pubkey, pubkey, 32u);
    pe.endpoint_ip = ip;
    pe.endpoint_port = port;
    pe.allowed_ip = allowed;
    pe.allowed_mask = mask;
    memcpy(dst, &pe, sizeof(pe));
}

/* Local wg_net is initiator; remote is an independent Noise responder. */
static int establish_session(uint8_t peer_id, const uint8_t remote_priv[32],
                             const uint8_t remote_pub[32],
                             const uint8_t local_pub[32], uint32_t eph_off,
                             uint32_t ts_off, uint32_t sender_index)
{
    uint8_t remote_eph[32], initiation[WG_NOISE_INITIATION_LEN];
    uint8_t response[WG_NOISE_RESPONSE_LEN], decoded_ts[12];
    uint8_t remote_send[32], remote_recv[32];
    wg_noise_handshake_t remote;
    sel4_msg_t reply;
    uint32_t i;

    for (i = 0u; i < 32u; i++)
        remote_eph[i] = (uint8_t)(0x40u + peer_id + i);

    if (dispatch(OP_WG_HANDSHAKE_START, peer_id, eph_off, ts_off, sender_index,
                 &reply) != SEL4_ERR_OK)
        return -1;
    memcpy(initiation, staging + WG_STAGING_TX_OFF, WG_NOISE_INITIATION_LEN);

    wg_noise_handshake_init(&remote, local_pub, NULL);
    if (wg_noise_consume_initiation(&remote, remote_priv, remote_pub,
                                    local_pub, initiation, decoded_ts) != 0)
        return -2;
    if (wg_noise_create_response(&remote, remote_eph, sender_index + 100u,
                                 response) != 0)
        return -3;
    if (wg_noise_begin_session(&remote, remote_send, remote_recv) != 0)
        return -4;
    memcpy(staging + WG_STAGING_INGRESS_OFF, response, WG_NOISE_RESPONSE_LEN);
    if (dispatch(OP_WG_INGEST, WG_STAGING_INGRESS_OFF, WG_NOISE_RESPONSE_LEN,
                 0u, 0u, &reply) != SEL4_ERR_OK)
        return -5;
    (void)remote_send;
    (void)remote_recv;
    return 0;
}

int main(void)
{
    static const uint8_t basepoint[32] = {9u};
    uint8_t local_priv[32], priv_a[32], priv_b[32], pub_a[32], pub_b[32];
    uint8_t local_pub[32], eph[32], timestamp[12] = {
        0x40, 0, 0, 0, 0, 0, 0, 0x30, 0, 0, 0, 1
    };
    uint8_t plain[] = "multi-peer-ping";
    uint32_t map_off = 0x18000u;
    uint32_t udp_before;
    sel4_msg_t reply;
    wg_peer_t *pa;
    wg_peer_t *pb;
    uint32_t i;
    uint8_t sk0;

    printf("1..27\n");
    for (i = 0u; i < 32u; i++) {
        local_priv[i] = (uint8_t)(i + 3u);
        priv_a[i] = (uint8_t)(i + 33u);
        priv_b[i] = (uint8_t)(i + 77u);
        eph[i] = (uint8_t)(i + 110u);
    }
    crypto_x25519(pub_a, priv_a, basepoint);
    crypto_x25519(pub_b, priv_b, basepoint);

    memset(staging, 0, sizeof(staging));
    memcpy(staging, local_priv, 32u);
    memcpy(staging + 0x40u, eph, 32u);
    memcpy(staging + 0x60u, timestamp, sizeof(timestamp));
    wg_staging_vaddr = (uintptr_t)staging;
    wg_net_test_init();

    CHECK(dispatch(OP_WG_SET_PRIVKEY, 0u, 0u, 0u, 0u, &reply) == SEL4_ERR_OK,
          "local key installed");
    memcpy(local_pub, staging + WG_STAGING_PUBKEY_OFF, 32u);

    {
        struct wg_netmap_header hdr = {
            .version = WG_NETMAP_VERSION,
            .peer_count = 2u,
        };
        memcpy(staging + map_off, &hdr, sizeof(hdr));
        write_netmap_peer(staging + map_off + 8u, pub_a, 0x0A000201u, 51820u,
                          0x0A800001u, 0xFFFFFFFFu);
        write_netmap_peer(staging + map_off + 8u + 48u, pub_b, 0x0A000202u,
                          51820u, 0x0A800002u, 0xFFFFFFFFu);
    }
    CHECK(dispatch(OP_WG_APPLY_NETMAP, map_off,
                   8u + 2u * WG_NETMAP_PEER_BYTES, 0u, 0u, &reply)
              == SEL4_ERR_OK,
          "netmap applies two peers");
    CHECK(active_peer_count == 2u, "two active peers");

    pa = find_peer_by_pubkey(pub_a);
    pb = find_peer_by_pubkey(pub_b);
    CHECK(pa != NULL && pb != NULL, "peers A and B present");
    CHECK(establish_session(pa->peer_id, priv_a, pub_a, local_pub, 0x40u, 0x60u,
                            7u) == 0,
          "session A established");
    /* Fresh ephemeral/timestamp for second initiation. */
    for (i = 0u; i < 32u; i++)
        staging[0x40u + i] = (uint8_t)(0x90u + i);
    timestamp[11] = 2;
    memcpy(staging + 0x60u, timestamp, sizeof(timestamp));
    CHECK(establish_session(pb->peer_id, priv_b, pub_b, local_pub, 0x40u, 0x60u,
                            9u) == 0,
          "session B established");

    udp_before = g_test_wg_udp_calls;
    memcpy(staging + WG_STAGING_TX_OFF + 0x100u, plain, sizeof(plain));
    CHECK(dispatch(OP_WG_SEND, pa->peer_id, 0x100u, sizeof(plain), 0u, &reply)
              == SEL4_ERR_OK,
          "SEND peer A over direct path");
    CHECK(data_rd32(reply.data, 0) == WG_OK
          && data_rd32(reply.data, 12) == WG_PATH_DIRECT,
          "SEND reports direct path");
    CHECK(g_test_wg_udp_calls == udp_before + 1u, "UDP forward invoked once");
    CHECK(g_test_last_wg_udp_ip == 0x0A000201u
          && g_test_last_wg_udp_port == 51820u,
          "UDP forward carries netmap endpoint");
    CHECK(g_test_last_wg_udp_len >= WG_TRANSPORT_HDR_LEN + sizeof(plain),
          "UDP payload covers transport ciphertext");

    CHECK(dispatch(OP_WG_SET_PATH_MODE, pa->peer_id, WG_PATH_DERP, 0u, 0u,
                   &reply) == SEL4_ERR_OK,
          "path mode DERP");
    udp_before = g_test_wg_udp_calls;
    memcpy(staging + WG_STAGING_TX_OFF + 0x100u, plain, sizeof(plain));
    CHECK(dispatch(OP_WG_SEND, pa->peer_id, 0x100u, sizeof(plain), 0u, &reply)
              == SEL4_ERR_OK,
          "SEND peer A over DERP path");
    CHECK(data_rd32(reply.data, 12) == WG_PATH_DERP
          && data_rd32(reply.data, 8) > 0u,
          "SEND reports DERP frame length");
    CHECK(g_test_wg_udp_calls == udp_before, "DERP path skips UDP forward");
    CHECK(staging[WG_STAGING_INGRESS_OFF] == WG_DERP_FRAME_SEND_PACKET,
          "DERP frame written to ingress staging");

    CHECK(dispatch(OP_WG_SET_PATH_MODE, pa->peer_id, WG_PATH_DIRECT, 0u, 0u,
                   &reply) == SEL4_ERR_OK,
          "path mode direct again");
    sk0 = pa->send_key[0];
    {
        struct wg_netmap_header hdr = {
            .version = WG_NETMAP_VERSION,
            .peer_count = 2u,
        };
        memcpy(staging + map_off, &hdr, sizeof(hdr));
        write_netmap_peer(staging + map_off + 8u, pub_a, 0x0A000299u, 41641u,
                          0x0A800001u, 0xFFFFFFFFu);
        write_netmap_peer(staging + map_off + 8u + 48u, pub_b, 0x0A000202u,
                          51820u, 0x0A800002u, 0xFFFFFFFFu);
        CHECK(dispatch(OP_WG_APPLY_NETMAP, map_off,
                       8u + 2u * WG_NETMAP_PEER_BYTES, 0u, 0u, &reply)
                  == SEL4_ERR_OK,
              "netmap roam under live session");
        CHECK(data_rd32(reply.data, 12) >= 1u, "roam counted");
        CHECK(pa->session_established && pa->send_key[0] == sk0,
              "roam retains transport keys");
        CHECK(pa->endpoint_ip == 0x0A000299u && pa->endpoint_port == 41641u,
              "endpoint updated");
    }

    memcpy(staging + WG_STAGING_TX_OFF + 0x100u, plain, sizeof(plain));
    CHECK(dispatch(OP_WG_SEND, pa->peer_id, 0x100u, sizeof(plain), 0u, &reply)
              == SEL4_ERR_OK,
          "SEND after roam");
    CHECK(g_test_last_wg_udp_ip == 0x0A000299u
          && g_test_last_wg_udp_port == 41641u,
          "UDP uses roamed endpoint");

    pa->last_handshake = 1u;
    timer_tick = 1u;
    keepalive_due = timer_tick + WG_KEEPALIVE_SECS + 1000u;
    for (i = 0u; i < WG_REKEY_AFTER_SECS + 2u; i++)
        (void)dispatch(OP_WG_TIMER_TICK, 0u, 0u, 0u, 0u, &reply);
    CHECK(!pa->session_established, "rekey-after-time clears session");
    CHECK(dispatch(OP_WG_SEND, pa->peer_id, 0x100u, sizeof(plain), 0u, &reply)
              == SEL4_ERR_PERM
          && data_rd32(reply.data, 0) == WG_ERR_NOSESSION,
          "SEND fails closed after rekey");

    for (i = 0u; i < 32u; i++)
        staging[0x40u + i] = (uint8_t)(0xA0u + i);
    timestamp[11] = 3;
    memcpy(staging + 0x60u, timestamp, sizeof(timestamp));
    CHECK(establish_session(pa->peer_id, priv_a, pub_a, local_pub, 0x40u, 0x60u,
                            11u) == 0,
          "re-handshake after rekey");
    CHECK(dispatch(OP_WG_SEND, pa->peer_id, 0x100u, sizeof(plain), 0u, &reply)
              == SEL4_ERR_OK,
          "SEND succeeds after re-handshake");

    if (failed) {
        fprintf(stderr, "# %d failed\n", failed);
        return 1;
    }
    return 0;
}
