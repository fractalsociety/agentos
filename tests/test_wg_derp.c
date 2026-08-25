/*
 * fos-gz0.5 — DERP frame wrap/unwrap (L2 host).
 *
 * Proves Tailscale-compatible DERP framing around opaque WireGuard
 * ciphertext without decrypting it. Live TLS DERP is out of scope.
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

int main(void)
{
    static const uint8_t basepoint[32] = {9u};
    uint8_t local_private[32], remote_private[32], remote_public[32];
    uint8_t cipher[64];
    uint8_t frame[256];
    uint32_t frame_len = 0u;
    uint8_t type = 0u;
    uint32_t plen = 0u;
    const uint8_t *dest = NULL;
    const uint8_t *src = NULL;
    const uint8_t *pkt = NULL;
    uint32_t pkt_len = 0u;
    const uint8_t *srv_pub = NULL;
    uint8_t ping_data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    sel4_msg_t reply;

    printf("1..28\n");

    for (uint32_t i = 0u; i < 32u; i++) {
        local_private[i] = (uint8_t)(i + 11u);
        remote_private[i] = (uint8_t)(i + 91u);
        cipher[i] = (uint8_t)(0xC0u ^ i);
        cipher[32u + i] = (uint8_t)(0x5Au + i);
    }
    crypto_x25519(remote_public, remote_private, basepoint);

    /* ── Pure codec ─────────────────────────────────────────────────────── */
    CHECK(wg_derp_write_header(frame, sizeof(frame),
                               WG_DERP_FRAME_KEEP_ALIVE, 0u) == 5,
          "write empty keepalive header");
    CHECK(wg_derp_parse_header(frame, 5u, &type, &plen) == 0
          && type == WG_DERP_FRAME_KEEP_ALIVE && plen == 0u,
          "parse keepalive header");

    CHECK(wg_derp_encode_send_packet(frame, sizeof(frame), remote_public,
                                     cipher, 64u, &frame_len) == 0,
          "encode SendPacket");
    CHECK(frame_len == WG_DERP_HDR_LEN + WG_DERP_KEY_LEN + 64u,
          "SendPacket framed length");
    CHECK(frame[0] == WG_DERP_FRAME_SEND_PACKET, "SendPacket type byte");
    CHECK(wg_derp_parse_header(frame, frame_len, &type, &plen) == 0
          && plen == WG_DERP_KEY_LEN + 64u,
          "SendPacket header payload length");
    CHECK(wg_derp_decode_send_packet(frame + WG_DERP_HDR_LEN, plen,
                                     &dest, &pkt, &pkt_len) == 0
          && pkt_len == 64u
          && memcmp(dest, remote_public, 32u) == 0
          && memcmp(pkt, cipher, 64u) == 0,
          "decode SendPacket preserves ciphertext");

    CHECK(wg_derp_encode_recv_packet(frame, sizeof(frame), remote_public,
                                     cipher, 64u, &frame_len) == 0,
          "encode RecvPacket");
    CHECK(wg_derp_parse_header(frame, frame_len, &type, &plen) == 0
          && type == WG_DERP_FRAME_RECV_PACKET,
          "RecvPacket type");
    CHECK(wg_derp_decode_recv_packet(frame + WG_DERP_HDR_LEN, plen,
                                     &src, &pkt, &pkt_len) == 0
          && memcmp(src, remote_public, 32u) == 0
          && memcmp(pkt, cipher, 64u) == 0,
          "decode RecvPacket preserves ciphertext");

    {
        uint8_t local_pub[32];
        crypto_x25519(local_pub, local_private, basepoint);
        CHECK(wg_derp_encode_forward_packet(frame, sizeof(frame),
                                            remote_public, local_pub,
                                            cipher, 32u, &frame_len) == 0,
              "encode ForwardPacket");
        CHECK(wg_derp_parse_header(frame, frame_len, &type, &plen) == 0
              && type == WG_DERP_FRAME_FWD_PACKET
              && plen == (WG_DERP_KEY_LEN * 2u) + 32u,
              "ForwardPacket layout");
    }

    {
        uint8_t sk_payload[WG_DERP_MAGIC_LEN + 32u];
        memcpy(sk_payload, wg_derp_magic, WG_DERP_MAGIC_LEN);
        memset(sk_payload + WG_DERP_MAGIC_LEN, 0xAB, 32u);
        CHECK(wg_derp_check_server_key(sk_payload, sizeof(sk_payload),
                                       &srv_pub) == 0
              && srv_pub != NULL
              && srv_pub[0] == 0xABu,
              "ServerKey magic accepted");
        sk_payload[0] = 'X';
        CHECK(wg_derp_check_server_key(sk_payload, sizeof(sk_payload),
                                       &srv_pub) != 0,
              "ServerKey bad magic rejected");
    }

    CHECK(wg_derp_encode_ping_pong(frame, sizeof(frame), WG_DERP_FRAME_PING,
                                   ping_data, &frame_len) == 0
          && frame_len == WG_DERP_HDR_LEN + 8u
          && frame[0] == WG_DERP_FRAME_PING,
          "encode Ping");

    /* Oversized payload rejected. */
    {
        uint32_t bad = 0u;
        CHECK(wg_derp_write_header(frame, sizeof(frame),
                                   WG_DERP_FRAME_SEND_PACKET,
                                   WG_DERP_MAX_PACKET + 1u) < 0,
              "oversized header length rejected");
        (void)bad;
    }

    /* ── wg_net opcodes ─────────────────────────────────────────────────── */
    memcpy(staging, local_private, 32u);
    memcpy(staging + WG_STAGING_PEER_KEY_OFF, remote_public, 32u);
    memcpy(staging + WG_STAGING_TX_OFF, cipher, 64u);
    wg_staging_vaddr = (uintptr_t)staging;
    wg_net_test_init();

    CHECK(dispatch(OP_WG_SET_PRIVKEY, 0u, 0u, 0u, 0u, &reply) == SEL4_ERR_OK,
          "static key installed");
    CHECK(dispatch(OP_WG_ADD_PEER, 0u, WG_STAGING_PEER_KEY_OFF, 0u, 51820u,
                   &reply) == SEL4_ERR_OK, "peer registered");

    CHECK(dispatch(OP_WG_DERP_WRAP, 0u, WG_STAGING_TX_OFF, 64u,
                   WG_STAGING_RX_OFF, &reply) == SEL4_ERR_OK,
          "DERP wrap succeeds");
    CHECK(data_rd32(reply.data, 0) == WG_OK, "wrap reply WG_OK");
    frame_len = data_rd32(reply.data, 8);
    CHECK(frame_len == WG_DERP_HDR_LEN + WG_DERP_KEY_LEN + 64u,
          "wrap frame length");
    CHECK(staging[WG_STAGING_RX_OFF] == WG_DERP_FRAME_SEND_PACKET,
          "wrap writes SendPacket type");

    /* Simulate server RecvPacket back to us using same ciphertext. */
    CHECK(wg_derp_encode_recv_packet(frame, sizeof(frame), remote_public,
                                     cipher, 64u, &frame_len) == 0,
          "build RecvPacket for unwrap");
    memcpy(staging + WG_STAGING_INGRESS_OFF, frame, frame_len);
    memset(staging + WG_STAGING_RX_OFF, 0, 64u);

    CHECK(dispatch(OP_WG_DERP_UNWRAP, WG_STAGING_INGRESS_OFF, frame_len,
                   WG_STAGING_RX_OFF, 0u, &reply) == SEL4_ERR_OK,
          "DERP unwrap RecvPacket succeeds");
    CHECK(data_rd32(reply.data, 0) == WG_OK
          && data_rd32(reply.data, 4) == 0u
          && data_rd32(reply.data, 8) == 64u
          && data_rd32(reply.data, 12) == WG_DERP_FRAME_RECV_PACKET,
          "unwrap reports peer 0 + Recv type");
    CHECK(memcmp(staging + WG_STAGING_RX_OFF, cipher, 64u) == 0,
          "unwrap restores opaque ciphertext");

    /* Unknown pubkey → NOPEER. */
    {
        uint8_t stranger[32];
        memset(stranger, 0xEE, 32u);
        CHECK(wg_derp_encode_recv_packet(frame, sizeof(frame), stranger,
                                         cipher, 16u, &frame_len) == 0,
              "build stranger RecvPacket");
        memcpy(staging + WG_STAGING_INGRESS_OFF, frame, frame_len);
        CHECK(dispatch(OP_WG_DERP_UNWRAP, WG_STAGING_INGRESS_OFF, frame_len,
                       WG_STAGING_RX_OFF, 0u, &reply) == SEL4_ERR_NOT_FOUND
              && data_rd32(reply.data, 0) == WG_ERR_NOPEER,
              "unwrap unknown src is NOPEER");
    }

    if (failed) {
        fprintf(stderr, "# %d failed\n", failed);
        return 1;
    }
    return 0;
}
