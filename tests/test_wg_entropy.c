/*
 * fos-gz0.5 — entropy-backed ephemeral / sender-index (L2 host).
 *
 * OP_WG_SEED_ENTROPY unlocks auto HANDSHAKE_START/INGEST (offset/index 0).
 * Without a seed, auto paths fail closed.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FRACTALOS_TEST_REAL_CRYPTO 1
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

static uint32_t dispatch6(uint32_t opcode, uint32_t a, uint32_t b,
                          uint32_t c, uint32_t d, uint32_t e, uint32_t f,
                          sel4_msg_t *reply)
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

int main(void)
{
    static const uint8_t basepoint[32] = {9u};
    uint8_t local_private[32], remote_private[32], remote_public[32];
    uint8_t seed[32];
    sel4_msg_t reply;
    uint32_t index_a, index_b;

    printf("1..19\n");
    for (uint32_t i = 0u; i < 32u; i++) {
        local_private[i] = (uint8_t)(i + 3u);
        remote_private[i] = (uint8_t)(i + 77u);
        seed[i] = (uint8_t)(0xA5u ^ i);
    }
    memcpy(staging, local_private, 32u);
    memcpy(staging + 0x90u, seed, 32u);
    crypto_x25519(remote_public, remote_private, basepoint);
    memcpy(staging + WG_STAGING_PEER_KEY_OFF, remote_public, 32u);

    wg_staging_vaddr = (uintptr_t)staging;
    wg_net_test_init();

    CHECK(dispatch(OP_WG_SET_PRIVKEY, 0u, 0u, 0u, 0u, &reply) == SEL4_ERR_OK,
          "static key installed");
    CHECK(dispatch(OP_WG_ADD_PEER, 0u, WG_STAGING_PEER_KEY_OFF, 0u, 51820u,
                   &reply) == SEL4_ERR_OK, "peer registered");

    /* Auto path fail-closed before seed. */
    CHECK(dispatch(OP_WG_HANDSHAKE_START, 0u, 0u, 0u, 0u, &reply)
              == SEL4_ERR_BAD_ARG,
          "auto handshake without seed is rejected");
    CHECK(data_rd32(reply.data, 0) == WG_ERR_CRYPTO,
          "unseeded auto reports WG_ERR_CRYPTO");

    CHECK(dispatch(OP_WG_SEED_ENTROPY, 0x90u, 0u, 0u, 0u, &reply)
              == SEL4_ERR_OK,
          "entropy seed accepted");
    CHECK(data_rd32(reply.data, 0) == WG_OK, "seed reply WG_OK");

    CHECK(dispatch(OP_WG_HANDSHAKE_START, 0u, 0u, 0u, 0u, &reply)
              == SEL4_ERR_OK,
          "auto handshake after seed succeeds");
    CHECK(data_rd32(reply.data, 0) == WG_OK, "auto start WG_OK");
    CHECK(data_rd32(reply.data, 8) == WG_NOISE_INITIATION_LEN,
          "auto start writes initiation");
    index_a = data_rd32(reply.data, 12);
    CHECK(index_a != 0u, "auto allocated non-zero sender_index");
    CHECK(staging[WG_STAGING_TX_OFF] == 1u, "initiation type byte is 1");

    /* Second auto must get a different index (high probability with DRBG). */
    CHECK(dispatch(OP_WG_HANDSHAKE_START, 0u, 0u, 0u, 0u, &reply)
              == SEL4_ERR_OK,
          "second auto handshake succeeds");
    index_b = data_rd32(reply.data, 12);
    CHECK(index_b != 0u && index_b != index_a,
          "second auto index differs from first");

    /* Responder ingest with auto ephemeral/index completes Noise. */
    {
        uint8_t remote_eph[32];
        uint8_t timestamp[12] = {
            0x40, 0, 0, 0, 0, 0, 0, 0x30, 0, 0, 0, 2
        };
        uint8_t initiation[WG_NOISE_INITIATION_LEN];
        wg_noise_handshake_t remote;
        for (uint32_t i = 0u; i < 32u; i++)
            remote_eph[i] = (uint8_t)(i + 200u);
        wg_noise_handshake_init(&remote, staging + WG_STAGING_PUBKEY_OFF,
                                (const uint8_t *)0);
        CHECK(wg_noise_create_initiation(
                  &remote, remote_private, remote_public,
                  remote_eph, timestamp, 0xABCDEF01u, initiation) == 0,
              "external initiator builds type-1");
        memcpy(staging + WG_STAGING_INGRESS_OFF, initiation,
               sizeof(initiation));
        CHECK(dispatch6(OP_WG_INGEST, WG_STAGING_INGRESS_OFF,
                        WG_NOISE_INITIATION_LEN, 0u, 0u, 0u, 0u, &reply)
                  == SEL4_ERR_OK,
              "ingest auto ephemeral/index completes");
        CHECK(data_rd32(reply.data, 0) == WG_OK, "ingest auto WG_OK");
        CHECK(data_rd32(reply.data, 8) == WG_NOISE_RESPONSE_LEN,
              "ingest auto emits response");
        CHECK(data_rd32(reply.data, 12) != 0u,
              "ingest auto allocated responder index");
        CHECK(peers[0].session_established,
              "session established via entropy responder path");
    }

    if (failed) {
        fprintf(stderr, "%d failed\n", failed);
        return 1;
    }
    printf("All wg entropy tests passed\n");
    return 0;
}
