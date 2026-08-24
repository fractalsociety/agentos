#include <stdint.h>
#include <stdio.h>
#include "wireguard_noise.h"
#include "monocypher.h"

static int passed, failed;
#define CHECK(x, name) do { if (x) passed++; else { failed++; printf("FAIL: %s\n", name); } } while (0)

static int equal(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    uint8_t diff = 0u;
    for (uint32_t i = 0u; i < n; i++) diff |= a[i] ^ b[i];
    return diff == 0u;
}

static void test_hashes(void)
{
    static const uint8_t empty[32] = {
        0x69,0x21,0x7a,0x30,0x79,0x90,0x80,0x94,0xe1,0x11,0x21,0xd0,0x42,0x35,0x4a,0x7c,
        0x1f,0x55,0xb6,0x48,0x2c,0xa1,0xa5,0x1e,0x1b,0x25,0x0d,0xfd,0x1e,0xd0,0xee,0xf9 };
    static const uint8_t abc[32] = {
        0x50,0x8c,0x5e,0x8c,0x32,0x7c,0x14,0xe2,0xe1,0xa7,0x2b,0xa3,0x4e,0xeb,0x45,0x2f,
        0x37,0x45,0x8b,0x20,0x9e,0xd6,0x3a,0x29,0x4d,0x99,0x9b,0x4c,0x86,0x67,0x59,0x82 };
    uint8_t out[32];
    wg_blake2s(out, (const uint8_t *)0, 0u);
    CHECK(equal(out, empty, 32u), "RFC 7693 BLAKE2s empty vector");
    wg_blake2s(out, (const uint8_t *)"abc", 3u);
    CHECK(equal(out, abc, 32u), "RFC 7693 BLAKE2s abc vector");
}

static void test_wireguard_kdf(void)
{
    static const uint8_t expected0[32] = {
        0x6a,0x96,0x44,0x4e,0x20,0xe8,0xd4,0xc1,0xce,0xe9,0x74,0x41,0x6a,0xca,0xe1,0xc1,
        0x0b,0x3c,0x92,0x88,0x60,0x10,0xe5,0x4e,0xd9,0x4d,0xaf,0xb2,0xc3,0xb8,0x0e,0xa0 };
    static const uint8_t expected1[32] = {
        0x57,0xaf,0x12,0x0b,0x0d,0xe7,0xac,0xbe,0x79,0x07,0xec,0x14,0x9c,0x5a,0xe8,0x70,
        0xa2,0xdb,0xb7,0x42,0x32,0xb6,0x57,0x77,0xba,0x41,0x23,0xf1,0xf7,0xf8,0x88,0xf5 };
    static const uint8_t expected2[32] = {
        0x09,0x26,0xc7,0xca,0xab,0xb6,0xe8,0xd7,0x3b,0xed,0xa7,0x59,0xe6,0xf4,0xf0,0xd3,
        0x24,0xce,0x5b,0x50,0x00,0xbc,0xf8,0xcd,0x78,0x4b,0x26,0xdb,0x30,0x49,0xfa,0xa9 };
    uint8_t ck[32], input[32], out0[32], out1[32], out2[32];
    for (uint32_t i = 0u; i < 32u; i++) { ck[i] = (uint8_t)i; input[i] = (uint8_t)(i + 32u); }
    wg_noise_kdf3(out0, out1, out2, ck, input, sizeof(input));
    CHECK(equal(out0, expected0, 32u), "WireGuard KDF output 1");
    CHECK(equal(out1, expected1, 32u), "WireGuard KDF output 2");
    CHECK(equal(out2, expected2, 32u), "WireGuard KDF output 3");
}

static void test_keyed_mac(void)
{
    static const uint8_t expected[16] = {
        0x3b,0x5b,0x59,0xcc,0x8a,0x59,0x12,0x7c,
        0x1c,0xc2,0x23,0x14,0xa3,0x70,0xd6,0x62 };
    static const uint8_t message[] = "agentOS WireGuard Noise";
    uint8_t key[32], out[16];
    for (uint32_t i = 0u; i < 32u; i++) key[i] = (uint8_t)i;
    wg_blake2s_keyed(out, sizeof(out), key, sizeof(key),
                     message, sizeof(message) - 1u);
    CHECK(equal(out, expected, sizeof(out)), "WireGuard keyed BLAKE2s MAC");
}

static void test_initial_transcript(void)
{
    static const uint8_t expected_ck[32] = {
        0x60,0xe2,0x6d,0xae,0xf3,0x27,0xef,0xc0,0x2e,0xc3,0x35,0xe2,0xa0,0x25,0xd2,0xd0,
        0x16,0xeb,0x42,0x06,0xf8,0x72,0x77,0xf5,0x2d,0x38,0xd1,0x98,0x8b,0x78,0xcd,0x36 };
    static const uint8_t expected_hash[32] = {
        0x22,0x11,0xb3,0x61,0x08,0x1a,0xc5,0x66,0x69,0x12,0x43,0xdb,0x45,0x8a,0xd5,0x32,
        0x2d,0x9c,0x6c,0x66,0x22,0x93,0xe8,0xb7,0x0e,0xe1,0x9c,0x65,0xba,0x07,0x9e,0xf3 };
    uint8_t ck[32], hash[32];
    wg_noise_initial(ck, hash);
    CHECK(equal(ck, expected_ck, 32u), "WireGuard initial chaining key");
    CHECK(equal(hash, expected_hash, 32u), "WireGuard initial transcript hash");
}

static void test_full_handshake(void)
{
    static const uint8_t basepoint[32] = {9u};
    uint8_t initiator_private[32], responder_private[32];
    uint8_t initiator_ephemeral[32], responder_ephemeral[32];
    uint8_t initiator_public[32], responder_public[32], psk[32] = {0};
    uint8_t timestamp[12] = {0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x25,1,2,3,4};
    uint8_t decoded_timestamp[12], initiation[148], response[92];
    uint8_t initiator_send[32], initiator_recv[32];
    uint8_t responder_send[32], responder_recv[32];
    wg_noise_handshake_t initiator, responder;

    for (uint32_t i = 0u; i < 32u; i++) {
        initiator_private[i] = (uint8_t)(i + 1u);
        responder_private[i] = (uint8_t)(i + 65u);
        initiator_ephemeral[i] = (uint8_t)(i + 101u);
        responder_ephemeral[i] = (uint8_t)(i + 151u);
    }
    crypto_x25519(initiator_public, initiator_private, basepoint);
    crypto_x25519(responder_public, responder_private, basepoint);
    wg_noise_handshake_init(&initiator, responder_public, psk);
    wg_noise_handshake_init(&responder, initiator_public, psk);

    CHECK(wg_noise_create_initiation(
              &initiator, initiator_private, initiator_public,
              initiator_ephemeral, timestamp, 0x11223344u, initiation) == 0,
          "initiator creates canonical 148-byte message");
    CHECK(initiation[0] == 1u && initiation[4] == 0x44u,
          "initiation uses little-endian type and sender index");
    CHECK(wg_noise_consume_initiation(
              &responder, responder_private, responder_public,
              initiator_public, initiation, decoded_timestamp) == 0,
          "responder authenticates initiation");
    CHECK(equal(timestamp, decoded_timestamp, sizeof(timestamp)),
          "responder decrypts exact TAI64N timestamp");
    CHECK(wg_noise_create_response(
              &responder, responder_ephemeral,
              0x55667788u, response) == 0,
          "responder creates canonical 92-byte response");
    CHECK(response[0] == 2u && response[8] == 0x44u,
          "response targets the initiator index");
    CHECK(wg_noise_consume_response(
              &initiator, initiator_private, initiator_public, response) == 0,
          "initiator authenticates response");
    CHECK(wg_noise_begin_session(&initiator, initiator_send, initiator_recv) == 0,
          "initiator derives transport session");
    CHECK(wg_noise_begin_session(&responder, responder_send, responder_recv) == 0,
          "responder derives transport session");
    CHECK(equal(initiator_send, responder_recv, 32u),
          "initiator send key equals responder receive key");
    CHECK(equal(initiator_recv, responder_send, 32u),
          "initiator receive key equals responder send key");

    initiation[116] ^= 1u;
    wg_noise_handshake_init(&responder, initiator_public, psk);
    CHECK(wg_noise_consume_initiation(
              &responder, responder_private, responder_public,
              initiator_public, initiation, decoded_timestamp) != 0,
          "responder rejects a modified MAC1");
}

int main(void)
{
    test_hashes();
    test_keyed_mac();
    test_wireguard_kdf();
    test_initial_transcript();
    test_full_handshake();
    printf("[wireguard_noise] %d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
