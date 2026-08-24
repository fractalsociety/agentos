/* WireGuard Noise_IKpsk2 hash and KDF primitives (BLAKE2s/HMAC-BLAKE2s). */
#pragma once

#include <stddef.h>
#include <stdint.h>

#define WG_NOISE_HASH_LEN 32u
#define WG_NOISE_KEY_LEN 32u
#define WG_NOISE_TIMESTAMP_LEN 12u
#define WG_NOISE_INITIATION_LEN 148u
#define WG_NOISE_RESPONSE_LEN 92u

enum wg_noise_state {
    WG_NOISE_ZEROED = 0u,
    WG_NOISE_INITIATION_CREATED,
    WG_NOISE_INITIATION_CONSUMED,
    WG_NOISE_RESPONSE_CREATED,
    WG_NOISE_RESPONSE_CONSUMED,
};

typedef struct {
    uint8_t hash[WG_NOISE_HASH_LEN];
    uint8_t chaining_key[WG_NOISE_HASH_LEN];
    uint8_t preshared_key[WG_NOISE_KEY_LEN];
    uint8_t local_ephemeral[WG_NOISE_KEY_LEN];
    uint8_t remote_static[WG_NOISE_KEY_LEN];
    uint8_t remote_ephemeral[WG_NOISE_KEY_LEN];
    uint32_t local_index;
    uint32_t remote_index;
    uint32_t state;
} wg_noise_handshake_t;

void wg_blake2s(uint8_t out[WG_NOISE_HASH_LEN], const uint8_t *input,
                size_t input_len);
void wg_blake2s_keyed(uint8_t *out, size_t out_len, const uint8_t *key,
                      size_t key_len, const uint8_t *input, size_t input_len);
void wg_hmac_blake2s(uint8_t out[WG_NOISE_HASH_LEN], const uint8_t *key,
                     size_t key_len, const uint8_t *input, size_t input_len);

void wg_noise_kdf1(uint8_t out0[WG_NOISE_HASH_LEN],
                   const uint8_t chaining_key[WG_NOISE_HASH_LEN],
                   const uint8_t *input, size_t input_len);
void wg_noise_kdf2(uint8_t out0[WG_NOISE_HASH_LEN],
                   uint8_t out1[WG_NOISE_HASH_LEN],
                   const uint8_t chaining_key[WG_NOISE_HASH_LEN],
                   const uint8_t *input, size_t input_len);
void wg_noise_kdf3(uint8_t out0[WG_NOISE_HASH_LEN],
                   uint8_t out1[WG_NOISE_HASH_LEN],
                   uint8_t out2[WG_NOISE_HASH_LEN],
                   const uint8_t chaining_key[WG_NOISE_HASH_LEN],
                   const uint8_t *input, size_t input_len);
void wg_noise_mix_hash(uint8_t hash[WG_NOISE_HASH_LEN],
                       const uint8_t *input, size_t input_len);
void wg_noise_initial(uint8_t chaining_key[WG_NOISE_HASH_LEN],
                      uint8_t hash[WG_NOISE_HASH_LEN]);

void wg_noise_handshake_init(wg_noise_handshake_t *handshake,
                             const uint8_t remote_static[WG_NOISE_KEY_LEN],
                             const uint8_t preshared_key[WG_NOISE_KEY_LEN]);
int wg_noise_create_initiation(
    wg_noise_handshake_t *handshake,
    const uint8_t local_static_private[WG_NOISE_KEY_LEN],
    const uint8_t local_static_public[WG_NOISE_KEY_LEN],
    const uint8_t ephemeral_private[WG_NOISE_KEY_LEN],
    const uint8_t timestamp[WG_NOISE_TIMESTAMP_LEN], uint32_t sender_index,
    uint8_t message[WG_NOISE_INITIATION_LEN]);
int wg_noise_consume_initiation(
    wg_noise_handshake_t *handshake,
    const uint8_t local_static_private[WG_NOISE_KEY_LEN],
    const uint8_t local_static_public[WG_NOISE_KEY_LEN],
    const uint8_t expected_remote_static[WG_NOISE_KEY_LEN],
    const uint8_t message[WG_NOISE_INITIATION_LEN],
    uint8_t timestamp[WG_NOISE_TIMESTAMP_LEN]);
int wg_noise_create_response(
    wg_noise_handshake_t *handshake,
    const uint8_t ephemeral_private[WG_NOISE_KEY_LEN], uint32_t sender_index,
    uint8_t message[WG_NOISE_RESPONSE_LEN]);
int wg_noise_consume_response(
    wg_noise_handshake_t *handshake,
    const uint8_t local_static_private[WG_NOISE_KEY_LEN],
    const uint8_t local_static_public[WG_NOISE_KEY_LEN],
    const uint8_t message[WG_NOISE_RESPONSE_LEN]);
int wg_noise_begin_session(wg_noise_handshake_t *handshake,
                           uint8_t send_key[WG_NOISE_KEY_LEN],
                           uint8_t receive_key[WG_NOISE_KEY_LEN]);
