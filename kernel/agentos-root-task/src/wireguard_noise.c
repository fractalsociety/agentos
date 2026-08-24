/*
 * Freestanding BLAKE2s and the exact HMAC-BLAKE2s KDF used by WireGuard's
 * Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s handshake.
 *
 * The compression function follows RFC 7693. No allocation, libc, or mutable
 * global state is used, so the same implementation runs in host vectors and
 * in the wg_net protection domain.
 */
#include "wireguard_noise.h"
#include "monocypher.h"

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t buffer[64];
    size_t buffer_len;
    size_t out_len;
} wg_blake2s_state_t;

static const uint32_t blake2s_iv[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

static const uint8_t blake2s_sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 },
};

static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8u)
        | ((uint32_t)p[2] << 16u) | ((uint32_t)p[3] << 24u);
}

static void store32_le(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8u);
    p[2] = (uint8_t)(value >> 16u);
    p[3] = (uint8_t)(value >> 24u);
}

static uint32_t rotate_right(uint32_t value, uint32_t bits)
{
    return (value >> bits) | (value << (32u - bits));
}

#define B2S_G(a, b, c, d, x, y) do { \
    (a) = (a) + (b) + (x);             \
    (d) = rotate_right((d) ^ (a), 16u);\
    (c) = (c) + (d);                   \
    (b) = rotate_right((b) ^ (c), 12u);\
    (a) = (a) + (b) + (y);             \
    (d) = rotate_right((d) ^ (a), 8u); \
    (c) = (c) + (d);                   \
    (b) = rotate_right((b) ^ (c), 7u); \
} while (0)

static void blake2s_compress(wg_blake2s_state_t *state,
                             const uint8_t block[64])
{
    uint32_t m[16], v[16];
    for (uint32_t i = 0u; i < 16u; i++) m[i] = load32_le(block + i * 4u);
    for (uint32_t i = 0u; i < 8u; i++) {
        v[i] = state->h[i];
        v[i + 8u] = blake2s_iv[i];
    }
    v[12] ^= state->t[0]; v[13] ^= state->t[1];
    v[14] ^= state->f[0]; v[15] ^= state->f[1];
    for (uint32_t round = 0u; round < 10u; round++) {
        const uint8_t *s = blake2s_sigma[round];
        B2S_G(v[0],v[4],v[ 8],v[12],m[s[ 0]],m[s[ 1]]);
        B2S_G(v[1],v[5],v[ 9],v[13],m[s[ 2]],m[s[ 3]]);
        B2S_G(v[2],v[6],v[10],v[14],m[s[ 4]],m[s[ 5]]);
        B2S_G(v[3],v[7],v[11],v[15],m[s[ 6]],m[s[ 7]]);
        B2S_G(v[0],v[5],v[10],v[15],m[s[ 8]],m[s[ 9]]);
        B2S_G(v[1],v[6],v[11],v[12],m[s[10]],m[s[11]]);
        B2S_G(v[2],v[7],v[ 8],v[13],m[s[12]],m[s[13]]);
        B2S_G(v[3],v[4],v[ 9],v[14],m[s[14]],m[s[15]]);
    }
    for (uint32_t i = 0u; i < 8u; i++) state->h[i] ^= v[i] ^ v[i + 8u];
}

static void blake2s_increment(wg_blake2s_state_t *state, uint32_t amount)
{
    uint32_t previous = state->t[0];
    state->t[0] += amount;
    if (state->t[0] < previous) state->t[1]++;
}

static void blake2s_init(wg_blake2s_state_t *state, size_t out_len,
                         const uint8_t *key, size_t key_len)
{
    *state = (wg_blake2s_state_t){0};
    for (uint32_t i = 0u; i < 8u; i++) state->h[i] = blake2s_iv[i];
    state->h[0] ^= 0x01010000u ^ ((uint32_t)key_len << 8u)
                 ^ (uint32_t)out_len;
    state->out_len = out_len;
    if (key_len != 0u) {
        for (size_t i = 0u; i < key_len; i++) state->buffer[i] = key[i];
        state->buffer_len = sizeof(state->buffer);
    }
}

static void blake2s_update(wg_blake2s_state_t *state, const uint8_t *input,
                           size_t input_len)
{
    if (input_len == 0u) return;
    if (state->buffer_len != 0u) {
        size_t fill = sizeof(state->buffer) - state->buffer_len;
        if (input_len > fill) {
            for (size_t i = 0u; i < fill; i++)
                state->buffer[state->buffer_len + i] = input[i];
            blake2s_increment(state, sizeof(state->buffer));
            blake2s_compress(state, state->buffer);
            state->buffer_len = 0u;
            input += fill;
            input_len -= fill;
        }
    }
    while (input_len > sizeof(state->buffer)) {
        blake2s_increment(state, sizeof(state->buffer));
        blake2s_compress(state, input);
        input += sizeof(state->buffer);
        input_len -= sizeof(state->buffer);
    }
    for (size_t i = 0u; i < input_len; i++)
        state->buffer[state->buffer_len + i] = input[i];
    state->buffer_len += input_len;
}

static void blake2s_final(wg_blake2s_state_t *state, uint8_t *out)
{
    uint8_t digest[WG_NOISE_HASH_LEN];
    blake2s_increment(state, (uint32_t)state->buffer_len);
    state->f[0] = 0xffffffffu;
    for (size_t i = state->buffer_len; i < sizeof(state->buffer); i++)
        state->buffer[i] = 0u;
    blake2s_compress(state, state->buffer);
    for (uint32_t i = 0u; i < 8u; i++) store32_le(digest + i * 4u, state->h[i]);
    for (size_t i = 0u; i < state->out_len; i++) out[i] = digest[i];
    *state = (wg_blake2s_state_t){0};
    for (size_t i = 0u; i < sizeof(digest); i++) digest[i] = 0u;
}

void wg_blake2s(uint8_t out[WG_NOISE_HASH_LEN], const uint8_t *input,
                size_t input_len)
{
    wg_blake2s_state_t state;
    blake2s_init(&state, WG_NOISE_HASH_LEN, (const uint8_t *)0, 0u);
    blake2s_update(&state, input, input_len);
    blake2s_final(&state, out);
}

void wg_blake2s_keyed(uint8_t *out, size_t out_len, const uint8_t *key,
                      size_t key_len, const uint8_t *input, size_t input_len)
{
    if (out_len == 0u || out_len > WG_NOISE_HASH_LEN || key_len == 0u
        || key_len > WG_NOISE_HASH_LEN)
        return;
    wg_blake2s_state_t state;
    blake2s_init(&state, out_len, key, key_len);
    blake2s_update(&state, input, input_len);
    blake2s_final(&state, out);
}

void wg_hmac_blake2s(uint8_t out[WG_NOISE_HASH_LEN], const uint8_t *key,
                     size_t key_len, const uint8_t *input, size_t input_len)
{
    uint8_t key_block[64] = {0}, inner[WG_NOISE_HASH_LEN];
    wg_blake2s_state_t state;
    if (key_len > sizeof(key_block)) {
        wg_blake2s(key_block, key, key_len);
        key_len = WG_NOISE_HASH_LEN;
    } else {
        for (size_t i = 0u; i < key_len; i++) key_block[i] = key[i];
    }
    for (size_t i = 0u; i < sizeof(key_block); i++) key_block[i] ^= 0x36u;
    blake2s_init(&state, WG_NOISE_HASH_LEN, (const uint8_t *)0, 0u);
    blake2s_update(&state, key_block, sizeof(key_block));
    blake2s_update(&state, input, input_len);
    blake2s_final(&state, inner);
    for (size_t i = 0u; i < sizeof(key_block); i++)
        key_block[i] ^= (uint8_t)(0x36u ^ 0x5cu);
    blake2s_init(&state, WG_NOISE_HASH_LEN, (const uint8_t *)0, 0u);
    blake2s_update(&state, key_block, sizeof(key_block));
    blake2s_update(&state, inner, sizeof(inner));
    blake2s_final(&state, out);
    for (size_t i = 0u; i < sizeof(key_block); i++) key_block[i] = 0u;
    for (size_t i = 0u; i < sizeof(inner); i++) inner[i] = 0u;
}

static void noise_extract(uint8_t prk[WG_NOISE_HASH_LEN],
                          const uint8_t chaining_key[WG_NOISE_HASH_LEN],
                          const uint8_t *input, size_t input_len)
{
    wg_hmac_blake2s(prk, chaining_key, WG_NOISE_HASH_LEN, input, input_len);
}

void wg_noise_kdf1(uint8_t out0[WG_NOISE_HASH_LEN],
                   const uint8_t chaining_key[WG_NOISE_HASH_LEN],
                   const uint8_t *input, size_t input_len)
{
    uint8_t prk[WG_NOISE_HASH_LEN], one = 1u;
    noise_extract(prk, chaining_key, input, input_len);
    wg_hmac_blake2s(out0, prk, sizeof(prk), &one, 1u);
    for (size_t i = 0u; i < sizeof(prk); i++) prk[i] = 0u;
}

void wg_noise_kdf2(uint8_t out0[WG_NOISE_HASH_LEN],
                   uint8_t out1[WG_NOISE_HASH_LEN],
                   const uint8_t chaining_key[WG_NOISE_HASH_LEN],
                   const uint8_t *input, size_t input_len)
{
    uint8_t prk[WG_NOISE_HASH_LEN], next[WG_NOISE_HASH_LEN + 1u];
    noise_extract(prk, chaining_key, input, input_len);
    next[0] = 1u;
    wg_hmac_blake2s(out0, prk, sizeof(prk), next, 1u);
    for (size_t i = 0u; i < WG_NOISE_HASH_LEN; i++) next[i] = out0[i];
    next[WG_NOISE_HASH_LEN] = 2u;
    wg_hmac_blake2s(out1, prk, sizeof(prk), next, sizeof(next));
    for (size_t i = 0u; i < sizeof(prk); i++) prk[i] = 0u;
    for (size_t i = 0u; i < sizeof(next); i++) next[i] = 0u;
}

void wg_noise_kdf3(uint8_t out0[WG_NOISE_HASH_LEN],
                   uint8_t out1[WG_NOISE_HASH_LEN],
                   uint8_t out2[WG_NOISE_HASH_LEN],
                   const uint8_t chaining_key[WG_NOISE_HASH_LEN],
                   const uint8_t *input, size_t input_len)
{
    uint8_t prk[WG_NOISE_HASH_LEN], next[WG_NOISE_HASH_LEN + 1u];
    noise_extract(prk, chaining_key, input, input_len);
    next[0] = 1u;
    wg_hmac_blake2s(out0, prk, sizeof(prk), next, 1u);
    for (size_t i = 0u; i < WG_NOISE_HASH_LEN; i++) next[i] = out0[i];
    next[WG_NOISE_HASH_LEN] = 2u;
    wg_hmac_blake2s(out1, prk, sizeof(prk), next, sizeof(next));
    for (size_t i = 0u; i < WG_NOISE_HASH_LEN; i++) next[i] = out1[i];
    next[WG_NOISE_HASH_LEN] = 3u;
    wg_hmac_blake2s(out2, prk, sizeof(prk), next, sizeof(next));
    for (size_t i = 0u; i < sizeof(prk); i++) prk[i] = 0u;
    for (size_t i = 0u; i < sizeof(next); i++) next[i] = 0u;
}

void wg_noise_mix_hash(uint8_t hash[WG_NOISE_HASH_LEN],
                       const uint8_t *input, size_t input_len)
{
    wg_blake2s_state_t state;
    blake2s_init(&state, WG_NOISE_HASH_LEN, (const uint8_t *)0, 0u);
    blake2s_update(&state, hash, WG_NOISE_HASH_LEN);
    blake2s_update(&state, input, input_len);
    blake2s_final(&state, hash);
}

void wg_noise_initial(uint8_t chaining_key[WG_NOISE_HASH_LEN],
                      uint8_t hash[WG_NOISE_HASH_LEN])
{
    static const uint8_t construction[] =
        "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    static const uint8_t identifier[] =
        "WireGuard v1 zx2c4 Jason@zx2c4.com";
    wg_blake2s(chaining_key, construction, sizeof(construction) - 1u);
    for (size_t i = 0u; i < WG_NOISE_HASH_LEN; i++) hash[i] = chaining_key[i];
    wg_noise_mix_hash(hash, identifier, sizeof(identifier) - 1u);
}

static void noise_copy(uint8_t *dst, const uint8_t *src, size_t len)
{
    for (size_t i = 0u; i < len; i++) dst[i] = src[i];
}

static void noise_zero(uint8_t *dst, size_t len)
{
    for (size_t i = 0u; i < len; i++) dst[i] = 0u;
}

static int noise_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0u;
    for (size_t i = 0u; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0u;
}

static int noise_nonzero(const uint8_t key[WG_NOISE_KEY_LEN])
{
    uint8_t value = 0u;
    for (size_t i = 0u; i < WG_NOISE_KEY_LEN; i++) value |= key[i];
    return value != 0u;
}

static void noise_store32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)value; dst[1] = (uint8_t)(value >> 8u);
    dst[2] = (uint8_t)(value >> 16u); dst[3] = (uint8_t)(value >> 24u);
}

static uint32_t noise_load32(const uint8_t *src)
{
    return (uint32_t)src[0] | ((uint32_t)src[1] << 8u)
        | ((uint32_t)src[2] << 16u) | ((uint32_t)src[3] << 24u);
}

static int noise_dh(uint8_t shared[WG_NOISE_KEY_LEN],
                    const uint8_t private_key[WG_NOISE_KEY_LEN],
                    const uint8_t public_key[WG_NOISE_KEY_LEN])
{
    crypto_x25519(shared, private_key, public_key);
    return noise_nonzero(shared) ? 0 : -1;
}

static void noise_public(uint8_t public_key[WG_NOISE_KEY_LEN],
                         const uint8_t private_key[WG_NOISE_KEY_LEN])
{
    static const uint8_t basepoint[WG_NOISE_KEY_LEN] = {9u};
    crypto_x25519(public_key, private_key, basepoint);
}

static void noise_aead_lock(uint8_t *cipher, const uint8_t *plain,
                            size_t plain_len,
                            const uint8_t key[WG_NOISE_KEY_LEN],
                            const uint8_t hash[WG_NOISE_HASH_LEN])
{
    static const uint8_t nonce[12] = {0};
    crypto_chacha20_poly1305_lock(cipher, cipher + plain_len, key, nonce,
                                  hash, WG_NOISE_HASH_LEN, plain, plain_len);
}

static int noise_aead_unlock(uint8_t *plain, const uint8_t *cipher,
                             size_t cipher_len,
                             const uint8_t key[WG_NOISE_KEY_LEN],
                             const uint8_t hash[WG_NOISE_HASH_LEN])
{
    static const uint8_t nonce[12] = {0};
    if (cipher_len < 16u) return -1;
    return crypto_chacha20_poly1305_unlock(
        plain, cipher + cipher_len - 16u, key, nonce, hash,
        WG_NOISE_HASH_LEN, cipher, cipher_len - 16u);
}

static void noise_mac1_key(uint8_t key[WG_NOISE_HASH_LEN],
                           const uint8_t receiver_static[WG_NOISE_KEY_LEN])
{
    static const uint8_t label[8] = {'m','a','c','1','-','-','-','-'};
    uint8_t input[8u + WG_NOISE_KEY_LEN];
    noise_copy(input, label, sizeof(label));
    noise_copy(input + sizeof(label), receiver_static, WG_NOISE_KEY_LEN);
    wg_blake2s(key, input, sizeof(input));
    noise_zero(input, sizeof(input));
}

static void noise_write_mac1(uint8_t *mac, const uint8_t *message,
                             size_t message_len,
                             const uint8_t receiver_static[WG_NOISE_KEY_LEN])
{
    uint8_t key[WG_NOISE_HASH_LEN];
    noise_mac1_key(key, receiver_static);
    wg_blake2s_keyed(mac, 16u, key, sizeof(key), message, message_len);
    noise_zero(key, sizeof(key));
}

static int noise_check_mac1(const uint8_t *mac, const uint8_t *message,
                            size_t message_len,
                            const uint8_t local_static[WG_NOISE_KEY_LEN])
{
    uint8_t expected[16];
    noise_write_mac1(expected, message, message_len, local_static);
    int valid = noise_equal(mac, expected, sizeof(expected));
    noise_zero(expected, sizeof(expected));
    return valid ? 0 : -1;
}

void wg_noise_handshake_init(wg_noise_handshake_t *handshake,
                             const uint8_t remote_static[WG_NOISE_KEY_LEN],
                             const uint8_t preshared_key[WG_NOISE_KEY_LEN])
{
    *handshake = (wg_noise_handshake_t){0};
    if (remote_static != (const uint8_t *)0)
        noise_copy(handshake->remote_static, remote_static, WG_NOISE_KEY_LEN);
    if (preshared_key != (const uint8_t *)0)
        noise_copy(handshake->preshared_key, preshared_key, WG_NOISE_KEY_LEN);
}

int wg_noise_create_initiation(
    wg_noise_handshake_t *handshake,
    const uint8_t local_static_private[WG_NOISE_KEY_LEN],
    const uint8_t local_static_public[WG_NOISE_KEY_LEN],
    const uint8_t ephemeral_private[WG_NOISE_KEY_LEN],
    const uint8_t timestamp[WG_NOISE_TIMESTAMP_LEN], uint32_t sender_index,
    uint8_t message[WG_NOISE_INITIATION_LEN])
{
    uint8_t key[WG_NOISE_KEY_LEN], shared[WG_NOISE_KEY_LEN], ephemeral[32];
    if (!noise_nonzero(handshake->remote_static) || sender_index == 0u)
        return -1;
    noise_zero(message, WG_NOISE_INITIATION_LEN);
    wg_noise_initial(handshake->chaining_key, handshake->hash);
    wg_noise_mix_hash(handshake->hash, handshake->remote_static, 32u);
    noise_copy(handshake->local_ephemeral, ephemeral_private, 32u);
    noise_public(ephemeral, ephemeral_private);
    noise_store32(message, 1u);
    noise_store32(message + 4u, sender_index);
    noise_copy(message + 8u, ephemeral, 32u);
    wg_noise_kdf1(handshake->chaining_key, handshake->chaining_key,
                  ephemeral, 32u);
    wg_noise_mix_hash(handshake->hash, ephemeral, 32u);
    if (noise_dh(shared, ephemeral_private, handshake->remote_static) != 0)
        return -1;
    wg_noise_kdf2(handshake->chaining_key, key, handshake->chaining_key,
                  shared, 32u);
    noise_aead_lock(message + 40u, local_static_public, 32u, key,
                    handshake->hash);
    wg_noise_mix_hash(handshake->hash, message + 40u, 48u);
    if (noise_dh(shared, local_static_private, handshake->remote_static) != 0)
        return -1;
    wg_noise_kdf2(handshake->chaining_key, key, handshake->chaining_key,
                  shared, 32u);
    noise_aead_lock(message + 88u, timestamp, WG_NOISE_TIMESTAMP_LEN, key,
                    handshake->hash);
    wg_noise_mix_hash(handshake->hash, message + 88u, 28u);
    noise_write_mac1(message + 116u, message, 116u,
                     handshake->remote_static);
    handshake->local_index = sender_index;
    handshake->state = WG_NOISE_INITIATION_CREATED;
    noise_zero(key, sizeof(key)); noise_zero(shared, sizeof(shared));
    noise_zero(ephemeral, sizeof(ephemeral));
    return 0;
}

int wg_noise_consume_initiation(
    wg_noise_handshake_t *handshake,
    const uint8_t local_static_private[WG_NOISE_KEY_LEN],
    const uint8_t local_static_public[WG_NOISE_KEY_LEN],
    const uint8_t expected_remote_static[WG_NOISE_KEY_LEN],
    const uint8_t message[WG_NOISE_INITIATION_LEN],
    uint8_t timestamp[WG_NOISE_TIMESTAMP_LEN])
{
    uint8_t key[32], shared[32], remote_static[32];
    uint32_t sender = noise_load32(message + 4u);
    if (noise_load32(message) != 1u || sender == 0u
        || noise_check_mac1(message + 116u, message, 116u,
                            local_static_public) != 0)
        return -1;
    wg_noise_initial(handshake->chaining_key, handshake->hash);
    wg_noise_mix_hash(handshake->hash, local_static_public, 32u);
    wg_noise_mix_hash(handshake->hash, message + 8u, 32u);
    wg_noise_kdf1(handshake->chaining_key, handshake->chaining_key,
                  message + 8u, 32u);
    if (noise_dh(shared, local_static_private, message + 8u) != 0)
        return -1;
    wg_noise_kdf2(handshake->chaining_key, key, handshake->chaining_key,
                  shared, 32u);
    if (noise_aead_unlock(remote_static, message + 40u, 48u, key,
                          handshake->hash) != 0
        || !noise_equal(remote_static, expected_remote_static, 32u))
        return -1;
    wg_noise_mix_hash(handshake->hash, message + 40u, 48u);
    if (noise_dh(shared, local_static_private, expected_remote_static) != 0)
        return -1;
    wg_noise_kdf2(handshake->chaining_key, key, handshake->chaining_key,
                  shared, 32u);
    if (noise_aead_unlock(timestamp, message + 88u, 28u, key,
                          handshake->hash) != 0)
        return -1;
    wg_noise_mix_hash(handshake->hash, message + 88u, 28u);
    noise_copy(handshake->remote_static, remote_static, 32u);
    noise_copy(handshake->remote_ephemeral, message + 8u, 32u);
    handshake->remote_index = sender;
    handshake->state = WG_NOISE_INITIATION_CONSUMED;
    noise_zero(key, sizeof(key)); noise_zero(shared, sizeof(shared));
    noise_zero(remote_static, sizeof(remote_static));
    return 0;
}

int wg_noise_create_response(
    wg_noise_handshake_t *handshake,
    const uint8_t ephemeral_private[WG_NOISE_KEY_LEN], uint32_t sender_index,
    uint8_t message[WG_NOISE_RESPONSE_LEN])
{
    uint8_t ephemeral[32], shared[32], tau[32], key[32], empty = 0u;
    if (handshake->state != WG_NOISE_INITIATION_CONSUMED
        || sender_index == 0u)
        return -1;
    noise_zero(message, WG_NOISE_RESPONSE_LEN);
    noise_store32(message, 2u);
    noise_store32(message + 4u, sender_index);
    noise_store32(message + 8u, handshake->remote_index);
    noise_copy(handshake->local_ephemeral, ephemeral_private, 32u);
    noise_public(ephemeral, ephemeral_private);
    noise_copy(message + 12u, ephemeral, 32u);
    wg_noise_mix_hash(handshake->hash, ephemeral, 32u);
    wg_noise_kdf1(handshake->chaining_key, handshake->chaining_key,
                  ephemeral, 32u);
    if (noise_dh(shared, ephemeral_private, handshake->remote_ephemeral) != 0)
        return -1;
    wg_noise_kdf1(handshake->chaining_key, handshake->chaining_key,
                  shared, 32u);
    if (noise_dh(shared, ephemeral_private, handshake->remote_static) != 0)
        return -1;
    wg_noise_kdf1(handshake->chaining_key, handshake->chaining_key,
                  shared, 32u);
    wg_noise_kdf3(handshake->chaining_key, tau, key,
                  handshake->chaining_key, handshake->preshared_key, 32u);
    wg_noise_mix_hash(handshake->hash, tau, 32u);
    noise_aead_lock(message + 44u, &empty, 0u, key, handshake->hash);
    wg_noise_mix_hash(handshake->hash, message + 44u, 16u);
    noise_write_mac1(message + 60u, message, 60u, handshake->remote_static);
    handshake->local_index = sender_index;
    handshake->state = WG_NOISE_RESPONSE_CREATED;
    noise_zero(ephemeral, sizeof(ephemeral)); noise_zero(shared, sizeof(shared));
    noise_zero(tau, sizeof(tau)); noise_zero(key, sizeof(key));
    return 0;
}

int wg_noise_consume_response(
    wg_noise_handshake_t *handshake,
    const uint8_t local_static_private[WG_NOISE_KEY_LEN],
    const uint8_t local_static_public[WG_NOISE_KEY_LEN],
    const uint8_t message[WG_NOISE_RESPONSE_LEN])
{
    uint8_t hash[32], chaining_key[32], shared[32], tau[32], key[32], empty;
    if (handshake->state != WG_NOISE_INITIATION_CREATED
        || noise_load32(message) != 2u
        || noise_load32(message + 8u) != handshake->local_index
        || noise_check_mac1(message + 60u, message, 60u,
                            local_static_public) != 0)
        return -1;
    noise_copy(hash, handshake->hash, 32u);
    noise_copy(chaining_key, handshake->chaining_key, 32u);
    wg_noise_mix_hash(hash, message + 12u, 32u);
    wg_noise_kdf1(chaining_key, chaining_key, message + 12u, 32u);
    if (noise_dh(shared, handshake->local_ephemeral, message + 12u) != 0)
        return -1;
    wg_noise_kdf1(chaining_key, chaining_key, shared, 32u);
    if (noise_dh(shared, local_static_private, message + 12u) != 0)
        return -1;
    wg_noise_kdf1(chaining_key, chaining_key, shared, 32u);
    wg_noise_kdf3(chaining_key, tau, key, chaining_key,
                  handshake->preshared_key, 32u);
    wg_noise_mix_hash(hash, tau, 32u);
    if (noise_aead_unlock(&empty, message + 44u, 16u, key, hash) != 0)
        return -1;
    wg_noise_mix_hash(hash, message + 44u, 16u);
    noise_copy(handshake->hash, hash, 32u);
    noise_copy(handshake->chaining_key, chaining_key, 32u);
    noise_copy(handshake->remote_ephemeral, message + 12u, 32u);
    handshake->remote_index = noise_load32(message + 4u);
    handshake->state = WG_NOISE_RESPONSE_CONSUMED;
    noise_zero(hash, sizeof(hash)); noise_zero(chaining_key, sizeof(chaining_key));
    noise_zero(shared, sizeof(shared)); noise_zero(tau, sizeof(tau));
    noise_zero(key, sizeof(key));
    return 0;
}

int wg_noise_begin_session(wg_noise_handshake_t *handshake,
                           uint8_t send_key[WG_NOISE_KEY_LEN],
                           uint8_t receive_key[WG_NOISE_KEY_LEN])
{
    uint8_t first[32], second[32];
    if (handshake->state != WG_NOISE_RESPONSE_CONSUMED
        && handshake->state != WG_NOISE_RESPONSE_CREATED)
        return -1;
    wg_noise_kdf2(first, second, handshake->chaining_key,
                  (const uint8_t *)0, 0u);
    if (handshake->state == WG_NOISE_RESPONSE_CONSUMED) {
        noise_copy(send_key, first, 32u);
        noise_copy(receive_key, second, 32u);
    } else {
        noise_copy(receive_key, first, 32u);
        noise_copy(send_key, second, 32u);
    }
    noise_zero(handshake->hash, sizeof(handshake->hash));
    noise_zero(handshake->chaining_key, sizeof(handshake->chaining_key));
    noise_zero(handshake->local_ephemeral, sizeof(handshake->local_ephemeral));
    handshake->state = WG_NOISE_ZEROED;
    noise_zero(first, sizeof(first)); noise_zero(second, sizeof(second));
    return 0;
}
