/* RFC 8439 proof for the exact ChaCha20-Poly1305 construction WireGuard uses. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/include/monocypher.h"

static int failures;

#define CHECK(condition, description) do {                              \
    if (condition) printf("ok - %s\n", description);                   \
    else { printf("not ok - %s\n", description); failures++; }        \
} while (0)

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_hex(uint8_t *out, size_t out_len, const char *hex)
{
    if (strlen(hex) != out_len * 2u) return -1;
    for (size_t i = 0; i < out_len; i++) {
        int high = hex_nibble(hex[i * 2u]);
        int low = hex_nibble(hex[i * 2u + 1u]);
        if (high < 0 || low < 0) return -1;
        out[i] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

int main(void)
{
    static const char plaintext[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you only "
        "one tip for the future, sunscreen would be it.";
    static const char expected_cipher_hex[] =
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116";
    static const char expected_tag_hex[] =
        "1ae10b594f09e26a7e902ecbd0600691";
    uint8_t key[32], nonce[12], aad[12];
    uint8_t expected_cipher[sizeof(plaintext) - 1u], expected_tag[16];
    uint8_t cipher[sizeof(plaintext) - 1u], tag[16];
    uint8_t recovered[sizeof(plaintext) - 1u];

    CHECK(decode_hex(key, sizeof(key),
                     "808182838485868788898a8b8c8d8e8f"
                     "909192939495969798999a9b9c9d9e9f") == 0,
          "RFC 8439 key fixture decodes");
    CHECK(decode_hex(nonce, sizeof(nonce),
                     "070000004041424344454647") == 0,
          "RFC 8439 nonce fixture decodes");
    CHECK(decode_hex(aad, sizeof(aad),
                     "50515253c0c1c2c3c4c5c6c7") == 0,
          "RFC 8439 AAD fixture decodes");
    CHECK(decode_hex(expected_cipher, sizeof(expected_cipher),
                     expected_cipher_hex) == 0,
          "RFC 8439 ciphertext fixture decodes");
    CHECK(decode_hex(expected_tag, sizeof(expected_tag),
                     expected_tag_hex) == 0,
          "RFC 8439 tag fixture decodes");

    crypto_chacha20_poly1305_lock(
        cipher, tag, key, nonce, aad, sizeof(aad),
        (const uint8_t *)plaintext, sizeof(plaintext) - 1u);
    CHECK(memcmp(cipher, expected_cipher, sizeof(cipher)) == 0,
          "WireGuard AEAD ciphertext matches RFC 8439");
    if (memcmp(tag, expected_tag, sizeof(tag)) != 0) {
        printf("# actual tag: ");
        for (size_t i = 0; i < sizeof(tag); i++) printf("%02x", tag[i]);
        printf("\n");
    }
    CHECK(memcmp(tag, expected_tag, sizeof(tag)) == 0,
          "WireGuard AEAD tag matches RFC 8439");

    memset(recovered, 0xa5, sizeof(recovered));
    CHECK(crypto_chacha20_poly1305_unlock(
              recovered, tag, key, nonce, aad, sizeof(aad),
              cipher, sizeof(cipher)) == 0,
          "WireGuard AEAD accepts the authenticated RFC vector");
    CHECK(memcmp(recovered, plaintext, sizeof(recovered)) == 0,
          "WireGuard AEAD recovers the exact plaintext");

    tag[0] ^= 1u;
    memset(recovered, 0xa5, sizeof(recovered));
    CHECK(crypto_chacha20_poly1305_unlock(
              recovered, tag, key, nonce, aad, sizeof(aad),
              cipher, sizeof(cipher)) == -1,
          "WireGuard AEAD rejects a modified authentication tag");
    uint8_t zero = 0u;
    for (size_t i = 0; i < sizeof(recovered); i++) zero |= recovered[i];
    CHECK(zero == 0u, "WireGuard AEAD wipes plaintext after authentication failure");

    tag[0] ^= 1u;
    cipher[0] ^= 1u;
    CHECK(crypto_chacha20_poly1305_unlock(
              recovered, tag, key, nonce, aad, sizeof(aad),
              cipher, sizeof(cipher)) == -1,
          "WireGuard AEAD rejects modified ciphertext");
    cipher[0] ^= 1u;
    aad[0] ^= 1u;
    CHECK(crypto_chacha20_poly1305_unlock(
              recovered, tag, key, nonce, aad, sizeof(aad),
              cipher, sizeof(cipher)) == -1,
          "WireGuard AEAD rejects modified associated data");

    printf("1..13\n");
    return failures == 0 ? 0 : 1;
}
