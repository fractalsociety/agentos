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

static int bytes_equal(const uint8_t *a, const uint8_t *b, uint32_t length)
{
    uint8_t difference = 0u;
    for (uint32_t i = 0u; i < length; i++) difference |= a[i] ^ b[i];
    return difference == 0u;
}

int main(void)
{
    static const uint8_t basepoint[32] = {9u};
    uint8_t local_private[32], remote_private[32], remote_public[32];
    uint8_t local_ephemeral[32], remote_ephemeral[32], local_public[32];
    uint8_t timestamp[12] = {
        0x40,0,0,0,0,0,0,0x25,0,0,0,1
    };
    uint8_t initiation[WG_NOISE_INITIATION_LEN], response[WG_NOISE_RESPONSE_LEN];
    uint8_t decoded_timestamp[12], remote_send[32], remote_receive[32];
    uint8_t initiator_send[32], initiator_receive[32];
    uint8_t nonce[12], inbound[64];
    const uint8_t outbound_plain[] = "native-agent-out";
    const uint8_t inbound_plain[] = "native-agent-in";
    uint32_t cipher_len, plain_len;
    wg_noise_handshake_t remote, initiator;
    sel4_msg_t reply;

    printf("1..40\n");
    for (uint32_t i = 0u; i < 32u; i++) {
        local_private[i] = (uint8_t)(i + 1u);
        remote_private[i] = (uint8_t)(i + 65u);
        local_ephemeral[i] = (uint8_t)(i + 101u);
        remote_ephemeral[i] = (uint8_t)(i + 151u);
        staging[0x40u + i] = local_ephemeral[i];
    }
    memcpy(staging, local_private, 32u);
    memcpy(staging + 0x60u, timestamp, sizeof(timestamp));
    crypto_x25519(remote_public, remote_private, basepoint);
    memcpy(staging + WG_STAGING_PEER_KEY_OFF, remote_public, 32u);

    wg_staging_vaddr = (uintptr_t)staging;
    wg_net_test_init();
    CHECK(dispatch(OP_WG_SET_PRIVKEY, 0u, 0u, 0u, 0u, &reply) == SEL4_ERR_OK,
          "local static key is accepted");
    memcpy(local_public, staging + WG_STAGING_PUBKEY_OFF, 32u);
    CHECK(dispatch(OP_WG_ADD_PEER, 0u, WG_STAGING_PEER_KEY_OFF, 0u, 51820u,
                   &reply) == SEL4_ERR_OK, "remote peer is registered");

    memcpy(staging + WG_STAGING_TX_OFF + 0x100u,
           outbound_plain, sizeof(outbound_plain));
    CHECK(dispatch(OP_WG_SEND, 0u, 0x100u, sizeof(outbound_plain), 0u,
                   &reply) == SEL4_ERR_PERM,
          "transport send fails closed before Noise authentication");
    CHECK(data_rd32(reply.data, 0) == WG_ERR_NOSESSION,
          "pre-handshake denial reports WG_ERR_NOSESSION");

    CHECK(dispatch(OP_WG_HANDSHAKE_START, 0u, 0x40u, 0x60u, 0x10203040u,
                   &reply) == SEL4_ERR_OK, "initiator creates handshake message");
    CHECK(data_rd32(reply.data, 8) == WG_NOISE_INITIATION_LEN,
          "initiation has canonical 148-byte length");
    memcpy(initiation, staging + WG_STAGING_TX_OFF, sizeof(initiation));
    CHECK(data_rd32(initiation, 0) == 1u, "initiation has WireGuard type 1");

    wg_noise_handshake_init(&remote, local_public, NULL);
    CHECK(wg_noise_consume_initiation(&remote, remote_private, remote_public,
                                      local_public, initiation,
                                      decoded_timestamp) == 0,
          "independent responder authenticates initiation");
    CHECK(bytes_equal(decoded_timestamp, timestamp, sizeof(timestamp)),
          "responder recovers the authenticated timestamp");
    CHECK(wg_noise_create_response(&remote, remote_ephemeral,
                                   0x50607080u, response) == 0,
          "independent responder creates response");
    CHECK(wg_noise_begin_session(&remote, remote_send, remote_receive) == 0,
          "independent responder installs transport keys");

    memcpy(staging + WG_STAGING_INGRESS_OFF, response, sizeof(response));
    CHECK(dispatch(OP_WG_INGEST, WG_STAGING_INGRESS_OFF, sizeof(response),
                   0u, 0u, &reply) == SEL4_ERR_OK,
          "initiator authenticates response and installs session");
    CHECK(peers[0].session_established, "peer records authenticated session");
    CHECK(peers[0].receive_index == 0x10203040u,
          "session retains local receiver index");
    CHECK(peers[0].send_index == 0x50607080u,
          "session retains remote receiver index");
    CHECK(bytes_equal(peers[0].send_key, remote_receive, 32u)
          && bytes_equal(peers[0].receive_key, remote_send, 32u),
          "initiator and responder derive inverse transport keys");

    memcpy(staging + WG_STAGING_TX_OFF + 0x100u,
           outbound_plain, sizeof(outbound_plain));
    CHECK(dispatch(OP_WG_SEND, 0u, 0x100u, sizeof(outbound_plain), 0u,
                   &reply) == SEL4_ERR_OK,
          "authenticated transport send succeeds");
    CHECK(data_rd32(staging + WG_STAGING_TX_OFF, 0) == 4u
          && data_rd32(staging + WG_STAGING_TX_OFF, 4) == 0x50607080u,
          "outbound packet uses canonical type and receiver index");
    wg_transport_counter_nonce(0u, nonce);
    CHECK(wg_decrypt(remote_receive, nonce,
                     staging + WG_STAGING_TX_OFF + WG_TRANSPORT_HDR_LEN,
                     data_rd32(reply.data, 4), inbound, &plain_len) == 0
          && plain_len == sizeof(outbound_plain)
          && bytes_equal(inbound, outbound_plain, plain_len),
          "remote key decrypts outbound payload");

    memset(inbound, 0, sizeof(inbound));
    data_wr32(inbound, 0, 4u);
    data_wr32(inbound, 4, 0x10203040u);
    wg_transport_counter_nonce(0u, nonce);
    for (uint32_t i = 0u; i < 8u; i++) inbound[8u + i] = nonce[4u + i];
    CHECK(wg_encrypt(remote_send, nonce, inbound_plain, sizeof(inbound_plain),
                     inbound + WG_TRANSPORT_HDR_LEN, &cipher_len) == 0,
          "remote encrypts inbound transport payload");
    memcpy(staging + WG_STAGING_INGRESS_OFF, inbound,
           WG_TRANSPORT_HDR_LEN + cipher_len);
    CHECK(dispatch(OP_WG_INGEST, WG_STAGING_INGRESS_OFF,
                   WG_TRANSPORT_HDR_LEN + cipher_len, 0u, 0u, &reply)
              == SEL4_ERR_OK,
          "ingest authenticates inbound transport packet");
    CHECK(dispatch(OP_WG_RECV, 0xffu, 0u, 0u, 0u, &reply) == SEL4_ERR_OK
          && data_rd32(reply.data, 12) == sizeof(inbound_plain),
          "receive releases authenticated plaintext");
    CHECK(bytes_equal(staging + WG_STAGING_RX_OFF, inbound_plain,
                      sizeof(inbound_plain)),
          "released plaintext matches the remote payload");

    memcpy(staging + WG_STAGING_INGRESS_OFF, inbound,
           WG_TRANSPORT_HDR_LEN + cipher_len);
    CHECK(dispatch(OP_WG_INGEST, WG_STAGING_INGRESS_OFF,
                   WG_TRANSPORT_HDR_LEN + cipher_len, 0u, 0u, &reply)
              == SEL4_ERR_PERM,
          "replay window rejects duplicate authenticated counter");

    wg_transport_counter_nonce(1u, nonce);
    for (uint32_t i = 0u; i < 8u; i++) inbound[8u + i] = nonce[4u + i];
    wg_encrypt(remote_send, nonce, inbound_plain, sizeof(inbound_plain),
               inbound + WG_TRANSPORT_HDR_LEN, &cipher_len);
    inbound[WG_TRANSPORT_HDR_LEN + cipher_len - 1u] ^= 1u;
    memcpy(staging + WG_STAGING_INGRESS_OFF, inbound,
           WG_TRANSPORT_HDR_LEN + cipher_len);
    CHECK(dispatch(OP_WG_INGEST, WG_STAGING_INGRESS_OFF,
                   WG_TRANSPORT_HDR_LEN + cipher_len, 0u, 0u, &reply)
              == SEL4_ERR_PERM,
          "tampered AEAD tag is rejected");
    inbound[WG_TRANSPORT_HDR_LEN + cipher_len - 1u] ^= 1u;
    memcpy(staging + WG_STAGING_INGRESS_OFF, inbound,
           WG_TRANSPORT_HDR_LEN + cipher_len);
    CHECK(dispatch(OP_WG_INGEST, WG_STAGING_INGRESS_OFF,
                   WG_TRANSPORT_HDR_LEN + cipher_len, 0u, 0u, &reply)
              == SEL4_ERR_OK,
          "failed authentication does not consume replay counter");
    CHECK(peers[0].rx_replay.top == 1u,
          "replay window commits only authenticated counter");
    CHECK(dispatch(OP_WG_HEALTH, 0u, 0u, 0u, 0u, &reply) == SEL4_ERR_OK
          && data_rd32(reply.data, 12) == 1u,
          "health reports one authenticated session");

    /* Exercise the service as responder, including timestamp replay denial. */
    memset(staging, 0, sizeof(staging));
    memcpy(staging, remote_private, 32u);
    memcpy(staging + WG_STAGING_PEER_KEY_OFF, local_public, 32u);
    memcpy(staging + 0x40u, remote_ephemeral, 32u);
    wg_net_test_init();
    CHECK(dispatch(OP_WG_SET_PRIVKEY, 0u, 0u, 0u, 0u, &reply) == SEL4_ERR_OK,
          "responder static key is accepted");
    CHECK(dispatch(OP_WG_ADD_PEER, 0u, WG_STAGING_PEER_KEY_OFF, 0u, 51820u,
                   &reply) == SEL4_ERR_OK, "initiating peer is registered");
    wg_noise_handshake_init(&initiator, remote_public, NULL);
    CHECK(wg_noise_create_initiation(&initiator, local_private, local_public,
                                     local_ephemeral, timestamp, 0x11121314u,
                                     initiation) == 0,
          "independent initiator creates message for service responder");
    memcpy(staging + WG_STAGING_INGRESS_OFF, initiation, sizeof(initiation));
    CHECK(dispatch(OP_WG_INGEST, WG_STAGING_INGRESS_OFF, sizeof(initiation),
                   0x40u, 0x21222324u, &reply) == SEL4_ERR_OK,
          "service responder authenticates initiation");
    CHECK(data_rd32(reply.data, 8) == WG_NOISE_RESPONSE_LEN,
          "service emits canonical 92-byte response");
    memcpy(response, staging + WG_STAGING_TX_OFF, sizeof(response));
    CHECK(wg_noise_consume_response(&initiator, local_private, local_public,
                                    response) == 0,
          "independent initiator authenticates service response");
    CHECK(wg_noise_begin_session(&initiator, initiator_send,
                                 initiator_receive) == 0,
          "independent initiator installs responder-derived keys");
    CHECK(bytes_equal(peers[0].send_key, initiator_receive, 32u)
          && bytes_equal(peers[0].receive_key, initiator_send, 32u),
          "responder and initiator derive inverse keys");
    CHECK(peers[0].receive_index == 0x21222324u
          && peers[0].send_index == 0x11121314u,
          "responder installs both authenticated receiver indices");
    memcpy(staging + WG_STAGING_INGRESS_OFF, initiation, sizeof(initiation));
    CHECK(dispatch(OP_WG_INGEST, WG_STAGING_INGRESS_OFF, sizeof(initiation),
                   0x40u, 0x31323334u, &reply) == SEL4_ERR_PERM,
          "responder rejects replayed authenticated timestamp");
    CHECK(data_rd32(reply.data, 0) == WG_ERR_CRYPTO,
          "timestamp replay denial does not disclose peer identity");
    CHECK(peers[0].receive_index == 0x21222324u,
          "rejected rehandshake preserves current transport session");

    return failed == 0 ? 0 : 1;
}
