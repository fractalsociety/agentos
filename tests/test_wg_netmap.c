/*
 * fos-gz0.5 — Headscale-style netmap apply + rekey-after-time (L2 host).
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

int main(void)
{
    static const uint8_t basepoint[32] = {9u};
    uint8_t priv_a[32], priv_b[32], pub_a[32], pub_b[32];
    uint8_t ephemeral[32], timestamp[12] = {
        0x40, 0, 0, 0, 0, 0, 0, 0x25, 0, 0, 0, 1
    };
    sel4_msg_t reply;
    uint32_t map_off = 0x18000u;
    uint32_t i;

    printf("1..12\n");
    for (i = 0u; i < 32u; i++) {
        priv_a[i] = (uint8_t)(i + 1u);
        priv_b[i] = (uint8_t)(i + 40u);
        ephemeral[i] = (uint8_t)(i + 90u);
    }
    crypto_x25519(pub_a, priv_a, basepoint);
    crypto_x25519(pub_b, priv_b, basepoint);

    memset(staging, 0, sizeof(staging));
    memcpy(staging, priv_a, 32u);
    memcpy(staging + 0x40u, ephemeral, 32u);
    memcpy(staging + 0x60u, timestamp, sizeof(timestamp));
    wg_staging_vaddr = (uintptr_t)staging;
    wg_net_test_init();

    CHECK(dispatch(OP_WG_SET_PRIVKEY, 0u, 0u, 0u, 0u, &reply) == SEL4_ERR_OK,
          "privkey installed");

    /* Build netmap with two peers (CGNAT-style endpoints). */
    {
        struct wg_netmap_header hdr = {
            .version = WG_NETMAP_VERSION,
            .peer_count = 2u,
        };
        memcpy(staging + map_off, &hdr, sizeof(hdr));
        write_netmap_peer(staging + map_off + 8u, pub_a, 0x0A000201u, 41641u,
                          0x0A800001u, 0xFFFFFFFFu);
        write_netmap_peer(staging + map_off + 8u + 48u, pub_b, 0x0A000202u,
                          41641u, 0x0A800002u, 0xFFFFFFFFu);
    }
    CHECK(dispatch(OP_WG_APPLY_NETMAP, map_off,
                   8u + 2u * WG_NETMAP_PEER_BYTES, 0u, 0u, &reply)
              == SEL4_ERR_OK,
          "netmap apply two peers");
    CHECK(data_rd32(reply.data, 0) == WG_OK, "netmap status OK");
    CHECK(data_rd32(reply.data, 4) == 2u, "applied=2");
    CHECK(active_peer_count == 2u, "active peer count 2");

    /* Roam peer A's endpoint without wiping a live session. */
    {
        wg_peer_t *pa = find_peer_by_pubkey(pub_a);
        CHECK(pa != NULL, "peer A located by pubkey");
        pa->session_established = true;
        pa->last_handshake = timer_tick;
        pa->send_key[0] = 0xABu;
        write_netmap_peer(staging + map_off + 8u, pub_a, 0x0A000299u, 51820u,
                          0x0A800001u, 0xFFFFFFFFu);
        /* Drop peer B from map → removed. */
        {
            struct wg_netmap_header hdr = {
                .version = WG_NETMAP_VERSION,
                .peer_count = 1u,
            };
            memcpy(staging + map_off, &hdr, sizeof(hdr));
        }
        CHECK(dispatch(OP_WG_APPLY_NETMAP, map_off,
                       8u + WG_NETMAP_PEER_BYTES, 0u, 0u, &reply)
                  == SEL4_ERR_OK,
              "netmap roam + remove");
        CHECK(data_rd32(reply.data, 12) >= 1u, "endpoints_roamed>=1");
        CHECK(data_rd32(reply.data, 8) >= 1u, "peers_removed>=1");
        CHECK(pa->session_established && pa->send_key[0] == 0xABu,
              "roam retains session keys");
        CHECK(pa->endpoint_ip == 0x0A000299u && pa->endpoint_port == 51820u,
              "endpoint updated from netmap");
        CHECK(active_peer_count == 1u, "only peer A remains");
    }

    /* Rekey-after-time clears session. */
    {
        wg_peer_t *pa = find_peer_by_pubkey(pub_a);
        pa->session_established = true;
        pa->last_handshake = 1u;
        timer_tick = 1u + WG_REKEY_AFTER_SECS;
        keepalive_due = timer_tick + WG_KEEPALIVE_SECS;
        wg_net_timer_tick();
        CHECK(!pa->session_established && pa->send_key[0] == 0u,
              "rekey-after-time clears session");
    }

    /* Malformed netmap rejected. */
    {
        struct wg_netmap_header bad = {.version = 99u, .peer_count = 1u};
        memcpy(staging + map_off, &bad, sizeof(bad));
        CHECK(dispatch(OP_WG_APPLY_NETMAP, map_off, 8u + 48u, 0u, 0u, &reply)
                  != SEL4_ERR_OK,
              "bad netmap version rejected");
    }

    if (failed) {
        fprintf(stderr, "%d failures\n", failed);
        return 1;
    }
    return 0;
}
