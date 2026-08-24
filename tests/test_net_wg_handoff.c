/* Capability and frame-contract tests for wg_net -> NetServer -> net_pd. */
#define AGENTOS_TEST_HOST 1
#define OP_NS_REGISTER 0xD0u

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../services/net-server/net_server.c"

static uint8_t dma_arena[NET_DMA_ARENA_BYTES];
static uint8_t wg_packet_view[NET_WG_PACKET_VIEW_BYTES];
static unsigned test_no;
static unsigned failures;

#define CHECK(condition, label) do {                                      \
    test_no++;                                                             \
    if (condition) printf("ok %u - %s\n", test_no, label);                \
    else { printf("not ok %u - %s\n", test_no, label); failures++; }     \
} while (0)

static void wr32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)value;
    dst[1] = (uint8_t)(value >> 8u);
    dst[2] = (uint8_t)(value >> 16u);
    dst[3] = (uint8_t)(value >> 24u);
}

static uint32_t rd32(const uint8_t *src)
{
    return (uint32_t)src[0] | ((uint32_t)src[1] << 8u)
        | ((uint32_t)src[2] << 16u) | ((uint32_t)src[3] << 24u);
}

static bool ipv4_checksum_valid(const uint8_t *header)
{
    uint32_t sum = 0u;
    for (uint32_t i = 0u; i < 20u; i += 2u)
        sum += ((uint32_t)header[i] << 8u) | header[i + 1u];
    while ((sum >> 16u) != 0u) sum = (sum & 0xffffu) + (sum >> 16u);
    return sum == 0xffffu;
}

static uint32_t invoke(sel4_badge_t badge, uint32_t offset, uint32_t len,
                       sel4_msg_t *rep)
{
    sel4_msg_t req = {0};
    req.opcode = OP_NET_WG_UDP_SEND;
    req.length = 16u;
    wr32(req.data, offset);
    wr32(req.data + 4u, len);
    wr32(req.data + 8u, 0x0A000202u);
    wr32(req.data + 12u, 51820u);
    return net_server_dispatch_one(badge, &req, rep);
}

int main(void)
{
    printf("TAP version 13\n1..12\n");
    memset(dma_arena, 0, sizeof(dma_arena));
    memset(wg_packet_view, 0, sizeof(wg_packet_view));
    net_packet_shmem_vaddr = (uintptr_t)dma_arena;
    wg_packet_view_vaddr = (uintptr_t)wg_packet_view;
    net_server_test_init();
    net_hw_present = true;

    static const uint8_t encrypted[] = {
        4u, 0u, 0u, 0u, 0x11u, 0x22u, 0x33u, 0x44u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
        0x8du, 0x71u, 0x29u, 0x42u,
    };
    memcpy(wg_packet_view, encrypted, sizeof(encrypted));

    sel4_msg_t rep = {0};
    uint32_t rc = invoke(0u, NET_WG_PACKET_BASE_OFF,
                         (uint32_t)sizeof(encrypted), &rep);
    CHECK(rc == SEL4_ERR_PERM && rd32(rep.data) == NET_ERR_PERM,
          "unbadged endpoint cannot send a WireGuard datagram");

    memset(&rep, 0, sizeof(rep));
    rc = invoke(NET_SERVER_RIGHT_WG_DATAGRAM,
                NET_WG_PACKET_BASE_OFF, (uint32_t)sizeof(encrypted), &rep);
    CHECK(rc == SEL4_ERR_OK && rd32(rep.data) == NET_OK,
          "badged WireGuard datagram right authorizes send");
    CHECK(rd32(rep.data + 4u) == sizeof(encrypted),
          "reply reports encrypted payload bytes");

    const uint8_t *frame = dma_arena + NET_DMA_WG_FRAME_OFFSET;
    CHECK(frame[12] == 0x08u && frame[13] == 0x00u && frame[23] == 17u,
          "frame is Ethernet IPv4 UDP");
    CHECK(frame[30] == 10u && frame[31] == 0u
          && frame[32] == 2u && frame[33] == 2u,
          "IPv4 envelope carries the peer endpoint");
    CHECK(frame[34] == 0xCAu && frame[35] == 0x6Cu
          && frame[36] == 0xCAu && frame[37] == 0x6Cu,
          "UDP envelope uses WireGuard source and destination ports");
    CHECK(ipv4_checksum_valid(frame + 14u), "IPv4 header checksum is valid");
    CHECK(memcmp(frame + 42u, encrypted, sizeof(encrypted)) == 0,
          "encrypted WireGuard bytes cross the packet-only view intact");

    memset(&rep, 0, sizeof(rep));
    rc = invoke(NET_SERVER_RIGHT_WG_DATAGRAM, 0u,
                (uint32_t)sizeof(encrypted), &rep);
    CHECK(rc == SEL4_ERR_BAD_ARG && rd32(rep.data) == NET_ERR_INVAL,
          "key-page offsets are rejected even with datagram authority");
    memset(&rep, 0, sizeof(rep));
    rc = invoke(NET_SERVER_RIGHT_WG_DATAGRAM, NET_WG_PACKET_BASE_OFF,
                NET_WG_MAX_PAYLOAD + 1u, &rep);
    CHECK(rc == SEL4_ERR_BAD_ARG && rd32(rep.data) == NET_ERR_INVAL,
          "oversize datagrams are rejected before DMA");

    sel4_msg_t cross_req = {0};
    memset(&rep, 0, sizeof(rep));
    cross_req.opcode = OP_NET_HTTP_POST;
    cross_req.length = 16u;
    rc = net_server_dispatch_one(NET_SERVER_RIGHT_WG_DATAGRAM,
                                 &cross_req, &rep);
    CHECK(rc == SEL4_ERR_PERM && rd32(rep.data) == NET_ERR_PERM,
          "WireGuard datagram right cannot invoke model HTTP");
    memset(&cross_req, 0, sizeof(cross_req));
    memset(&rep, 0, sizeof(rep));
    cross_req.opcode = OP_NET_VNIC_CREATE;
    cross_req.length = 12u;
    wr32(cross_req.data, 0xffu);
    wr32(cross_req.data + 4u, CAP_CLASS_NET);
    rc = net_server_dispatch_one(NET_SERVER_RIGHT_WG_DATAGRAM,
                                 &cross_req, &rep);
    CHECK(rc == SEL4_ERR_PERM && rd32(rep.data) == NET_ERR_PERM,
          "WireGuard datagram right cannot administer vNICs");

    return failures == 0u ? 0 : 1;
}
