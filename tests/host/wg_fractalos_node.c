/*
 * Host FractalOS wg_net node — UDP underlay between two processes.
 *
 * Speaks the same OP_WG_* opcodes as the freestanding PD. Outbound
 * OP_NET_WG_UDP_SEND is mirrored onto a real UDP socket using the peer
 * endpoint from the netmap; inbound datagrams are OP_WG_INGESTed.
 */
#define FRACTALOS_TEST_REAL_CRYPTO 1

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "../../kernel/fractalos-root-task/src/wireguard_derp.c"
#include "../../kernel/fractalos-root-task/src/wg_net.c"

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

static uint32_t dispatch6(uint32_t opcode, uint32_t a, uint32_t b, uint32_t c,
                          uint32_t d, uint32_t e, uint32_t f, sel4_msg_t *reply)
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

static int read_file(const char *path, void *buf, size_t n)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    size_t got = fread(buf, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}

static int udp_open(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;
    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int udp_send_to(int fd, uint32_t ip_host_be_style, uint16_t port,
                       const void *buf, size_t len)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    /* Match wg_net / net_server: endpoint_ip is BE wire value as uint32. */
    addr.sin_addr.s_addr = htonl(ip_host_be_style);
    /* On LE host, 0x7F000001 stored as endpoint means 127.0.0.1 when written BE.
     * Our packed netmap uses u32::from_be_bytes([127,0,0,1]) = 0x7F000001.
     * net_wr32be writes that as 127.0.0.1. For UDP we need sin_addr = 127.0.0.1
     * which is htonl(0x7F000001) on LE... actually inet 127.0.0.1 is
     * htonl(INADDR_LOOPBACK)=0x0100007f in memory on LE.
     * So we should set s_addr = htonl(ip) when ip is 0x7F000001.
     */
    addr.sin_addr.s_addr = htonl(ip_host_be_style);
    addr.sin_port = htons(port);
    return (int)sendto(fd, buf, len, 0, (struct sockaddr *)&addr, sizeof(addr));
}

static void flush_udp_forward(int fd)
{
    if (g_test_wg_udp_calls == 0u)
        return;
    /* Last forward: copy TX staging packet to UDP peer. */
    uint32_t off = g_test_last_wg_udp_off;
    uint32_t len = g_test_last_wg_udp_len;
    uint32_t ip = g_test_last_wg_udp_ip;
    uint16_t port = (uint16_t)g_test_last_wg_udp_port;
    if (len == 0u || len > 2048u)
        return;
    udp_send_to(fd, ip, port, (const void *)(staging + off), len);
    g_test_wg_udp_calls = 0u;
}

static int poll_ingest(int fd, uint32_t timeout_ms)
{
    fd_set rfds;
    struct timeval tv;
    uint8_t buf[2048];
    struct sockaddr_in src;
    socklen_t slen = sizeof(src);
    sel4_msg_t reply;
    int n;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    tv.tv_sec = (time_t)(timeout_ms / 1000u);
    tv.tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u);
    if (select(fd + 1, &rfds, NULL, NULL, &tv) <= 0)
        return 0;
    n = (int)recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&src, &slen);
    if (n <= 0)
        return 0;
    memcpy(staging + WG_STAGING_INGRESS_OFF, buf, (size_t)n);
    /* MR5/MR6 optional src — pack LE ipv4 for cookie path; localhost ok. */
    if (dispatch6(OP_WG_INGEST, WG_STAGING_INGRESS_OFF, (uint32_t)n, 0u, 0u,
                  0x0100007fu, (uint32_t)ntohs(src.sin_port), &reply)
        != SEL4_ERR_OK) {
        fprintf(stderr, "INGEST failed type=%u len=%d mr0=%u\n",
                buf[0], n, data_rd32(reply.data, 0));
        return -1;
    }
    flush_udp_forward(fd);
    return 1;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s --role initiator|responder --privkey FILE --netmap FILE "
            "--listen PORT --msg TEXT\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *role = NULL;
    const char *priv_path = NULL;
    const char *netmap_path = NULL;
    const char *msg = "fractalos-two-node-ping";
    uint16_t listen_port = 0;
    uint8_t priv[32];
    uint8_t *netmap = NULL;
    long netmap_len = 0;
    sel4_msg_t reply;
    int fd;
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--role") && i + 1 < argc)
            role = argv[++i];
        else if (!strcmp(argv[i], "--privkey") && i + 1 < argc)
            priv_path = argv[++i];
        else if (!strcmp(argv[i], "--netmap") && i + 1 < argc)
            netmap_path = argv[++i];
        else if (!strcmp(argv[i], "--listen") && i + 1 < argc)
            listen_port = (uint16_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--msg") && i + 1 < argc)
            msg = argv[++i];
        else {
            usage(argv[0]);
            return 2;
        }
    }
    if (!role || !priv_path || !netmap_path || listen_port == 0) {
        usage(argv[0]);
        return 2;
    }

    if (read_file(priv_path, priv, 32) != 0) {
        perror(priv_path);
        return 1;
    }
    {
        FILE *f = fopen(netmap_path, "rb");
        if (!f) {
            perror(netmap_path);
            return 1;
        }
        fseek(f, 0, SEEK_END);
        netmap_len = ftell(f);
        fseek(f, 0, SEEK_SET);
        netmap = malloc((size_t)netmap_len);
        if (!netmap || fread(netmap, 1, (size_t)netmap_len, f) != (size_t)netmap_len) {
            fprintf(stderr, "netmap read failed\n");
            return 1;
        }
        fclose(f);
    }

    memset(staging, 0, sizeof(staging));
    memcpy(staging, priv, 32);
    memcpy(staging + 0x18000u, netmap, (size_t)netmap_len);
    /* Ephemeral + timestamp for auto handshake. */
    for (i = 0; i < 32; i++)
        staging[0x90u + i] = (uint8_t)(0xA5u ^ i);
    wg_staging_vaddr = (uintptr_t)staging;
    wg_net_test_init();

    if (dispatch(OP_WG_SET_PRIVKEY, 0u, 0u, 0u, 0u, &reply) != SEL4_ERR_OK) {
        fprintf(stderr, "SET_PRIVKEY failed\n");
        return 1;
    }
    if (dispatch(OP_WG_SEED_ENTROPY, 0x90u, 0u, 0u, 0u, &reply) != SEL4_ERR_OK) {
        fprintf(stderr, "SEED_ENTROPY failed\n");
        return 1;
    }
    if (dispatch(OP_WG_APPLY_NETMAP, 0x18000u, (uint32_t)netmap_len, 0u, 0u, &reply)
        != SEL4_ERR_OK) {
        fprintf(stderr, "APPLY_NETMAP failed\n");
        return 1;
    }
    fprintf(stderr, "netmap applied peers=%u\n", data_rd32(reply.data, 4));

    fd = udp_open(listen_port);
    if (fd < 0) {
        perror("udp_open");
        return 1;
    }

    if (!strcmp(role, "initiator")) {
        wg_peer_t *peer = NULL;
        uint8_t peer_id;
        for (i = 0; i < (int)WG_MAX_PEERS; i++) {
            if (peers[i].active) {
                peer = &peers[i];
                break;
            }
        }
        if (!peer) {
            fprintf(stderr, "no peers in netmap\n");
            return 1;
        }
        peer_id = peer->peer_id;
        if (dispatch(OP_WG_HANDSHAKE_START, peer_id, 0u, 0u, 0u, &reply)
            != SEL4_ERR_OK) {
            fprintf(stderr, "HANDSHAKE_START failed mr0=%u\n",
                    data_rd32(reply.data, 0));
            return 1;
        }
        flush_udp_forward(fd);
        fprintf(stderr, "initiation sent to peer %u\n", peer_id);

        for (i = 0; i < 50; i++) {
            if (poll_ingest(fd, 200) < 0)
                return 1;
            if (peer->session_established)
                break;
        }
        if (!peer->session_established) {
            fprintf(stderr, "session not established\n");
            return 1;
        }
        memcpy(staging + WG_STAGING_TX_OFF + 0x100u, msg, strlen(msg) + 1u);
        if (dispatch(OP_WG_SEND, peer_id, 0x100u, (uint32_t)strlen(msg) + 1u, 0u,
                     &reply)
            != SEL4_ERR_OK) {
            fprintf(stderr, "SEND failed\n");
            return 1;
        }
        flush_udp_forward(fd);
        printf("SEND_OK peer=%u path=%u\n", peer_id, data_rd32(reply.data, 12));
        return 0;
    }

    if (!strcmp(role, "responder")) {
        int got_plain = 0;
        for (i = 0; i < 100 && !got_plain; i++) {
            int pr = poll_ingest(fd, 200);
            if (pr < 0)
                return 1;
            if (dispatch(OP_WG_RECV, 0xffu, 0u, 0u, 0u, &reply) == SEL4_ERR_OK
                && data_rd32(reply.data, 12) > 0u) {
                uint32_t plen = data_rd32(reply.data, 12);
                staging[WG_STAGING_RX_OFF + plen] = 0;
                printf("RECV_OK len=%u msg=%s\n", plen,
                       (char *)(staging + WG_STAGING_RX_OFF));
                got_plain = 1;
            }
        }
        if (!got_plain) {
            fprintf(stderr, "timeout waiting for plaintext\n");
            return 1;
        }
        return 0;
    }

    usage(argv[0]);
    return 2;
}
