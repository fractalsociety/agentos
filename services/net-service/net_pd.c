/*
 * agentOS Network Device Protection Domain — E5-S4: raw seL4 IPC
 *
 * OS-neutral network service PD that moves lwIP behind a proper PD boundary.
 * Owns the virtio-net hardware exclusively via seL4 device frame capabilities.
 *
 * Migration notes (E5-S4):
 *   - Priority ordering constraint ELIMINATED.  net_pd_main() uses a
 *     sel4_server_t receive loop; callers block on endpoint IPC.
 *   - CH_NET_PD / CH_NET_SERVER channel constants removed.  The nameserver
 *     provides the endpoint cap at runtime.
 *   - net_pd registers itself as "net_pd" with the nameserver at startup.
 *   - Timer notification (ch=1) becomes an out-of-band seL4 notification;
 *     in-band timer handling can be done via a dedicated opcode if needed.
 *
 * API surface (see contracts/net_contract.h):
 *   Packet I/O:  MSG_NET_OPEN/CLOSE/SEND/RECV/DEV_STATUS/CONFIGURE/
 *                MSG_NET_FILTER_ADD/FILTER_REMOVE
 *   Sockets:     MSG_NET_SOCKET_OPEN/CLOSE/CONNECT/BIND/LISTEN/ACCEPT/SET_OPT
 *
 * Copyright (c) 2026 The agentOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* ── Conditional compilation ─────────────────────────────────────────────── */

#ifdef AGENTOS_TEST_HOST
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef unsigned long      seL4_CPtr;
typedef unsigned long long sel4_badge_t;

typedef struct {
    uint32_t opcode;
    uint32_t length;
    uint8_t  data[48];
} sel4_msg_t;

#define SEL4_ERR_OK          0u
#define SEL4_ERR_INVALID_OP  1u
#define SEL4_ERR_NOT_FOUND   2u
#define SEL4_ERR_PERM        3u
#define SEL4_ERR_BAD_ARG     4u
#define SEL4_ERR_NO_MEM      5u

typedef uint32_t (*sel4_handler_fn)(sel4_badge_t badge,
                                     const sel4_msg_t *req,
                                     sel4_msg_t *rep,
                                     void *ctx);
#define SEL4_SERVER_MAX_HANDLERS 32u
typedef struct {
    struct {
        uint32_t        opcode;
        sel4_handler_fn fn;
        void           *ctx;
    } handlers[SEL4_SERVER_MAX_HANDLERS];
    uint32_t  handler_count;
    seL4_CPtr ep;
} sel4_server_t;

static inline void sel4_server_init(sel4_server_t *srv, seL4_CPtr ep)
{
    srv->handler_count = 0;
    srv->ep            = ep;
    for (uint32_t i = 0; i < SEL4_SERVER_MAX_HANDLERS; i++) {
        srv->handlers[i].opcode = 0;
        srv->handlers[i].fn     = (sel4_handler_fn)0;
        srv->handlers[i].ctx    = (void *)0;
    }
}
static inline int sel4_server_register(sel4_server_t *srv, uint32_t opcode,
                                        sel4_handler_fn fn, void *ctx)
{
    if (srv->handler_count >= SEL4_SERVER_MAX_HANDLERS) return -1;
    srv->handlers[srv->handler_count].opcode = opcode;
    srv->handlers[srv->handler_count].fn     = fn;
    srv->handlers[srv->handler_count].ctx    = ctx;
    srv->handler_count++;
    return 0;
}
static inline uint32_t sel4_server_dispatch(sel4_server_t *srv,
                                             sel4_badge_t badge,
                                             const sel4_msg_t *req,
                                             sel4_msg_t *rep)
{
    for (uint32_t i = 0; i < srv->handler_count; i++) {
        if (srv->handlers[i].opcode == req->opcode) {
            uint32_t rc = srv->handlers[i].fn(badge, req, rep,
                                               srv->handlers[i].ctx);
            rep->opcode = rc;
            return rc;
        }
    }
    rep->opcode = SEL4_ERR_INVALID_OP;
    rep->length = 0;
    return SEL4_ERR_INVALID_OP;
}

static inline uint32_t data_rd32(const uint8_t *d, int off)
{
    return (uint32_t)d[off]
         | ((uint32_t)d[off+1] <<  8)
         | ((uint32_t)d[off+2] << 16)
         | ((uint32_t)d[off+3] << 24);
}
static inline void data_wr32(uint8_t *d, int off, uint32_t v)
{
    d[off  ] = (uint8_t)(v      );
    d[off+1] = (uint8_t)(v >>  8);
    d[off+2] = (uint8_t)(v >> 16);
    d[off+3] = (uint8_t)(v >> 24);
}

/* lwIP / TCP stubs */
struct netif { int (*linkoutput)(struct netif *, void *); };
static struct netif g_netif;
typedef void* pbuf;
#define PBUF_LINK  0
#define PBUF_RAM   0
static inline pbuf *pbuf_alloc(int l, unsigned short s, int t) { (void)l;(void)s;(void)t; return (void*)0; }
static inline void pbuf_free(pbuf *p) { (void)p; }
static inline void net_server_lwip_init(uintptr_t m, uint32_t a, uint32_t b) { (void)m;(void)a;(void)b; }
static inline void lwip_tick(void) {}
static inline void lwip_virtio_rx_poll(void) {}
static inline void sys_check_timeouts(void) {}
static inline int  lwip_net_recv(uint8_t id, uint8_t *buf, uint32_t len) { (void)id;(void)buf;(void)len; return 0; }
static inline int  lwip_net_connect(uint8_t id, uint32_t ip, uint16_t port) { (void)id;(void)ip;(void)port; return -1; }
static inline int  lwip_net_send(uint8_t id, const uint8_t *d, uint16_t l) { (void)id;(void)d;(void)l; return -1; }
struct lwip_conn { void *tcp; uint32_t state; };
static struct lwip_conn g_conns[16];
struct tcp_pcb;
static inline int tcp_close(struct tcp_pcb *p) { (void)p; return 0; }

static inline void log_drain_write(int a, int b, const char *s) { (void)a;(void)b;(void)s; }
static inline void agentos_log_boot(const char *s) { (void)s; }
static inline void seL4_Signal(seL4_CPtr cap) { (void)cap; }

/* OP_NS_REGISTER stub */
#ifndef OP_NS_REGISTER
#define OP_NS_REGISTER 0xD0u
#endif

#else /* !AGENTOS_TEST_HOST */

#define AGENTOS_DEBUG 1
#include "agentos.h"
#include "contracts/net_contract.h"
#include "lwip_sys.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "sel4_ipc.h"
#include "sel4_server.h"
#include "sel4_client.h"
#include "nameserver.h"

static inline uint32_t data_rd32(const uint8_t *d, int off)
{
    return (uint32_t)d[off]
         | ((uint32_t)d[off+1] <<  8)
         | ((uint32_t)d[off+2] << 16)
         | ((uint32_t)d[off+3] << 24);
}
static inline void data_wr32(uint8_t *d, int off, uint32_t v)
{
    d[off  ] = (uint8_t)(v      );
    d[off+1] = (uint8_t)(v >>  8);
    d[off+2] = (uint8_t)(v >> 16);
    d[off+3] = (uint8_t)(v >> 24);
}

#endif /* AGENTOS_TEST_HOST */

#include "net_fastpath.h"
#include "contracts/net_device_contract.h"

/* ── Contract opcodes (keep identical to Microkit version) ───────────────── */
/* These mirror agentos.h MSG_NET_* constants so the wire format is unchanged */
#ifndef MSG_NET_OPEN
#define MSG_NET_OPEN           0x2101u
#define MSG_NET_CLOSE          0x2102u
#define MSG_NET_SEND           0x2103u
#define MSG_NET_RECV           0x2104u
#define MSG_NET_DEV_STATUS     0x2105u
#define MSG_NET_CONFIGURE      0x2106u
#define MSG_NET_FILTER_ADD     0x2107u
#define MSG_NET_FILTER_REMOVE  0x2108u
#define MSG_NET_SOCKET_OPEN    0x2109u
#define MSG_NET_SOCKET_CLOSE   0x210Au
#define MSG_NET_SOCKET_CONNECT 0x210Bu
#define MSG_NET_SOCKET_BIND    0x210Cu
#define MSG_NET_SOCKET_LISTEN  0x210Du
#define MSG_NET_SOCKET_ACCEPT  0x210Eu
#define MSG_NET_SOCKET_SET_OPT 0x210Fu
#endif

/* ── Result codes ────────────────────────────────────────────────────────── */
#ifndef NET_OK
#define NET_OK              0u
#define NET_ERR_NO_SLOTS    1u
#define NET_ERR_BAD_HANDLE  2u
#define NET_ERR_FRAME_TOO_LARGE 3u
#define NET_ERR_FILTER_FULL 4u
#define NET_ERR_BAD_FILTER_ID 5u
#endif

/* ── virtio-MMIO register offsets ───────────────────────────────────────── */
#define VIRTIO_MMIO_MAGIC_VALUE  0x000u
#define VIRTIO_MMIO_VERSION      0x004u
#define VIRTIO_MMIO_DEVICE_ID    0x008u
#define VIRTIO_MMIO_DEVICE_FEATURES 0x010u
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL 0x014u
#define VIRTIO_MMIO_DRIVER_FEATURES 0x020u
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL 0x024u
#define VIRTIO_MMIO_QUEUE_SEL    0x030u
#define VIRTIO_MMIO_QUEUE_NUM_MAX 0x034u
#define VIRTIO_MMIO_QUEUE_NUM    0x038u
#define VIRTIO_MMIO_QUEUE_READY  0x044u
#define VIRTIO_MMIO_QUEUE_NOTIFY 0x050u
#define VIRTIO_MMIO_INTERRUPT_STATUS 0x060u
#define VIRTIO_MMIO_INTERRUPT_ACK    0x064u
#define VIRTIO_MMIO_STATUS       0x070u
#define VIRTIO_MMIO_QUEUE_DESC_LOW 0x080u
#define VIRTIO_MMIO_QUEUE_DESC_HIGH 0x084u
#define VIRTIO_MMIO_QUEUE_AVAIL_LOW 0x090u
#define VIRTIO_MMIO_QUEUE_AVAIL_HIGH 0x094u
#define VIRTIO_MMIO_QUEUE_USED_LOW 0x0a0u
#define VIRTIO_MMIO_QUEUE_USED_HIGH 0x0a4u
#define VIRTIO_MMIO_CONFIG       0x100u
#define VIRTIO_MMIO_MAGIC        0x74726976u
#define VIRTIO_STATUS_ACKNOWLEDGE (1u << 0)
#define VIRTIO_STATUS_DRIVER      (1u << 1)
#define VIRTIO_STATUS_DRIVER_OK   (1u << 2)
#define VIRTIO_STATUS_FEATURES_OK (1u << 3)
#define VIRTIO_STATUS_FAILED      (1u << 7)
#define VIRTIO_NET_DEVICE_ID     1u
#define VIRTIO_NET_F_MAC         (1u << 5)
#define VIRTIO_F_VERSION_1_HIGH  (1u << 0)
#define VIRTQ_DESC_F_WRITE       (1u << 1)
#define NET_PD_IRQ_BADGE         0x1u
#define NET_PD_IRQ_CAP           64u

/* ── Shared memory ───────────────────────────────────────────────────────── */
uintptr_t net_pd_shmem_vaddr;
uintptr_t net_pd_mmio_vaddr;
uintptr_t log_drain_rings_vaddr;

#define NET_PD_SHMEM ((volatile uint8_t *)net_pd_shmem_vaddr)

/* ── Shmem layout ────────────────────────────────────────────────────────── */
#define NETPD_SHMEM_TOTAL      0x40000u
#define NETPD_SLOT_SIZE        0x4000u
#define NETPD_SLOT_HDR_SIZE    1024u
#define NETPD_SLOT_DATA_SIZE   (NETPD_SLOT_SIZE - NETPD_SLOT_HDR_SIZE)
#define NETPD_SLOT_OFFSET(n)   ((n) * NETPD_SLOT_SIZE)

/* ── Handle type discriminators ─────────────────────────────────────────── */
#define HANDLE_TYPE_INVALID  0u
#define HANDLE_TYPE_NIC      1u
#define HANDLE_TYPE_SOCKET   2u

/* ── Socket states ───────────────────────────────────────────────────────── */
#define SOCK_STATE_FREE        0u
#define SOCK_STATE_BOUND       1u
#define SOCK_STATE_CONNECTING  2u
#define SOCK_STATE_CONNECTED   3u
#define SOCK_STATE_LISTENING   4u
#define SOCK_STATE_CLOSED      5u

/* ── Socket options ──────────────────────────────────────────────────────── */
#define NET_SOCKOPT_REUSEADDR  0u
#define NET_SOCKOPT_NODELAY    1u
#define NET_SOCKOPT_KEEPALIVE  2u

/* ── Config limits ───────────────────────────────────────────────────────── */
#ifndef NET_MAX_CLIENTS
#define NET_MAX_CLIENTS  16u
#endif
#ifndef NET_MAX_FILTERS
#define NET_MAX_FILTERS  32u
#endif
#ifndef NET_MAX_FRAME_BYTES
#define NET_MAX_FRAME_BYTES  1514u
#endif
#ifndef NET_PROTO_TCP
#define NET_PROTO_TCP  0u
#define NET_PROTO_UDP  1u
#endif

/* ── NIC ring header ─────────────────────────────────────────────────────── */
#define NETPD_RING_MAGIC  0x4E455450u

typedef struct {
    uint32_t magic;
    uint32_t handle;
    uint32_t tx_head;
    uint32_t tx_tail;
    uint32_t rx_head;
    uint32_t rx_tail;
    uint32_t tx_drops;
    uint32_t rx_drops;
} netpd_ring_t;

/* ── Per-client handle entry ─────────────────────────────────────────────── */
typedef struct {
    bool     active;
    uint32_t type;
    uint32_t shmem_slot;

    /* NIC handle state */
    uint32_t iface_id;
    uint32_t mtu;
    uint32_t cfg_flags;
    uint64_t rx_pkts;
    uint64_t tx_pkts;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint32_t rx_errors;
    uint32_t tx_errors;
    uint8_t  mac[6];
    uint8_t  _mac_pad[2];
    uint32_t filter_count;
    uint32_t next_filter_id;
    uint32_t filter_ids[NET_MAX_FILTERS];
    uint32_t filter_lens[NET_MAX_FILTERS];

    /* Socket handle state */
    uint8_t  proto;
    uint8_t  sock_state;
    uint32_t local_port;
    uint32_t remote_ip;
    uint32_t remote_port;
} net_pd_client_t;

/* ── Module state ────────────────────────────────────────────────────────── */
static net_pd_client_t clients[NET_MAX_CLIENTS];
static uint32_t        active_clients = 0;
static uint32_t        slot_bitmap    = 0u;
static bool            hw_present     = false;

static uint64_t iface_rx_pkts = 0, iface_tx_pkts = 0;
static uint64_t iface_rx_bytes = 0, iface_tx_bytes = 0;
static uint32_t iface_rx_errors = 0, iface_tx_errors = 0;
static bool     iface_link_up = false;
static netfp_state_t *fastpath;
#ifdef AGENTOS_TEST_HOST
static netfp_state_t fastpath_host;
#endif
static uint64_t dma_base_pa;
static uint16_t rx_last_used;
static uint16_t tx_last_used;
static uint8_t  device_mac[6] = { 0x02u, 0u, 0u, 0u, 0u, 1u };
static uint32_t virtio_probe_stage;
static uint32_t virtio_probe_magic;
static uint32_t virtio_probe_version;
static uint32_t virtio_probe_device_id;
static uint32_t virtio_probe_detail;

/* sel4_server_t instance */
static sel4_server_t g_srv;

/* ── Logging helpers ─────────────────────────────────────────────────────── */
static void log_dec(uint32_t v)
{
    if (v == 0) { log_drain_write(17, 17, "0"); return; }
    char buf[12];
    int  i = 11;
    buf[i] = '\0';
    while (v > 0 && i > 0) { buf[--i] = '0' + (char)(v % 10u); v /= 10u; }
    log_drain_write(17, 17, &buf[i]);
}

static void log_hex(uint32_t v)
{
    static const char hex[] = "0123456789abcdef";
    char buf[11];
    buf[0]  = '0'; buf[1]  = 'x';
    buf[2]  = hex[(v >> 28) & 0xf]; buf[3]  = hex[(v >> 24) & 0xf];
    buf[4]  = hex[(v >> 20) & 0xf]; buf[5]  = hex[(v >> 16) & 0xf];
    buf[6]  = hex[(v >> 12) & 0xf]; buf[7]  = hex[(v >>  8) & 0xf];
    buf[8]  = hex[(v >>  4) & 0xf]; buf[9]  = hex[ v        & 0xf];
    buf[10] = '\0';
    log_drain_write(17, 17, buf);
}

/* ── MMIO helpers ────────────────────────────────────────────────────────── */
static inline uint32_t mmio_read32(uintptr_t base, uint32_t off)
{
    return *(volatile uint32_t *)(base + off);
}
static inline void mmio_write32(uintptr_t base, uint32_t off, uint32_t val)
{
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    *(volatile uint32_t *)(base + off) = val;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

static inline volatile net_dma_desc_t *dma_desc(uint32_t offset)
{
    return (volatile net_dma_desc_t *)(net_pd_shmem_vaddr + offset);
}

static inline volatile uint16_t *dma_avail(uint32_t offset)
{
    return (volatile uint16_t *)(net_pd_shmem_vaddr + offset);
}

static inline volatile uint16_t *dma_used_header(uint32_t offset)
{
    return (volatile uint16_t *)(net_pd_shmem_vaddr + offset);
}

static inline volatile net_dma_used_elem_t *dma_used_ring(uint32_t offset)
{
    return (volatile net_dma_used_elem_t *)(net_pd_shmem_vaddr + offset + 4u);
}

/* ── Shmem slot allocation ───────────────────────────────────────────────── */
static int alloc_slot(void)
{
    for (int i = 0; i < (int)NET_MAX_CLIENTS; i++) {
        if (!(slot_bitmap & (1u << i))) {
            slot_bitmap |= (1u << i);
            return i;
        }
    }
    return -1;
}
static void free_slot(uint32_t slot)
{
    if (slot < NET_MAX_CLIENTS)
        slot_bitmap &= ~(1u << slot);
}

/* ── Handle lookup helpers ───────────────────────────────────────────────── */
static net_pd_client_t *find_client(uint32_t handle)
{
    if (handle >= NET_MAX_CLIENTS) return NULL;
    net_pd_client_t *c = &clients[handle];
    return (c->active) ? c : NULL;
}
static net_pd_client_t *find_nic(uint32_t handle)
{
    net_pd_client_t *c = find_client(handle);
    return (c && c->type == HANDLE_TYPE_NIC) ? c : NULL;
}
static net_pd_client_t *find_sock(uint32_t handle)
{
    net_pd_client_t *c = find_client(handle);
    return (c && c->type == HANDLE_TYPE_SOCKET) ? c : NULL;
}

/* ── Ring accessor ───────────────────────────────────────────────────────── */
static volatile netpd_ring_t *slot_ring(uint32_t slot)
{
    return (volatile netpd_ring_t *)(net_pd_shmem_vaddr + NETPD_SLOT_OFFSET(slot));
}
static void init_ring(uint32_t slot, uint32_t handle)
{
    volatile netpd_ring_t *r = slot_ring(slot);
    r->magic    = NETPD_RING_MAGIC;
    r->handle   = handle;
    r->tx_head  = 0; r->tx_tail = 0;
    r->rx_head  = 0; r->rx_tail = 0;
    r->tx_drops = 0; r->rx_drops = 0;
    __asm__ volatile("" ::: "memory");
}
static void clear_ring(uint32_t slot)
{
    volatile netpd_ring_t *r = slot_ring(slot);
    r->magic = 0;
    __asm__ volatile("" ::: "memory");
}

static void virtio_fail(const char *message)
{
    log_drain_write(17, 17, message);
    if (net_pd_mmio_vaddr != 0u) {
        uint32_t status = mmio_read32(net_pd_mmio_vaddr, VIRTIO_MMIO_STATUS);
        mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_STATUS,
                     status | VIRTIO_STATUS_FAILED);
    }
    hw_present = false;
    iface_link_up = false;
}

static bool virtio_setup_queue(uint32_t queue_id, uint32_t desc_offset,
                               uint32_t avail_offset, uint32_t used_offset)
{
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_QUEUE_SEL, queue_id);
    uint32_t ready = mmio_read32(net_pd_mmio_vaddr, VIRTIO_MMIO_QUEUE_READY);
    uint32_t queue_max =
        mmio_read32(net_pd_mmio_vaddr, VIRTIO_MMIO_QUEUE_NUM_MAX);
    virtio_probe_detail = (queue_id << 24u) | (ready << 16u)
                        | (queue_max & 0xffffu);
    if (ready != 0u)
        return false;
    if (queue_max < NET_DMA_QUEUE_DEPTH)
        return false;

    uint64_t desc_pa = dma_base_pa + desc_offset;
    uint64_t avail_pa = dma_base_pa + avail_offset;
    uint64_t used_pa = dma_base_pa + used_offset;
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_QUEUE_NUM,
                 NET_DMA_QUEUE_DEPTH);
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_QUEUE_DESC_LOW,
                 (uint32_t)desc_pa);
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_QUEUE_DESC_HIGH,
                 (uint32_t)(desc_pa >> 32u));
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_QUEUE_AVAIL_LOW,
                 (uint32_t)avail_pa);
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_QUEUE_AVAIL_HIGH,
                 (uint32_t)(avail_pa >> 32u));
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_QUEUE_USED_LOW,
                 (uint32_t)used_pa);
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_QUEUE_USED_HIGH,
                 (uint32_t)(used_pa >> 32u));
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_QUEUE_READY, 1u);
    ready = mmio_read32(net_pd_mmio_vaddr, VIRTIO_MMIO_QUEUE_READY);
    virtio_probe_detail = (queue_id << 24u) | (ready << 16u)
                        | (queue_max & 0xffffu);
    return ready == 1u;
}

static void virtio_zero_dma_layout(void)
{
    volatile uint8_t *arena = (volatile uint8_t *)net_pd_shmem_vaddr;
    for (uint32_t i = NET_DMA_FASTPATH_OFFSET; i < NET_DMA_LAYOUT_END; i++)
        arena[i] = 0u;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

static void virtio_post_initial_rx(void)
{
    volatile net_dma_desc_t *desc = dma_desc(NET_DMA_RX_DESC_OFFSET);
    volatile uint16_t *avail = dma_avail(NET_DMA_RX_AVAIL_OFFSET);
    for (uint32_t i = 0u; i < NET_DMA_QUEUE_DEPTH; i++) {
        desc[i].addr = dma_base_pa + NET_DMA_RX_BUFFER_OFFSET
                     + i * NET_DMA_BUFFER_STRIDE;
        desc[i].len = NET_DMA_BUFFER_STRIDE;
        desc[i].flags = VIRTQ_DESC_F_WRITE;
        desc[i].next = 0u;
        avail[2u + i] = (uint16_t)i;
    }
    __atomic_thread_fence(__ATOMIC_RELEASE);
    avail[1] = (uint16_t)NET_DMA_QUEUE_DEPTH;
}

/* ── virtio-net probe and full split-queue negotiation ──────────────────── */
static void probe_virtio_net(void)
{
    virtio_probe_stage = 1u;
    if (!net_pd_mmio_vaddr) {
        log_drain_write(17, 17, "[net_pd] virtio-net: MMIO not mapped, stub mode\n");
        return;
    }

    uint32_t magic     = mmio_read32(net_pd_mmio_vaddr, VIRTIO_MMIO_MAGIC_VALUE);
    uint32_t version   = mmio_read32(net_pd_mmio_vaddr, VIRTIO_MMIO_VERSION);
    uint32_t device_id = mmio_read32(net_pd_mmio_vaddr, VIRTIO_MMIO_DEVICE_ID);
    virtio_probe_magic = magic;
    virtio_probe_version = version;
    virtio_probe_device_id = device_id;

    if (magic != VIRTIO_MMIO_MAGIC || version != 2u
            || device_id != VIRTIO_NET_DEVICE_ID) {
        log_drain_write(17, 17, "[net_pd] virtio-net not detected (magic=");
        log_hex(magic);
        log_drain_write(17, 17, "), stub mode\n");
        return;
    }

    const volatile net_dma_startup_t *startup =
        (const volatile net_dma_startup_t *)NET_DMA_STARTUP_VA;
    virtio_probe_stage = 2u;
    virtio_probe_detail = startup->magic;
    if (startup->magic != NET_DMA_STARTUP_MAGIC
        || startup->version != NET_DMA_STARTUP_VERSION
        || startup->size != sizeof(net_dma_startup_t)
        || startup->dma_base_pa == 0u
        || startup->dma_bytes < NET_DMA_LAYOUT_END) {
        virtio_fail("[net_pd] ERROR: invalid DMA startup record\n");
        return;
    }
    dma_base_pa = startup->dma_base_pa;

    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_STATUS, 0u);
    uint32_t status = VIRTIO_STATUS_ACKNOWLEDGE;
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_STATUS, status);
    status |= VIRTIO_STATUS_DRIVER;
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_STATUS, status);

    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_DEVICE_FEATURES_SEL, 1u);
    uint32_t features_high =
        mmio_read32(net_pd_mmio_vaddr, VIRTIO_MMIO_DEVICE_FEATURES);
    virtio_probe_stage = 3u;
    virtio_probe_detail = features_high;
    if ((features_high & VIRTIO_F_VERSION_1_HIGH) == 0u) {
        virtio_fail("[net_pd] ERROR: VirtIO 1 feature unavailable\n");
        return;
    }
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_DEVICE_FEATURES_SEL, 0u);
    uint32_t features_low =
        mmio_read32(net_pd_mmio_vaddr, VIRTIO_MMIO_DEVICE_FEATURES);
    uint32_t driver_low = features_low & VIRTIO_NET_F_MAC;
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0u);
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_DRIVER_FEATURES, driver_low);
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_DRIVER_FEATURES_SEL, 1u);
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_DRIVER_FEATURES,
                 VIRTIO_F_VERSION_1_HIGH);
    status |= VIRTIO_STATUS_FEATURES_OK;
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_STATUS, status);
    if ((mmio_read32(net_pd_mmio_vaddr, VIRTIO_MMIO_STATUS)
         & VIRTIO_STATUS_FEATURES_OK) == 0u) {
        virtio_fail("[net_pd] ERROR: VirtIO feature negotiation rejected\n");
        return;
    }

    virtio_zero_dma_layout();
    fastpath = (netfp_state_t *)(net_pd_shmem_vaddr
                                 + NET_DMA_FASTPATH_OFFSET);
    netfp_init(fastpath, 1u);
    rx_last_used = 0u;
    tx_last_used = 0u;
    virtio_probe_stage = 4u;
    if (!virtio_setup_queue(0u, NET_DMA_RX_DESC_OFFSET,
                            NET_DMA_RX_AVAIL_OFFSET,
                            NET_DMA_RX_USED_OFFSET)
        || !virtio_setup_queue(1u, NET_DMA_TX_DESC_OFFSET,
                               NET_DMA_TX_AVAIL_OFFSET,
                               NET_DMA_TX_USED_OFFSET)) {
        virtio_fail("[net_pd] ERROR: VirtIO queue setup failed\n");
        return;
    }
    virtio_post_initial_rx();
    if ((driver_low & VIRTIO_NET_F_MAC) != 0u) {
        for (uint32_t i = 0u; i < 6u; i++)
            device_mac[i] = *(volatile uint8_t *)(net_pd_mmio_vaddr
                                                  + VIRTIO_MMIO_CONFIG + i);
    }
    status |= VIRTIO_STATUS_DRIVER_OK;
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_STATUS, status);
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_QUEUE_NOTIFY, 0u);
    hw_present = true;
    iface_link_up = true;
    virtio_probe_stage = 5u;
    virtio_probe_detail = status;

    log_drain_write(17, 17, "[net_pd] virtio-net detected at ");
    log_hex((uint32_t)net_pd_mmio_vaddr);
    log_drain_write(17, 17, ", RX/TX queues ready\n");
}

static bool enqueue_rx_for_client(net_pd_client_t *client,
                                  const uint8_t *frame, uint32_t frame_len)
{
    volatile netpd_ring_t *ring = slot_ring(client->shmem_slot);
    uint32_t record_len = frame_len + 2u;
    if (record_len >= NETPD_SLOT_DATA_SIZE) return false;

    uint32_t head = ring->rx_head;
    uint32_t tail = ring->rx_tail;
    if (head >= tail) {
        if (NETPD_SLOT_DATA_SIZE - head < record_len) {
            if (tail <= record_len) return false;
            head = 0u;
        } else if (tail == 0u && head + record_len == NETPD_SLOT_DATA_SIZE) {
            return false;
        }
    } else if (head + record_len >= tail) {
        return false;
    }

    volatile uint8_t *dst = NET_PD_SHMEM
        + NETPD_SLOT_OFFSET(client->shmem_slot) + NETPD_SLOT_HDR_SIZE + head;
    dst[0] = (uint8_t)frame_len;
    dst[1] = (uint8_t)(frame_len >> 8u);
    for (uint32_t i = 0u; i < frame_len; i++) dst[2u + i] = frame[i];
    __atomic_thread_fence(__ATOMIC_RELEASE);
    ring->rx_head = head + record_len;
    if (ring->rx_head == NETPD_SLOT_DATA_SIZE) ring->rx_head = 0u;
    return true;
}

static void virtio_reap_rx(void)
{
    volatile uint16_t *used = dma_used_header(NET_DMA_RX_USED_OFFSET);
    volatile net_dma_used_elem_t *ring = dma_used_ring(NET_DMA_RX_USED_OFFSET);
    volatile uint16_t *avail = dma_avail(NET_DMA_RX_AVAIL_OFFSET);
    uint16_t device_idx = __atomic_load_n(&used[1], __ATOMIC_ACQUIRE);
    bool reposted = false;
    while (rx_last_used != device_idx) {
        net_dma_used_elem_t elem = ring[rx_last_used % NET_DMA_QUEUE_DEPTH];
        uint32_t id = elem.id;
        if (id < NET_DMA_QUEUE_DEPTH
            && elem.len >= NET_DMA_VIRTIO_HDR_BYTES
            && elem.len <= NET_DMA_BUFFER_STRIDE) {
            const uint8_t *frame = (const uint8_t *)(net_pd_shmem_vaddr
                + NET_DMA_RX_BUFFER_OFFSET + id * NET_DMA_BUFFER_STRIDE
                + NET_DMA_VIRTIO_HDR_BYTES);
            uint32_t frame_len = elem.len - NET_DMA_VIRTIO_HDR_BYTES;
            for (uint32_t i = 0u; i < NET_MAX_CLIENTS; i++) {
                if (!clients[i].active || clients[i].type != HANDLE_TYPE_NIC)
                    continue;
                if (enqueue_rx_for_client(&clients[i], frame, frame_len)) {
                    clients[i].rx_pkts++;
                    clients[i].rx_bytes += frame_len;
                } else {
                    clients[i].rx_errors++;
                    slot_ring(clients[i].shmem_slot)->rx_drops++;
                }
            }
            iface_rx_pkts++;
            iface_rx_bytes += frame_len;
        } else {
            iface_rx_errors++;
        }

        if (id < NET_DMA_QUEUE_DEPTH) {
            uint16_t avail_idx = avail[1];
            avail[2u + (avail_idx % NET_DMA_QUEUE_DEPTH)] = (uint16_t)id;
            __atomic_thread_fence(__ATOMIC_RELEASE);
            avail[1] = (uint16_t)(avail_idx + 1u);
            reposted = true;
        }
        rx_last_used++;
    }
    if (reposted)
        mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_QUEUE_NOTIFY, 0u);
}

static void virtio_reap_tx(void)
{
    volatile uint16_t *used = dma_used_header(NET_DMA_TX_USED_OFFSET);
    volatile net_dma_used_elem_t *ring = dma_used_ring(NET_DMA_TX_USED_OFFSET);
    uint16_t device_idx = __atomic_load_n(&used[1], __ATOMIC_ACQUIRE);
    while (tx_last_used != device_idx) {
        uint32_t id = ring[tx_last_used % NET_DMA_QUEUE_DEPTH].id;
        if (id < NET_DMA_QUEUE_DEPTH
            && netfp_driver_complete(fastpath, 0u, id, tx_last_used) == 0) {
            (void)netfp_client_release(fastpath, 0u, id);
        } else {
            iface_tx_errors++;
        }
        tx_last_used++;
    }
}

static int virtio_submit_tx(const uint8_t *frame, uint32_t frame_len)
{
    virtio_reap_tx();
    uint32_t slot = 0u;
    if (netfp_client_reserve(fastpath, 0u, &slot) != 0) return -1;

    uint8_t *buffer = (uint8_t *)(net_pd_shmem_vaddr
        + NET_DMA_TX_BUFFER_OFFSET + slot * NET_DMA_BUFFER_STRIDE);
    for (uint32_t i = 0u; i < NET_DMA_VIRTIO_HDR_BYTES; i++) buffer[i] = 0u;
    for (uint32_t i = 0u; i < frame_len; i++)
        buffer[NET_DMA_VIRTIO_HDR_BYTES + i] = frame[i];
    if (netfp_client_submit(fastpath, 0u, slot, frame_len, 0u) != 0)
        return -1;
    uint32_t batched = 0u;
    if (netfp_driver_batch(fastpath, 0u, 1u, &batched) != 1u
        || batched != slot)
        return -1;

    volatile net_dma_desc_t *desc = dma_desc(NET_DMA_TX_DESC_OFFSET);
    desc[slot].addr = dma_base_pa + NET_DMA_TX_BUFFER_OFFSET
                    + slot * NET_DMA_BUFFER_STRIDE;
    desc[slot].len = NET_DMA_VIRTIO_HDR_BYTES + frame_len;
    desc[slot].flags = 0u;
    desc[slot].next = 0u;
    volatile uint16_t *avail = dma_avail(NET_DMA_TX_AVAIL_OFFSET);
    uint16_t avail_idx = avail[1];
    avail[2u + (avail_idx % NET_DMA_QUEUE_DEPTH)] = (uint16_t)slot;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    avail[1] = (uint16_t)(avail_idx + 1u);
    mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_QUEUE_NOTIFY, 1u);
    return 0;
}

static bool badge_has_fastpath(sel4_badge_t badge)
{
    return (((uint32_t)(uint64_t)badge) & NET_PD_RIGHT_FASTPATH) != 0u;
}

static uint32_t handle_fastpath_send(sel4_badge_t badge,
                                     const sel4_msg_t *req,
                                     sel4_msg_t *rep,
                                     void *ctx __attribute__((unused)))
{
    if (!badge_has_fastpath(badge)) return SEL4_ERR_PERM;
    uint32_t offset = data_rd32(req->data, 0);
    uint32_t len = data_rd32(req->data, 4);
    if (!hw_present || fastpath == (netfp_state_t *)0)
        return SEL4_ERR_NOT_FOUND;
    bool client_frame = offset >= NETPD_SLOT_HDR_SIZE
        && offset < NET_DMA_CLIENT_BYTES
        && len <= NET_DMA_CLIENT_BYTES - offset;
    bool wg_frame = offset >= NET_DMA_WG_FRAME_OFFSET
        && offset < NET_DMA_WG_FRAME_OFFSET + NET_DMA_WG_FRAME_BYTES
        && len <= NET_DMA_WG_FRAME_OFFSET + NET_DMA_WG_FRAME_BYTES - offset;
    if (len == 0u || len > NET_DMA_MAX_FRAME_BYTES
        || (!client_frame && !wg_frame))
        return SEL4_ERR_BAD_ARG;
    const uint8_t *frame = (const uint8_t *)(net_pd_shmem_vaddr + offset);
    if (virtio_submit_tx(frame, len) != 0) return SEL4_ERR_NO_MEM;
    data_wr32(rep->data, 0, 1u);
    data_wr32(rep->data, 4, 0u);
    rep->length = 8u;
    return SEL4_ERR_OK;
}

static uint32_t handle_fastpath_status(sel4_badge_t badge,
                                       const sel4_msg_t *req __attribute__((unused)),
                                       sel4_msg_t *rep,
                                       void *ctx __attribute__((unused)))
{
    if (!badge_has_fastpath(badge)) return SEL4_ERR_PERM;
    if (hw_present && fastpath != (netfp_state_t *)0)
        virtio_reap_tx();
    data_wr32(rep->data, 0, iface_link_up ? 1u : 0u);
    data_wr32(rep->data, 4, hw_present ? NET_DMA_QUEUE_DEPTH : 0u);
    data_wr32(rep->data, 8,
              fastpath != (netfp_state_t *)0
                  ? fastpath->queues[0].in_flight : 0u);
    data_wr32(rep->data, 12,
              fastpath != (netfp_state_t *)0
                  ? (uint32_t)fastpath->irq_count : 0u);
    data_wr32(rep->data, 16, virtio_probe_stage);
    data_wr32(rep->data, 20, virtio_probe_magic);
    data_wr32(rep->data, 24, virtio_probe_version);
    data_wr32(rep->data, 28, virtio_probe_device_id);
    data_wr32(rep->data, 32, virtio_probe_detail);
    data_wr32(rep->data, 36, (uint32_t)iface_rx_pkts);
    for (uint32_t i = 0u; i < 6u; i++) rep->data[40u + i] = device_mac[i];
    rep->length = 46u;
    return SEL4_ERR_OK;
}

static void handle_net_irq(void)
{
    if (hw_present) {
        uint32_t status = mmio_read32(net_pd_mmio_vaddr,
                                      VIRTIO_MMIO_INTERRUPT_STATUS);
        if (status != 0u) {
            mmio_write32(net_pd_mmio_vaddr, VIRTIO_MMIO_INTERRUPT_ACK, status);
            netfp_record_irq(fastpath);
            virtio_reap_rx();
            virtio_reap_tx();
        }
    }
#ifndef AGENTOS_TEST_HOST
    (void)seL4_IRQHandler_Ack((seL4_CPtr)NET_PD_IRQ_CAP);
#endif
}

/* ── Nameserver registration ─────────────────────────────────────────────── */
static void register_with_nameserver(seL4_CPtr ns_ep)
{
    if (!ns_ep) return;
    sel4_msg_t req = {0}, rep = {0};
    req.opcode = (uint32_t)OP_NS_REGISTER;
    data_wr32(req.data,  0, 0u);
    data_wr32(req.data,  4, 0u);
    data_wr32(req.data,  8, 0u);
    data_wr32(req.data, 12, 1u);
    /* Name "net_pd" at data[16..] */
    req.data[16] = 'n'; req.data[17] = 'e'; req.data[18] = 't'; req.data[19] = '_';
    req.data[20] = 'p'; req.data[21] = 'd'; req.data[22] = '\0';
    req.length = 23;
#ifndef AGENTOS_TEST_HOST
    sel4_call(ns_ep, &req, &rep);
#else
    (void)rep;
#endif
    log_drain_write(17, 17, "[net_pd] registered with nameserver as 'net_pd'\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MSG_NET_OPEN (0x2101)
 *   req.data[0..3] = iface_id
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_net_open(sel4_badge_t badge __attribute__((unused)),
                                 const sel4_msg_t *req,
                                 sel4_msg_t *rep,
                                 void *ctx __attribute__((unused)))
{
    uint32_t iface_id = data_rd32(req->data, 0);

    if (active_clients >= NET_MAX_CLIENTS) {
        data_wr32(rep->data, 0, NET_ERR_NO_SLOTS);
        rep->length = 4;
        return SEL4_ERR_NO_MEM;
    }

    int slot = alloc_slot();
    if (slot < 0) {
        data_wr32(rep->data, 0, NET_ERR_NO_SLOTS);
        rep->length = 4;
        return SEL4_ERR_NO_MEM;
    }

    int handle = -1;
    for (int i = 0; i < (int)NET_MAX_CLIENTS; i++) {
        if (!clients[i].active) { handle = i; break; }
    }
    if (handle < 0) {
        free_slot((uint32_t)slot);
        data_wr32(rep->data, 0, NET_ERR_NO_SLOTS);
        rep->length = 4;
        return SEL4_ERR_NO_MEM;
    }

    net_pd_client_t *c = &clients[handle];
    c->active       = true;
    c->type         = HANDLE_TYPE_NIC;
    c->shmem_slot   = (uint32_t)slot;
    c->iface_id     = iface_id;
    c->mtu          = 1500u;
    c->cfg_flags    = 0u;
    c->rx_pkts      = 0; c->tx_pkts = 0;
    c->rx_bytes     = 0; c->tx_bytes = 0;
    c->rx_errors    = 0; c->tx_errors = 0;
    c->filter_count = 0; c->next_filter_id = 1u;
    for (uint32_t i = 0; i < NET_MAX_FILTERS; i++) {
        c->filter_ids[i]  = 0;
        c->filter_lens[i] = 0;
    }

    for (uint32_t i = 0u; i < 6u; i++) c->mac[i] = device_mac[i];

    init_ring((uint32_t)slot, (uint32_t)handle);
    active_clients++;

    uint32_t slot_off = NETPD_SLOT_OFFSET((uint32_t)slot);

    log_drain_write(17, 17, "[net_pd] OPEN: handle=");
    log_dec((uint32_t)handle);
    log_drain_write(17, 17, " iface=");
    log_dec(iface_id);
    log_drain_write(17, 17, " slot=");
    log_dec((uint32_t)slot);
    log_drain_write(17, 17, "\n");

    data_wr32(rep->data,  0, NET_OK);
    data_wr32(rep->data,  4, (uint32_t)handle);
    data_wr32(rep->data,  8, slot_off);
    /* MAC in data[12..17] */
    rep->data[12] = c->mac[0]; rep->data[13] = c->mac[1];
    rep->data[14] = c->mac[2]; rep->data[15] = c->mac[3];
    rep->data[16] = c->mac[4]; rep->data[17] = c->mac[5];
    rep->length = 18;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MSG_NET_CLOSE (0x2102)
 *   req.data[0..3] = handle
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_net_close(sel4_badge_t badge __attribute__((unused)),
                                  const sel4_msg_t *req,
                                  sel4_msg_t *rep,
                                  void *ctx __attribute__((unused)))
{
    uint32_t handle = data_rd32(req->data, 0);
    net_pd_client_t *c = find_nic(handle);
    if (!c) {
        data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
        rep->length = 4;
        return SEL4_ERR_NOT_FOUND;
    }

    log_drain_write(17, 17, "[net_pd] CLOSE: handle=");
    log_dec(handle);
    log_drain_write(17, 17, "\n");

    clear_ring(c->shmem_slot);
    free_slot(c->shmem_slot);
    c->active = false;
    if (active_clients > 0) active_clients--;

    data_wr32(rep->data, 0, NET_OK);
    rep->length = 4;
    return SEL4_ERR_OK;
}

/* ── MSG_NET_SEND helpers ────────────────────────────────────────────────── */

static uint32_t handle_net_send_nic(net_pd_client_t *c, uint32_t handle,
                                     sel4_msg_t *rep)
{
    uint32_t frame_len = data_rd32(rep->data, 0);  /* re-read from original req */
    /* NOTE: rep is used as scratch here; frame_len is re-decoded from the
     * call site wrapper which places it in rep->data[4..7] before this call. */
    frame_len = *(uint32_t *)(void *)&rep->data[4]; /* set by wrapper */

    if (frame_len == 0 || frame_len > NET_MAX_FRAME_BYTES) {
        c->tx_errors++;
        data_wr32(rep->data, 0, NET_ERR_FRAME_TOO_LARGE);
        rep->length = 4;
        return SEL4_ERR_BAD_ARG;
    }

    uint32_t slot_off = NETPD_SLOT_OFFSET(c->shmem_slot) + NETPD_SLOT_HDR_SIZE;
    if (slot_off + frame_len > NETPD_SHMEM_TOTAL) {
        c->tx_errors++;
        data_wr32(rep->data, 0, NET_ERR_FRAME_TOO_LARGE);
        rep->length = 4;
        return SEL4_ERR_BAD_ARG;
    }

    if (hw_present) {
#ifndef AGENTOS_TEST_HOST
        const uint8_t *frame = (const uint8_t *)(net_pd_shmem_vaddr + slot_off);
        if (virtio_submit_tx(frame, frame_len) != 0) {
            c->tx_errors++;
            slot_ring(c->shmem_slot)->tx_drops++;
            data_wr32(rep->data, 0, NET_ERR_NO_SLOTS);
            rep->length = 4;
            return SEL4_ERR_NO_MEM;
        }
#endif
    } else {
        log_drain_write(17, 17, "[net_pd] TX stub (no hw): handle=");
        log_dec(handle);
        log_drain_write(17, 17, " len=");
        log_dec(frame_len);
        log_drain_write(17, 17, "\n");
    }

    c->tx_pkts++;
    c->tx_bytes += frame_len;
    iface_tx_pkts++;
    iface_tx_bytes += frame_len;

    data_wr32(rep->data, 0, NET_OK);
    rep->length = 4;
    return SEL4_ERR_OK;
}

static uint32_t handle_net_send_sock(net_pd_client_t *c, uint32_t handle,
                                      uint32_t data_len,
                                      sel4_msg_t *rep)
{
    if (data_len == 0) {
        data_wr32(rep->data, 0, NET_OK);
        rep->length = 4;
        return SEL4_ERR_OK;
    }

    uint32_t slot_off = NETPD_SLOT_OFFSET(c->shmem_slot) + NETPD_SLOT_HDR_SIZE;
    const uint8_t *data = (const uint8_t *)(net_pd_shmem_vaddr + slot_off);

    if (c->sock_state != SOCK_STATE_CONNECTED) {
        data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
        rep->length = 4;
        return SEL4_ERR_BAD_ARG;
    }

    uint16_t len16 = (data_len > 65535u) ? 65535u : (uint16_t)data_len;
    int sent = lwip_net_send((uint8_t)(c->shmem_slot & 0xFFu), data, len16);

    if (sent < 0) {
        c->tx_errors++;
        data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
        rep->length = 4;
        return SEL4_ERR_BAD_ARG;
    }

    c->tx_pkts++;
    c->tx_bytes += (uint32_t)sent;

    log_drain_write(17, 17, "[net_pd] SOCK_SEND: handle=");
    log_dec(handle);
    log_drain_write(17, 17, " sent=");
    log_dec((uint32_t)sent);
    log_drain_write(17, 17, "\n");

    data_wr32(rep->data, 0, NET_OK);
    rep->length = 4;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MSG_NET_SEND (0x2103)
 *   req.data[0..3] = handle
 *   req.data[4..7] = len (frame bytes for NIC; data bytes for socket)
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_net_send(sel4_badge_t badge __attribute__((unused)),
                                 const sel4_msg_t *req,
                                 sel4_msg_t *rep,
                                 void *ctx __attribute__((unused)))
{
    uint32_t handle   = data_rd32(req->data, 0);
    uint32_t data_len = data_rd32(req->data, 4);

    net_pd_client_t *c = find_client(handle);
    if (!c) {
        data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
        rep->length = 4;
        return SEL4_ERR_NOT_FOUND;
    }

    if (c->type == HANDLE_TYPE_NIC) {
        /* pass frame_len via rep scratch slot */
        data_wr32(rep->data, 4, data_len);
        return handle_net_send_nic(c, handle, rep);
    }
    return handle_net_send_sock(c, handle, data_len, rep);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MSG_NET_RECV (0x2104)
 *   req.data[0..3] = handle
 *   req.data[4..7] = max_bytes
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_net_recv_nic(net_pd_client_t *c,
                                     uint32_t max_len,
                                     sel4_msg_t *rep)
{
    volatile netpd_ring_t *ring = slot_ring(c->shmem_slot);
    uint32_t data_off = NETPD_SLOT_OFFSET(c->shmem_slot) + NETPD_SLOT_HDR_SIZE;

    if (ring->rx_head == ring->rx_tail) {
        data_wr32(rep->data, 0, NET_OK);
        data_wr32(rep->data, 4, 0u);
        data_wr32(rep->data, 8, 0u);
        rep->length = 12;
        return SEL4_ERR_OK;
    }

    uint32_t stored_len = *(volatile uint16_t *)(net_pd_shmem_vaddr + data_off
                           + ring->rx_tail);
    uint32_t frame_len = stored_len;
    if (frame_len > max_len) frame_len = max_len;

    uint32_t frame_off = data_off + ring->rx_tail + 2u;
    ring->rx_tail = (ring->rx_tail + 2u + stored_len) % NETPD_SLOT_DATA_SIZE;

    data_wr32(rep->data, 0, NET_OK);
    data_wr32(rep->data, 4, frame_len);
    data_wr32(rep->data, 8, frame_off);
    rep->length = 12;
    return SEL4_ERR_OK;
}

static uint32_t handle_net_recv_sock(net_pd_client_t *c,
                                      uint32_t max_len,
                                      sel4_msg_t *rep)
{
    uint32_t slot_off = NETPD_SLOT_OFFSET(c->shmem_slot) + NETPD_SLOT_HDR_SIZE;
    uint8_t *buf = (uint8_t *)(net_pd_shmem_vaddr + slot_off);

    if (max_len > NETPD_SLOT_DATA_SIZE) max_len = NETPD_SLOT_DATA_SIZE;

    int n = lwip_net_recv((uint8_t)(c->shmem_slot & 0xFFu), buf,
                          max_len > 65536u ? 65536u : max_len);
    if (n > 0) {
        c->rx_pkts++;
        c->rx_bytes += (uint32_t)n;
    }

    data_wr32(rep->data, 0, NET_OK);
    data_wr32(rep->data, 4, (uint32_t)(n > 0 ? n : 0));
    data_wr32(rep->data, 8, slot_off);
    rep->length = 12;
    return SEL4_ERR_OK;
}

static uint32_t handle_net_recv(sel4_badge_t badge __attribute__((unused)),
                                  const sel4_msg_t *req,
                                  sel4_msg_t *rep,
                                  void *ctx __attribute__((unused)))
{
    uint32_t handle  = data_rd32(req->data, 0);
    uint32_t max_len = data_rd32(req->data, 4);

    net_pd_client_t *c = find_client(handle);
    if (!c) {
        data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
        data_wr32(rep->data, 4, 0);
        data_wr32(rep->data, 8, 0);
        rep->length = 12;
        return SEL4_ERR_NOT_FOUND;
    }
    if (c->type == HANDLE_TYPE_NIC)
        return handle_net_recv_nic(c, max_len, rep);
    return handle_net_recv_sock(c, max_len, rep);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MSG_NET_DEV_STATUS (0x2105)
 *   req.data[0..3] = handle (0xFFFFFFFF = global)
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_net_dev_status(sel4_badge_t badge __attribute__((unused)),
                                       const sel4_msg_t *req,
                                       sel4_msg_t *rep,
                                       void *ctx __attribute__((unused)))
{
    uint32_t handle = data_rd32(req->data, 0);

    uint64_t rx_pkts, tx_pkts, rx_bytes, tx_bytes;
    uint32_t rx_errors, tx_errors, link;

    if (handle == 0xFFFFFFFFu) {
        rx_pkts   = iface_rx_pkts;   tx_pkts   = iface_tx_pkts;
        rx_bytes  = iface_rx_bytes;  tx_bytes  = iface_tx_bytes;
        rx_errors = iface_rx_errors; tx_errors = iface_tx_errors;
        link      = iface_link_up ? 1u : 0u;
    } else {
        net_pd_client_t *c = find_client(handle);
        if (!c) {
            data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
            rep->length = 4;
            return SEL4_ERR_NOT_FOUND;
        }
        rx_pkts   = c->rx_pkts;   tx_pkts   = c->tx_pkts;
        rx_bytes  = c->rx_bytes;  tx_bytes  = c->tx_bytes;
        rx_errors = c->rx_errors; tx_errors = c->tx_errors;
        link      = iface_link_up ? 1u : 0u;
    }

    data_wr32(rep->data,  0, NET_OK);
    data_wr32(rep->data,  4, link);
    data_wr32(rep->data,  8, (uint32_t)(rx_pkts  & 0xFFFFFFFFu));
    data_wr32(rep->data, 12, (uint32_t)(tx_pkts  & 0xFFFFFFFFu));
    data_wr32(rep->data, 16, (uint32_t)(rx_bytes & 0xFFFFFFFFu));
    data_wr32(rep->data, 20, (uint32_t)(tx_bytes & 0xFFFFFFFFu));
    data_wr32(rep->data, 24, rx_errors);
    data_wr32(rep->data, 28, tx_errors);
    rep->length = 32;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MSG_NET_CONFIGURE (0x2106)
 *   req.data[0..3]  = handle
 *   req.data[4..7]  = mtu
 *   req.data[8..11] = flags
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_net_configure(sel4_badge_t badge __attribute__((unused)),
                                      const sel4_msg_t *req,
                                      sel4_msg_t *rep,
                                      void *ctx __attribute__((unused)))
{
    uint32_t handle = data_rd32(req->data, 0);
    uint32_t mtu    = data_rd32(req->data, 4);
    uint32_t flags  = data_rd32(req->data, 8);

    net_pd_client_t *c = find_nic(handle);
    if (!c) {
        data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
        rep->length = 4;
        return SEL4_ERR_NOT_FOUND;
    }

    if (mtu > 0u && mtu <= 9000u) c->mtu = mtu;
    c->cfg_flags = flags;

    log_drain_write(17, 17, "[net_pd] CONFIGURE: handle=");
    log_dec(handle);
    log_drain_write(17, 17, " mtu=");
    log_dec(c->mtu);
    log_drain_write(17, 17, " flags=");
    log_hex(flags);
    log_drain_write(17, 17, "\n");

    data_wr32(rep->data, 0, NET_OK);
    rep->length = 4;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MSG_NET_FILTER_ADD (0x2107)
 *   req.data[0..3] = handle
 *   req.data[4..7] = filter_len
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_net_filter_add(sel4_badge_t badge __attribute__((unused)),
                                       const sel4_msg_t *req,
                                       sel4_msg_t *rep,
                                       void *ctx __attribute__((unused)))
{
    uint32_t handle     = data_rd32(req->data, 0);
    uint32_t filter_len = data_rd32(req->data, 4);

    net_pd_client_t *c = find_nic(handle);
    if (!c) {
        data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
        data_wr32(rep->data, 4, 0);
        rep->length = 8;
        return SEL4_ERR_NOT_FOUND;
    }

    if (c->filter_count >= NET_MAX_FILTERS) {
        data_wr32(rep->data, 0, NET_ERR_FILTER_FULL);
        data_wr32(rep->data, 4, 0);
        rep->length = 8;
        return SEL4_ERR_NO_MEM;
    }

    uint32_t filter_id = c->next_filter_id++;
    uint32_t slot      = c->filter_count;
    c->filter_ids[slot]  = filter_id;
    c->filter_lens[slot] = filter_len;
    c->filter_count++;

    log_drain_write(17, 17, "[net_pd] FILTER_ADD: handle=");
    log_dec(handle);
    log_drain_write(17, 17, " filter_id=");
    log_dec(filter_id);
    log_drain_write(17, 17, "\n");

    data_wr32(rep->data, 0, NET_OK);
    data_wr32(rep->data, 4, filter_id);
    rep->length = 8;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MSG_NET_FILTER_REMOVE (0x2108)
 *   req.data[0..3] = handle
 *   req.data[4..7] = filter_id
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_net_filter_remove(sel4_badge_t badge __attribute__((unused)),
                                          const sel4_msg_t *req,
                                          sel4_msg_t *rep,
                                          void *ctx __attribute__((unused)))
{
    uint32_t handle    = data_rd32(req->data, 0);
    uint32_t filter_id = data_rd32(req->data, 4);

    net_pd_client_t *c = find_nic(handle);
    if (!c) {
        data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
        rep->length = 4;
        return SEL4_ERR_NOT_FOUND;
    }

    for (uint32_t i = 0; i < c->filter_count; i++) {
        if (c->filter_ids[i] == filter_id) {
            for (uint32_t j = i; j + 1u < c->filter_count; j++) {
                c->filter_ids[j]  = c->filter_ids[j + 1u];
                c->filter_lens[j] = c->filter_lens[j + 1u];
            }
            c->filter_count--;
            log_drain_write(17, 17, "[net_pd] FILTER_REMOVE: handle=");
            log_dec(handle);
            log_drain_write(17, 17, " filter_id=");
            log_dec(filter_id);
            log_drain_write(17, 17, "\n");
            data_wr32(rep->data, 0, NET_OK);
            rep->length = 4;
            return SEL4_ERR_OK;
        }
    }

    data_wr32(rep->data, 0, NET_ERR_BAD_FILTER_ID);
    rep->length = 4;
    return SEL4_ERR_NOT_FOUND;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MSG_NET_SOCKET_OPEN (0x2109)
 *   req.data[0..3] = proto (NET_PROTO_TCP=0, NET_PROTO_UDP=1)
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_socket_open(sel4_badge_t badge __attribute__((unused)),
                                    const sel4_msg_t *req,
                                    sel4_msg_t *rep,
                                    void *ctx __attribute__((unused)))
{
    uint32_t proto = data_rd32(req->data, 0);

    if (proto != NET_PROTO_TCP && proto != NET_PROTO_UDP) {
        data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
        rep->length = 4;
        return SEL4_ERR_BAD_ARG;
    }

    if (active_clients >= NET_MAX_CLIENTS) {
        data_wr32(rep->data, 0, NET_ERR_NO_SLOTS);
        rep->length = 4;
        return SEL4_ERR_NO_MEM;
    }

    int slot = alloc_slot();
    if (slot < 0) {
        data_wr32(rep->data, 0, NET_ERR_NO_SLOTS);
        rep->length = 4;
        return SEL4_ERR_NO_MEM;
    }

    int handle = -1;
    for (int i = 0; i < (int)NET_MAX_CLIENTS; i++) {
        if (!clients[i].active) { handle = i; break; }
    }
    if (handle < 0) {
        free_slot((uint32_t)slot);
        data_wr32(rep->data, 0, NET_ERR_NO_SLOTS);
        rep->length = 4;
        return SEL4_ERR_NO_MEM;
    }

    net_pd_client_t *c = &clients[handle];
    c->active      = true;
    c->type        = HANDLE_TYPE_SOCKET;
    c->shmem_slot  = (uint32_t)slot;
    c->proto       = (uint8_t)proto;
    c->sock_state  = SOCK_STATE_FREE;
    c->local_port  = 0;
    c->remote_ip   = 0;
    c->remote_port = 0;
    c->rx_pkts  = 0; c->tx_pkts  = 0;
    c->rx_bytes = 0; c->tx_bytes = 0;
    c->rx_errors = 0; c->tx_errors = 0;

    init_ring((uint32_t)slot, (uint32_t)handle);
    active_clients++;

    log_drain_write(17, 17, "[net_pd] SOCKET_OPEN: handle=");
    log_dec((uint32_t)handle);
    log_drain_write(17, 17, " proto=");
    log_dec(proto);
    log_drain_write(17, 17, "\n");

    data_wr32(rep->data, 0, NET_OK);
    data_wr32(rep->data, 4, (uint32_t)handle);
    data_wr32(rep->data, 8, NETPD_SLOT_OFFSET((uint32_t)slot));
    rep->length = 12;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MSG_NET_SOCKET_CLOSE (0x210A)
 *   req.data[0..3] = handle
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_socket_close(sel4_badge_t badge __attribute__((unused)),
                                     const sel4_msg_t *req,
                                     sel4_msg_t *rep,
                                     void *ctx __attribute__((unused)))
{
    uint32_t handle = data_rd32(req->data, 0);
    net_pd_client_t *c = find_sock(handle);
    if (!c) {
        data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
        rep->length = 4;
        return SEL4_ERR_NOT_FOUND;
    }

#ifndef AGENTOS_TEST_HOST
    uint32_t slot = c->shmem_slot;
    if (c->proto == NET_PROTO_TCP && g_conns[slot].tcp) {
        tcp_close(g_conns[slot].tcp);
        g_conns[slot].tcp   = NULL;
        g_conns[slot].state = 0u;
    }
#endif

    log_drain_write(17, 17, "[net_pd] SOCKET_CLOSE: handle=");
    log_dec(handle);
    log_drain_write(17, 17, "\n");

    clear_ring(c->shmem_slot);
    free_slot(c->shmem_slot);
    c->active = false;
    if (active_clients > 0) active_clients--;

    data_wr32(rep->data, 0, NET_OK);
    rep->length = 4;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MSG_NET_SOCKET_CONNECT (0x210B)
 *   req.data[0..3]  = handle
 *   req.data[4..7]  = dest_ip
 *   req.data[8..11] = dest_port
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_socket_connect(sel4_badge_t badge __attribute__((unused)),
                                       const sel4_msg_t *req,
                                       sel4_msg_t *rep,
                                       void *ctx __attribute__((unused)))
{
    uint32_t handle    = data_rd32(req->data, 0);
    uint32_t dest_ip   = data_rd32(req->data, 4);
    uint32_t dest_port = data_rd32(req->data, 8);

    net_pd_client_t *c = find_sock(handle);
    if (!c || c->proto != NET_PROTO_TCP) {
        data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
        rep->length = 4;
        return SEL4_ERR_NOT_FOUND;
    }

    int err = lwip_net_connect((uint8_t)(c->shmem_slot & 0xFFu),
                               dest_ip, (uint16_t)(dest_port & 0xFFFFu));
    if (err == 0) {
        c->sock_state  = SOCK_STATE_CONNECTING;
        c->remote_ip   = dest_ip;
        c->remote_port = dest_port;
    }

    log_drain_write(17, 17, "[net_pd] SOCKET_CONNECT: handle=");
    log_dec(handle);
    log_drain_write(17, 17, " dst_ip=");
    log_hex(dest_ip);
    log_drain_write(17, 17, " port=");
    log_dec(dest_port);
    log_drain_write(17, 17, "\n");

    data_wr32(rep->data, 0, err == 0 ? NET_OK : NET_ERR_BAD_HANDLE);
    rep->length = 4;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MSG_NET_SOCKET_BIND (0x210C)
 *   req.data[0..3] = handle
 *   req.data[4..7] = port
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_socket_bind(sel4_badge_t badge __attribute__((unused)),
                                    const sel4_msg_t *req,
                                    sel4_msg_t *rep,
                                    void *ctx __attribute__((unused)))
{
    uint32_t handle = data_rd32(req->data, 0);
    uint32_t port   = data_rd32(req->data, 4);

    net_pd_client_t *c = find_sock(handle);
    if (!c || port == 0 || port > 65535u) {
        data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
        rep->length = 4;
        return SEL4_ERR_BAD_ARG;
    }

    c->local_port = port;
    c->sock_state = SOCK_STATE_BOUND;

    log_drain_write(17, 17, "[net_pd] SOCKET_BIND: handle=");
    log_dec(handle);
    log_drain_write(17, 17, " port=");
    log_dec(port);
    log_drain_write(17, 17, "\n");

    data_wr32(rep->data, 0, NET_OK);
    rep->length = 4;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MSG_NET_SOCKET_LISTEN (0x210D)
 *   req.data[0..3] = handle
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_socket_listen(sel4_badge_t badge __attribute__((unused)),
                                      const sel4_msg_t *req,
                                      sel4_msg_t *rep,
                                      void *ctx __attribute__((unused)))
{
    uint32_t handle = data_rd32(req->data, 0);
    net_pd_client_t *c = find_sock(handle);
    if (!c || c->proto != NET_PROTO_TCP || c->sock_state != SOCK_STATE_BOUND) {
        data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
        rep->length = 4;
        return SEL4_ERR_BAD_ARG;
    }

    c->sock_state = SOCK_STATE_LISTENING;

    log_drain_write(17, 17, "[net_pd] SOCKET_LISTEN: handle=");
    log_dec(handle);
    log_drain_write(17, 17, " port=");
    log_dec(c->local_port);
    log_drain_write(17, 17, "\n");

    data_wr32(rep->data, 0, NET_OK);
    rep->length = 4;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MSG_NET_SOCKET_ACCEPT (0x210E)
 *   req.data[0..3] = handle (listening socket)
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_socket_accept(sel4_badge_t badge __attribute__((unused)),
                                      const sel4_msg_t *req,
                                      sel4_msg_t *rep,
                                      void *ctx __attribute__((unused)))
{
    uint32_t handle = data_rd32(req->data, 0);
    net_pd_client_t *c = find_sock(handle);
    if (!c || c->sock_state != SOCK_STATE_LISTENING) {
        data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
        data_wr32(rep->data, 4, 0); data_wr32(rep->data, 8, 0); data_wr32(rep->data, 12, 0);
        rep->length = 16;
        return SEL4_ERR_BAD_ARG;
    }

    log_drain_write(17, 17, "[net_pd] SOCKET_ACCEPT: handle=");
    log_dec(handle);
    log_drain_write(17, 17, " (no pending connection)\n");

    data_wr32(rep->data,  0, NET_OK);
    data_wr32(rep->data,  4, 0u);
    data_wr32(rep->data,  8, 0u);
    data_wr32(rep->data, 12, 0u);
    rep->length = 16;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MSG_NET_SOCKET_SET_OPT (0x210F)
 *   req.data[0..3]  = handle
 *   req.data[4..7]  = option_id
 *   req.data[8..11] = value
 * ═══════════════════════════════════════════════════════════════════════════ */
static uint32_t handle_socket_set_opt(sel4_badge_t badge __attribute__((unused)),
                                       const sel4_msg_t *req,
                                       sel4_msg_t *rep,
                                       void *ctx __attribute__((unused)))
{
    uint32_t handle = data_rd32(req->data, 0);
    uint32_t opt    = data_rd32(req->data, 4);
    uint32_t val    = data_rd32(req->data, 8);
    (void)val;

    net_pd_client_t *c = find_sock(handle);
    if (!c) {
        data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
        rep->length = 4;
        return SEL4_ERR_NOT_FOUND;
    }

    switch (opt) {
    case NET_SOCKOPT_REUSEADDR:
    case NET_SOCKOPT_NODELAY:
    case NET_SOCKOPT_KEEPALIVE:
        break;
    default:
        data_wr32(rep->data, 0, NET_ERR_BAD_HANDLE);
        rep->length = 4;
        return SEL4_ERR_BAD_ARG;
    }

    log_drain_write(17, 17, "[net_pd] SOCKET_SET_OPT: handle=");
    log_dec(handle);
    log_drain_write(17, 17, " opt=");
    log_dec(opt);
    log_drain_write(17, 17, "\n");

    data_wr32(rep->data, 0, NET_OK);
    rep->length = 4;
    return SEL4_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * net_pd_test_init() — set up the server's dispatch table for host-side tests
 * ═══════════════════════════════════════════════════════════════════════════ */
static void net_pd_test_init(void)
{
    for (int i = 0; i < (int)NET_MAX_CLIENTS; i++) {
        clients[i].active     = false;
        clients[i].type       = HANDLE_TYPE_INVALID;
        clients[i].shmem_slot = 0;
    }
    active_clients = 0;
    slot_bitmap    = 0u;
    hw_present     = false;
    iface_link_up  = false;

#ifdef AGENTOS_TEST_HOST
    fastpath = &fastpath_host;
    netfp_init(fastpath, 1u);
#else
    fastpath = (netfp_state_t *)0;
#endif
    sel4_server_init(&g_srv, 0u);
    sel4_server_register(&g_srv, MSG_NET_OPEN,           handle_net_open,          NULL);
    sel4_server_register(&g_srv, MSG_NET_CLOSE,          handle_net_close,         NULL);
    sel4_server_register(&g_srv, MSG_NET_SEND,           handle_net_send,          NULL);
    sel4_server_register(&g_srv, MSG_NET_RECV,           handle_net_recv,          NULL);
    sel4_server_register(&g_srv, MSG_NET_DEV_STATUS,     handle_net_dev_status,    NULL);
    sel4_server_register(&g_srv, MSG_NET_CONFIGURE,      handle_net_configure,     NULL);
    sel4_server_register(&g_srv, MSG_NET_FILTER_ADD,     handle_net_filter_add,    NULL);
    sel4_server_register(&g_srv, MSG_NET_FILTER_REMOVE,  handle_net_filter_remove, NULL);
    sel4_server_register(&g_srv, MSG_NET_SOCKET_OPEN,    handle_socket_open,       NULL);
    sel4_server_register(&g_srv, MSG_NET_SOCKET_CLOSE,   handle_socket_close,      NULL);
    sel4_server_register(&g_srv, MSG_NET_SOCKET_CONNECT, handle_socket_connect,    NULL);
    sel4_server_register(&g_srv, MSG_NET_SOCKET_BIND,    handle_socket_bind,       NULL);
    sel4_server_register(&g_srv, MSG_NET_SOCKET_LISTEN,  handle_socket_listen,     NULL);
    sel4_server_register(&g_srv, MSG_NET_SOCKET_ACCEPT,  handle_socket_accept,     NULL);
    sel4_server_register(&g_srv, MSG_NET_SOCKET_SET_OPT, handle_socket_set_opt,    NULL);
    sel4_server_register(&g_srv, MSG_NET_FASTPATH_SEND,  handle_fastpath_send,     NULL);
    sel4_server_register(&g_srv, MSG_NET_FASTPATH_STATUS,handle_fastpath_status,   NULL);
}

/* ── dispatch helper for tests ───────────────────────────────────────────── */
static uint32_t net_pd_dispatch_one(sel4_badge_t badge,
                                     const sel4_msg_t *req,
                                     sel4_msg_t *rep)
{
    return sel4_server_dispatch(&g_srv, badge, req, rep);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * net_pd_main() — raw seL4 IPC entry point (replaces init() / protected())
 *
 * E5-S4: No priority ordering constraint.  Callers block on endpoint IPC.
 * ═══════════════════════════════════════════════════════════════════════════ */
#ifndef AGENTOS_TEST_HOST
void net_pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    net_pd_shmem_vaddr = (uintptr_t)0x30000000u;
    net_pd_mmio_vaddr = (uintptr_t)0x10010000u;
    agentos_log_boot("net_pd");
    log_drain_write(17, 17,
        "[net_pd] Initialising net_pd (raw seL4 IPC, no priority constraint)\n");

    net_pd_test_init();
    probe_virtio_net();
    register_with_nameserver(ns_ep);

    log_drain_write(17, 17, "[net_pd] READY — max_clients=");
    log_dec(NET_MAX_CLIENTS);
    log_drain_write(17, 17, " hw=");
    log_drain_write(17, 17, hw_present ? "1" : "0");
    log_drain_write(17, 17, "\n");

    g_srv.ep = my_ep;
    /* Arm the hardware IRQ only after the device status has been inspected. */
    (void)seL4_IRQHandler_Ack((seL4_CPtr)NET_PD_IRQ_CAP);
    log_drain_write(17, 17, "[net_pd] IRQ-driven queues armed\n");

    /* Bound notifications may wake an endpoint receive without a caller or a
     * reply object. Track whether a real RPC reply is pending so an IRQ is
     * never followed by an invalid ReplyRecv. */
    sel4_msg_t req = {0}, rep = {0};
    bool have_reply = false;
    for (;;) {
        sel4_badge_t badge = have_reply
            ? sel4_reply_recv(g_srv.ep, &rep, &req)
            : sel4_recv(g_srv.ep, &req);
        have_reply = false;
        if (((uint64_t)badge & NET_PD_IRQ_BADGE) != 0u
            && ((uint64_t)badge >> 32u) == 0u) {
            handle_net_irq();
            continue;
        }
        rep = (sel4_msg_t){0};
        sel4_server_dispatch(&g_srv, badge, &req, &rep);
        have_reply = true;
    }
}

void pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    net_pd_main(my_ep, ns_ep);
}
#endif /* !AGENTOS_TEST_HOST */
