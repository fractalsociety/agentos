/*
 * mcp_transport.c — shared, capability-scoped external MCP bridge.
 *
 * Only ToolSvc may call this PD. It maps only ToolSvc's service-private arena
 * and owns one dedicated VirtIO console. Workers have neither capability.
 */

#define AGENTOS_DEBUG 1
#include "agentos.h"
#include "mcp_transport.h"
#include "system_desc.h"
#include "../../../contracts/toolsvc/interface.h"
#include "sel4_server.h"
#include <stdbool.h>
#include <stdint.h>

#define MP_VIRTIO_VA   0x1000b000UL
#define MP_STARTUP_VA  0x1000c000UL
#define MP_SLOT_OFF    0u

#define VMMIO_MAGIC         0x000u
#define VMMIO_VERSION       0x004u
#define VMMIO_DEVICE_ID     0x008u
#define VMMIO_DEV_FEAT      0x010u
#define VMMIO_DEV_FEAT_SEL  0x014u
#define VMMIO_DRV_FEAT      0x020u
#define VMMIO_DRV_FEAT_SEL  0x024u
#define VMMIO_QUEUE_SEL     0x030u
#define VMMIO_QUEUE_NUM_MAX 0x034u
#define VMMIO_QUEUE_NUM     0x038u
#define VMMIO_QUEUE_READY   0x044u
#define VMMIO_QUEUE_NOTIFY  0x050u
#define VMMIO_STATUS        0x070u
#define VMMIO_Q_DESC_LO     0x080u
#define VMMIO_Q_DESC_HI     0x084u
#define VMMIO_Q_AVAIL_LO    0x090u
#define VMMIO_Q_AVAIL_HI    0x094u
#define VMMIO_Q_USED_LO     0x0a0u
#define VMMIO_Q_USED_HI     0x0a4u

#define VSTATUS_ACK       1u
#define VSTATUS_DRIVER    2u
#define VSTATUS_DRIVER_OK 4u
#define VSTATUS_FEAT_OK   8u
#define VSTATUS_FAILED    128u
#define VIRTIO_MAGIC      0x74726976u
#define VIRTIO_ID_CONSOLE 3u
#define VQ_DEPTH          4u
#define MP_WAIT_LIMIT     5000000u

typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} vq_desc_t;
typedef struct __attribute__((packed)) {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[VQ_DEPTH];
    uint16_t used_event;
} vq_avail_t;
typedef struct __attribute__((packed)) {
    uint32_t id;
    uint32_t len;
} vq_used_elem_t;
typedef struct __attribute__((packed)) {
    uint16_t flags;
    uint16_t idx;
    vq_used_elem_t ring[VQ_DEPTH];
    uint16_t avail_event;
} vq_used_t;

#define TX_DESC_OFF  0u
#define TX_AVAIL_OFF 128u
#define TX_USED_OFF  256u
#define RX_DESC_OFF  512u
#define RX_AVAIL_OFF 640u
#define RX_USED_OFF  768u

static seL4_Word g_vq_pa[3];
static volatile uint32_t *g_virtio;
static uint16_t g_rx_used_last;
static uint8_t g_rx_stash[4096];
static uint32_t g_rx_stash_offset;
static uint32_t g_rx_stash_length;
static bool g_ready;
static sel4_server_t g_server;

#define QP       ((uintptr_t)g_vq_pa[0])
#define TX_DESC  ((volatile vq_desc_t *)(QP + TX_DESC_OFF))
#define TX_AVAIL ((volatile vq_avail_t *)(QP + TX_AVAIL_OFF))
#define TX_USED  ((volatile vq_used_t *)(QP + TX_USED_OFF))
#define RX_DESC  ((volatile vq_desc_t *)(QP + RX_DESC_OFF))
#define RX_AVAIL ((volatile vq_avail_t *)(QP + RX_AVAIL_OFF))
#define RX_USED  ((volatile vq_used_t *)(QP + RX_USED_OFF))

#if defined(__aarch64__)
#define MP_MB() __asm__ volatile("dsb sy" ::: "memory")
#elif defined(__riscv)
#define MP_MB() __asm__ volatile("fence rw,rw" ::: "memory")
#elif defined(__x86_64__)
#define MP_MB() __asm__ volatile("mfence" ::: "memory")
#else
#define MP_MB() __asm__ volatile("" ::: "memory")
#endif

static inline uint32_t vio_read(uint32_t offset)
{
    return *(volatile uint32_t *)((uintptr_t)g_virtio + offset);
}

static inline void vio_write(uint32_t offset, uint32_t value)
{
    *(volatile uint32_t *)((uintptr_t)g_virtio + offset) = value;
    MP_MB();
}

static void bytes_zero(volatile void *dst, uint32_t len)
{
    volatile uint8_t *bytes = (volatile uint8_t *)dst;
    for (uint32_t i = 0u; i < len; i++) bytes[i] = 0u;
}

static bool internal_range(uint32_t offset, uint32_t len)
{
    return offset >= TOOLSVC_INTERNAL_ARENA_OFFSET
        && offset <= TOOLSVC_SHMEM_SIZE
        && len <= TOOLSVC_SHMEM_SIZE - offset;
}

static bool ranges_overlap(uint32_t a, uint32_t a_len,
                           uint32_t b, uint32_t b_len)
{
    if (a_len == 0u || b_len == 0u) return false;
    return a < b + b_len && b < a + a_len;
}

static bool queue_setup(uint32_t queue, seL4_Word desc,
                        seL4_Word avail, seL4_Word used)
{
    vio_write(VMMIO_QUEUE_SEL, queue);
    if (vio_read(VMMIO_QUEUE_NUM_MAX) < VQ_DEPTH) return false;
    vio_write(VMMIO_QUEUE_NUM, VQ_DEPTH);
    vio_write(VMMIO_Q_DESC_LO, (uint32_t)desc);
    vio_write(VMMIO_Q_DESC_HI, (uint32_t)(desc >> 32u));
    vio_write(VMMIO_Q_AVAIL_LO, (uint32_t)avail);
    vio_write(VMMIO_Q_AVAIL_HI, (uint32_t)(avail >> 32u));
    vio_write(VMMIO_Q_USED_LO, (uint32_t)used);
    vio_write(VMMIO_Q_USED_HI, (uint32_t)(used >> 32u));
    vio_write(VMMIO_QUEUE_READY, 1u);
    return vio_read(VMMIO_QUEUE_READY) == 1u;
}

static void transport_init(void)
{
    volatile seL4_Word *startup = (volatile seL4_Word *)MP_STARTUP_VA;
    g_vq_pa[0] = startup[0];
    g_vq_pa[1] = startup[1];
    g_vq_pa[2] = startup[2];
    g_virtio = (volatile uint32_t *)(MP_VIRTIO_VA + MP_SLOT_OFF);
    g_ready = false;

    if (g_vq_pa[0] == 0u || g_vq_pa[1] == 0u || g_vq_pa[2] == 0u
        || vio_read(VMMIO_MAGIC) != VIRTIO_MAGIC
        || vio_read(VMMIO_VERSION) != 2u
        || vio_read(VMMIO_DEVICE_ID) != VIRTIO_ID_CONSOLE) {
        log_drain_write(31, 31, "[mcp_transport] VirtIO console unavailable\n");
        return;
    }

    bytes_zero((void *)QP, 4096u);
    vio_write(VMMIO_STATUS, 0u);
    uint32_t status = VSTATUS_ACK | VSTATUS_DRIVER;
    vio_write(VMMIO_STATUS, status);
    vio_write(VMMIO_DEV_FEAT_SEL, 0u);
    uint32_t features0 = vio_read(VMMIO_DEV_FEAT) & ~(1u << 1u);
    vio_write(VMMIO_DEV_FEAT_SEL, 1u);
    uint32_t features1 = vio_read(VMMIO_DEV_FEAT);
    vio_write(VMMIO_DRV_FEAT_SEL, 0u);
    vio_write(VMMIO_DRV_FEAT, features0);
    vio_write(VMMIO_DRV_FEAT_SEL, 1u);
    vio_write(VMMIO_DRV_FEAT, features1);
    status |= VSTATUS_FEAT_OK;
    vio_write(VMMIO_STATUS, status);
    if ((vio_read(VMMIO_STATUS) & VSTATUS_FEAT_OK) == 0u) {
        vio_write(VMMIO_STATUS, VSTATUS_FAILED);
        return;
    }
    if (!queue_setup(0u, g_vq_pa[0] + RX_DESC_OFF,
                     g_vq_pa[0] + RX_AVAIL_OFF, g_vq_pa[0] + RX_USED_OFF)
        || !queue_setup(1u, g_vq_pa[0] + TX_DESC_OFF,
                        g_vq_pa[0] + TX_AVAIL_OFF, g_vq_pa[0] + TX_USED_OFF)) {
        vio_write(VMMIO_STATUS, VSTATUS_FAILED);
        return;
    }
    status |= VSTATUS_DRIVER_OK;
    vio_write(VMMIO_STATUS, status);
    RX_DESC[0].addr = g_vq_pa[2];
    RX_DESC[0].len = 4096u;
    RX_DESC[0].flags = 2u;
    RX_DESC[0].next = 0u;
    RX_AVAIL->ring[0] = 0u;
    MP_MB();
    RX_AVAIL->idx = 1u;
    MP_MB();
    vio_write(VMMIO_QUEUE_NOTIFY, 0u);
    g_rx_used_last = 0u;
    g_rx_stash_offset = 0u;
    g_rx_stash_length = 0u;
    g_ready = true;
    log_drain_write(31, 31, "[mcp_transport] VirtIO console ready\n");
}

static bool serial_write(const void *buffer, uint32_t length)
{
    const uint8_t *src = (const uint8_t *)buffer;
    while (length != 0u) {
        uint32_t chunk = length > 4096u ? 4096u : length;
        __builtin_memcpy((void *)g_vq_pa[1], src, chunk);
        TX_DESC[0].addr = g_vq_pa[1];
        TX_DESC[0].len = chunk;
        TX_DESC[0].flags = 0u;
        TX_DESC[0].next = 0u;
        uint16_t used = TX_USED->idx;
        TX_AVAIL->ring[TX_AVAIL->idx & (VQ_DEPTH - 1u)] = 0u;
        MP_MB();
        TX_AVAIL->idx++;
        MP_MB();
        vio_write(VMMIO_QUEUE_NOTIFY, 1u);
        uint32_t waits = 0u;
        while (TX_USED->idx == used) {
            MP_MB();
            seL4_Yield();
            if (++waits == MP_WAIT_LIMIT) return false;
        }
        src += chunk;
        length -= chunk;
    }
    return true;
}

static bool serial_read(void *buffer, uint32_t length)
{
    uint8_t *dst = (uint8_t *)buffer;
    while (length != 0u) {
        if (g_rx_stash_length != 0u) {
            uint32_t take = g_rx_stash_length > length
                ? length : g_rx_stash_length;
            __builtin_memcpy(dst, &g_rx_stash[g_rx_stash_offset], take);
            dst += take;
            length -= take;
            g_rx_stash_offset += take;
            g_rx_stash_length -= take;
            if (g_rx_stash_length == 0u) g_rx_stash_offset = 0u;
            continue;
        }
        uint32_t waits = 0u;
        while (RX_USED->idx == g_rx_used_last) {
            MP_MB();
            seL4_Yield();
            if (++waits == MP_WAIT_LIMIT) return false;
        }
        uint32_t got = RX_USED->ring[g_rx_used_last & (VQ_DEPTH - 1u)].len;
        if (got == 0u || got > 4096u) return false;
        __builtin_memcpy(g_rx_stash, (const void *)g_vq_pa[2], got);
        g_rx_stash_offset = 0u;
        g_rx_stash_length = got;
        g_rx_used_last++;
        RX_DESC[0].addr = g_vq_pa[2];
        RX_DESC[0].len = 4096u;
        RX_DESC[0].flags = 2u;
        RX_DESC[0].next = 0u;
        RX_AVAIL->ring[RX_AVAIL->idx & (VQ_DEPTH - 1u)] = 0u;
        MP_MB();
        RX_AVAIL->idx++;
        MP_MB();
        vio_write(VMMIO_QUEUE_NOTIFY, 0u);
    }
    return true;
}

static uint32_t handle_request(sel4_badge_t badge, const sel4_msg_t *req,
                               sel4_msg_t *rep,
                               void *ctx __attribute__((unused)))
{
    mcp_transport_reply_t reply = {
        .status = TOOLSVC_ERR_PROVIDER_DOWN,
        .output_len = 0u,
        .request_tag = 0u,
    };
    mcp_transport_wire_t wire;
    if ((uint16_t)(badge >> 48u) != SVC_ID_MCP_TRANSPORT) {
        reply.status = TOOLSVC_ERR_DENIED;
        goto out;
    }
    if (req->length != sizeof(wire)) {
        reply.status = TOOLSVC_ERR_INVALID_ARG;
        goto out;
    }
    __builtin_memcpy(&wire, req->data, sizeof(wire));
    reply.request_tag = wire.request_tag;
    if ((wire.operation != MCP_TRANSPORT_REQUEST_LIST
         && wire.operation != MCP_TRANSPORT_REQUEST_INVOKE)
        || wire.name_len < TOOLSVC_MCP_PREFIX_LEN
        || wire.name_len >= TOOLSVC_TOOL_NAME_MAX
        || wire.input_len > TOOLSVC_MCP_INPUT_MAX
        || wire.output_capacity == 0u
        || wire.output_capacity > TOOLSVC_MCP_OUTPUT_MAX
        || !internal_range(wire.name_offset, wire.name_len)
        || !internal_range(wire.input_offset, wire.input_len)
        || !internal_range(wire.output_offset, wire.output_capacity)
        || ranges_overlap(wire.output_offset, wire.output_capacity,
                          wire.name_offset, wire.name_len)
        || ranges_overlap(wire.output_offset, wire.output_capacity,
                          wire.input_offset, wire.input_len)) {
        reply.status = TOOLSVC_ERR_DENIED;
        goto out;
    }
    if (!g_ready) goto out;

    mcp_transport_request_header_t header = {
        .magic = MCP_TRANSPORT_WIRE_MAGIC,
        .version = MCP_TRANSPORT_WIRE_VERSION,
        .operation = wire.operation,
        .name_len = wire.name_len,
        .input_len = wire.input_len,
        .output_capacity = wire.output_capacity,
        .request_tag = wire.request_tag,
    };
    uint8_t *name = (uint8_t *)(uintptr_t)
        (TOOLSVC_SHMEM_VADDR + wire.name_offset);
    uint8_t *input = (uint8_t *)(uintptr_t)
        (TOOLSVC_SHMEM_VADDR + wire.input_offset);
    if (!serial_write(&header, sizeof(header))
        || !serial_write(name, wire.name_len)
        || (wire.input_len != 0u && !serial_write(input, wire.input_len))) {
        g_ready = false;
        goto out;
    }

    mcp_transport_response_header_t response;
    if (!serial_read(&response, sizeof(response))
        || response.magic != MCP_TRANSPORT_WIRE_MAGIC
        || response.request_tag != wire.request_tag
        || response.output_len >= wire.output_capacity
        || response.output_len > TOOLSVC_MCP_OUTPUT_MAX) {
        g_ready = false;
        goto out;
    }
    uint8_t *output = (uint8_t *)(uintptr_t)
        (TOOLSVC_SHMEM_VADDR + wire.output_offset);
    if (response.output_len != 0u
        && !serial_read(output, response.output_len)) {
        g_ready = false;
        goto out;
    }
    reply.status = response.status;
    reply.output_len = response.output_len;

out:
    __builtin_memcpy(rep->data, &reply, sizeof(reply));
    rep->length = sizeof(reply);
    return SEL4_ERR_OK;
}

void pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    (void)ns_ep;
    agentos_log_boot("mcp_transport");
    transport_init();
    sel4_server_init(&g_server, my_ep);
    (void)sel4_server_register(&g_server, MCP_TRANSPORT_OP_REQUEST,
                               handle_request, NULL);
    sel4_server_run(&g_server);
}
