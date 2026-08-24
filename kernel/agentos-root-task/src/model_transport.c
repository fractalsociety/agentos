/*
 * model_transport.c — native AgentOS model bridge transport PD
 *
 * This PD is deliberately small and policy-free.  NetServer supplies checked
 * offsets into ModelSvc's service-private arena.  The PD frames the JSON over
 * a dedicated VirtIO console and writes the bounded response back to the same
 * arena.  It has no ToolSvc, AgentFS, ExecServer, repository, or worker caps.
 */

#define AGENTOS_DEBUG 1
#include "agentos.h"
#include "model_transport.h"
#include "../../../contracts/modelsvc/interface.h"
#include "sel4_server.h"
#include <stdbool.h>
#include <stdint.h>

#define MT_VIRTIO_VA   0x10007000UL
#define MT_STARTUP_VA  0x10008000UL
#define MT_SLOT_OFF    (3u * 0x200u)

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
#define MT_WAIT_LIMIT     5000000u

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
#define MT_MB() __asm__ volatile("dsb sy" ::: "memory")
#elif defined(__riscv)
#define MT_MB() __asm__ volatile("fence rw,rw" ::: "memory")
#elif defined(__x86_64__)
#define MT_MB() __asm__ volatile("mfence" ::: "memory")
#else
#define MT_MB() __asm__ volatile("" ::: "memory")
#endif

static inline uint32_t vio_read(uint32_t offset)
{
    return *(volatile uint32_t *)((uintptr_t)g_virtio + offset);
}

static inline void vio_write(uint32_t offset, uint32_t value)
{
    *(volatile uint32_t *)((uintptr_t)g_virtio + offset) = value;
    MT_MB();
}

static void bytes_zero(volatile void *dst, uint32_t len)
{
    volatile uint8_t *bytes = (volatile uint8_t *)dst;
    for (uint32_t i = 0u; i < len; i++) bytes[i] = 0u;
}

static uint32_t rd32(const uint8_t *data, uint32_t offset)
{
    return (uint32_t)data[offset]
         | ((uint32_t)data[offset + 1u] << 8u)
         | ((uint32_t)data[offset + 2u] << 16u)
         | ((uint32_t)data[offset + 3u] << 24u);
}

static void wr32(uint8_t *data, uint32_t offset, uint32_t value)
{
    data[offset] = (uint8_t)value;
    data[offset + 1u] = (uint8_t)(value >> 8u);
    data[offset + 2u] = (uint8_t)(value >> 16u);
    data[offset + 3u] = (uint8_t)(value >> 24u);
}

static bool arena_range(uint32_t offset, uint32_t len)
{
    return offset <= MODELSVC_SHMEM_SIZE && len <= MODELSVC_SHMEM_SIZE - offset;
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
    volatile seL4_Word *startup = (volatile seL4_Word *)MT_STARTUP_VA;
    g_vq_pa[0] = startup[0];
    g_vq_pa[1] = startup[1];
    g_vq_pa[2] = startup[2];
    g_virtio = (volatile uint32_t *)(MT_VIRTIO_VA + MT_SLOT_OFF);
    g_ready = false;

    if (g_vq_pa[0] == 0u || g_vq_pa[1] == 0u || g_vq_pa[2] == 0u
        || vio_read(VMMIO_MAGIC) != VIRTIO_MAGIC
        || vio_read(VMMIO_VERSION) != 2u
        || vio_read(VMMIO_DEVICE_ID) != VIRTIO_ID_CONSOLE) {
        log_drain_write(31, 31, "[model_transport] VirtIO console unavailable\n");
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
    MT_MB();
    RX_AVAIL->idx = 1u;
    MT_MB();
    vio_write(VMMIO_QUEUE_NOTIFY, 0u);
    g_rx_used_last = 0u;
    g_rx_stash_offset = 0u;
    g_rx_stash_length = 0u;
    g_ready = true;
    log_drain_write(31, 31, "[model_transport] VirtIO console ready\n");
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
        MT_MB();
        TX_AVAIL->idx++;
        MT_MB();
        vio_write(VMMIO_QUEUE_NOTIFY, 1u);
        uint32_t waits = 0u;
        while (TX_USED->idx == used) {
            MT_MB();
            seL4_Yield();
            if (++waits == MT_WAIT_LIMIT) return false;
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
            MT_MB();
            seL4_Yield();
            if (++waits == MT_WAIT_LIMIT) return false;
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
        MT_MB();
        RX_AVAIL->idx++;
        MT_MB();
        vio_write(VMMIO_QUEUE_NOTIFY, 0u);
    }
    return true;
}

static uint32_t handle_post(sel4_badge_t badge __attribute__((unused)),
                            const sel4_msg_t *req, sel4_msg_t *rep,
                            void *ctx __attribute__((unused)))
{
    uint32_t body_offset = rd32(req->data, 8u);
    uint32_t body_len = rd32(req->data, 12u);
    uint32_t response_cap = MODELSVC_SHMEM_SIZE - body_offset;
    wr32(rep->data, 0u, 0u);
    wr32(rep->data, 4u, body_offset);
    wr32(rep->data, 8u, 0u);
    rep->length = 12u;

    if (!g_ready || body_len == 0u || body_len > MODEL_TRANSPORT_MAX_BODY
        || !arena_range(body_offset, body_len)
        || !arena_range(body_offset, response_cap)) return SEL4_ERR_OK;

    model_transport_request_header_t header = {
        .magic = MODEL_TRANSPORT_WIRE_MAGIC,
        .version = MODEL_TRANSPORT_WIRE_VERSION,
        .body_len = body_len,
        .response_cap = response_cap,
    };
    uint8_t *body = (uint8_t *)(uintptr_t)(MODELSVC_SHMEM_VADDR + body_offset);
    if (!serial_write(&header, sizeof(header)) || !serial_write(body, body_len)) {
        g_ready = false;
        return SEL4_ERR_OK;
    }

    model_transport_response_header_t response;
    if (!serial_read(&response, sizeof(response))
        || response.magic != MODEL_TRANSPORT_WIRE_MAGIC
        || response.transport_status != 0u
        || response.body_len > response_cap
        || response.body_len > MODEL_TRANSPORT_MAX_BODY
        || !serial_read(body, response.body_len)) {
        g_ready = false;
        return SEL4_ERR_OK;
    }
    wr32(rep->data, 0u, response.http_status);
    wr32(rep->data, 4u, body_offset);
    wr32(rep->data, 8u, response.body_len);
    return SEL4_ERR_OK;
}

void pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    (void)ns_ep;
    agentos_log_boot("model_transport");
    transport_init();
    sel4_server_init(&g_server, my_ep);
    (void)sel4_server_register(&g_server, MODEL_TRANSPORT_OP_POST,
                               handle_post, NULL);
    sel4_server_run(&g_server);
}
