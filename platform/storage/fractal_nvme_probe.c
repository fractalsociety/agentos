/* Native seL4 NVMe PCI qualification. This PD owns controller MMIO and a
 * private DMA frame. Default builds only read. Opt-in QEMU modes prove a
 * GPT-bounded witness or a hashed plan/result exchange with Flush. */
#include "agentos.h"
#include "system_desc.h"
#include <platform/fractal_nvme.h>
#include <platform/fractal_gpt.h>
#include <platform/fractal_partition.h>
#ifdef AGENTOS_BOOT_DISPLAY
#include <platform/boot_display.h>
#endif
#ifdef AGENTOS_FRACTAL_NVME_EXCHANGE
#include <platform/fractal_exchange_cycle.h>
#include <platform/fractal_exchange.h>
#endif

#define NVME_Q_DEPTH 16u
#define NVME_SQ0_OFF 0x1000u
#define NVME_CQ0_OFF 0x2000u
#define NVME_DATA_OFF 0x3000u
#define NVME_CQ1_OFF 0x4000u
#define NVME_SQ1_OFF 0x5000u
#define NVME_READ_OFF 0x6000u
#define NVME_POLL_ITERS 100000000u

static volatile uint8_t *const regs = (volatile uint8_t *)FRACTAL_NVME_MMIO_VA;
static volatile uint8_t *const dma = (volatile uint8_t *)FRACTAL_NVME_DMA_VA;
static uint64_t dma_pa;
static uint32_t db_stride;
static uint16_t sq_tail[2], cq_head[2];
static uint8_t cq_phase[2] = {1u, 1u};
static uint32_t last_completion;
static uint32_t last_completion_dw2, last_command_dw0;
#ifdef AGENTOS_FRACTAL_NVME_WRITE_PROBE
static bool gpt_pair_verified;
#endif
#ifdef AGENTOS_FRACTAL_NVME_EXCHANGE
static uint8_t exchange_block[4096];
#endif

static uint32_t mmio32(uint32_t off)
{
    return *(volatile uint32_t *)(regs + off);
}
static void mmio32_write(uint32_t off, uint32_t value)
{
    *(volatile uint32_t *)(regs + off) = value;
}
static uint64_t mmio64(uint32_t off)
{
    return (uint64_t)mmio32(off) | ((uint64_t)mmio32(off + 4u) << 32);
}
static void mmio64_write(uint32_t off, uint64_t value)
{
    mmio32_write(off, (uint32_t)value);
    mmio32_write(off + 4u, (uint32_t)(value >> 32));
}
static uint32_t read32(const volatile uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t read64(const volatile uint8_t *p)
{
    return (uint64_t)read32(p) | ((uint64_t)read32(p + 4u) << 32);
}
static void put32(volatile uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4u; ++i) p[i] = (uint8_t)(value >> (8u * i));
}
static void put64(volatile uint8_t *p, uint64_t value)
{
    put32(p, (uint32_t)value);
    put32(p + 4u, (uint32_t)(value >> 32));
}
static void clear(volatile uint8_t *p, uint32_t count)
{
    for (uint32_t i = 0; i < count; ++i) p[i] = 0u;
}
static void copy_from_dma(uint8_t *dest, const volatile uint8_t *src,
                          uint32_t count)
{
    for (uint32_t i = 0u; i < count; ++i) dest[i] = src[i];
}
static bool wait_ready(bool wanted)
{
    for (uint32_t i = 0; i < NVME_POLL_ITERS; ++i) {
        uint32_t status = mmio32(0x1cu);
        if (status & 2u) return false;
        if ((status & 1u) == (wanted ? 1u : 0u)) return true;
    }
    return false;
}
static bool command(unsigned queue, uint8_t opcode, uint32_t nsid,
                    uint64_t prp1, uint32_t cdw10, uint32_t cdw11,
                    uint32_t cdw12)
{
    if (queue > 1u) return false;
    volatile uint8_t *sq = dma + (queue ? NVME_SQ1_OFF : NVME_SQ0_OFF);
    volatile uint8_t *cq = dma + (queue ? NVME_CQ1_OFF : NVME_CQ0_OFF);
    volatile uint8_t *entry = sq + sq_tail[queue] * 64u;
    /* A single synchronous command is outstanding, so CID 0 is unambiguous. */
    uint16_t cid = 0u;
    clear(entry, 64u);
    put32(entry + 0u, (uint32_t)opcode | ((uint32_t)cid << 16));
    put32(entry + 4u, nsid);
    put64(entry + 24u, prp1);
    put32(entry + 40u, cdw10);
    put32(entry + 44u, cdw11);
    put32(entry + 48u, cdw12);
    last_command_dw0 = read32(entry);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    sq_tail[queue] = (uint16_t)((sq_tail[queue] + 1u) % NVME_Q_DEPTH);
    mmio32_write(0x1000u + 2u * queue * db_stride, sq_tail[queue]);

    volatile uint8_t *completion = cq + cq_head[queue] * 16u;
    for (uint32_t i = 0; i < NVME_POLL_ITERS; ++i) {
        uint32_t word = read32(completion + 12u);
        uint16_t status = (uint16_t)(word >> 16);
        if ((status & 1u) != cq_phase[queue]) continue;
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        last_completion = word;
        last_completion_dw2 = read32(completion + 8u);
        bool ok = (uint16_t)word == cid && (status >> 1) == 0u;
        cq_head[queue] = (uint16_t)((cq_head[queue] + 1u) % NVME_Q_DEPTH);
        if (cq_head[queue] == 0u) cq_phase[queue] ^= 1u;
        mmio32_write(0x1000u + (2u * queue + 1u) * db_stride,
                     cq_head[queue]);
        return ok;
    }
    return false;
}

static bool read_sectors(uint64_t lba, uint16_t count)
{
    if (!count || count > 8u || lba > FRACTAL_DISK_SECTORS - count)
        return false;
#ifdef AGENTOS_FRACTAL_PHYSICAL_WRITE_CANDIDATE
    if (!fractal_candidate_read_allowed(lba, count)) return false;
#endif
    clear(dma + NVME_READ_OFF, 4096u);
    return command(1u, 0x02u, 1u, dma_pa + NVME_READ_OFF,
                   (uint32_t)lba, (uint32_t)(lba >> 32), count - 1u);
}

#ifdef AGENTOS_FRACTAL_NVME_WRITE_PROBE
static bool write_sectors(const fractal_gpt_guard_t *guard, uint64_t lba,
                          uint16_t count)
{
    if (!gpt_pair_verified || count != 8u ||
        !fractal_gpt_in_range(guard, lba, count)) return false;
    return command(1u, 0x01u, 1u, dma_pa + NVME_READ_OFF,
                   (uint32_t)lba, (uint32_t)(lba >> 32), count - 1u);
}

static bool flush_namespace(void)
{
    return command(1u, 0x00u, 1u, 0u, 0u, 0u, 0u);
}
#endif

#ifdef AGENTOS_FRACTAL_NVME_EXCHANGE
static bool exchange_read(void *context, uint64_t block_index, uint8_t *block)
{
    const fractal_gpt_guard_t *guard = context;
    if (block_index > FRACTAL_PART_LAST / 8u) return false;
    uint64_t lba = block_index * 8u;
    if (!fractal_gpt_in_range(guard, lba, 8u) || !read_sectors(lba, 8u))
        return false;
    copy_from_dma(block, dma + NVME_READ_OFF, 4096u);
    return true;
}
static bool exchange_write(void *context, uint64_t block_index,
                           const uint8_t *block)
{
    const fractal_gpt_guard_t *guard = context;
    if (block_index > FRACTAL_PART_LAST / 8u) return false;
    uint64_t lba = block_index * 8u;
    if (!fractal_gpt_in_range(guard, lba, 8u)) return false;
    for (uint32_t i = 0u; i < 4096u; ++i) dma[NVME_READ_OFF + i] = block[i];
    return write_sectors(guard, lba, 8u);
}
static bool exchange_flush(void *context)
{
    (void)context;
    return flush_namespace();
}
#endif

static uint32_t qualify(uint64_t *sectors_out)
{
    const fractal_nvme_meta_t *meta = (const fractal_nvme_meta_t *)dma;
    if (meta->magic != FRACTAL_NVME_META_MAGIC ||
        (meta->version != 1u && meta->version != 2u) ||
        meta->dma_bytes != FRACTAL_NVME_DMA_BYTES ||
        (meta->dma_paddr & 0xfffu)) return 10u;
    dma_pa = meta->dma_paddr;
    uint64_t cap = mmio64(0u);
    uint32_t vs = mmio32(8u);
    if (!cap || cap == UINT64_MAX || (cap & 0xffffu) < NVME_Q_DEPTH - 1u ||
        ((cap >> 48) & 15u) != 0u || (vs >> 16) == 0u) return 11u;
    uint32_t stride_shift = (uint32_t)((cap >> 32) & 15u);
    if (stride_shift > 5u) return 12u;
    db_stride = 4u << stride_shift;
    if (0x1000u + 4u * db_stride > FRACTAL_NVME_MMIO_PAGES * 4096u)
        return 12u;

    mmio32_write(0x14u, 0u);
    if (!wait_ready(false)) return 13u;
    clear(dma + NVME_SQ0_OFF, 0x6000u);
    mmio32_write(0x24u, (NVME_Q_DEPTH - 1u) | ((NVME_Q_DEPTH - 1u) << 16));
    mmio64_write(0x28u, dma_pa + NVME_SQ0_OFF);
    mmio64_write(0x30u, dma_pa + NVME_CQ0_OFF);
    mmio32_write(0x14u, (6u << 16) | (4u << 20) | 1u);
    if (!wait_ready(true)) return 14u;

    if (!command(0u, 0x06u, 0u, dma_pa + NVME_DATA_OFF,
                 1u, 0u, 0u)) return 15u; /* Identify Controller */
    volatile uint8_t *data = dma + NVME_DATA_OFF;
    uint32_t nn = read32(data + 516u); /* Number of namespaces */
    if (nn < 1u || nn > 1024u) return 16u;
    clear(data, 4096u);
    if (!command(0u, 0x06u, 1u, dma_pa + NVME_DATA_OFF,
                 0u, 0u, 0u)) return 17u; /* Identify Namespace 1 */
    uint64_t sectors = read64(data);
    uint8_t selected_format = data[26u] & 15u;
    if (sectors != FRACTAL_DISK_SECTORS || selected_format >= 16u ||
        data[128u + selected_format * 4u + 2u] != 9u) return 18u;

    /* One physically contiguous, polled I/O queue pair. */
    if (!command(0u, 0x05u, 0u, dma_pa + NVME_CQ1_OFF,
                 (NVME_Q_DEPTH - 1u) << 16 | 1u, 1u, 0u)) return 19u;
    if (!command(0u, 0x01u, 0u, dma_pa + NVME_SQ1_OFF,
                 (NVME_Q_DEPTH - 1u) << 16 | 1u, (1u << 16) | 1u,
                 0u)) return 20u;
    if (!read_sectors(0u, 1u)) return 21u;
    volatile uint8_t *mbr = dma + NVME_READ_OFF;
    if (mbr[510u] != 0x55u || mbr[511u] != 0xaau || mbr[450u] != 0xeeu)
        return 22u;
    if (!read_sectors(1u, 1u)) return 23u;
    uint8_t header[FRACTAL_GPT_SECTOR_BYTES];
    copy_from_dma(header, dma + NVME_READ_OFF, sizeof(header));
    fractal_gpt_guard_t guard;
    if (!fractal_gpt_begin(&guard, header, sectors, fractal_part_guid,
                           fractal_linux_type, FRACTAL_PART_FIRST,
                           FRACTAL_PART_LAST)) return 24u;
    uint8_t entries[FRACTAL_GPT_CHUNK_BYTES];
    for (uint32_t chunk = 0u; chunk < FRACTAL_GPT_CHUNKS; ++chunk) {
        if (!read_sectors(2u + chunk * 8u, 8u)) return 25u;
        copy_from_dma(entries, dma + NVME_READ_OFF, sizeof(entries));
        if (!fractal_gpt_feed(&guard, entries)) return 26u;
    }
    uint64_t tail_sectors = 32u;
#ifdef AGENTOS_FRACTAL_NVME_EXCHANGE
    tail_sectors = FRACTAL_XFER_BLOCK_COUNT * 8u;
#endif
    if (!fractal_gpt_finish(&guard) ||
        !fractal_gpt_in_range(&guard,
                              FRACTAL_PART_LAST + 1u - tail_sectors,
                              tail_sectors)) return 27u;
    if (!read_sectors(sectors - 1u, 1u)) return 32u;
    copy_from_dma(header, dma + NVME_READ_OFF, sizeof(header));
    fractal_gpt_guard_t backup;
    if (!fractal_gpt_begin_backup(&backup, header, &guard)) return 33u;
    for (uint32_t chunk = 0u; chunk < FRACTAL_GPT_CHUNKS; ++chunk) {
        if (!read_sectors(sectors - 33u + chunk * 8u, 8u)) return 34u;
        copy_from_dma(entries, dma + NVME_READ_OFF, sizeof(entries));
        if (!fractal_gpt_feed(&backup, entries)) return 35u;
    }
    if (!fractal_gpt_finish(&backup)) return 36u;
#ifdef AGENTOS_FRACTAL_NVME_WRITE_PROBE
    gpt_pair_verified = true;
#endif
    *sectors_out = sectors;
#ifdef AGENTOS_FRACTAL_NVME_EXCHANGE
    fractal_exchange_io_t io = {
        .context = &guard, .block = exchange_block,
        .read_block = exchange_read, .write_block = exchange_write,
        .flush = exchange_flush,
    };
    uint32_t exchange_step = fractal_exchange_cycle_run(
        &io, (FRACTAL_PART_LAST + 1u) / 8u);
    if (exchange_step == FRACTAL_XFER_PANIC_STEP) return exchange_step;
    return exchange_step == 2u ? 4u : (0x100u | exchange_step);
#else
#ifdef AGENTOS_FRACTAL_NVME_WRITE_PROBE
    /* One disposable QEMU witness in p8. Every namespace write passes the
     * exact GPT identity and per-command LBA range check above. */
    const uint64_t witness_lba = FRACTAL_PART_LAST + 1u - 24u;
    for (uint32_t i = 0u; i < 4096u; ++i)
        dma[NVME_READ_OFF + i] = (uint8_t)(i ^ 0x5au);
    if (!write_sectors(&guard, witness_lba, 8u)) return 28u;
    if (!flush_namespace()) return 29u;
    if (!read_sectors(witness_lba, 8u)) return 30u;
    for (uint32_t i = 0u; i < 4096u; ++i)
        if (dma[NVME_READ_OFF + i] != (uint8_t)(i ^ 0x5au)) return 31u;
    return 3u;
#endif
    return 2u;
#endif
}

void pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    (void)ns_ep;
    agentos_log_boot("fractal_nvme_probe");
#ifdef AGENTOS_BOOT_DISPLAY
    aos_boot_progress_publish(AOS_BOOT_STORAGE,0u,1u);
#endif
    uint64_t sectors = 0u;
    uint32_t result = qualify(&sectors);
#ifdef AGENTOS_BOOT_DISPLAY
    aos_boot_progress_publish(result==2u ? AOS_BOOT_STORAGE_READY : AOS_BOOT_FAILED,
                              result==2u ? 1u : 0u,1u);
#endif
    seL4_SetMR(0, result);
    seL4_SetMR(1, sectors);
    seL4_SetMR(2, last_completion);
    seL4_SetMR(3, last_completion_dw2);
    seL4_SetMR(4, last_command_dw0);
    seL4_Send(PD_CNODE_SLOT_FRACTAL_NVME_REPORT,
              seL4_MessageInfo_new(FRACTAL_NVME_REPORT_LABEL, 0u, 0u, 5u));
#ifdef AGENTOS_FRACTAL_NVME_EXCHANGE
    if (result == FRACTAL_XFER_PANIC_STEP) __builtin_trap();
#endif
    for (;;) {
        seL4_Word badge = 0u;
        (void)seL4_Wait(my_ep, &badge);
    }
}
