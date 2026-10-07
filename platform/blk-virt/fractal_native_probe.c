/* Native seL4 block persistence bring-up. This PD has only its own queue,
 * blk_virt control endpoint, and two notification capabilities. It never maps
 * the driver's DMA window or a guest VMM frame. The disposable QEMU media is
 * deliberately unformatted; the final four 4 KiB blocks hold the optional
 * plan/result exchange, or the final two blocks hold the basic probe. */
#include "agentos.h"
#include "sel4_ipc.h"
#include "system_desc.h"
#include <contracts/blk_virt_contract.h>
#include <platform/blk_layout.h>
#include <platform/blk_virt_pump.h>
#ifdef AGENTOS_FRACTAL_EXCHANGE_CYCLE
#include <platform/fractal_exchange.h>
#include "sha256_mini.h"
#include <stdio.h>
#endif
#ifdef AGENTOS_FRACTAL_GPT_QUALIFY
#include <platform/fractal_gpt.h>
#include <platform/fractal_partition.h>
#endif

#define PROBE_CLIENT 2u
#define PROBE_MEDIA 1u

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put32(uint8_t *p, uint32_t n)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(n >> (i * 8u));
}

static void put64(uint8_t *p, uint64_t n)
{
    for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(n >> (i * 8u));
}

static bool transact(aos_blk_virt_client_t *q, aos_blk_req_code_t code,
                     uint64_t block, uint32_t id);
static bool transact_response(aos_blk_virt_client_t *q,
                              aos_blk_req_code_t code, uint64_t block,
                              uint32_t id, aos_blk_resp_t *response_out);
static void report_step(uint32_t step);

#ifdef AGENTOS_FRACTAL_EXCHANGE_CYCLE
static bool same(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    uint8_t difference = 0u;
    for (uint32_t i = 0; i < n; ++i) difference |= a[i] ^ b[i];
    return difference == 0u;
}

static void copy(uint8_t *dst, const uint8_t *src, uint32_t n)
{
    for (uint32_t i = 0; i < n; ++i) dst[i] = src[i];
}

static void zero(uint8_t *dst, uint32_t n)
{
    for (uint32_t i = 0; i < n; ++i) dst[i] = 0u;
}

static void hex_text(const uint8_t *bytes, uint32_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (uint32_t i = 0; i < n; ++i) {
        out[2u * i] = digits[bytes[i] >> 4];
        out[2u * i + 1u] = digits[bytes[i] & 15u];
    }
    out[2u * n] = '\0';
}

static void uuid_text(const uint8_t run_id[16], char out[37])
{
    static const char digits[] = "0123456789abcdef";
    uint32_t j = 0u;
    for (uint32_t i = 0; i < 16u; ++i) {
        if (i == 4u || i == 6u || i == 8u || i == 10u) out[j++] = '-';
        out[j++] = digits[run_id[i] >> 4];
        out[j++] = digits[run_id[i] & 15u];
    }
    out[j] = '\0';
}

#ifdef AGENTOS_FRACTAL_GPT_QUALIFY
static uint8_t fractal_gpt_entries[FRACTAL_GPT_ENTRIES * FRACTAL_GPT_ENTRY_BYTES];

static bool qualify_partition(aos_blk_virt_client_t *queue,
                              fractal_gpt_guard_t *guard)
{
    if (queue->info->capacity * 8u != FRACTAL_DISK_SECTORS) return false;
    uint8_t header[FRACTAL_GPT_SECTOR_BYTES];
    for (uint64_t block = 0u; block < 5u; ++block) {
        if (!transact(queue, AOS_BLK_REQ_READ, block, 40u + (uint32_t)block))
            return false;
        if (block == 0u)
            copy(header, queue->data + FRACTAL_GPT_SECTOR_BYTES,
                 FRACTAL_GPT_SECTOR_BYTES);
        uint32_t start = block == 0u ? 1024u : (uint32_t)(block * 4096u);
        uint32_t end = block == 4u ? 17408u : (uint32_t)((block + 1u) * 4096u);
        copy(fractal_gpt_entries + start - 1024u,
             queue->data + start - (uint32_t)(block * 4096u), end - start);
    }
    if (!fractal_gpt_begin(guard, header, FRACTAL_DISK_SECTORS,
                           fractal_part_guid, fractal_linux_type,
                           FRACTAL_PART_FIRST, FRACTAL_PART_LAST)) return false;
    for (uint32_t chunk = 0u; chunk < FRACTAL_GPT_CHUNKS; ++chunk)
        if (!fractal_gpt_feed(guard,
            fractal_gpt_entries + chunk * FRACTAL_GPT_CHUNK_BYTES)) return false;
    return fractal_gpt_finish(guard) &&
           fractal_gpt_in_range(guard, FRACTAL_PART_LAST + 1u - 32u, 32u);
}
#endif

static uint32_t run_exchange(aos_blk_virt_client_t *queue)
{
    if (queue->info->capacity < FRACTAL_XFER_BLOCK_COUNT) return 20u;
#ifdef AGENTOS_FRACTAL_GPT_QUALIFY
    fractal_gpt_guard_t guard;
    if (!qualify_partition(queue, &guard)) return 36u;
    const uint64_t cap = (FRACTAL_PART_LAST + 1u) / 8u;
#else
    const uint64_t cap = queue->info->capacity;
#endif
    uint8_t digest[32], run_id[16], image_hash[32], plan_hash[32];
    uint8_t witness_hash[32], result_hash[32];
    char run_text[37], image_text[65], witness_text[65];
    char expected_plan[160];

    if (!transact(queue, AOS_BLK_REQ_READ,
                  cap - FRACTAL_XFER_PLAN_OFFSET, 10u)) return 21u;
    uint8_t *block = queue->data;
    if (!same(block, (const uint8_t *)FRACTAL_XFER_PLAN_MAGIC, 8u) ||
        get32(block + 8u) != FRACTAL_XFER_VERSION) return 22u;
    uint32_t plan_len = get32(block + 12u);
    if (!plan_len || plan_len > FRACTAL_XFER_BLOCK_BYTES -
        FRACTAL_XFER_PLAN_HEADER_BYTES) return 23u;
    sha256_mini(block, 96u, digest);
    if (!same(digest, block + 96u, 32u)) return 24u;
    sha256_mini(block + FRACTAL_XFER_PLAN_JSON_OFFSET, plan_len, digest);
    if (!same(digest, block + 64u, 32u)) return 25u;
    for (uint32_t i = FRACTAL_XFER_PLAN_JSON_OFFSET + plan_len;
         i < FRACTAL_XFER_BLOCK_BYTES; ++i)
        if (block[i] != 0u) return 26u;
    copy(run_id, block + 16u, 16u);
    copy(image_hash, block + 32u, 32u);
    copy(plan_hash, block + 64u, 32u);
    uuid_text(run_id, run_text);
    int expected_len = snprintf(expected_plan, sizeof(expected_plan),
        "{\"run_id\":\"%s\",\"schema\":\"fractal.test-plan.v1\","
        "\"tests\":[\"native-alive\"]}\n", run_text);
    if (expected_len <= 0 || (uint32_t)expected_len != plan_len ||
        !same((const uint8_t *)expected_plan,
              block + FRACTAL_XFER_PLAN_JSON_OFFSET, plan_len)) return 27u;

    const uint64_t witness_block = cap - FRACTAL_XFER_WITNESS_OFFSET;
    for (uint32_t i = 0; i < FRACTAL_XFER_BLOCK_BYTES; ++i)
        block[i] = (uint8_t)(i ^ run_id[i % 16u] ^ 0xa5u);
    sha256_mini(block, FRACTAL_XFER_BLOCK_BYTES, witness_hash);
    if (!transact(queue, AOS_BLK_REQ_WRITE, witness_block, 11u) ||
        !transact(queue, AOS_BLK_REQ_FLUSH, 0u, 12u)) return 28u;
    zero(block, FRACTAL_XFER_BLOCK_BYTES);
    if (!transact(queue, AOS_BLK_REQ_READ, witness_block, 13u)) return 29u;
    for (uint32_t i = 0; i < FRACTAL_XFER_BLOCK_BYTES; ++i)
        if (block[i] != (uint8_t)(i ^ run_id[i % 16u] ^ 0xa5u)) return 30u;

    zero(block, FRACTAL_XFER_BLOCK_BYTES);
    copy(block, (const uint8_t *)FRACTAL_XFER_RESULT_MAGIC, 8u);
    put32(block + 8u, FRACTAL_XFER_VERSION);
    put32(block + 12u, 0u);
    copy(block + 16u, run_id, 16u);
    copy(block + 32u, plan_hash, 32u);
    copy(block + 64u, image_hash, 32u);
    copy(block + 96u, witness_hash, 32u);
    hex_text(image_hash, 32u, image_text);
    hex_text(witness_hash, 32u, witness_text);
    int final_len = snprintf((char *)block + FRACTAL_XFER_RESULT_JSON_OFFSET,
        FRACTAL_XFER_BLOCK_BYTES - FRACTAL_XFER_RESULT_JSON_OFFSET,
        "{\"agentos_image_hash\":\"%s\",\"artifacts_hash\":\"%s\","
        "\"bytes_communicated\":24576,\"energy_estimate_j\":null,"
        "\"failed_tasks\":[],\"latency_ms\":null,\"peak_ram_bytes\":null,"
        "\"run_id\":\"%s\",\"schema\":\"fractal.final.v1\","
        "\"status\":\"pass\",\"system_one_decisions\":0,"
        "\"system_two_calls\":0,\"tokens_in\":0,\"tokens_out\":0,"
        "\"tool_calls\":0,\"verified_tasks\":[\"native-alive\"]}\n",
        image_text, witness_text, run_text);
    if (final_len <= 0 || (uint32_t)final_len >=
        FRACTAL_XFER_BLOCK_BYTES - FRACTAL_XFER_RESULT_JSON_OFFSET)
        return 31u;
    put32(block + 128u, (uint32_t)final_len);
    sha256_mini(block + FRACTAL_XFER_RESULT_JSON_OFFSET,
                (uint32_t)final_len, block + 132u);
    sha256_mini(block, 164u, block + 164u);
    sha256_mini(block, FRACTAL_XFER_BLOCK_BYTES, result_hash);
    if (!transact(queue, AOS_BLK_REQ_WRITE,
                  cap - FRACTAL_XFER_RESULT_OFFSET, 14u) ||
        !transact(queue, AOS_BLK_REQ_FLUSH, 0u, 15u)) return 32u;

    zero(block, FRACTAL_XFER_BLOCK_BYTES);
    copy(block, (const uint8_t *)FRACTAL_XFER_COMPLETE_MAGIC, 8u);
    put32(block + 8u, FRACTAL_XFER_VERSION);
    copy(block + 16u, run_id, 16u);
    copy(block + 32u, result_hash, 32u);
    copy(block + 64u, plan_hash, 32u);
    sha256_mini(block, 96u, block + 96u);
    if (!transact(queue, AOS_BLK_REQ_WRITE,
                  cap - FRACTAL_XFER_COMPLETE_OFFSET, 16u) ||
        !transact(queue, AOS_BLK_REQ_FLUSH, 0u, 17u)) return 33u;
    zero(block, FRACTAL_XFER_BLOCK_BYTES);
    if (!transact(queue, AOS_BLK_REQ_READ,
                  cap - FRACTAL_XFER_COMPLETE_OFFSET, 18u)) return 34u;
    sha256_mini(block, 96u, digest);
    if (!same(block, (const uint8_t *)FRACTAL_XFER_COMPLETE_MAGIC, 8u) ||
        get32(block + 8u) != FRACTAL_XFER_VERSION ||
        !same(block + 16u, run_id, 16u) ||
        !same(block + 32u, result_hash, 32u) ||
        !same(block + 64u, plan_hash, 32u) ||
        !same(block + 96u, digest, 32u)) return 35u;
    return 2u;
}
#endif

static bool transact_response(aos_blk_virt_client_t *q,
                              aos_blk_req_code_t code, uint64_t block,
                              uint32_t id, aos_blk_resp_t *response_out)
{
    if (q->req->head != q->req->tail || q->resp->head != q->resp->tail)
        return false;
    aos_blk_req_t request = {
        .code = code, .io_or_offset = 0u, .block_number = block,
        .count = code == AOS_BLK_REQ_FLUSH ? 0u : 1u, .id = id,
    };
    q->req->buffers[q->req->tail % q->capacity] = request;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    q->req->tail++;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    seL4_Signal(PD_CNODE_SLOT_BLK_VIRT_NOTIFY);
    while (q->resp->head == q->resp->tail) {
        seL4_Word badge = 0u;
        (void)seL4_Wait(PD_CNODE_SLOT_BLK_NATIVE_WAIT, &badge);
        if (badge != BLK_VIRT_VMM_WAKE_BADGE) return false;
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
    }
    aos_blk_resp_t response = q->resp->buffers[q->resp->head % q->capacity];
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    q->resp->head++;
    if (response.id != id) return false;
    *response_out = response;
    return true;
}

static bool transact(aos_blk_virt_client_t *q, aos_blk_req_code_t code,
                     uint64_t block, uint32_t id)
{
    aos_blk_resp_t response;
    return transact_response(q, code, block, id, &response) &&
           response.status == AOS_BLK_RESP_OK &&
           response.success_count == (code == AOS_BLK_REQ_FLUSH ? 0u : 1u);
}

#ifdef AGENTOS_FRACTAL_NATIVE_ISOLATION_TEST
static bool denied(aos_blk_virt_client_t *queue, aos_blk_req_code_t code,
                   uint64_t block, uint32_t id)
{
    aos_blk_resp_t response;
    return transact_response(queue, code, block, id, &response) &&
           response.status == AOS_BLK_RESP_ERR_INVALID_PARAM &&
           response.success_count == 0u;
}
#endif

static uint32_t run_probe(void)
{
    aos_blk_virt_client_t queue = {0};
    aos_blk_client_bind((uint8_t *)AOS_BLK_SHMEM_VA, PROBE_CLIENT, &queue);
    if (!queue.info || !queue.req || !queue.resp || !queue.data) return 10u;
    for (uint32_t i = 0; i < AOS_BLK_QUEUE_BYTES; ++i) {
        ((volatile uint8_t *)queue.req)[i] = 0u;
        ((volatile uint8_t *)queue.resp)[i] = 0u;
    }
    if (queue.signal) queue.signal->req_consumer_signalled = 0u;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);

    sel4_msg_t request = {.opcode = BLK_VIRT_OP_ATTACH,
                          .length = sizeof(blk_virt_attach_req_t)};
    sel4_msg_t reply = {0};
    put32(request.data, BLK_VIRT_CONTRACT_VERSION);
    put32(request.data + 4u, PROBE_CLIENT);
    put32(request.data + 8u, BLK_VIRT_NATIVE_SLOT);
    put32(request.data + 12u, PROBE_MEDIA);
    sel4_call(PD_CNODE_SLOT_BLK_VIRT_EP, &request, &reply);
    if (reply.opcode != SEL4_ERR_OK) return 0x1100u | reply.opcode;
    if (reply.length != sizeof(blk_virt_attach_reply_t)) return 0x1200u | reply.length;
    if (get32(reply.data) != BLK_VIRT_OK) return 0x1300u | get32(reply.data);
    if (get32(reply.data + 4u) != BLK_VIRT_CONTRACT_VERSION) return 0x1400u;
    if (get32(reply.data + 8u) != BLK_VIRT_HW_VIRTIO_BLK)
        return 0x1500u | get32(reply.data + 8u);
    if (!queue.info->ready) return 0x1600u;
    if (queue.info->read_only) return 0x1700u;
    if (queue.info->capacity < 2u || queue.info->capacity > UINT32_MAX)
        return 0x1800u;

#ifdef AGENTOS_FRACTAL_NATIVE_ISOLATION_TEST
    if (queue.info->capacity != FRACTAL_DISK_SECTORS / 8u ||
        !denied(&queue, AOS_BLK_REQ_READ, 5u, 80u) ||
        !denied(&queue, AOS_BLK_REQ_READ,
                FRACTAL_PART_FIRST / 8u - 1u, 81u) ||
        !denied(&queue, AOS_BLK_REQ_WRITE, 0u, 82u) ||
        !denied(&queue, AOS_BLK_REQ_WRITE,
                (FRACTAL_PART_LAST + 1u) / 8u, 83u)) return 0x1900u;
    report_step(0x1a00u);
#endif

#ifdef AGENTOS_FRACTAL_EXCHANGE_CYCLE
    return run_exchange(&queue);
#else

    const uint64_t witness_block = queue.info->capacity - 2u;
    const uint64_t result_block = queue.info->capacity - 1u;
    for (uint32_t i = 0; i < AOS_BLK_TRANSFER_SIZE; ++i)
        queue.data[i] = (uint8_t)(i ^ 0xa5u);
    if (!transact(&queue, AOS_BLK_REQ_WRITE, witness_block, 1u)) return 12u;
    if (!transact(&queue, AOS_BLK_REQ_FLUSH, 0u, 2u)) return 13u;
    for (uint32_t i = 0; i < AOS_BLK_TRANSFER_SIZE; ++i) queue.data[i] = 0u;
    if (!transact(&queue, AOS_BLK_REQ_READ, witness_block, 3u)) return 14u;
    for (uint32_t i = 0; i < AOS_BLK_TRANSFER_SIZE; ++i)
        if (queue.data[i] != (uint8_t)(i ^ 0xa5u)) return 15u;

    for (uint32_t i = 0; i < AOS_BLK_TRANSFER_SIZE; ++i) queue.data[i] = 0u;
    static const char marker[] = "FRACTAL_NATIVE_BLOCK_PASS_v1\n";
    for (uint32_t i = 0; i < sizeof(marker) - 1u; ++i)
        queue.data[i] = (uint8_t)marker[i];
    put64(queue.data + 32u, witness_block);
    put64(queue.data + 40u, result_block);
    put64(queue.data + 48u, queue.info->capacity);
    if (!transact(&queue, AOS_BLK_REQ_WRITE, result_block, 4u)) return 16u;
    if (!transact(&queue, AOS_BLK_REQ_FLUSH, 0u, 5u)) return 17u;
    return 2u;
#endif
}

static void report_step(uint32_t step)
{
    seL4_SetMR(0, step);
    seL4_Send(PD_CNODE_SLOT_FRACTAL_REPORT,
              seL4_MessageInfo_new(FRACTAL_NATIVE_REPORT_LABEL, 0u, 0u, 1u));
}

void pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    (void)ns_ep;
    report_step(1u);
    agentos_log_boot("fractal_native_probe");
    uint32_t result = run_probe();
    if (result == 2u) {
        report_step(result);
        agentos_log_info("fractal_native_probe", "native block write/flush/readback persisted");
    } else {
        report_step(result);
        agentos_log_info("fractal_native_probe", "native block persistence proof failed");
    }
    for (;;) {
        seL4_Word badge = 0u;
        (void)seL4_Wait(my_ep, &badge);
    }
}
