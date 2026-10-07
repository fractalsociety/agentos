#include <platform/fractal_exchange_cycle.h>
#include <platform/fractal_exchange.h>
#include "sha256_mini.h"
#include <stdio.h>
#ifdef AGENTOS_FRACTAL_SIGNED_PLAN
#include "monocypher.h"
#include <platform/fractal_plan_public_key.h>
#endif

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void wr32(uint8_t *p, uint32_t value)
{
    for (uint32_t i = 0; i < 4u; ++i) p[i] = (uint8_t)(value >> (8u * i));
}
static void copy(uint8_t *dst, const uint8_t *src, uint32_t count)
{
    for (uint32_t i = 0; i < count; ++i) dst[i] = src[i];
}
static void zero(uint8_t *dst, uint32_t count)
{
    for (uint32_t i = 0; i < count; ++i) dst[i] = 0u;
}
static bool same(const uint8_t *a, const uint8_t *b, uint32_t count)
{
    uint8_t difference = 0u;
    for (uint32_t i = 0; i < count; ++i) difference |= a[i] ^ b[i];
    return difference == 0u;
}
static bool all_zero(const uint8_t *block)
{
    for (uint32_t i = 0u; i < FRACTAL_XFER_BLOCK_BYTES; ++i)
        if (block[i] != 0u) return false;
    return true;
}
static bool valid_crash(const uint8_t *block)
{
    uint8_t digest[32];
    sha256_mini(block, 96u, digest);
    if (!same(block, (const uint8_t *)FRACTAL_XFER_CRASH_MAGIC, 8u) ||
        rd32(block + 8u) != FRACTAL_XFER_VERSION ||
        rd32(block + 12u) != 1u ||
        !same(block + 96u, digest, 32u)) return false;
    for (uint32_t i = 128u; i < FRACTAL_XFER_BLOCK_BYTES; ++i)
        if (block[i] != 0u) return false;
    return true;
}
static bool valid_event(const uint8_t *block, const uint8_t prior_hash[32])
{
    uint8_t digest[32];
    sha256_mini(block, 128u, digest);
    if (!same(block, (const uint8_t *)FRACTAL_XFER_EVENT_MAGIC, 8u) ||
        rd32(block + 8u) != FRACTAL_XFER_VERSION ||
        rd32(block + 12u) != 1u ||
        !same(block + 96u, prior_hash, 32u) ||
        !same(block + 128u, digest, 32u)) return false;
    for (uint32_t i = 160u; i < FRACTAL_XFER_BLOCK_BYTES; ++i)
        if (block[i] != 0u) return false;
    return true;
}
static void hex_text(const uint8_t *bytes, uint32_t count, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (uint32_t i = 0; i < count; ++i) {
        out[2u * i] = digits[bytes[i] >> 4];
        out[2u * i + 1u] = digits[bytes[i] & 15u];
    }
    out[2u * count] = '\0';
}
static void uuid_text(const uint8_t bytes[16], char out[37])
{
    static const char digits[] = "0123456789abcdef";
    uint32_t j = 0u;
    for (uint32_t i = 0; i < 16u; ++i) {
        if (i == 4u || i == 6u || i == 8u || i == 10u) out[j++] = '-';
        out[j++] = digits[bytes[i] >> 4];
        out[j++] = digits[bytes[i] & 15u];
    }
    out[j] = '\0';
}

static uint32_t append_plan_event(const fractal_exchange_io_t *io,
                                  uint64_t capacity_blocks,
                                  const uint8_t run_id[16],
                                  const uint8_t plan_hash[32],
                                  const uint8_t image_hash[32])
{
    uint8_t *block = io->block;
    uint8_t prior_hash[32] = {0};
    uint8_t event_ids[FRACTAL_XFER_EVENT_RING_BLOCKS][16];
    uint32_t occupied = 0u;
    uint32_t free_slot = FRACTAL_XFER_EVENT_RING_BLOCKS;
    for (uint32_t slot = 0u; slot < FRACTAL_XFER_EVENT_RING_BLOCKS; ++slot) {
        if (!io->read_block(io->context,
                capacity_blocks - FRACTAL_XFER_EVENT_OFFSET - slot,
                block)) return 43u;
        if (all_zero(block)) {
            if (free_slot == FRACTAL_XFER_EVENT_RING_BLOCKS) free_slot = slot;
        } else {
            if (free_slot != FRACTAL_XFER_EVENT_RING_BLOCKS ||
                !valid_event(block, prior_hash)) return 44u;
            for (uint32_t previous = 0u; previous < occupied; ++previous)
                if (same(block + 16u, event_ids[previous], 16u)) return 45u;
            if (same(block + 16u, run_id, 16u)) return 45u;
            copy(event_ids[occupied++], block + 16u, 16u);
            sha256_mini(block, FRACTAL_XFER_BLOCK_BYTES, prior_hash);
        }
    }
    if (free_slot == FRACTAL_XFER_EVENT_RING_BLOCKS) return 46u;
    const uint64_t event_block = capacity_blocks -
        FRACTAL_XFER_EVENT_OFFSET - free_slot;
    zero(block, FRACTAL_XFER_BLOCK_BYTES);
    copy(block, (const uint8_t *)FRACTAL_XFER_EVENT_MAGIC, 8u);
    wr32(block + 8u, FRACTAL_XFER_VERSION);
    wr32(block + 12u, 1u); /* plan admitted before work */
    copy(block + 16u, run_id, 16u);
    copy(block + 32u, plan_hash, 32u);
    copy(block + 64u, image_hash, 32u);
    copy(block + 96u, prior_hash, 32u);
    sha256_mini(block, 128u, block + 128u);
    if (!io->write_block(io->context, event_block, block) ||
        !io->flush(io->context)) return 47u;
    zero(block, FRACTAL_XFER_BLOCK_BYTES);
    if (!io->read_block(io->context, event_block, block)) return 48u;
    if (!valid_event(block, prior_hash) ||
        !same(block + 16u, run_id, 16u) ||
        !same(block + 32u, plan_hash, 32u) ||
        !same(block + 64u, image_hash, 32u)) return 49u;
    return 0u;
}

uint32_t fractal_exchange_cycle_run(const fractal_exchange_io_t *io,
                                    uint64_t capacity_blocks)
{
    const uint64_t end_guard =
#ifdef AGENTOS_FRACTAL_PERSISTENT_MARKER
        FRACTAL_XFER_MARKER_END_GUARD_BLOCKS;
#else
        0u;
#endif
    if (!io || !io->block || !io->read_block || !io->write_block || !io->flush ||
        capacity_blocks < FRACTAL_XFER_BLOCK_COUNT + end_guard) return 20u;
    capacity_blocks -= end_guard;
    uint8_t *block = io->block;
    uint8_t digest[32], run_id[16], image_hash[32], plan_hash[32];
    uint8_t witness_hash[32], result_hash[32];
    char run_text[37], image_text[65], witness_text[65], expected_plan[160];

    if (!io->read_block(io->context, capacity_blocks - FRACTAL_XFER_PLAN_OFFSET,
                        block)) return 21u;
#ifdef AGENTOS_FRACTAL_SIGNED_PLAN
    const uint32_t plan_json_offset = FRACTAL_XFER_SIGNED_PLAN_JSON_OFFSET;
    if (!same(block, (const uint8_t *)FRACTAL_XFER_SIGNED_PLAN_MAGIC, 8u) ||
        rd32(block + 8u) != FRACTAL_XFER_SIGNED_PLAN_VERSION) return 22u;
#else
    const uint32_t plan_json_offset = FRACTAL_XFER_PLAN_JSON_OFFSET;
    if (!same(block, (const uint8_t *)FRACTAL_XFER_PLAN_MAGIC, 8u) ||
        rd32(block + 8u) != FRACTAL_XFER_VERSION) return 22u;
#endif
    uint32_t plan_len = rd32(block + 12u);
    if (!plan_len || plan_len > FRACTAL_XFER_BLOCK_BYTES -
        plan_json_offset) return 23u;
    sha256_mini(block, 96u, digest);
    if (!same(digest, block + 96u, 32u)) return 24u;
#ifdef AGENTOS_FRACTAL_SIGNED_PLAN
    if (crypto_ed25519_check(
            block + FRACTAL_XFER_SIGNED_PLAN_SIGNATURE_OFFSET,
            block, 96u, fractal_plan_public_key) != 0) return 50u;
#endif
    sha256_mini(block + plan_json_offset, plan_len, digest);
    if (!same(digest, block + 64u, 32u)) return 25u;
    for (uint32_t i = plan_json_offset + plan_len;
         i < FRACTAL_XFER_BLOCK_BYTES; ++i)
        if (block[i] != 0u) return 26u;
    copy(run_id, block + 16u, 16u);
    copy(image_hash, block + 32u, 32u);
    copy(plan_hash, block + 64u, 32u);
    uuid_text(run_id, run_text);
    int expected_len = snprintf(expected_plan, sizeof(expected_plan),
        "{\"run_id\":\"%s\",\"schema\":\"fractal.test-plan.v1\","
        "\"tests\":[\"native-alive\"]}\n", run_text);
    bool panic_requested = false;
    if (expected_len <= 0 || (uint32_t)expected_len != plan_len ||
        !same((const uint8_t *)expected_plan,
              block + plan_json_offset, plan_len)) {
        expected_len = snprintf(expected_plan, sizeof(expected_plan),
            "{\"run_id\":\"%s\",\"schema\":\"fractal.test-plan.v1\","
            "\"tests\":[\"native-panic\"]}\n", run_text);
        if (expected_len <= 0 || (uint32_t)expected_len != plan_len ||
            !same((const uint8_t *)expected_plan,
                  block + plan_json_offset, plan_len)) return 27u;
        panic_requested = true;
    }

    if (panic_requested) {
        uint32_t free_slot = FRACTAL_XFER_CRASH_RING_BLOCKS;
        uint8_t previous_ids[FRACTAL_XFER_CRASH_RING_BLOCKS][16];
        uint32_t occupied = 0u;
        for (uint32_t slot = 0u; slot < FRACTAL_XFER_CRASH_RING_BLOCKS;
             ++slot) {
            if (!io->read_block(io->context,
                    capacity_blocks - FRACTAL_XFER_CRASH_OFFSET - slot,
                    block)) return 39u;
            if (all_zero(block)) {
                if (free_slot == FRACTAL_XFER_CRASH_RING_BLOCKS)
                    free_slot = slot;
            } else {
                if (free_slot != FRACTAL_XFER_CRASH_RING_BLOCKS ||
                    !valid_crash(block)) return 40u;
                for (uint32_t previous = 0u; previous < occupied; ++previous)
                    if (same(block + 16u, previous_ids[previous], 16u))
                        return 40u;
                if (same(block + 16u, run_id, 16u)) return 41u;
                copy(previous_ids[occupied++], block + 16u, 16u);
            }
        }
        if (free_slot == FRACTAL_XFER_CRASH_RING_BLOCKS) return 42u;
        const uint64_t crash_block = capacity_blocks -
            FRACTAL_XFER_CRASH_OFFSET - free_slot;

        uint32_t event_error = append_plan_event(io, capacity_blocks, run_id,
                                                 plan_hash, image_hash);
        if (event_error) return event_error;

        zero(block, FRACTAL_XFER_BLOCK_BYTES);
        copy(block, (const uint8_t *)FRACTAL_XFER_CRASH_MAGIC, 8u);
        wr32(block + 8u, FRACTAL_XFER_VERSION);
        wr32(block + 12u, 1u); /* deliberate native-panic test */
        copy(block + 16u, run_id, 16u);
        copy(block + 32u, plan_hash, 32u);
        copy(block + 64u, image_hash, 32u);
        sha256_mini(block, 96u, block + 96u);
        if (!io->write_block(io->context, crash_block, block) ||
            !io->flush(io->context)) return 36u;
        zero(block, FRACTAL_XFER_BLOCK_BYTES);
        if (!io->read_block(io->context, crash_block, block)) return 37u;
        if (!valid_crash(block) ||
            !same(block + 16u, run_id, 16u) ||
            !same(block + 32u, plan_hash, 32u) ||
            !same(block + 64u, image_hash, 32u)) return 38u;
        return FRACTAL_XFER_PANIC_STEP;
    }

    uint32_t event_error = append_plan_event(io, capacity_blocks, run_id,
                                             plan_hash, image_hash);
    if (event_error) return event_error;
    const uint64_t witness_block = capacity_blocks - FRACTAL_XFER_WITNESS_OFFSET;
    for (uint32_t i = 0; i < FRACTAL_XFER_BLOCK_BYTES; ++i)
        block[i] = (uint8_t)(i ^ run_id[i % 16u] ^ 0xa5u);
    sha256_mini(block, FRACTAL_XFER_BLOCK_BYTES, witness_hash);
    if (!io->write_block(io->context, witness_block, block) ||
        !io->flush(io->context)) return 28u;
    zero(block, FRACTAL_XFER_BLOCK_BYTES);
    if (!io->read_block(io->context, witness_block, block)) return 29u;
    for (uint32_t i = 0; i < FRACTAL_XFER_BLOCK_BYTES; ++i)
        if (block[i] != (uint8_t)(i ^ run_id[i % 16u] ^ 0xa5u)) return 30u;

    zero(block, FRACTAL_XFER_BLOCK_BYTES);
    copy(block, (const uint8_t *)FRACTAL_XFER_RESULT_MAGIC, 8u);
    wr32(block + 8u, FRACTAL_XFER_VERSION);
    wr32(block + 12u, 0u);
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
    wr32(block + 128u, (uint32_t)final_len);
    sha256_mini(block + FRACTAL_XFER_RESULT_JSON_OFFSET,
                (uint32_t)final_len, block + 132u);
    sha256_mini(block, 164u, block + 164u);
    sha256_mini(block, FRACTAL_XFER_BLOCK_BYTES, result_hash);
    if (!io->write_block(io->context,
            capacity_blocks - FRACTAL_XFER_RESULT_OFFSET, block) ||
        !io->flush(io->context)) return 32u;

    zero(block, FRACTAL_XFER_BLOCK_BYTES);
    copy(block, (const uint8_t *)FRACTAL_XFER_COMPLETE_MAGIC, 8u);
    wr32(block + 8u, FRACTAL_XFER_VERSION);
    copy(block + 16u, run_id, 16u);
    copy(block + 32u, result_hash, 32u);
    copy(block + 64u, plan_hash, 32u);
    sha256_mini(block, 96u, block + 96u);
    if (!io->write_block(io->context,
            capacity_blocks - FRACTAL_XFER_COMPLETE_OFFSET, block) ||
        !io->flush(io->context)) return 33u;
    zero(block, FRACTAL_XFER_BLOCK_BYTES);
    if (!io->read_block(io->context,
            capacity_blocks - FRACTAL_XFER_COMPLETE_OFFSET, block)) return 34u;
    sha256_mini(block, 96u, digest);
    if (!same(block, (const uint8_t *)FRACTAL_XFER_COMPLETE_MAGIC, 8u) ||
        rd32(block + 8u) != FRACTAL_XFER_VERSION ||
        !same(block + 16u, run_id, 16u) ||
        !same(block + 32u, result_hash, 32u) ||
        !same(block + 64u, plan_hash, 32u) ||
        !same(block + 96u, digest, 32u)) return 35u;
    return 2u;
}
