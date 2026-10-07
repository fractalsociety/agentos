/* Exact block authority for the native Fractal client on this test disk.
 * The block virtualizer enforces this independently of the client PD. */
#ifndef AOS_PLATFORM_FRACTAL_BLOCK_POLICY_H
#define AOS_PLATFORM_FRACTAL_BLOCK_POLICY_H

#include <stdbool.h>
#include <stdint.h>
#include <platform/fractal_partition.h>

#define FRACTAL_BLOCK_SECTORS UINT64_C(8)
#define FRACTAL_GPT_EDGE_BLOCKS UINT64_C(5)

static inline bool fractal_native_block_allowed(uint64_t block,
                                                uint32_t count,
                                                uint64_t capacity,
                                                bool write)
{
    const uint64_t expected = FRACTAL_DISK_SECTORS / FRACTAL_BLOCK_SECTORS;
    const uint64_t first = FRACTAL_PART_FIRST / FRACTAL_BLOCK_SECTORS;
    const uint64_t end = (FRACTAL_PART_LAST + 1u) / FRACTAL_BLOCK_SECTORS;
    if (FRACTAL_DISK_SECTORS % FRACTAL_BLOCK_SECTORS ||
        FRACTAL_PART_FIRST % FRACTAL_BLOCK_SECTORS ||
        (FRACTAL_PART_LAST + 1u) % FRACTAL_BLOCK_SECTORS ||
        capacity != expected || !count || block > capacity ||
        count > capacity - block) return false;
    const uint64_t after = block + count;
    if (block >= first && after <= end) return true;
    return !write && (after <= FRACTAL_GPT_EDGE_BLOCKS ||
                      block >= capacity - FRACTAL_GPT_EDGE_BLOCKS);
}

#endif
