#include <assert.h>
#include <stdint.h>
#include <platform/fractal_block_policy.h>

int main(void)
{
    const uint64_t capacity = FRACTAL_DISK_SECTORS / FRACTAL_BLOCK_SECTORS;
    const uint64_t first = FRACTAL_PART_FIRST / FRACTAL_BLOCK_SECTORS;
    const uint64_t end = (FRACTAL_PART_LAST + 1u) / FRACTAL_BLOCK_SECTORS;

    assert(fractal_native_block_allowed(0u, 5u, capacity, false));
    assert(fractal_native_block_allowed(capacity - 5u, 5u, capacity, false));
    assert(fractal_native_block_allowed(first, 1u, capacity, false));
    assert(fractal_native_block_allowed(end - 1u, 1u, capacity, true));
    assert(fractal_native_block_allowed(first, (uint32_t)(end - first),
                                        capacity, true));

    assert(!fractal_native_block_allowed(0u, 1u, capacity, true));
    assert(!fractal_native_block_allowed(5u, 1u, capacity, false));
    assert(!fractal_native_block_allowed(first - 1u, 1u, capacity, false));
    assert(!fractal_native_block_allowed(first - 1u, 2u, capacity, true));
    assert(!fractal_native_block_allowed(end, 1u, capacity, false));
    assert(!fractal_native_block_allowed(end - 1u, 2u, capacity, true));
    assert(!fractal_native_block_allowed(capacity - 5u, 1u,
                                         capacity, true));
    assert(!fractal_native_block_allowed(capacity, 1u, capacity, false));
    assert(!fractal_native_block_allowed(UINT64_MAX, 1u, capacity, false));
    assert(!fractal_native_block_allowed(first, 0u, capacity, false));
    assert(!fractal_native_block_allowed(first, 1u, capacity - 1u, true));

    assert(fractal_candidate_read_allowed(0u, 1u));
    assert(fractal_candidate_read_allowed(2u, 8u));
    assert(fractal_candidate_read_allowed(33u, 1u));
    assert(fractal_candidate_read_allowed(FRACTAL_DISK_SECTORS - 33u, 8u));
    assert(fractal_candidate_read_allowed(FRACTAL_DISK_SECTORS - 1u, 1u));
    assert(fractal_candidate_read_allowed(FRACTAL_PART_FIRST, 8u));
    assert(fractal_candidate_read_allowed(FRACTAL_PART_LAST - 7u, 8u));
    assert(!fractal_candidate_read_allowed(34u, 1u));
    assert(!fractal_candidate_read_allowed(FRACTAL_PART_FIRST - 1u, 2u));
    assert(!fractal_candidate_read_allowed(FRACTAL_PART_LAST, 2u));
    assert(!fractal_candidate_read_allowed(FRACTAL_DISK_SECTORS - 34u, 2u));
    assert(!fractal_candidate_read_allowed(0u, 0u));
    assert(!fractal_candidate_read_allowed(FRACTAL_DISK_SECTORS, 1u));
    return 0;
}
