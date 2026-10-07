/* Exact namespace and partition identity for the dedicated Fractal test area.
 * These values are build-specific and are not inferred from a GPT type alone. */
#ifndef AOS_PLATFORM_FRACTAL_PARTITION_H
#define AOS_PLATFORM_FRACTAL_PARTITION_H

#include <stdbool.h>
#include <stdint.h>

#define FRACTAL_DISK_SECTORS UINT64_C(2000409264)
#define FRACTAL_PART_FIRST UINT64_C(924848128)
#define FRACTAL_PART_LAST UINT64_C(1553993727)

/* The physical write candidate may read GPT headers/tables and its own
 * partition; no other namespace contents are needed for its test cycle. */
static inline bool fractal_candidate_read_allowed(uint64_t lba,
                                                   uint16_t count)
{
    if (!count || lba >= FRACTAL_DISK_SECTORS ||
        count > FRACTAL_DISK_SECTORS - lba) return false;
    const uint64_t end = lba + count;
    return end <= 34u ||
           (lba >= FRACTAL_DISK_SECTORS - 33u &&
            end <= FRACTAL_DISK_SECTORS) ||
           (lba >= FRACTAL_PART_FIRST && end <= FRACTAL_PART_LAST + 1u);
}

static const uint8_t fractal_part_guid[16] = {
    0xe0,0x85,0x24,0x76,0x97,0x96,0xf6,0x48,
    0x85,0x19,0xa4,0xc1,0xe8,0xc4,0x39,0xe5
};
static const uint8_t fractal_linux_type[16] = {
    0xaf,0x3d,0xc6,0x0f,0x83,0x84,0x72,0x47,
    0x8e,0x79,0x3d,0x69,0xd8,0x47,0x7d,0xe4
};

#endif
