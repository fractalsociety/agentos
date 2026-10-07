/* Bounded GPT authorization before a native block client may write.
 * The caller validates both headers and both 16 KiB entry arrays. */
#ifndef AOS_PLATFORM_FRACTAL_GPT_H
#define AOS_PLATFORM_FRACTAL_GPT_H

#include <stdbool.h>
#include <stdint.h>

#define FRACTAL_GPT_SECTOR_BYTES 512u
#define FRACTAL_GPT_ENTRIES 128u
#define FRACTAL_GPT_ENTRY_BYTES 128u
#define FRACTAL_GPT_CHUNK_BYTES 4096u
#define FRACTAL_GPT_CHUNKS 4u

typedef struct {
    uint8_t partition_guid[16];
    uint8_t type_guid[16];
    uint8_t disk_guid[16];
    uint64_t first_lba;
    uint64_t last_lba;
    uint64_t usable_first;
    uint64_t usable_last;
    uint64_t namespace_sectors;
    uint32_t expected_entries_crc;
    uint32_t running_crc;
    uint32_t entries_seen;
    uint32_t matches;
} fractal_gpt_guard_t;

bool fractal_gpt_begin(fractal_gpt_guard_t *guard,
                       const uint8_t header[FRACTAL_GPT_SECTOR_BYTES],
                       uint64_t namespace_sectors,
                       const uint8_t partition_guid[16],
                       const uint8_t type_guid[16],
                       uint64_t first_lba, uint64_t last_lba);
bool fractal_gpt_begin_backup(fractal_gpt_guard_t *backup,
                              const uint8_t header[FRACTAL_GPT_SECTOR_BYTES],
                              const fractal_gpt_guard_t *primary);
bool fractal_gpt_feed(fractal_gpt_guard_t *guard,
                      const uint8_t entries[FRACTAL_GPT_CHUNK_BYTES]);
bool fractal_gpt_finish(const fractal_gpt_guard_t *guard);
bool fractal_gpt_in_range(const fractal_gpt_guard_t *guard,
                          uint64_t lba, uint32_t sectors);

#endif
