#include <platform/fractal_gpt.h>

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4u) << 32);
}

static bool equal(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    uint8_t delta = 0u;
    for (uint32_t i = 0; i < n; ++i) delta |= a[i] ^ b[i];
    return delta == 0u;
}

static bool nonzero(const uint8_t *p, uint32_t n)
{
    uint8_t value = 0u;
    for (uint32_t i = 0; i < n; ++i) value |= p[i];
    return value != 0u;
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *p, uint32_t n)
{
    for (uint32_t i = 0; i < n; ++i) {
        crc ^= p[i];
        for (unsigned bit = 0; bit < 8u; ++bit)
            crc = (crc >> 1) ^ ((crc & 1u) ? UINT32_C(0xedb88320) : 0u);
    }
    return crc;
}

static bool header_crc_valid(const uint8_t header[FRACTAL_GPT_SECTOR_BYTES])
{
    static const uint8_t magic[8] = {'E','F','I',' ','P','A','R','T'};
    if (!equal(header, magic, 8u) || rd32(header + 8u) != 0x00010000u ||
        rd32(header + 12u) != 92u || rd32(header + 20u) != 0u ||
        !nonzero(header + 56u, 16u) ||
        rd32(header + 80u) != FRACTAL_GPT_ENTRIES ||
        rd32(header + 84u) != FRACTAL_GPT_ENTRY_BYTES) return false;
    for (uint32_t i = 92u; i < FRACTAL_GPT_SECTOR_BYTES; ++i)
        if (header[i] != 0u) return false;
    uint8_t copy[92];
    for (uint32_t i = 0; i < 92u; ++i) copy[i] = header[i];
    copy[16] = copy[17] = copy[18] = copy[19] = 0u;
    return (~crc32_update(UINT32_MAX, copy, 92u)) == rd32(header + 16u);
}

bool fractal_gpt_begin(fractal_gpt_guard_t *guard,
                       const uint8_t header[FRACTAL_GPT_SECTOR_BYTES],
                       uint64_t namespace_sectors,
                       const uint8_t partition_guid[16],
                       const uint8_t type_guid[16],
                       uint64_t first_lba, uint64_t last_lba)
{
    if (!guard || !header || !partition_guid || !type_guid ||
        namespace_sectors < 68u || first_lba < 34u ||
        first_lba > last_lba || last_lba >= namespace_sectors - 1u ||
        !nonzero(partition_guid, 16u) || !nonzero(type_guid, 16u)) return false;
    *guard = (fractal_gpt_guard_t){0};
    if (!header_crc_valid(header) || rd64(header + 24u) != 1u ||
        rd64(header + 32u) != namespace_sectors - 1u ||
        rd64(header + 40u) < 34u ||
        rd64(header + 40u) > first_lba ||
        rd64(header + 40u) > rd64(header + 48u) ||
        rd64(header + 48u) < last_lba ||
        rd64(header + 48u) > namespace_sectors - 34u ||
        rd64(header + 72u) != 2u)
        return false;
    for (uint32_t i = 0; i < 16u; ++i) {
        guard->partition_guid[i] = partition_guid[i];
        guard->type_guid[i] = type_guid[i];
        guard->disk_guid[i] = header[56u + i];
    }
    guard->first_lba = first_lba;
    guard->last_lba = last_lba;
    guard->usable_first = rd64(header + 40u);
    guard->usable_last = rd64(header + 48u);
    guard->namespace_sectors = namespace_sectors;
    guard->expected_entries_crc = rd32(header + 88u);
    guard->running_crc = UINT32_MAX;
    return true;
}

bool fractal_gpt_begin_backup(fractal_gpt_guard_t *backup,
                              const uint8_t header[FRACTAL_GPT_SECTOR_BYTES],
                              const fractal_gpt_guard_t *primary)
{
    if (!backup || !header || !fractal_gpt_finish(primary)) return false;
    const uint64_t sectors = primary->namespace_sectors;
    if (!header_crc_valid(header) ||
        rd64(header + 24u) != sectors - 1u ||
        rd64(header + 32u) != 1u ||
        rd64(header + 40u) != primary->usable_first ||
        rd64(header + 48u) != primary->usable_last ||
        !equal(header + 56u, primary->disk_guid, 16u) ||
        rd64(header + 72u) != sectors - 33u ||
        rd32(header + 88u) != primary->expected_entries_crc)
        return false;
    *backup = *primary;
    backup->running_crc = UINT32_MAX;
    backup->entries_seen = 0u;
    backup->matches = 0u;
    return true;
}

bool fractal_gpt_feed(fractal_gpt_guard_t *guard,
                      const uint8_t entries[FRACTAL_GPT_CHUNK_BYTES])
{
    if (!guard || !entries || guard->entries_seen >= FRACTAL_GPT_ENTRIES)
        return false;
    for (uint32_t i = 0; i < FRACTAL_GPT_CHUNK_BYTES;
         i += FRACTAL_GPT_ENTRY_BYTES) {
        const uint8_t *entry = entries + i;
        if (!nonzero(entry, 16u)) continue;
        uint64_t first = rd64(entry + 32u), last = rd64(entry + 40u);
        if (first < guard->usable_first || first > last ||
            last > guard->usable_last) return false;
        if (first <= guard->last_lba && last >= guard->first_lba) {
            if (!equal(entry + 16u, guard->partition_guid, 16u) ||
                !equal(entry, guard->type_guid, 16u) ||
                first != guard->first_lba || last != guard->last_lba ||
                ++guard->matches != 1u) return false;
        } else if (equal(entry + 16u, guard->partition_guid, 16u)) {
            return false;
        }
    }
    guard->running_crc = crc32_update(guard->running_crc, entries,
                                      FRACTAL_GPT_CHUNK_BYTES);
    guard->entries_seen += FRACTAL_GPT_CHUNK_BYTES / FRACTAL_GPT_ENTRY_BYTES;
    return true;
}

bool fractal_gpt_finish(const fractal_gpt_guard_t *guard)
{
    return guard && guard->entries_seen == FRACTAL_GPT_ENTRIES &&
           guard->matches == 1u &&
           ~guard->running_crc == guard->expected_entries_crc;
}

bool fractal_gpt_in_range(const fractal_gpt_guard_t *guard,
                          uint64_t lba, uint32_t sectors)
{
    if (!fractal_gpt_finish(guard) || !sectors || lba < guard->first_lba ||
        lba > guard->last_lba) return false;
    return (uint64_t)sectors - 1u <= guard->last_lba - lba;
}
