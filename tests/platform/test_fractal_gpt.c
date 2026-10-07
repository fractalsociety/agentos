#include <platform/fractal_gpt.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t target_guid[16] = {
    0xe0,0x85,0x24,0x76,0x97,0x96,0xf6,0x48,
    0x85,0x19,0xa4,0xc1,0xe8,0xc4,0x39,0xe5
};
static const uint8_t linux_type[16] = {
    0xaf,0x3d,0xc6,0x0f,0x83,0x84,0x72,0x47,
    0x8e,0x79,0x3d,0x69,0xd8,0x47,0x7d,0xe4
};
static const uint8_t other_guid[16] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
};
static uint8_t header[512], backup_header[512];
static uint8_t entries[16384], backup_entries[16384];

static void wr32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4u; ++i) p[i] = (uint8_t)(value >> (i * 8u));
}

static void wr64(uint8_t *p, uint64_t value)
{
    wr32(p, (uint32_t)value);
    wr32(p + 4u, (uint32_t)(value >> 32));
}

/* Independent fixture CRC: byte-at-a-time polynomial division. */
static uint32_t fixture_crc(const uint8_t *bytes, unsigned count)
{
    uint32_t crc = 0xffffffffu;
    for (unsigned i = 0; i < count; ++i) {
        crc ^= bytes[i];
        for (unsigned j = 0; j < 8u; ++j) {
            if (crc & 1u) crc = (crc >> 1) ^ 0xedb88320u;
            else crc >>= 1;
        }
    }
    return ~crc;
}

static void set_entry(unsigned index, const uint8_t *guid,
                      uint64_t first, uint64_t last)
{
    uint8_t *entry = entries + index * 128u;
    memcpy(entry, linux_type, 16u);
    memcpy(entry + 16u, guid, 16u);
    wr64(entry + 32u, first);
    wr64(entry + 40u, last);
}

static void seal(void)
{
    wr32(header + 88u, fixture_crc(entries, sizeof(entries)));
    wr32(header + 16u, 0u);
    wr32(header + 16u, fixture_crc(header, 92u));
    memcpy(backup_entries, entries, sizeof(entries));
    memcpy(backup_header, header, sizeof(header));
    wr64(backup_header + 24u, 99999u);
    wr64(backup_header + 32u, 1u);
    wr64(backup_header + 72u, 99967u);
    wr32(backup_header + 16u, 0u);
    wr32(backup_header + 16u, fixture_crc(backup_header, 92u));
}

static void fixture(void)
{
    memset(header, 0, sizeof(header));
    memset(entries, 0, sizeof(entries));
    memcpy(header, "EFI PART", 8u);
    wr32(header + 8u, 0x00010000u);
    wr32(header + 12u, 92u);
    wr64(header + 24u, 1u);
    wr64(header + 32u, 99999u);
    wr64(header + 40u, 34u);
    wr64(header + 48u, 99966u);
    memcpy(header + 56u, other_guid, 16u);
    wr64(header + 72u, 2u);
    wr32(header + 80u, 128u);
    wr32(header + 84u, 128u);
    set_entry(2u, other_guid, 34u, 999u);
    set_entry(7u, target_guid, 1000u, 1999u);
    seal();
}

static bool authorize(void)
{
    fractal_gpt_guard_t guard;
    if (!fractal_gpt_begin(&guard, header, 100000u, target_guid,
                           linux_type, 1000u, 1999u)) return false;
    for (unsigned chunk = 0; chunk < 4u; ++chunk)
        if (!fractal_gpt_feed(&guard, entries + chunk * 4096u)) return false;
    if (!fractal_gpt_finish(&guard)) return false;
    fractal_gpt_guard_t backup;
    if (!fractal_gpt_begin_backup(&backup, backup_header, &guard)) return false;
    for (unsigned chunk = 0; chunk < 4u; ++chunk)
        if (!fractal_gpt_feed(&backup, backup_entries + chunk * 4096u))
            return false;
    if (!fractal_gpt_finish(&backup)) return false;
    assert(fractal_gpt_in_range(&guard, 1000u, 1u));
    assert(fractal_gpt_in_range(&guard, 1992u, 8u));
    assert(!fractal_gpt_in_range(&guard, 999u, 1u));
    assert(!fractal_gpt_in_range(&guard, 1999u, 2u));
    assert(!fractal_gpt_in_range(&guard, 1000u, 0u));
    assert(!fractal_gpt_in_range(&guard, UINT64_MAX, UINT32_MAX));
    return true;
}

int main(void)
{
    assert(fixture_crc((const uint8_t *)"123456789", 9u) == 0xcbf43926u);
    fixture();
    assert(authorize());

    backup_header[16] ^= 1u;
    assert(!authorize());
    fixture();
    backup_header[56] ^= 1u;
    wr32(backup_header + 16u, 0u);
    wr32(backup_header + 16u, fixture_crc(backup_header, 92u));
    assert(!authorize());
    fixture();
    backup_entries[7u * 128u + 20u] ^= 1u;
    assert(!authorize());
    fixture();
    backup_header[88] ^= 1u;
    wr32(backup_header + 16u, 0u);
    wr32(backup_header + 16u, fixture_crc(backup_header, 92u));
    assert(!authorize());
    fixture();

    header[16] ^= 1u;
    assert(!authorize());
    fixture();
    entries[7u * 128u + 20u] ^= 1u;
    assert(!authorize());
    seal();
    assert(!authorize());
    fixture();
    entries[7u * 128u] ^= 1u;
    seal();
    assert(!authorize());
    fixture();
    set_entry(2u, other_guid, 999u, 1200u);
    seal();
    assert(!authorize());
    fixture();
    set_entry(2u, target_guid, 34u, 999u);
    seal();
    assert(!authorize());
    fixture();
    fractal_gpt_guard_t guard;
    assert(fractal_gpt_begin(&guard, header, 100000u, target_guid,
                             linux_type, 999u, 1999u));
    assert(!fractal_gpt_feed(&guard, entries));
    puts("Fractal GPT guard: both copies, exact GUID/span, CRC, overlap and I/O bounds passed");
    return 0;
}
