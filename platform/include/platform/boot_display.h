/* Native boot-display contracts. Renderer clients never receive device frames. */
#ifndef AOS_BOOT_DISPLAY_H
#define AOS_BOOT_DISPLAY_H
#include <stddef.h>
#include <stdint.h>
#define AOS_BOOT_FB_VA UINT64_C(0x40000000)
#define AOS_BOOT_FB_META_VA UINT64_C(0x2f200000)
#define AOS_BOOT_PROGRESS_VA UINT64_C(0x2f000000)
#define AOS_BOOT_FB_MAX_BYTES (64u * 1024u * 1024u)
#define AOS_BOOT_FB_MAGIC 0x42464231u
typedef struct {
    uint32_t magic, version;
    uint64_t physical, bytes;
    uint32_t width, height, pitch, reserved;
} aos_boot_fb_t;
/* seL4 extra BootInfo uses two 64-bit header words, then the 22-byte
 * multiboot2 framebuffer payload. Pixel channel masks are not retained by
 * seL4: the display contract therefore uses grayscale, equal byte channels. */
int aos_boot_fb_parse(const uint8_t *extra, size_t bytes, aos_boot_fb_t *out);
int aos_boot_fb_valid(const aos_boot_fb_t *);
int aos_boot_fb_present(const aos_boot_fb_t *, volatile uint32_t *fb,
                        const uint32_t *pixels, uint32_t width, uint32_t height);

enum aos_boot_stage {
    AOS_BOOT_STARTING=1, AOS_BOOT_BLOCK_READY, AOS_BOOT_LOADING,
    AOS_BOOT_BACKBONE, AOS_BOOT_ROUTING, AOS_BOOT_JOINT, AOS_BOOT_CHECKING,
    AOS_BOOT_READY, AOS_BOOT_FAILED, AOS_BOOT_STORAGE, AOS_BOOT_STORAGE_READY
};
/* Single writer: native probe. Read-only mapping: external renderer.
 * Atomics and odd/even sequence protect snapshots across scheduling points.
 * Zero means no observation. A reader must bound retries and keep its prior
 * snapshot on an in-progress write. Values are advisory and confer no caps. */
typedef struct {
    uint32_t sequence, version, stage, reserved;
    uint64_t completed, total;
} aos_boot_progress_t;
_Static_assert(sizeof(aos_boot_progress_t)==32, "boot progress ABI");
static inline void aos_boot_progress_publish(uint32_t stage, uint64_t done, uint64_t total)
{
    aos_boot_progress_t *p=(void *)AOS_BOOT_PROGRESS_VA;
    uint32_t seq=__atomic_load_n(&p->sequence,__ATOMIC_RELAXED);
    __atomic_store_n(&p->sequence,seq+1u,__ATOMIC_SEQ_CST);
    __atomic_store_n(&p->version,1u,__ATOMIC_RELAXED);
    __atomic_store_n(&p->stage,stage,__ATOMIC_RELAXED);
    __atomic_store_n(&p->completed,done,__ATOMIC_RELAXED);
    __atomic_store_n(&p->total,total,__ATOMIC_RELAXED);
    __atomic_store_n(&p->sequence,seq+2u,__ATOMIC_RELEASE);
}
static inline int aos_boot_progress_read(const aos_boot_progress_t *p, aos_boot_progress_t *out)
{
    uint32_t seq=__atomic_load_n(&p->sequence,__ATOMIC_ACQUIRE);
    if (!seq || (seq&1u)) return 0;
    aos_boot_progress_t v={.sequence=seq};
    v.version=__atomic_load_n(&p->version,__ATOMIC_RELAXED);
    v.stage=__atomic_load_n(&p->stage,__ATOMIC_RELAXED);
    v.completed=__atomic_load_n(&p->completed,__ATOMIC_RELAXED);
    v.total=__atomic_load_n(&p->total,__ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (seq!=__atomic_load_n(&p->sequence,__ATOMIC_ACQUIRE)) return 0;
    if (v.version!=1 || v.stage<AOS_BOOT_STARTING || v.stage>AOS_BOOT_STORAGE_READY ||
        !v.total || v.completed>v.total) return -1;
    *out=v;
    return 1;
}
#endif
