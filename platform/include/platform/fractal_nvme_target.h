/* Explicit PCI identity for the one authorized NVMe controller. */
#ifndef AOS_PLATFORM_FRACTAL_NVME_TARGET_H
#define AOS_PLATFORM_FRACTAL_NVME_TARGET_H

#include <stdbool.h>
#include <stdint.h>

#define FRACTAL_NVME_TARGET_QEMU_SLOT9 0u
#define FRACTAL_NVME_TARGET_QEMU_BUS81 1u
#define FRACTAL_NVME_TARGET_SAMSUNG_BUS81 2u

static inline bool fractal_nvme_target_config(unsigned target,
                                              uint32_t *selector,
                                              uint32_t *identity)
{
    if (!selector || !identity) return false;
    *selector = 0u;
    *identity = 0u;
    switch (target) {
    case FRACTAL_NVME_TARGET_QEMU_SLOT9:
        *selector = UINT32_C(0x80004800); /* 00:09.0 */
        *identity = UINT32_C(0x00101b36); /* QEMU NVMe */
        return true;
    case FRACTAL_NVME_TARGET_QEMU_BUS81:
        *selector = UINT32_C(0x80810000); /* 81:00.0 */
        *identity = UINT32_C(0x00101b36);
        return true;
    case FRACTAL_NVME_TARGET_SAMSUNG_BUS81:
        *selector = UINT32_C(0x80810000); /* 81:00.0 */
        *identity = UINT32_C(0xa80d144d); /* PM9C1a */
        return true;
    default:
        return false;
    }
}

#endif
