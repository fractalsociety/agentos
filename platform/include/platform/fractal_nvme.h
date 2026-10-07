/* Isolated, polling NVMe qualification layout. No writes to namespace media. */
#ifndef AOS_PLATFORM_FRACTAL_NVME_H
#define AOS_PLATFORM_FRACTAL_NVME_H
#include <stdint.h>

#define FRACTAL_NVME_MMIO_VA 0x06010000UL
#define FRACTAL_NVME_MMIO_PAGES 4u
#define FRACTAL_NVME_DMA_VA 0x2a000000UL
#define FRACTAL_NVME_DMA_BYTES 0x200000u
#define FRACTAL_NVME_DMA_PAGES (FRACTAL_NVME_DMA_BYTES / 4096u)
#define FRACTAL_NVME_DMA_IOVA UINT64_C(0x20000000)
#define FRACTAL_NVME_META_MAGIC UINT32_C(0x4e564d46) /* FMVN */

typedef struct {
    uint32_t magic;
    uint32_t version; /* 1: physical DMA; 2: device-private IOMMU address */
    uint64_t dma_paddr; /* Device-visible base; an IOVA in version 2. */
    uint64_t dma_bytes;
} fractal_nvme_meta_t;

#endif
