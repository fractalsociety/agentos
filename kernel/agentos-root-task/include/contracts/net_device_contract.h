/*
 * net_device_contract.h — native VirtIO-net DMA contract
 *
 * net_pd is the sole owner of the writable VirtIO MMIO page and IRQ.  The
 * root task gives it this immutable startup record plus a shared, physically
 * contiguous arena.  net_server can see packet storage and ownership metadata
 * but never receives either the MMIO frame or the arena physical address.
 */
#pragma once

#include <stdint.h>

#define NET_DMA_STARTUP_VA          0x1000D000UL
#define NET_DMA_STARTUP_MAGIC       0x4E445041u /* "NDPA" */
#define NET_DMA_STARTUP_VERSION     1u
#define NET_DMA_ARENA_VA            0x30000000UL
#define NET_DMA_ARENA_BYTES         0x200000u

#define NET_DMA_QUEUE_DEPTH         64u
#define NET_DMA_BUFFER_STRIDE       2048u
#define NET_DMA_VIRTIO_HDR_BYTES    10u
#define NET_DMA_MAX_FRAME_BYTES     1514u

/* The first 256 KiB remains the public per-client packet arena. */
#define NET_DMA_CLIENT_BYTES        0x40000u
#define NET_DMA_FASTPATH_OFFSET     0x40000u
#define NET_DMA_RX_DESC_OFFSET      0x42000u
#define NET_DMA_RX_AVAIL_OFFSET     0x43000u
#define NET_DMA_RX_USED_OFFSET      0x44000u
#define NET_DMA_TX_DESC_OFFSET      0x45000u
#define NET_DMA_TX_AVAIL_OFFSET     0x46000u
#define NET_DMA_TX_USED_OFFSET      0x47000u
#define NET_DMA_RX_BUFFER_OFFSET    0x50000u
#define NET_DMA_TX_BUFFER_OFFSET    0x70000u
#define NET_DMA_LAYOUT_END          0x90000u

/* Low badge bits minted by the root task. Only NetServer receives this bit;
 * a tailnet identity or ordinary NetCap cannot invoke driver-internal DMA. */
#define NET_PD_RIGHT_FASTPATH       (1u << 0)

typedef struct __attribute__((packed)) {
    uint32_t packet_offset;
    uint32_t packet_len;
} net_fastpath_send_req_t;

typedef struct __attribute__((packed)) {
    uint32_t queued;
    uint32_t queue_id;
} net_fastpath_send_reply_t;

typedef struct __attribute__((packed)) {
    uint32_t link_up;
    uint32_t queue_depth;
    uint32_t tx_in_flight;
    uint32_t irq_count;
} net_fastpath_status_reply_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint64_t dma_base_pa;
    uint32_t dma_bytes;
    uint32_t reserved;
} net_dma_startup_t;

typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} net_dma_desc_t;

typedef struct __attribute__((packed)) {
    uint32_t id;
    uint32_t len;
} net_dma_used_elem_t;

typedef struct __attribute__((packed)) {
    uint8_t flags;
    uint8_t gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
} net_dma_virtio_hdr_t;

_Static_assert(sizeof(net_dma_startup_t) == 24u, "net DMA startup ABI");
_Static_assert(sizeof(net_dma_desc_t) == 16u, "VirtIO descriptor ABI");
_Static_assert(sizeof(net_dma_used_elem_t) == 8u, "VirtIO used element ABI");
_Static_assert(sizeof(net_dma_virtio_hdr_t) == NET_DMA_VIRTIO_HDR_BYTES,
               "VirtIO-net header ABI");
_Static_assert(NET_DMA_LAYOUT_END <= NET_DMA_ARENA_BYTES,
               "DMA layout must fit shared arena");
