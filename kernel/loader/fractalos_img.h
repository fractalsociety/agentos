/*
 * fractalos_img.h — FractalOS flat-binary image format (C mirror of xtask structs)
 *
 * This header describes the on-disk format of fractalos.img as produced by
 * `xtask gen-image`.  The loader reads this format from the blob QEMU maps
 * at IMAGE_DATA_ADDR (0x48000000).
 *
 * Wire layout (little-endian throughout):
 *
 *   [0..64)                 fractalos_img_hdr_t (64 bytes)
 *   [64..64+N*64)           fractalos_pd_entry_t table, N = num_pds
 *   [kernel_off..)          seL4 kernel ELF
 *   [root_off..)            root_task ELF
 *   [pd_elf_off[0]..)       PD ELF #0
 *   ...
 *
 * Copyright (c) 2026 The FractalOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stdint.h>

/* Magic: ASCII "FRACTALOS\0" as little-endian uint64 */
#define FRACTALOS_IMAGE_MAGIC  UINT64_C(0x4652414354414C4F)

#define FRACTALOS_IMAGE_VERSION  1u

/*
 * fractalos_img_hdr_t — 64-byte image header.
 *
 * All offset fields are byte offsets from the start of the image blob.
 */
typedef struct {
    uint64_t magic;         /* FRACTALOS_IMAGE_MAGIC                    [0..8)   */
    uint32_t version;       /* FRACTALOS_IMAGE_VERSION (= 1)            [8..12)  */
    uint32_t num_pds;       /* number of PD entries in the table      [12..16) */
    uint32_t kernel_off;    /* byte offset of kernel ELF              [16..20) */
    uint32_t kernel_len;    /* byte length of kernel ELF              [20..24) */
    uint32_t root_off;      /* byte offset of root task ELF           [24..28) */
    uint32_t root_len;      /* byte length of root task ELF           [28..32) */
    uint32_t pd_table_off;  /* byte offset of PD entry table          [32..36) */
    uint8_t  _pad[28];      /* reserved, must be zero                 [36..64) */
} __attribute__((packed)) fractalos_img_hdr_t;

/*
 * fractalos_pd_entry_t — 64-byte entry describing one Protection Domain ELF.
 */
typedef struct {
    char     name[48];   /* NUL-terminated PD name (e.g. "controller")  [0..48)  */
    uint32_t elf_off;    /* byte offset of ELF from start of image       [48..52) */
    uint32_t elf_len;    /* byte length of ELF image                     [52..56) */
    uint8_t  priority;   /* PD scheduling priority (0 = lowest)          [56]     */
    uint8_t  _pad[7];    /* reserved, must be zero                       [57..64) */
} __attribute__((packed)) fractalos_pd_entry_t;
