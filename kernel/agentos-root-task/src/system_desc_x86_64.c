/*
 * system_desc_x86_64.c - reduced QEMU x86_64 smoke topology.
 *
 * x86_64 currently validates the seL4 root-task boot path only. The service
 * PD topology is AArch64-oriented and requires board-specific endpoint/MMIO
 * work before it can run safely on q35, so this descriptor intentionally starts
 * no PDs. The x86 acceptance gate is therefore: root task boots, no PD fault
 * reports are emitted, and the reduced scope is documented.
 */

#include "system_desc.h"

const system_desc_t system_desc_x86_64 = {
    .pd_count = 0u,
    .pds = {},
};
