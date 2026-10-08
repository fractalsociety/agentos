/*
 * system_desc_x86_64.c - reduced smoke and opt-in VMX qualification topologies.
 *
 * The normal x86_64_generic board intentionally starts no PDs.  The separate
 * x86_64_generic_vtx board starts exactly one VMM PD for a one-instruction,
 * EPT-backed HLT-exit proof. The firmware composition starts the COM2 serial
 * driver and serial_virt, plus block and network drivers and virtualizers.
 * Host register/DMA mappings belong to drivers; the VMM maps its queue pages.
 * The Fractal native-only build keeps seven native service/client PDs, or
 * eight with the isolated NVMe probe. The separate offline NVMe composition
 * has one PD. Neither starts guest execution runners.
 */

#include "system_desc.h"
#include "contracts/guest_ram_caps.h"
#include "contracts/x86_vtx_proof.h"
#ifdef AGENTOS_BOOT_DISPLAY
#define BOOT_DISPLAY_PDS \
    {.name="boot_display",.elf_path="boot_display.elf",.stack_size=0x8000u, \
     .cnode_size_bits=10u,.priority=250u,.self_svc_id=SVC_ID_BOOT_DISPLAY}, \
    {.name="boot_screen",.elf_path="boot_screen.elf",.stack_size=0x8000u, \
     .cnode_size_bits=10u,.priority=249u,.self_svc_id=SVC_ID_BOOT_SCREEN},
#else
#define BOOT_DISPLAY_PDS
#endif

#if defined(AGENTOS_FRACTAL_NVME_ONLY)
const system_desc_t system_desc_x86_64 = {
    .pd_count = 1u
#ifdef AGENTOS_BOOT_DISPLAY
        +2u
#endif
        ,
    .pds = {BOOT_DISPLAY_PDS {
        .name = "fractal_nvme_probe",
        .elf_path = "fractal_nvme_probe.elf",
        .stack_size = 0x4000u,
        .cnode_size_bits = 10u,
        .priority = 254u,
        .self_svc_id = SVC_ID_FRACTAL_NVME_PROBE,
    }},
};
#elif defined(AGENTOS_X86_VTX)
const system_desc_t system_desc_x86_64 = {
#ifdef AGENTOS_X86_FIRMWARE_RESET
    .pd_count = 9u
#ifdef AGENTOS_BOOT_DISPLAY
        +2u
#endif
#ifdef AGENTOS_FRACTAL_NATIVE_ONLY
        - 3u
#endif
#ifdef AGENTOS_FRACTAL_NATIVE_PROBE
        + 1u
#endif
#ifdef AGENTOS_FRACTAL_NVME_PROBE
        + 1u
#endif
#ifdef AGENTOS_X86_DUAL_GUEST
        + 3u
#endif
#ifdef AGENTOS_X86_USERSPACE_PROOF
        + 1u
#endif
#ifdef AGENTOS_X86_MANAGED_START
        + 1u
#endif
        ,
#else
    .pd_count = 1u,
#endif
    .pds = {
        BOOT_DISPLAY_PDS
#ifdef AGENTOS_X86_FIRMWARE_RESET
        {
            .name = "net_pd",
            .elf_path = "net_pd.elf",
            .stack_size = 0x8000u,
            .cnode_size_bits = 10u,
            .priority = 215u,
            .self_svc_id = SVC_ID_NET_PD,
            .init_ep_count = 1u,
            .init_eps = {{ SVC_ID_NET_VIRT, PD_CNODE_SLOT_NET_VIRT_EP }},
        },
        {
            .name = "net_virt",
            .elf_path = "net_virt.elf",
            .stack_size = 0x8000u,
            .cnode_size_bits = 10u,
            .priority = 205u,
            .self_svc_id = SVC_ID_NET_VIRT,
            .init_ep_count = 1u,
            .init_eps = {{ SVC_ID_NET_PD, PD_CNODE_SLOT_NET_PD_EP }},
        },
        {
            .name = "virtio_blk",
            .elf_path = "virtio_blk.elf",
            .stack_size = 0x4000u,
            .cnode_size_bits = 10u,
#ifdef AGENTOS_FRACTAL_NATIVE_PROBE
            .priority = 253u,
#else
            .priority = 215u,
#endif
            .self_svc_id = SVC_ID_VIRTIO_BLK,
        },
        {
            .name = "blk_virt",
            .elf_path = "blk_virt.elf",
            .stack_size = 0x8000u,
            .cnode_size_bits = 10u,
#ifdef AGENTOS_FRACTAL_NATIVE_PROBE
            .priority = 252u,
#else
            .priority = 210u,
#endif
            .self_svc_id = SVC_ID_BLK_VIRT,
            .init_ep_count = 1u,
            .init_eps = {{ SVC_ID_VIRTIO_BLK, PD_CNODE_SLOT_VIRTIO_BLK_EP }},
        },
#ifdef AGENTOS_FRACTAL_NATIVE_PROBE
        {
            .name = "fractal_native_probe",
            .elf_path = "fractal_native_probe.elf",
#ifdef AGENTOS_FRACTAL_CLEF_TEST
            .stack_size = 0x20000u,
            .mr_count = 3u,
            .memory_regions = {
                {.vaddr=UINT64_C(0x200000000), .size=0xc0000000u, .writable=1u, .name="clef_model_0"},
                {.vaddr=UINT64_C(0x2c0000000), .size=0xc0000000u, .writable=1u, .name="clef_model_1"},
                {.vaddr=UINT64_C(0x380000000), .size=0x80000000u, .writable=1u, .name="clef_work"},
            },
#else
            .stack_size = 0x4000u,
#endif
            .cnode_size_bits = 10u,
            .priority = 251u,
            .self_svc_id = SVC_ID_FRACTAL_NATIVE_PROBE,
            .init_ep_count = 1u,
            .init_eps = {{ SVC_ID_BLK_VIRT, PD_CNODE_SLOT_BLK_VIRT_EP }},
        },
#endif
#ifdef AGENTOS_FRACTAL_NVME_PROBE
        {
            .name = "fractal_nvme_probe",
            .elf_path = "fractal_nvme_probe.elf",
            .stack_size = 0x4000u,
            .cnode_size_bits = 10u,
            .priority = 254u,
            .self_svc_id = SVC_ID_FRACTAL_NVME_PROBE,
        },
#endif
#ifndef AGENTOS_X86_CC_PCI
        {
            .name = "serial_pd",
            .elf_path = "serial_pd.elf",
            .stack_size = 0x8000u,
            .cnode_size_bits = 10u,
            .priority = 180u,
            .self_svc_id = SVC_ID_SERIAL,
            .init_ep_count = 1u,
            .init_eps = {{ SVC_ID_SERIAL_VIRT, PD_CNODE_SLOT_SERIAL_VIRT_EP }},
        },
#endif
        {
            .name = "serial_virt",
            .elf_path = "serial_virt.elf",
            .stack_size = 0x8000u,
            .cnode_size_bits = 10u,
            .priority = 203u,
            .self_svc_id = SVC_ID_SERIAL_VIRT,
        },
#ifndef AGENTOS_FRACTAL_NATIVE_ONLY
        {
            .name = "x86_runner",
            .elf_path = "x86_runner.elf",
            .stack_size = 0x8000u,
            .cnode_size_bits = 10u,
            .priority = 250u,
            .self_svc_id = SVC_ID_X86_RUNNER,
        },
        {
            .name = "x86_runner_ap",
            .elf_path = "x86_runner_ap.elf",
            .stack_size = 0x8000u,
            .cnode_size_bits = 10u,
            .priority = 250u,
            .self_svc_id = SVC_ID_X86_AP_RUNNER,
        },
#endif
#endif
#ifndef AGENTOS_FRACTAL_NATIVE_ONLY
        {
            .name = "guest_vmm_primary",
            .elf_path = "guest_vmm_primary.elf",
            .stack_size = 0x10000u,
#ifdef AGENTOS_X86_FIRMWARE_RESET
            /* Private RAM/ROM pool grants and future frame/alias ranges. */
            .cnode_size_bits = AOS_GUEST_RAM_CNODE_BITS,
#else
            .cnode_size_bits = 10u,
#endif
            .priority = 250u,
            .self_svc_id = SVC_ID_GUEST_VMM_PRIMARY,
#ifdef AGENTOS_X86_FIRMWARE_RESET
#ifdef AGENTOS_X86_USERSPACE_PROOF
            .init_ep_count = 4u,
#else
            .init_ep_count = 3u,
#endif
            .init_eps = {
                { SVC_ID_SERIAL_VIRT, PD_CNODE_SLOT_SERIAL_VIRT_EP },
                { SVC_ID_BLK_VIRT, PD_CNODE_SLOT_BLK_VIRT_EP },
                { SVC_ID_NET_VIRT, PD_CNODE_SLOT_NET_VIRT_EP },
#ifdef AGENTOS_X86_USERSPACE_PROOF
                { SVC_ID_X86_LIFECYCLE_PROBE, AOS_X86_LIFECYCLE_PROBE_CAP },
#endif
            },
#else
            .init_ep_count = 0u,
#endif
            .irq_count = 0u,
            .device_frame_count = 0u,
            .mr_count = 0u,
        },
#endif
#ifdef AGENTOS_X86_USERSPACE_PROOF
        {
            .name = "x86_lifecycle_probe",
            .elf_path = "x86_lifecycle_probe.elf",
            .stack_size = 0x4000u,
            .cnode_size_bits = 10u,
            .priority = 251u,
            .self_svc_id = SVC_ID_X86_LIFECYCLE_PROBE,
            .init_ep_count = 2u,
            .init_eps = {
                { SVC_ID_GUEST_VMM_PRIMARY, PD_CNODE_SLOT_GUEST_VMM_PRIMARY_EP },
                { SVC_ID_VM_MANAGER, PD_CNODE_SLOT_VM_MANAGER_EP },
            },
        },
#endif
#ifdef AGENTOS_X86_MANAGED_START
#ifdef AGENTOS_X86_DUAL_GUEST
        {
            .name = "x86_secondary_runner",
            .elf_path = "x86_secondary_runner.elf",
            .stack_size = 0x8000u,
            .cnode_size_bits = 10u,
            .priority = 250u,
            .self_svc_id = SVC_ID_X86_SECONDARY_RUNNER,
        },
        {
            .name = "x86_secondary_runner_ap",
            .elf_path = "x86_secondary_runner_ap.elf",
            .stack_size = 0x8000u,
            .cnode_size_bits = 10u,
            .priority = 250u,
            .self_svc_id = SVC_ID_X86_SECONDARY_AP_RUNNER,
        },
        {
            .name = "guest_vmm_secondary",
            .elf_path = "guest_vmm_secondary.elf",
            .stack_size = 0x10000u,
            .cnode_size_bits = AOS_GUEST_RAM_CNODE_BITS,
            .priority = 250u,
            .self_svc_id = SVC_ID_GUEST_VMM_SECONDARY,
            .init_ep_count = 3u,
            .init_eps = {
                { SVC_ID_SERIAL_VIRT, PD_CNODE_SLOT_SERIAL_VIRT_EP },
                { SVC_ID_BLK_VIRT, PD_CNODE_SLOT_BLK_VIRT_EP },
                { SVC_ID_NET_VIRT, PD_CNODE_SLOT_NET_VIRT_EP },
            },
        },
#endif
        {
            .name = "vm_manager",
            .elf_path = "vm_manager.elf",
            .stack_size = 0x8000u,
            .cnode_size_bits = 10u,
            .priority = 220u,
            .self_svc_id = SVC_ID_VM_MANAGER,
#ifdef AGENTOS_X86_DUAL_GUEST
            .init_ep_count = 2u,
            .init_eps = {
                { SVC_ID_GUEST_VMM_PRIMARY, PD_CNODE_SLOT_GUEST_VMM_PRIMARY_EP },
                { SVC_ID_GUEST_VMM_SECONDARY, PD_CNODE_SLOT_GUEST_VMM_SECONDARY_EP },
            },
#else
            .init_ep_count = 1u,
            .init_eps = {{ SVC_ID_GUEST_VMM_PRIMARY, PD_CNODE_SLOT_GUEST_VMM_PRIMARY_EP }},
#endif
        },
#endif
#ifdef AGENTOS_X86_CC_PCI
        /* Replaces serial_pd in this composition, so the count is unchanged.
         * The PCI transport and guest-console frontend have one owner. */
        {
            .name = "cc_pd",
            .elf_path = "cc_pd.elf",
            .stack_size = 0x8000u,
            .cnode_size_bits = 10u,
            .priority = 200u,
            .self_svc_id = SVC_ID_CC_PD,
            .init_ep_count = 2u,
            .init_eps = {
                { SVC_ID_VM_MANAGER, PD_CNODE_SLOT_VM_MANAGER_EP },
                { SVC_ID_SERIAL_VIRT, PD_CNODE_SLOT_SERIAL_VIRT_EP },
            },
        },
#endif
    },
};
#else
const system_desc_t system_desc_x86_64 = {
    .pd_count = 0u,
    .pds = {},
};
#endif
