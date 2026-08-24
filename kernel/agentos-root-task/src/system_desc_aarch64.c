/*
 * system_desc_aarch64.c — compile-time system topology for AArch64 / QEMU virt
 *
 * Defines the system_desc_aarch64 constant used by the root task boot sequence
 * on AArch64 targets (qemu_virt_aarch64, ZCU102, RPi5, etc.).
 *
 * PD ordering is critical: the nameserver MUST be first so that subsequent
 * PDs can register themselves with it before any inter-PD communication.
 *
 * ── Priority DAG ──────────────────────────────────────────────────────────────
 *
 * Priorities follow the dependency DAG: a service that is called by others
 * (a "provider") runs at HIGHER priority than the services that call it (the
 * "clients").  This prevents priority inversion on blocking IPC calls and
 * ensures providers can respond quickly even when high-priority clients block
 * waiting for them.
 *
 * DAG level → priority range:
 *
 *   255  fault_handler      — fault delivery must preempt everything
 *   250  linux_vmm          — VM-exit latency is latency-critical
 *   245  nameserver         — foundation: every PD does cap lookup at boot/runtime
 *   235  log_drain          — nearly every PD logs; must respond before callers time-out
 *   225  serial_pd          — UART hardware driver; log_drain and others may call it
 *   215  virtio_blk         — block device driver; agentfs/vfs_server depend on it
 *   205  net_server         — TCP/IP stack; vfs_server calls it for network FS
 *   195  event_bus          — pub/sub backbone; init_agent and controller subscribe
 *   185  vfs_server         — VFS multiplexer; controller and init_agent use it
 *   175  agentfs            — content store; controller and vibe_engine use it
 *   165  vibe_engine        — WASM hot-swap engine; called by controller
 *   160  cc_pd              — CC relay; passive, woken by PPC from callers
 *   155  vm_manager         — VM lifecycle; called by controller
 *   110  init_agent         — agent-ecosystem bootstrapper; calls most services
 *    50  controller         — policy coordinator; calls everything above it
 *
 * Copyright (c) 2026 The agentOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "system_desc.h"
#include "cap_authority.h"
#include "contracts/net_device_contract.h"
#include "net_server.h"
#include "../../../contracts/execsvc/interface.h"
#include "../../../contracts/toolsvc/interface.h"

/* agentos-8f5: a target contract-runner PD is appended only in test images. */
#ifdef AGENTOS_SEL4_TEST_IMAGE
#define AOS_TEST_PD_EXTRA 1u
#else
#define AOS_TEST_PD_EXTRA 0u
#endif

/* CC init-ep counts include the agentos-7j5 controller endpoint (+1). */
#if defined(AGENTOS_FAULT_INJECT) && defined(AGENTOS_GUEST_BOTH)
#define AOS_AARCH64_PD_COUNT (29u + AOS_TEST_PD_EXTRA)
#define AOS_CC_INIT_EP_COUNT 7u
#elif defined(AGENTOS_FAULT_INJECT)
#define AOS_AARCH64_PD_COUNT (28u + AOS_TEST_PD_EXTRA)
#define AOS_CC_INIT_EP_COUNT 7u
#elif defined(AGENTOS_GUEST_BOTH)
#define AOS_AARCH64_PD_COUNT (28u + AOS_TEST_PD_EXTRA)
#define AOS_CC_INIT_EP_COUNT 6u
#else
#define AOS_AARCH64_PD_COUNT (27u + AOS_TEST_PD_EXTRA)
#define AOS_CC_INIT_EP_COUNT 6u
#endif

#if defined(AGENTOS_GUEST_BOTH)
#define AOS_VM_MANAGER_INIT_EP_COUNT 4u
#elif defined(AGENTOS_GUEST_LINUX) || defined(AGENTOS_GUEST_FREEBSD)
#define AOS_VM_MANAGER_INIT_EP_COUNT 3u
#else
#define AOS_VM_MANAGER_INIT_EP_COUNT 2u
#endif

/* ── AArch64 system description ───────────────────────────────────────────── */

const system_desc_t system_desc_aarch64 = {
    .pd_count = AOS_AARCH64_PD_COUNT,
    .pds = {

        /* pd[0] — nameserver (MUST be first; prio 245)
         * Foundation service: every PD resolves endpoint caps through it.
         * Runs above all drivers and servers so that boot-time registration
         * and runtime lookups complete without blocking the calling PD. */
        {
            .name           = "nameserver",
            .elf_path       = "nameserver.elf",
            .stack_size     = 0x4000u,   /* 16 KB */
            .cnode_size_bits = 10u,       /* 1024 slots */
            .priority       = 245u,
            .self_svc_id    = SVC_ID_NAMESERVER,
            .init_ep_count  = 0u,
            .init_eps       = {},
        },

        /* pd[1] — log_drain (prio 235; just below nameserver)
         * Nearly every PD makes blocking log IPC calls.  Running above all
         * hardware drivers and application servers prevents priority inversion
         * where a caller blocks on a log call while the log server is starved. */
        {
            .name           = "log_drain",
            .elf_path       = "log_drain.elf",
            .stack_size     = 0x4000u,
            .cnode_size_bits = 10u,
            .priority       = 235u,
            .self_svc_id    = SVC_ID_LOG_DRAIN,
            .init_ep_count  = 1u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
            },
        },

        /* pd[2] — serial_pd (prio 225; UART hardware driver)
         * Provides low-latency serial I/O.  Runs above net/storage servers
         * that may call it for console output, but below log_drain which
         * drives it. */
        {
            .name           = "serial_pd",
            .elf_path       = "serial_pd.elf",
            .stack_size     = 0x4000u,
            .cnode_size_bits = 10u,
            .priority       = 225u,
            .self_svc_id    = SVC_ID_SERIAL,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
        },

        /* pd[3] — event_bus (prio 195; pub/sub backbone)
         * Receives events from and dispatches to init_agent and controller.
         * Sits above those consumers so event delivery is not starved. */
        {
            .name           = "event_bus",
            .elf_path       = "event_bus.elf",
            .stack_size     = 0x4000u,
            .cnode_size_bits = 10u,
            .priority       = 195u,
            .self_svc_id    = SVC_ID_EVENTBUS,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
        },

        /* pd[4] — controller (prio 50; policy coordinator)
         * Calls every service above it.  Lowest-priority PD so that any
         * service it is waiting for can preempt and respond. */
        {
            .name           = "controller",
            .elf_path       = "controller.elf",
            .stack_size     = 0x10000u,  /* 64 KB — larger stack for policy work */
            .cnode_size_bits = 10u,
            .priority       = 50u,
            /* agentos-7j5: expose the controller's inbound server endpoint so
             * peer PDs (cc_pd) can relay MSG_AGENTPOOL_STATUS to it.  The root
             * task mints this EP at PD_CNODE_SLOT_SELF_EP and passes it as the
             * controller's my_ep (arg0), which sel4_server_run() listens on. */
            .self_svc_id    = SVC_ID_CONTROLLER,
            .init_ep_count  = 5u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_EVENTBUS,   PD_CNODE_SLOT_EVENTBUS_EP   },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
                { SVC_ID_MODELSVC,   PD_CNODE_SLOT_MODELSVC_EP   },
                { SVC_ID_AGENT_HARNESS, PD_CNODE_SLOT_AGENT_HARNESS_EP },
            },
        },

        /* pd[5] — init_agent (prio 110; agent-ecosystem bootstrapper)
         * Calls nameserver, event_bus, and log_drain.  Runs above controller
         * since controller may delegate spawn operations through it, but below
         * all the services it calls. */
        {
            .name           = "init_agent",
            .elf_path       = "init_agent.elf",
            .stack_size     = 0x8000u,
            .cnode_size_bits = 10u,
            .priority       = 110u,
            .self_svc_id    = SVC_ID_INIT_AGENT,
            .init_ep_count  = 5u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_EVENTBUS,   PD_CNODE_SLOT_EVENTBUS_EP   },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
                { SVC_ID_MODELSVC,   PD_CNODE_SLOT_MODELSVC_EP   },
                { SVC_ID_CONTROLLER, PD_CNODE_SLOT_CONTROLLER_EP,
                  CONTROLLER_RIGHT_CAP_ADMIN },
            },
        },

        /* pd[6] — agentfs (prio 175; content-addressed object store)
         * Called by controller and vibe_engine.  Runs above both callers;
         * depends on virtio_blk (215) for persistence so virtio_blk can
         * preempt agentfs I/O requests. */
        {
            .name           = "agentfs",
            .elf_path       = "agentfs.elf",
            .stack_size     = 0x8000u,
            .cnode_size_bits = 10u,
            .priority       = 175u,
            .self_svc_id    = SVC_ID_AGENTFS,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
        },

        /* pd[7] — vibe_engine (prio 165; WASM hot-swap lifecycle)
         * Called by controller for WASM component validation and install.
         * Calls agentfs (175) for object retrieval, which can preempt it. */
        {
            .name           = "vibe_engine",
            .elf_path       = "vibe_engine.elf",
            .stack_size     = 0x8000u,
            .cnode_size_bits = 10u,
            .priority       = 165u,
            .self_svc_id    = SVC_ID_VIBE_ENGINE,
            .init_ep_count  = 3u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
                { SVC_ID_VM_MANAGER, PD_CNODE_SLOT_VM_MANAGER_EP },
            },
        },

        /* pd[8] — vfs_server (prio 185; virtual filesystem multiplexer)
         * Called by controller and init_agent.  Depends on virtio_blk (215)
         * and net_server (205) for backing storage, both of which run above it. */
        {
            .name           = "vfs_server",
            .elf_path       = "vfs_server.elf",
            .stack_size     = 0x8000u,
            .cnode_size_bits = 10u,
            .priority       = 185u,
            .self_svc_id    = SVC_ID_VFS_SERVER,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
        },

        /* pd[9] — net_server (prio 205; lwIP-based network stack)
         * Called by vfs_server for network filesystems and by controller.
         * Runs above both callers; depends on virtio_blk (215) indirectly
         * via the network device (virtio-net). */
        {
            .name           = "net_server",
            .elf_path       = "net_server.elf",
            .stack_size     = 0x8000u,
            .cnode_size_bits = 10u,
            .priority       = 205u,
            .self_svc_id    = SVC_ID_NET_SERVER,
            .init_ep_count  = 4u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
                { SVC_ID_NET_PD,     PD_CNODE_SLOT_NET_PD_EP,
                  NET_PD_RIGHT_FASTPATH },
                { SVC_ID_MODEL_TRANSPORT, PD_CNODE_SLOT_MODEL_TRANSPORT_EP },
            },
        },

        /* Native inference infrastructure. NetServer owns network hardware
         * and runs above this proxy, while agents only receive ModelSvc. */
        {
            .name           = "model_svc",
            .elf_path       = "model_svc.elf",
            .stack_size     = 0x10000u,
            .cnode_size_bits = 10u,
            .priority       = 190u,
            .self_svc_id    = SVC_ID_MODELSVC,
            .init_ep_count  = 3u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
                { SVC_ID_NET_SERVER, PD_CNODE_SLOT_NET_SERVER_EP,
                  NET_SERVER_RIGHT_MODEL_HTTP },
            },
        },

        /* Native Codex-style harness. ModelSvc, ToolSvc, AgentFS, and
         * ExecServer are distinct effect capabilities; NetServer is absent. */
        {
            .name           = "codex_harness",
            .elf_path       = "codex_harness.elf",
            .stack_size     = 0x10000u,
            .cnode_size_bits = 8u,
            .priority       = 120u,
            .self_svc_id    = SVC_ID_AGENT_HARNESS,
            .init_ep_count  = 4u,
            .init_eps = {
                { SVC_ID_LOG_DRAIN, PD_CNODE_SLOT_LOG_DRAIN_EP },
                { SVC_ID_MODELSVC,  PD_CNODE_SLOT_MODELSVC_EP  },
                { SVC_ID_AGENTFS,   PD_CNODE_SLOT_AGENTFS_EP   },
                { SVC_ID_EXEC_SERVER, PD_CNODE_SLOT_EXEC_SERVER_EP,
                  EXECSVC_RIGHT_ALL },
            },
        },

        /* Materially smaller AgentHarness assembly: the same control contract
         * with only ModelCap and read-only ToolCap. No AgentFS, ExecServer, or
         * NetServer endpoint means those components receive neither endpoint
         * authority nor a client-arena mapping. Shared services stay singletons. */
        {
            .name           = "read_only_harness",
            .elf_path       = "read_only_harness.elf",
            .stack_size     = 0x8000u,
            .cnode_size_bits = 8u,
            .priority       = 120u,
            .self_svc_id    = SVC_ID_READ_ONLY_HARNESS,
            .init_ep_count  = 3u,
            .init_eps = {
                { SVC_ID_LOG_DRAIN, PD_CNODE_SLOT_LOG_DRAIN_EP },
                { SVC_ID_MODELSVC, PD_CNODE_SLOT_MODELSVC_EP },
                { SVC_ID_TOOLSVC, PD_CNODE_SLOT_TOOLSVC_EP,
                  TOOLSVC_RIGHT_REPO_SEARCH | TOOLSVC_RIGHT_REPO_READ },
            },
        },

        /* Shared MCP-compatible tool registry and dispatch service. */
        {
            .name           = "tool_svc",
            .elf_path       = "tool_svc.elf",
            .stack_size     = 0x4000u,
            .cnode_size_bits = 8u,
            .priority       = 185u,
            .self_svc_id    = SVC_ID_TOOLSVC,
            .init_ep_count  = 3u,
            .init_eps = {
                { SVC_ID_LOG_DRAIN, PD_CNODE_SLOT_LOG_DRAIN_EP },
                { SVC_ID_EXEC_SERVER, PD_CNODE_SLOT_EXEC_SERVER_EP,
                  EXECSVC_RIGHT_AGENTOS_REPOSITORY },
                { SVC_ID_MCP_TRANSPORT, PD_CNODE_SLOT_MCP_TRANSPORT_EP },
            },
        },

        /* Independent verification service. It has no ModelCap, MemoryCap,
         * ToolCap, or NetCap; callers pass bounded snapshots via ExecCap. */
        {
            .name           = "exec_verify",
            .elf_path       = "exec_verify.elf",
            .stack_size     = 0x4000u,
            .cnode_size_bits = 8u,
            .priority       = 185u,
            .self_svc_id    = SVC_ID_EXEC_SERVER,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_LOG_DRAIN, PD_CNODE_SLOT_LOG_DRAIN_EP },
                { SVC_ID_EXEC_TRANSPORT, PD_CNODE_SLOT_EXEC_TRANSPORT_EP },
            },
        },

        /* pd[10] — virtio_blk (prio 215; virtio block device driver)
         * Lowest-level I/O provider; agentfs and vfs_server call it.
         * Runs above all storage consumers so block I/O completions are
         * processed before the callers time out. */
        {
            .name           = "virtio_blk",
            .elf_path       = "virtio_blk.elf",
            .stack_size     = 0x4000u,
            .cnode_size_bits = 10u,
            .priority       = 215u,
            .self_svc_id    = SVC_ID_VIRTIO_BLK,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
        },

        /* pd[11] — block_pd (prio 213; OS-neutral block API)
         * Exposes the block contract to VMMs and native services. */
        {
            .name           = "block_pd",
            .elf_path       = "block_pd.elf",
            .stack_size     = 0x4000u,
            .cnode_size_bits = 10u,
            .priority       = 213u,
            .self_svc_id    = SVC_ID_BLOCK_SERVICE,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
        },

        /* pd[12] — net_pd (prio 207; OS-neutral network API)
         * Starts alongside net_server so guest bindings can target a generic
         * device PD rather than a per-guest driver path. */
        {
            .name           = "net_pd",
            .elf_path       = "net_pd.elf",
            .stack_size     = 0x8000u,
            .cnode_size_bits = 10u,
            .priority       = 207u,
            .self_svc_id    = SVC_ID_NET_PD,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
            .irq_count = 1u,
            .irqs = {
                { .irq_number = 48u, .ntfn_badge = 0x1u, .name = "virtio-net" },
            },
        },

        /* pd[13] — framebuffer_pd (prio 206; OS-neutral framebuffer API) */
        {
            .name           = "framebuffer_pd",
            .elf_path       = "framebuffer_pd.elf",
            .stack_size     = 0x8000u,
            .cnode_size_bits = 10u,
            .priority       = 206u,
            .self_svc_id    = SVC_ID_FB_PD,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
        },

        /* pd[14] — usb_pd (prio 204; OS-neutral USB API) */
        {
            .name           = "usb_pd",
            .elf_path       = "usb_pd.elf",
            .stack_size     = 0x4000u,
            .cnode_size_bits = 10u,
            .priority       = 204u,
            .self_svc_id    = SVC_ID_USB_PD,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
        },

        /* pd[15] — guest VMM (prio 250; VM-exit latency is latency-critical)
         *
         * VM exits must be handled near-immediately to avoid guest stalls.
         * Runs just below fault_handler (255) and above all services.
         *
         * IRQ assignments (QEMU virt AArch64 GIC SPI numbers):
         *   virtio-net INTID 48 is owned exclusively by net_pd.
         *   virtio-blk0: SPI 17 → INTID 49 → irq_number=49, badge 0x2
         *   virtio-blk1: SPI 19 → INTID 51 → irq_number=51, badge 0x4
         *                (used by ubuntu guest for cloud-init seed disk on bus.3)
         */
        {
#if defined(AGENTOS_GUEST_FREEBSD) && !defined(AGENTOS_GUEST_BOTH)
            .name           = "freebsd_vmm",
            .elf_path       = "freebsd_vmm.elf",
            .stack_size     = 0x10000u,
            .cnode_size_bits = 10u,
            .priority       = 250u,
            .self_svc_id    = SVC_ID_FREEBSD_VMM,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
            .irq_count = 1u,
            .irqs = {
                { .irq_number = 79u, .ntfn_badge = 0x2u, .name = "virtio-blk" },
            },
            .mr_count = 1u,
            .memory_regions = {
                { .vaddr    =
                              0x40000000ULL,
                  .size     = 0x20000000u,  /* 512 MB FreeBSD guest RAM */
                  .writable = 1u,
                  .name     = "guest_ram" },
            },
#else
            .name           = "linux_vmm",
            .elf_path       = "linux_vmm.elf",
            .stack_size     = 0x10000u,
            .cnode_size_bits = 10u,  /* 1024 slots — IRQ handler caps + microkit layout */
            .priority       = 250u,
            .self_svc_id    = SVC_ID_LINUX_VMM,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
            .irq_count = 2u,
            .irqs = {
                { .irq_number = 49u, .ntfn_badge = 0x2u, .name = "virtio-blk0" },
                { .irq_number = 51u, .ntfn_badge = 0x4u, .name = "virtio-blk1" },
            },
            /* Codex needs 768 MiB while its large static binary is unpacked;
             * other Linux guests retain the proven 512 MiB allocation. */
            .mr_count = 1u,
            .memory_regions = {
                { .vaddr    =
#if defined(AGENTOS_GUEST_BOTH)
                              0xc0000000ULL,
#elif defined(AGENTOS_GUEST_CODEX)
                              0x80000000ULL,
#else
                              0x40000000ULL,
#endif
#if defined(AGENTOS_GUEST_CODEX)
                  .size     = 0x30000000u,  /* 768 MiB compatibility guest */
#else
                  .size     = 0x20000000u,  /* 512 MiB */
#endif
                  .writable = 1u,
                  .name     = "guest_ram" },
            },
#endif
        },

#if defined(AGENTOS_GUEST_BOTH)
        /* pd[16] — FreeBSD VMM in dual-guest images.
         *
         * FreeBSD remains in the standalone-proven 0x40000000 layout. Linux
         * uses a separate high guest RAM window in dual images.
         */
        {
            .name           = "freebsd_vmm",
            .elf_path       = "freebsd_vmm.elf",
            .stack_size     = 0x10000u,
            .cnode_size_bits = 10u,
            .priority       = 250u,
            .self_svc_id    = SVC_ID_FREEBSD_VMM,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
            .irq_count = 1u,
            .irqs = {
                { .irq_number = 79u, .ntfn_badge = 0x2u, .name = "virtio-blk" },
            },
            .mr_count = 1u,
            .memory_regions = {
                { .vaddr    = 0x40000000ULL,
                  .size     = 0x20000000u,  /* 512 MB FreeBSD guest RAM */
                  .writable = 1u,
                  .name     = "guest_ram" },
            },
        },

#endif

        /* pd[16] — vm_manager (prio 155; multi-VM lifecycle manager)
         * Called by controller to create/destroy/snapshot VMs.  Runs above
         * controller (50) but below all the services it calls. */
        {
            .name           = "vm_manager",
            .elf_path       = "vm_manager.elf",
            .stack_size     = 0x8000u,
            .cnode_size_bits = 10u,
            .priority       = 155u,
            .self_svc_id    = SVC_ID_VM_MANAGER,
            .init_ep_count  = AOS_VM_MANAGER_INIT_EP_COUNT,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
#if defined(AGENTOS_GUEST_LINUX)
                { SVC_ID_LINUX_VMM,  PD_CNODE_SLOT_LINUX_VMM_EP  },
#endif
#if defined(AGENTOS_GUEST_FREEBSD)
                { SVC_ID_FREEBSD_VMM, PD_CNODE_SLOT_FREEBSD_VMM_EP },
#endif
            },
        },

        /* pd[17] — cc_pd (prio 160; command-and-control relay)
         * Pure IPC relay: receives MSG_CC_* from external callers and routes
         * each to the appropriate service PD.  Passive — woken by PPC.
         * Priority 160: above vm_manager (155) and controller (50) callers;
         * below vibe_engine (165) and other providers it calls. */
        {
            .name           = "cc_pd",
            .elf_path       = "cc_pd.elf",
            .stack_size     = 0x4000u,
            .cnode_size_bits = 10u,
            .priority       = 160u,
            .self_svc_id    = SVC_ID_CC_PD,
            .init_ep_count  = AOS_CC_INIT_EP_COUNT,
            .init_eps = {
                { SVC_ID_NAMESERVER,  PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,   PD_CNODE_SLOT_LOG_DRAIN_EP  },
#if defined(AGENTOS_GUEST_FREEBSD) && !defined(AGENTOS_GUEST_BOTH)
                { SVC_ID_FREEBSD_VMM, PD_CNODE_SLOT_GUEST_VMM_EP },
#else
                { SVC_ID_LINUX_VMM,   PD_CNODE_SLOT_GUEST_VMM_EP },
#endif
                { SVC_ID_VIBE_ENGINE, PD_CNODE_SLOT_VIBE_ENGINE_EP },
                { SVC_ID_VM_MANAGER,  PD_CNODE_SLOT_VM_MANAGER_EP  },
                /* agentos-7j5: controller EP for live MSG_AGENTPOOL_STATUS. */
                { SVC_ID_CONTROLLER,  PD_CNODE_SLOT_CONTROLLER_EP,
                  CONTROLLER_RIGHT_AGENT_TASK },
#if defined(AGENTOS_FAULT_INJECT)
                { SVC_ID_FAULT_INJECT, PD_CNODE_SLOT_FAULT_INJECT_EP },
#endif
            },
        },

        /* Optional fault-injection PD used by CI through the CC-PD relay. */
#if defined(AGENTOS_FAULT_INJECT)
        {
            .name           = "fault_inject",
            .elf_path       = "fault_inject.elf",
            .stack_size     = 0x4000u,
            .cnode_size_bits = 10u,
            .priority       = 254u,
            .self_svc_id    = SVC_ID_FAULT_INJECT,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
        },
#endif

        /* pd[18/19] — fault_handler (prio 255; highest priority for fault recovery)
         * Must preempt every other PD to handle seL4 fault IPC promptly.
         * The root task receives kernel fault IPC and identifies the faulting
         * PD. This service endpoint exposes policy/history operations without
         * ever attempting to receive on capability slot zero. */
        {
            .name           = "fault_handler",
            .elf_path       = "fault_handler.elf",
            .stack_size     = 0x4000u,
            .cnode_size_bits = 10u,
            .priority       = 255u,
            .self_svc_id    = SVC_ID_FAULT_HANDLER,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
        },

#ifdef AGENTOS_SEL4_TEST_IMAGE
        /* agentos-8f5 / agentos-0h4: on-target contract TAP runner.  Test image
         * only. Most legacy suites issue microkit_ppcall(ch) — i.e.
         * seL4_Call(BASE_ENDPOINT_CAP[74] + ch). Native contracts use their
         * explicit well-known capability slots instead:
         *   EventBus   ch=MONITOR_CH_EVENTBUS(1)  -> slot 75
         *   serial_pd  ch=CH_SERIAL_PD(44)        -> slot 118
         *   log_drain  native well-known cap      -> slot 4
         *   ExecSvc raw capability                 -> slot 200
         * cnode_size_bits=9 (512 slots) covers both layouts. */
        {
            .name           = "test_runner",
            .elf_path       = "test_runner.elf",
            .stack_size     = 0x4000u,
            .cnode_size_bits = 9u,
            /* High priority (just below fault_handler at 255) so a service that
             * busy-polls — e.g. cc_pd at 160 spinning on its virtio-serial ring
             * when no virtio device is attached in the test QEMU — cannot starve
             * the runner.  Each runner PPC blocks on the target service's Recv,
             * letting the lower-priority services run to answer; ordering vs the
             * controller does not matter since the eventbus assertions tolerate
             * the ring-unmapped state (agentos-gom). */
            .priority       = 250u,
            .self_svc_id    = 0u,
            .init_ep_count  = 17u,
            .init_eps = {
                { SVC_ID_EXEC_SERVER, 200u, EXECSVC_RIGHT_ALL },
                { SVC_ID_EXEC_SERVER, 201u, EXECSVC_RIGHT_C11_COMPILE },
                { SVC_ID_EVENTBUS,   75u  },   /* 74 + MONITOR_CH_EVENTBUS(1) */
                { SVC_ID_SERIAL,     118u },   /* 74 + CH_SERIAL_PD(44)       */
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP },
                { SVC_ID_MODELSVC,   130u },   /* raw seL4 contract cap        */
                { SVC_ID_AGENT_HARNESS, 131u }, /* native harness contract cap   */
                { SVC_ID_TOOLSVC,   132u, TOOLSVC_RIGHT_ALL },
                { SVC_ID_AGENTFS,   133u },   /* raw AgentFS contract cap       */
                { SVC_ID_CONTROLLER, 134u,
                  CONTROLLER_RIGHT_CAP_ADMIN | CONTROLLER_RIGHT_AGENT_TASK },
                { SVC_ID_WG_NET,    135u },   /* native WireGuard contract cap */
                { SVC_ID_NET_PD,    136u, NET_PD_RIGHT_FASTPATH },
                { SVC_ID_NET_PD,    137u, 0u }, /* negative authority probe */
                { SVC_ID_NET_SERVER, 138u, NET_SERVER_RIGHT_WG_DATAGRAM },
                { SVC_ID_NET_SERVER, 139u, 0u }, /* negative WG probe */
                { SVC_ID_INIT_AGENT, 140u }, /* composition contract */
                { SVC_ID_READ_ONLY_HARNESS, 141u }, /* minimal profile */
            },
        },
#endif

        /* Dedicated capability-scoped transport for native model requests.
         * Appended after the optional runner so existing badge-selected test
         * partitions retain their stable descriptor indices. */
        {
            .name           = "model_transport",
            .elf_path       = "model_transport.elf",
            .stack_size     = 0x8000u,
            .cnode_size_bits = 8u,
            .priority       = 210u,
            .self_svc_id    = SVC_ID_MODEL_TRANSPORT,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
        },

        /* Shared execution bridge. It owns only its dedicated bus.8 console,
         * the ExecSvc arena, and logging/nameserver caps. ExecSvc is its sole
         * caller; native workers never receive this endpoint or device cap. */
        {
            .name           = "exec_transport",
            .elf_path       = "exec_transport.elf",
            .stack_size     = 0x8000u,
            .cnode_size_bits = 8u,
            .priority       = 210u,
            .self_svc_id    = SVC_ID_EXEC_TRANSPORT,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
        },

        /* Shared external MCP bridge. It owns only a dedicated bus.16
         * console, the service-private part of ToolSvc's arena, and logging.
         * ToolSvc is its sole caller; workers receive only badged ToolCaps. */
        {
            .name           = "mcp_transport",
            .elf_path       = "mcp_transport.elf",
            .stack_size     = 0x8000u,
            .cnode_size_bits = 8u,
            .priority       = 210u,
            .self_svc_id    = SVC_ID_MCP_TRANSPORT,
            .init_ep_count  = 2u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
            },
        },

        /* Capability-native WireGuard overlay. The PD receives the packet
         * service endpoint with NET_SERVER_RIGHT_WG_DATAGRAM so session traffic
         * reaches net_pd through the net_device underlay while Headscale/netmap
         * endpoints stay connectivity metadata. It cannot manufacture a NetCap
         * through nameserver metadata and has no model/tool/memory/exec authority. */
        {
            .name           = "wg_net",
            .elf_path       = "wg_net.elf",
            .stack_size     = 0x10000u,
            .cnode_size_bits = 8u,
            .priority       = 180u,
            .self_svc_id    = SVC_ID_WG_NET,
            .init_ep_count  = 3u,
            .init_eps = {
                { SVC_ID_NAMESERVER, PD_CNODE_SLOT_NAMESERVER_EP },
                { SVC_ID_LOG_DRAIN,  PD_CNODE_SLOT_LOG_DRAIN_EP  },
                { SVC_ID_NET_SERVER, PD_CNODE_SLOT_NET_SERVER_EP,
                  NET_SERVER_RIGHT_WG_DATAGRAM },
            },
        },
    },
};
