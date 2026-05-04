/*
 * vm_manager.c — Multi-VM lifecycle manager for agentOS
 * Copyright 2026, agentOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Passive PD (priority 145) that manages up to 4 simultaneous guest VMs.
 * Controller calls in via the vm_manager IPC endpoint.
 *
 * Opcodes (opcode in data[0..3]):
 *   OP_VM_CREATE    0x10  data[0]=label_vaddr data[4]=ram_mb → ok, slot_id
 *   OP_VM_DESTROY   0x11  data[0]=slot_id → ok
 *   OP_VM_START     0x12  data[0]=slot_id → ok
 *   OP_VM_STOP      0x13  data[0]=slot_id → ok
 *   OP_VM_PAUSE     0x14  data[0]=slot_id → ok
 *   OP_VM_RESUME    0x15  data[0]=slot_id → ok
 *   OP_VM_CONSOLE   0x16  data[0]=slot_id → ok
 *   OP_VM_INFO      0x17  data[0]=slot_id → ok, state, ram_vaddr
 *   OP_VM_LIST      0x18  → ok, count; vm_list_shmem has vm_list_entry_t[]
 *   OP_VM_SNAPSHOT  0x19  data[0]=slot_id → ok, snap_hash_lo, snap_hash_hi
 *   OP_VM_RESTORE   0x1A  data[0]=slot_id, [4]=snap_lo, [8]=snap_hi → ok
 *   OP_VM_CONFIGURE 0x1B  data[0]=slot_id data[4]=ram_mb
 *                         data[8]=cpu_budget_us data[12]=cpu_period_us → ok
 *   OP_VM_SET_QUOTA 0x30  data[0]=slot_id data[4]=cpu_pct → ok
 *   OP_VM_GET_STATS 0x31  data[0]=slot_id → ok, state, max_cpu_pct,
 *                         run_ticks_lo, run_ticks_hi,
 *                         preempt_count_lo, preempt_count_hi
 *   OP_VM_SET_AFFINITY 0x32 data[0]=slot_id data[4]=cpu_mask → ok
 *   OP_VM_INJECT_IRQ   0x33 data[0]=slot_id data[4]=irq_num  → ok
 *
 * E5-S8: migrated from Microkit to raw seL4 IPC.
 */

#define AGENTOS_DEBUG 1
#include "agentos.h"
#include "sel4_server.h"
/* vm_manager.h includes vmm_mux.h (found via -I../../freebsd-vmm in Makefile) */
#include "vm_manager.h"

/* ── Shared memory output region ─────────────────────────────────────────
 * vm_list_shmem (4KB) is mapped rw into this PD and r into controller.
 */
uintptr_t vm_list_vaddr;   /* set by linker (setvar_vaddr) */

/* ── VM list entry written into vm_list_shmem on OP_VM_LIST ─────────────
 * Packed so the controller can read it without alignment surprises.
 */
typedef struct __attribute__((packed)) {
    uint8_t  slot_id;
    uint8_t  state;      /* VM_SLOT_* from vmm_mux.h */
    uint8_t  _pad[2];
    uint32_t ram_mb;
    char     label[16];
} vm_list_entry_t;

/* ── Global VM multiplexer ─────────────────────────────────────────────── */
static vm_mux_t g_mux;

/* ── Additional IPC opcodes (extend vmm_mux.h's OP_VM_* set) ──────────── */
#define OP_VM_SET_QUOTA    0x30u
#define OP_VM_GET_STATS    0x31u
#define OP_VM_SET_AFFINITY 0x32u
#define OP_VM_INJECT_IRQ   0x33u

/* ── Result codes ────────────────────────────────────────────────────────*/
#define VM_OK       0u
#define VM_ERR      1u
#define VM_NOT_IMPL 0xFEu

/* ── Per-slot CPU quota and scheduler state ──────────────────────────────*/
static vm_slot_quota_t g_quotas[VM_MAX_SLOTS];
static uint8_t g_sched_current = 0;
static uint32_t g_affinity[VM_MAX_SLOTS];

/* ── IPC-driven scheduler tick ───────────────────────────────────────────
 * Fire vm_sched_tick() every VM_SCHED_IPC_QUANTUM IPC dispatches.
 * Provides work-conserving credit scheduling without a hardware timer;
 * a real timer PD will replace this once timer-service is implemented.
 */
#define VM_SCHED_IPC_QUANTUM 16u
static uint32_t g_ipc_counter = 0;

/* ── msg helpers ────────────────────────────────────────────────────────*/
#ifndef AGENTOS_IPC_HELPERS_DEFINED
#define AGENTOS_IPC_HELPERS_DEFINED
static inline uint32_t msg_u32(const sel4_msg_t *m, uint32_t off) {
    uint32_t v = 0;
    if (off + 4u <= SEL4_MSG_DATA_BYTES) {
        v  = (uint32_t)m->data[off]; v |= (uint32_t)m->data[off+1]<<8;
        v |= (uint32_t)m->data[off+2]<<16; v |= (uint32_t)m->data[off+3]<<24;
    }
    return v;
}
static inline void rep_u32(sel4_msg_t *m, uint32_t off, uint32_t v) {
    if (off + 4u <= SEL4_MSG_DATA_BYTES) {
        m->data[off]=(uint8_t)v; m->data[off+1]=(uint8_t)(v>>8);
        m->data[off+2]=(uint8_t)(v>>16); m->data[off+3]=(uint8_t)(v>>24);
    }
}
#endif /* AGENTOS_IPC_HELPERS_DEFINED */
static inline void rep_u64(sel4_msg_t *m, uint32_t off, uint64_t v) {
    rep_u32(m, off,     (uint32_t)(v & 0xFFFFFFFFU));
    rep_u32(m, off + 4, (uint32_t)(v >> 32));
}

static inline uint32_t vm_arg_u32(const sel4_msg_t *req, uint32_t arg)
{
    uint32_t raw_off = arg * 4u;
    if (req->length >= raw_off + 4u)
        return msg_u32(req, raw_off);

    /* Compatibility with older tests/callers that encoded the opcode in
     * data[0] even though sel4_msg_t already carries req->opcode. */
    return msg_u32(req, raw_off + 4u);
}

/* ── Helper: print a small decimal number without libc ──────────────────*/
static void dbg_u8(uint8_t v)
{
    char buf[4];
    buf[0] = '0' + (char)(v / 100 % 10);
    buf[1] = '0' + (char)(v / 10  % 10);
    buf[2] = '0' + (char)(v       % 10);
    buf[3] = '\0';
    if (buf[0] == '0' && buf[1] == '0') {
        sel4_dbg_puts(buf + 2);
    } else if (buf[0] == '0') {
        sel4_dbg_puts(buf + 1);
    } else {
        sel4_dbg_puts(buf);
    }
}

/* ── vm_sched_tick — round-robin scheduler ──────────────────────────────*/
void vm_sched_tick(vm_mux_t *mux)
{
    uint8_t cur = g_sched_current;

    for (uint8_t i = 0; i < VM_MAX_SLOTS; i++) {
        vm_slot_state_t st = mux->slots[i].state;
        if (st == VM_SLOT_RUNNING || st == VM_SLOT_BOOTING) {
            g_quotas[i].run_ticks++;
        }
    }

    vm_slot_state_t cur_state = mux->slots[cur].state;
    bool cur_runnable = (cur_state == VM_SLOT_RUNNING ||
                         cur_state == VM_SLOT_BOOTING) &&
                        g_quotas[cur].max_cpu_pct > 0;

    if (!cur_runnable) {
        bool found = false;
        for (uint8_t i = 0; i < VM_MAX_SLOTS; i++) {
            vm_slot_state_t s = mux->slots[i].state;
            if ((s == VM_SLOT_RUNNING || s == VM_SLOT_BOOTING) &&
                g_quotas[i].max_cpu_pct > 0) {
                g_sched_current = i;
                g_quotas[i].credits =
                    (int32_t)((uint32_t)g_quotas[i].max_cpu_pct *
                              SCHED_CREDITS_PER_PCT);
                found = true;
                break;
            }
        }
        (void)found;
        return;
    }

    g_quotas[cur].credits -= (int32_t)SCHED_CREDIT_QUANTUM;

    if (g_quotas[cur].credits > 0) return;

    uint8_t next = cur;
    bool switched = false;
    for (uint8_t step = 1; step <= VM_MAX_SLOTS; step++) {
        uint8_t candidate = (uint8_t)((cur + step) % VM_MAX_SLOTS);
        vm_slot_state_t s = mux->slots[candidate].state;
        if ((s == VM_SLOT_RUNNING || s == VM_SLOT_BOOTING) &&
            g_quotas[candidate].max_cpu_pct > 0 &&
            candidate != cur) {
            next = candidate;
            switched = true;
            break;
        }
    }

    if (!switched) {
        g_quotas[cur].credits =
            (int32_t)((uint32_t)g_quotas[cur].max_cpu_pct *
                      SCHED_CREDITS_PER_PCT);
        return;
    }

    g_quotas[cur].preempt_count++;
    vmm_mux_pause(mux, cur);

    g_quotas[next].credits =
        (int32_t)((uint32_t)g_quotas[next].max_cpu_pct *
                  SCHED_CREDITS_PER_PCT);
    vmm_mux_resume(mux, next);

    g_sched_current = next;

    sel4_dbg_puts("[vm_manager] sched: preempted slot ");
    dbg_u8(cur);
    sel4_dbg_puts(" -> slot ");
    dbg_u8(next);
    sel4_dbg_puts("\n");
}

/* ── vm_set_quota ────────────────────────────────────────────────────────*/
int vm_set_quota(vm_mux_t *mux, uint8_t slot_id, uint8_t cpu_pct)
{
    (void)mux;
    if (slot_id >= VM_MAX_SLOTS) return -1;
    if (cpu_pct > 100u) cpu_pct = 100u;
    g_quotas[slot_id].max_cpu_pct = cpu_pct;
    g_quotas[slot_id].credits =
        (int32_t)((uint32_t)cpu_pct * SCHED_CREDITS_PER_PCT);
    return 0;
}

/* ── vm_get_stats ────────────────────────────────────────────────────────*/
int vm_get_stats(const vm_mux_t *mux, uint8_t slot_id, vm_stats_t *out)
{
    if (slot_id >= VM_MAX_SLOTS || !out) return -1;

    const vm_slot_t       *s = &mux->slots[slot_id];
    const vm_slot_quota_t *q = &g_quotas[slot_id];

    out->slot_id       = slot_id;
    out->state         = (uint8_t)s->state;
    out->max_cpu_pct   = q->max_cpu_pct;
    out->_pad          = 0;
    out->ram_mb        = (uint32_t)(s->ram_size >> 20);
    out->run_ticks     = q->run_ticks;
    out->preempt_count = q->preempt_count;

    for (int i = 0; i < 15; i++) {
        out->label[i] = s->label[i];
        if (!s->label[i]) break;
    }
    out->label[15] = '\0';

    return 0;
}

/* ── vmm_set_affinity ────────────────────────────────────────────────────*/
int vmm_set_affinity(uint8_t slot_id, uint32_t cpu_mask)
{
    if (slot_id >= VM_MAX_SLOTS) return -1;
    g_affinity[slot_id] = cpu_mask;
    sel4_dbg_puts("[vm_manager] affinity: slot ");
    dbg_u8(slot_id);
    sel4_dbg_puts(" cpu_mask set\n");
    /* TODO: call seL4_TCB_SetAffinity(vcpu_tcb_cap, cpu_mask) when available */
    return 0;
}

/* ── vmm_inject_irq ──────────────────────────────────────────────────────*/
int vmm_inject_irq(uint8_t slot_id, uint32_t irq_num)
{
    if (slot_id >= VM_MAX_SLOTS) return -1;
    sel4_dbg_puts("[vm_manager] inject_irq: slot ");
    dbg_u8(slot_id);
    sel4_dbg_puts(" irq=");
    dbg_u8((uint8_t)(irq_num & 0xFF));
    sel4_dbg_puts(" (stub)\n");
    /* TODO: virq_inject(slot_vcpu_id, irq_num) via libvmm */
    return 0;
}

/* ── IPC handlers ────────────────────────────────────────────────────────*/

static uint32_t h_create(sel4_badge_t ba, const sel4_msg_t *req,
                           sel4_msg_t *rep, void *ctx) {
    (void)ba; (void)ctx;
    const char *label = (const char *)(uintptr_t)vm_arg_u32(req, 0);
    if (!label || (uintptr_t)label < 0x1000u) label = "vm";
    uint8_t slot_id = vmm_mux_create(&g_mux, label);
    if (slot_id == 0xFF) {
        sel4_dbg_puts("[vm_manager] CREATE failed: no free slots\n");
        rep_u32(rep, 0, VM_ERR); rep->length = 4;
        return SEL4_ERR_NO_MEM;
    }

    /* Rebalance quotas equally across all now-active slots.
     * Reset credits so existing slots don't carry excess credit from their
     * previous higher quota into the new smaller-quota regime. */
    {
        uint8_t active = g_mux.slot_count;
        uint8_t share  = (active > 0u) ? (uint8_t)(100u / active) : 100u;
        for (uint8_t i = 0; i < VM_MAX_SLOTS; i++) {
            if (g_mux.slots[i].state != VM_SLOT_FREE) {
                g_quotas[i].max_cpu_pct = share;
                g_quotas[i].credits =
                    (int32_t)((uint32_t)share * SCHED_CREDITS_PER_PCT);
            }
        }
    }

    sel4_dbg_puts("[vm_manager] CREATE slot=");
    dbg_u8(slot_id);
    sel4_dbg_puts("\n");
    rep_u32(rep, 0, VM_OK);
    rep_u32(rep, 4, (uint32_t)slot_id);
    rep->length = 8;
    return SEL4_ERR_OK;
}

static uint32_t h_destroy(sel4_badge_t ba, const sel4_msg_t *req,
                            sel4_msg_t *rep, void *ctx) {
    (void)ba; (void)ctx;
    uint8_t slot_id = (uint8_t)vm_arg_u32(req, 0);
    int r = vmm_mux_destroy(&g_mux, slot_id);
    rep_u32(rep, 0, r == 0 ? VM_OK : VM_ERR);
    rep->length = 4;
    return SEL4_ERR_OK;
}

static uint32_t h_start(sel4_badge_t ba, const sel4_msg_t *req,
                          sel4_msg_t *rep, void *ctx) {
    (void)ba; (void)ctx;
    uint8_t slot_id = (uint8_t)vm_arg_u32(req, 0);
    uint32_t result = VM_ERR;
    if (slot_id < VM_MAX_SLOTS && g_mux.slots[slot_id].state != VM_SLOT_FREE) {
        if (g_mux.slots[slot_id].state == VM_SLOT_RUNNING ||
            g_mux.slots[slot_id].state == VM_SLOT_BOOTING) {
            result = VM_OK;
        } else {
            int r = vmm_mux_resume(&g_mux, slot_id);
            result = (r == 0) ? VM_OK : VM_ERR;
        }
    }
    rep_u32(rep, 0, result); rep->length = 4;
    return SEL4_ERR_OK;
}

static uint32_t h_stop(sel4_badge_t ba, const sel4_msg_t *req,
                         sel4_msg_t *rep, void *ctx) {
    (void)ba; (void)ctx;
    uint8_t slot_id = (uint8_t)vm_arg_u32(req, 0);
    uint32_t result = VM_ERR;
    if (slot_id < VM_MAX_SLOTS && g_mux.slots[slot_id].state != VM_SLOT_FREE) {
        int r = vmm_mux_pause(&g_mux, slot_id);
        result = (r == 0) ? VM_OK : VM_ERR;
    }
    rep_u32(rep, 0, result); rep->length = 4;
    return SEL4_ERR_OK;
}

static uint32_t h_pause(sel4_badge_t ba, const sel4_msg_t *req,
                          sel4_msg_t *rep, void *ctx) {
    (void)ba; (void)ctx;
    uint8_t slot_id = (uint8_t)vm_arg_u32(req, 0);
    int r = vmm_mux_pause(&g_mux, slot_id);
    rep_u32(rep, 0, r == 0 ? VM_OK : VM_ERR); rep->length = 4;
    return SEL4_ERR_OK;
}

static uint32_t h_resume(sel4_badge_t ba, const sel4_msg_t *req,
                           sel4_msg_t *rep, void *ctx) {
    (void)ba; (void)ctx;
    uint8_t slot_id = (uint8_t)vm_arg_u32(req, 0);
    int r = vmm_mux_resume(&g_mux, slot_id);
    rep_u32(rep, 0, r == 0 ? VM_OK : VM_ERR); rep->length = 4;
    return SEL4_ERR_OK;
}

static uint32_t h_console(sel4_badge_t ba, const sel4_msg_t *req,
                            sel4_msg_t *rep, void *ctx) {
    (void)ba; (void)ctx;
    uint8_t slot_id = (uint8_t)vm_arg_u32(req, 0);
    int r = vmm_mux_switch(&g_mux, slot_id);
    rep_u32(rep, 0, r == 0 ? VM_OK : VM_ERR); rep->length = 4;
    return SEL4_ERR_OK;
}

static uint32_t h_info(sel4_badge_t ba, const sel4_msg_t *req,
                         sel4_msg_t *rep, void *ctx) {
    (void)ba; (void)ctx;
    uint8_t slot_id = (uint8_t)vm_arg_u32(req, 0);
    if (slot_id >= VM_MAX_SLOTS) {
        rep_u32(rep, 0, VM_ERR); rep->length = 4;
        return SEL4_ERR_BAD_ARG;
    }
    vm_slot_t *s = &g_mux.slots[slot_id];
    rep_u32(rep, 0, VM_OK);
    rep_u32(rep, 4, (uint32_t)s->state);
    rep_u32(rep, 8, (uint32_t)(s->ram_vaddr & 0xFFFFFFFFu));
    rep->length = 12;
    return SEL4_ERR_OK;
}

static uint32_t h_list(sel4_badge_t ba, const sel4_msg_t *req,
                         sel4_msg_t *rep, void *ctx) {
    (void)ba; (void)req; (void)ctx;
    uint32_t count = 0;
    if (vm_list_vaddr) {
        vm_list_entry_t *entries = (vm_list_entry_t *)(uintptr_t)vm_list_vaddr;
        for (uint8_t i = 0; i < VM_MAX_SLOTS; i++) {
            vm_slot_t *s = &g_mux.slots[i];
            if (s->state != VM_SLOT_FREE) {
                entries[count].slot_id = i;
                entries[count].state   = (uint8_t)s->state;
                entries[count]._pad[0] = 0;
                entries[count]._pad[1] = 0;
                entries[count].ram_mb  = (uint32_t)(s->ram_size >> 20);
                for (int j = 0; j < 15; j++) {
                    entries[count].label[j] = s->label[j];
                    if (!s->label[j]) break;
                }
                entries[count].label[15] = '\0';
                count++;
            }
        }
    }
    rep_u32(rep, 0, VM_OK);
    rep_u32(rep, 4, count);
    rep->length = 8;
    return SEL4_ERR_OK;
}

static uint32_t h_snapshot_restore(sel4_badge_t ba, const sel4_msg_t *req,
                                     sel4_msg_t *rep, void *ctx) {
    (void)ba; (void)req; (void)ctx;
    sel4_dbg_puts("[vm_manager] SNAPSHOT/RESTORE: not implemented (Phase 1)\n");
    rep_u32(rep, 0, VM_NOT_IMPL); rep->length = 4;
    return SEL4_ERR_OK;
}

static uint32_t h_configure(sel4_badge_t ba, const sel4_msg_t *req,
                              sel4_msg_t *rep, void *ctx) {
    (void)ba; (void)ctx;
    uint8_t  slot_id       = (uint8_t)vm_arg_u32(req, 0);
    uint32_t new_ram_mb    = vm_arg_u32(req, 1);
    uint32_t cpu_budget_us = vm_arg_u32(req, 2);
    uint32_t cpu_period_us = vm_arg_u32(req, 3);

    if (slot_id >= VM_MAX_SLOTS ||
        g_mux.slots[slot_id].state == VM_SLOT_FREE) {
        rep_u32(rep, 0, VM_ERR);
        rep->length = 4;
        return SEL4_ERR_NOT_FOUND;
    }

    uint32_t current_ram_mb =
        (uint32_t)(g_mux.slots[slot_id].ram_size >> 20);
    if (new_ram_mb != 0u && new_ram_mb != current_ram_mb) {
        rep_u32(rep, 0, VM_NOT_IMPL);
        rep->length = 4;
        return SEL4_ERR_OK;
    }

    if (cpu_budget_us != 0u && cpu_period_us != 0u) {
        uint32_t pct = (cpu_budget_us >= cpu_period_us)
                       ? 100u : (cpu_budget_us * 100u) / cpu_period_us;
        (void)vm_set_quota(&g_mux, slot_id, (uint8_t)pct);
    }

    rep_u32(rep, 0, VM_OK);
    rep->length = 4;
    return SEL4_ERR_OK;
}

static uint32_t h_set_quota(sel4_badge_t ba, const sel4_msg_t *req,
                              sel4_msg_t *rep, void *ctx) {
    (void)ba; (void)ctx;
    uint8_t slot_id = (uint8_t)vm_arg_u32(req, 0);
    uint8_t cpu_pct = (uint8_t)vm_arg_u32(req, 1);
    int r = vm_set_quota(&g_mux, slot_id, cpu_pct);
    if (r == 0) {
        sel4_dbg_puts("[vm_manager] SET_QUOTA slot=");
        dbg_u8(slot_id);
        sel4_dbg_puts(" pct=");
        dbg_u8(cpu_pct);
        sel4_dbg_puts("\n");
    }
    rep_u32(rep, 0, r == 0 ? VM_OK : VM_ERR); rep->length = 4;
    return SEL4_ERR_OK;
}

static uint32_t h_get_stats(sel4_badge_t ba, const sel4_msg_t *req,
                              sel4_msg_t *rep, void *ctx) {
    (void)ba; (void)ctx;
    uint8_t slot_id = (uint8_t)vm_arg_u32(req, 0);
    vm_stats_t stats;
    int r = vm_get_stats(&g_mux, slot_id, &stats);
    if (r != 0) {
        rep_u32(rep, 0, VM_ERR); rep->length = 4;
        return SEL4_ERR_NOT_FOUND;
    }
    rep_u32(rep, 0,  VM_OK);
    rep_u32(rep, 4,  (uint32_t)stats.state);
    rep_u32(rep, 8,  (uint32_t)stats.max_cpu_pct);
    rep_u64(rep, 12, stats.run_ticks);
    rep_u64(rep, 20, stats.preempt_count);
    rep->length = 28;
    return SEL4_ERR_OK;
}

static uint32_t h_set_affinity(sel4_badge_t ba, const sel4_msg_t *req,
                                 sel4_msg_t *rep, void *ctx) {
    (void)ba; (void)ctx;
    uint8_t  slot_id  = (uint8_t)vm_arg_u32(req, 0);
    uint32_t cpu_mask = vm_arg_u32(req, 1);
    int r = vmm_set_affinity(slot_id, cpu_mask);
    rep_u32(rep, 0, r == 0 ? VM_OK : VM_ERR); rep->length = 4;
    return SEL4_ERR_OK;
}

static uint32_t h_inject_irq(sel4_badge_t ba, const sel4_msg_t *req,
                               sel4_msg_t *rep, void *ctx) {
    (void)ba; (void)ctx;
    uint8_t  slot_id = (uint8_t)vm_arg_u32(req, 0);
    uint32_t irq_num = vm_arg_u32(req, 1);
    int r = vmm_inject_irq(slot_id, irq_num);
    rep_u32(rep, 0, r == 0 ? VM_OK : VM_ERR); rep->length = 4;
    return SEL4_ERR_OK;
}

/* ── Nameserver registration ────────────────────────────────────────────
 * Make this PD discoverable by name so vibe_engine (and any future caller)
 * can resolve our endpoint via OP_NS_LOOKUP("vm_manager"), unblocking the
 * vibe_engine → vm_manager relay path.
 */
static void vm_manager_register_with_nameserver(seL4_CPtr ns_ep)
{
    if (!ns_ep) return;
    sel4_msg_t req = {0}, rep = {0};
    req.opcode = 0xD0u;  /* OP_NS_REGISTER */
    /* data[0..3]   = channel_id (0 for dynamic PD) */
    /* data[4..7]   = pd_id (0 — assigned by nameserver) */
    /* data[8..11]  = cap_classes (0) */
    /* data[12..15] = version (1) */
    /* data[16..]   = name "vm_manager" */
    {
        uint8_t *d = req.data;
        d[ 0] = 0; d[ 1] = 0; d[ 2] = 0; d[ 3] = 0;
        d[ 4] = 0; d[ 5] = 0; d[ 6] = 0; d[ 7] = 0;
        d[ 8] = 0; d[ 9] = 0; d[10] = 0; d[11] = 0;
        d[12] = 1; d[13] = 0; d[14] = 0; d[15] = 0;
    }
    {
        const char nm[] = "vm_manager";
        for (int i = 0; nm[i] && (16 + i) < 48; i++)
            req.data[16 + i] = (uint8_t)nm[i];
    }
    req.length = 48;
    sel4_call(ns_ep, &req, &rep);
}

/* ── Entry point ────────────────────────────────────────────────────────*/

void vm_manager_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    vmm_mux_init(&g_mux);

    for (uint8_t i = 0; i < VM_MAX_SLOTS; i++) {
        g_quotas[i].max_cpu_pct   = (uint8_t)(100u / VM_MAX_SLOTS);
        g_quotas[i].credits       = 0;
        g_quotas[i].run_ticks     = 0;
        g_quotas[i].preempt_count = 0;
        g_affinity[i]             = 0xFFFFFFFFu;
    }
    g_sched_current = 0;

    sel4_dbg_puts("[vm_manager] init: 4-slot VM multiplexer ready\n");
    sel4_dbg_puts("[vm_manager] scheduler: round-robin, 25% quota/slot\n");

    /* Publish under "vm_manager" so vibe_engine's lookup_service finds us. */
    vm_manager_register_with_nameserver(ns_ep);

    static sel4_server_t srv;
    sel4_server_init(&srv, my_ep);
    sel4_server_register(&srv, OP_VM_CREATE,       h_create,           (void *)0);
    sel4_server_register(&srv, OP_VM_DESTROY,      h_destroy,          (void *)0);
    sel4_server_register(&srv, OP_VM_START,        h_start,            (void *)0);
    sel4_server_register(&srv, OP_VM_STOP,         h_stop,             (void *)0);
    sel4_server_register(&srv, OP_VM_PAUSE,        h_pause,            (void *)0);
    sel4_server_register(&srv, OP_VM_RESUME,       h_resume,           (void *)0);
    sel4_server_register(&srv, OP_VM_CONSOLE,      h_console,          (void *)0);
    sel4_server_register(&srv, OP_VM_INFO,         h_info,             (void *)0);
    sel4_server_register(&srv, OP_VM_LIST,         h_list,             (void *)0);
    sel4_server_register(&srv, OP_VM_SNAPSHOT,     h_snapshot_restore, (void *)0);
    sel4_server_register(&srv, OP_VM_RESTORE,      h_snapshot_restore, (void *)0);
    sel4_server_register(&srv, OP_VM_CONFIGURE,    h_configure,        (void *)0);
    sel4_server_register(&srv, OP_VM_SET_QUOTA,    h_set_quota,        (void *)0);
    sel4_server_register(&srv, OP_VM_GET_STATS,    h_get_stats,        (void *)0);
    sel4_server_register(&srv, OP_VM_SET_AFFINITY, h_set_affinity,     (void *)0);
    sel4_server_register(&srv, OP_VM_INJECT_IRQ,   h_inject_irq,       (void *)0);
    /* Custom dispatch loop: fire vm_sched_tick() every VM_SCHED_IPC_QUANTUM
     * IPC dispatches.  Provides work-conserving credit scheduling without a
     * hardware timer; replace with a timer-notification path once timer-service
     * is implemented. */
    {
        sel4_msg_t   req   = {0};
        sel4_msg_t   rep   = {0};
        sel4_badge_t badge;
        int          first = 1;

        while (1) {
            if (first) {
                badge = sel4_recv(srv.ep, &req);
                first = 0;
            } else {
                badge = sel4_reply_recv(srv.ep, &rep, &req);
            }

            rep.opcode = 0;
            rep.length = 0;

            if (++g_ipc_counter >= VM_SCHED_IPC_QUANTUM) {
                g_ipc_counter = 0;
                vm_sched_tick(&g_mux);
            }

            sel4_server_dispatch(&srv, badge, &req, &rep);
        }
    }
}

void pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep) { vm_manager_main(my_ep, ns_ep); }
