/*
 * FractalOS pd_startup_record — Host Unit Test (fos-3ev)
 *
 * Asserts the documented, packed startup-record contract that parameterized
 * PD wrappers (swap_slot, app_slot, wg_net, vibe_swap) consume instead of
 * hard-coding slot 0 / NULL controller caps:
 *
 *   - struct layout / size / field offsets are stable
 *   - magic + version validation gates all field reads
 *   - accessors return populated values for a valid record
 *   - accessors fall back to safe defaults (slot 0, no caps) for an
 *     absent/invalid record — exactly the legacy wrapper behaviour
 *   - it reproduces the slot-id / peer-cap selection each wrapper's pd_main
 *     performs, proving the wrapper logic reads the record correctly
 *
 * Build:  cc -std=c11 -o /tmp/test_pd_startup_record \
 *             tests/test_pd_startup_record.c \
 *             -I kernel/fractalos-root-task/include
 * Run:    /tmp/test_pd_startup_record   (TAP output; exit 0 on success)
 */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "pd_startup_record.h"

/* ── Minimal TAP harness ───────────────────────────────────────────────── */

static int g_test_no = 0;
static int g_failures = 0;

#define OK(cond, desc) do {                                        \
    g_test_no++;                                                   \
    if (cond) {                                                    \
        printf("ok %d - %s\n", g_test_no, (desc));                 \
    } else {                                                       \
        printf("not ok %d - %s\n", g_test_no, (desc));             \
        g_failures++;                                              \
    }                                                              \
} while (0)

/*
 * Mirror of the slot-id + cap selection that swap_slot/app_slot/wg_net/
 * vibe_swap pd_main wrappers perform.  Exercising it here proves the wrappers
 * decode a populated record correctly, without seL4.
 */
static void wrapper_decode(const pd_startup_record_t *rec,
                           uint32_t *slot_id,
                           uint32_t *controller,
                           uint32_t *peer0,
                           uint32_t *peer3)
{
    *slot_id    = pd_startup_record_slot_id(rec);
    *controller = pd_startup_record_controller_ntfn(rec);
    *peer0      = pd_startup_record_peer_ep(rec, 0u);
    *peer3      = pd_startup_record_peer_ep(rec, 3u);
}

int main(void)
{
    /* ── Layout / contract ─────────────────────────────────────────────── */
    OK(sizeof(pd_startup_record_t) == 64u, "record is exactly 64 bytes");
    OK(offsetof(pd_startup_record_t, magic)           == 0u,  "magic at +0");
    OK(offsetof(pd_startup_record_t, version)         == 4u,  "version at +4");
    OK(offsetof(pd_startup_record_t, slot_id)         == 8u,  "slot_id at +8");
    OK(offsetof(pd_startup_record_t, controller_ntfn) == 12u, "controller_ntfn at +12");
    OK(offsetof(pd_startup_record_t, peer_ep_count)   == 16u, "peer_ep_count at +16");
    OK(offsetof(pd_startup_record_t, peer_ep)         == 20u, "peer_ep at +20");
    OK(PD_STARTUP_RECORD_MAGIC   == 0x50445352u, "magic == 'PDSR'");
    OK(PD_STARTUP_RECORD_VERSION == 1u,          "version == 1");
    OK(PD_STARTUP_CAP_NONE       == 0u,          "cap-none sentinel == 0");

    /* ── init stamps magic/version and zeroes the rest ─────────────────── */
    pd_startup_record_t rec;
    memset(&rec, 0xAB, sizeof(rec));           /* poison */
    pd_startup_record_init(&rec);
    OK(rec.magic == PD_STARTUP_RECORD_MAGIC,   "init sets magic");
    OK(rec.version == PD_STARTUP_RECORD_VERSION, "init sets version");
    OK(rec.slot_id == 0u && rec.peer_ep_count == 0u &&
       rec.controller_ntfn == 0u,              "init zeroes payload");
    OK(pd_startup_record_valid(&rec),          "freshly-init record is valid");

    /* ── Populated record: swap_slot-style (slot 2 + controller cap) ───── */
    pd_startup_record_t ss;
    pd_startup_record_init(&ss);
    ss.slot_id         = 2u;
    ss.controller_ntfn = 8u;          /* CNode slot of controller-notify cap */
    ss.peer_ep_count   = 0u;
    OK(pd_startup_record_slot_id(&ss) == 2u,         "swap_slot reads slot 2");
    OK(pd_startup_record_controller_ntfn(&ss) == 8u, "swap_slot reads controller cap");

    /* ── Populated record: vibe_swap-style (four worker peer eps) ──────── */
    pd_startup_record_t vs;
    pd_startup_record_init(&vs);
    vs.peer_ep_count = 4u;
    vs.peer_ep[0] = 10u; vs.peer_ep[1] = 11u;
    vs.peer_ep[2] = 12u; vs.peer_ep[3] = 13u;
    OK(pd_startup_record_peer_ep(&vs, 0u) == 10u, "vibe_swap reads peer ep 0");
    OK(pd_startup_record_peer_ep(&vs, 3u) == 13u, "vibe_swap reads peer ep 3");
    OK(pd_startup_record_peer_ep(&vs, 4u) == PD_STARTUP_CAP_NONE,
       "out-of-range peer ep -> NONE");

    /* peer_ep beyond declared count must read NONE even if backing slot set */
    pd_startup_record_t vs2;
    pd_startup_record_init(&vs2);
    vs2.peer_ep_count = 1u;
    vs2.peer_ep[0] = 10u; vs2.peer_ep[1] = 11u;
    OK(pd_startup_record_peer_ep(&vs2, 0u) == 10u,
       "peer ep within count is read");
    OK(pd_startup_record_peer_ep(&vs2, 1u) == PD_STARTUP_CAP_NONE,
       "peer ep beyond count -> NONE");

    /* ── Invalid records fall back to legacy defaults ──────────────────── */
    pd_startup_record_t bad_magic = ss;
    bad_magic.magic = 0xDEADBEEFu;
    OK(!pd_startup_record_valid(&bad_magic),                 "bad magic invalid");
    OK(pd_startup_record_slot_id(&bad_magic) == 0u,          "bad magic -> slot 0");
    OK(pd_startup_record_controller_ntfn(&bad_magic) == PD_STARTUP_CAP_NONE,
       "bad magic -> no controller cap");

    pd_startup_record_t bad_ver = ss;
    bad_ver.version = 99u;
    OK(!pd_startup_record_valid(&bad_ver),                   "bad version invalid");
    OK(pd_startup_record_slot_id(&bad_ver) == 0u,            "bad version -> slot 0");

    OK(pd_startup_record_valid(NULL) == 0,                   "NULL record invalid");
    OK(pd_startup_record_slot_id(NULL) == 0u,               "NULL -> slot 0");
    OK(pd_startup_record_controller_ntfn(NULL) == PD_STARTUP_CAP_NONE,
       "NULL -> no controller cap");
    OK(pd_startup_record_peer_ep(NULL, 0u) == PD_STARTUP_CAP_NONE,
       "NULL -> no peer cap");

    /* ── End-to-end: wrapper decode of a fully populated record ────────── */
    pd_startup_record_t full;
    pd_startup_record_init(&full);
    full.slot_id         = 3u;
    full.controller_ntfn = 8u;
    full.peer_ep_count   = 4u;
    full.peer_ep[0] = 20u; full.peer_ep[3] = 23u;
    uint32_t s, c, p0, p3;
    wrapper_decode(&full, &s, &c, &p0, &p3);
    OK(s == 3u && c == 8u && p0 == 20u && p3 == 23u,
       "wrapper decodes populated record");

    /* ── End-to-end: wrapper decode of an unmapped/zeroed page ─────────── */
    pd_startup_record_t zeroed;
    memset(&zeroed, 0, sizeof(zeroed));        /* simulates blank frame */
    wrapper_decode(&zeroed, &s, &c, &p0, &p3);
    OK(s == 0u && c == PD_STARTUP_CAP_NONE &&
       p0 == PD_STARTUP_CAP_NONE && p3 == PD_STARTUP_CAP_NONE,
       "wrapper decode of blank page -> legacy defaults");

    printf("1..%d\n", g_test_no);
    if (g_failures) {
        printf("# FAILED %d/%d\n", g_failures, g_test_no);
        return 1;
    }
    printf("# all %d assertions passed\n", g_test_no);
    return 0;
}
