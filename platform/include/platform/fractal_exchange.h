/* Fractal raw exchange v1: four terminal 4 KiB exchange blocks plus
 * preceding 16-block append-only crash and event rings on one disk.
 * This is a bounded native/Omarchy transport while a filesystem and physical
 * NVMe driver are absent. Multi-byte integers are little-endian; SHA-256
 * fields are raw digest bytes. The COMPLETE block is written last. */
#ifndef AOS_PLATFORM_FRACTAL_EXCHANGE_H
#define AOS_PLATFORM_FRACTAL_EXCHANGE_H

#include <stdint.h>

#define FRACTAL_XFER_VERSION 1u
#define FRACTAL_XFER_SIGNED_PLAN_VERSION 2u
#define FRACTAL_XFER_BLOCK_BYTES 4096u
/* The physical boot-marker variant leaves the terminal partition block
 * untouched, including any historical filesystem backup boot sector. */
#define FRACTAL_XFER_MARKER_END_GUARD_BLOCKS 1u
#define FRACTAL_XFER_CRASH_RING_BLOCKS 16u
#define FRACTAL_XFER_EVENT_RING_BLOCKS 16u
#define FRACTAL_XFER_BLOCK_COUNT (4u + FRACTAL_XFER_CRASH_RING_BLOCKS + FRACTAL_XFER_EVENT_RING_BLOCKS)
#define FRACTAL_XFER_CRASH_OFFSET 5u
#define FRACTAL_XFER_EVENT_OFFSET (FRACTAL_XFER_CRASH_OFFSET + FRACTAL_XFER_CRASH_RING_BLOCKS)
#define FRACTAL_XFER_PLAN_OFFSET 4u
#define FRACTAL_XFER_WITNESS_OFFSET 3u
#define FRACTAL_XFER_RESULT_OFFSET 2u
#define FRACTAL_XFER_COMPLETE_OFFSET 1u

#define FRACTAL_XFER_PLAN_HEADER_BYTES 128u
#define FRACTAL_XFER_SIGNED_PLAN_HEADER_BYTES 192u
#define FRACTAL_XFER_RESULT_HEADER_BYTES 196u
#define FRACTAL_XFER_COMPLETE_HEADER_BYTES 128u

#define FRACTAL_XFER_PLAN_MAGIC "FRXPLAN1"
#define FRACTAL_XFER_SIGNED_PLAN_MAGIC "FRXPLAN2"
#define FRACTAL_XFER_RESULT_MAGIC "FRXRESL1"
#define FRACTAL_XFER_COMPLETE_MAGIC "FRXCMIT1"
#define FRACTAL_XFER_CRASH_MAGIC "FRXCRSH1"
#define FRACTAL_XFER_EVENT_MAGIC "FRXEVNT1"
#define FRACTAL_XFER_PANIC_STEP 0x200u

/* PLAN: magic[0:8], version[8:12], JSON length[12:16], run ID[16:32],
 * image SHA-256[32:64], JSON SHA-256[64:96], header SHA-256[96:128],
 * canonical test-plan JSON[128:128+length], zero padding. Header digest
 * covers bytes [0,96). Supported v1 tests are native-alive and native-panic. */
#define FRACTAL_XFER_PLAN_JSON_OFFSET 128u

/* SIGNED PLAN v2: same identity and hashes in [0,128), but magic/version 2;
 * Ed25519 signature[128:192] covers bytes [0,96), and canonical JSON starts
 * at byte 192. The public verification key is fixed in the native image.
 * This authenticates the Omarchy plan, not the image measurement or result. */
#define FRACTAL_XFER_SIGNED_PLAN_SIGNATURE_OFFSET 128u
#define FRACTAL_XFER_SIGNED_PLAN_JSON_OFFSET 192u

/* RESULT: magic[0:8], version[8:12], status[12:16], run ID[16:32],
 * plan SHA-256[32:64], image SHA-256[64:96], witness SHA-256[96:128],
 * final JSON length[128:132], final JSON SHA-256[132:164],
 * header SHA-256[164:196], final JSON[196:196+length], zero padding.
 * Header digest covers bytes [0,164). Status zero means pass. */
#define FRACTAL_XFER_RESULT_JSON_OFFSET 196u

/* COMPLETE: magic[0:8], version[8:12], reserved zero[12:16],
 * run ID[16:32], full result-block SHA-256[32:64],
 * plan JSON SHA-256[64:96], header SHA-256[96:128], zero padding.
 * Header digest covers bytes [0,96). It is committed only after RESULT flush. */

/* CRASH: magic[0:8], version[8:12], reason=1[12:16], run ID[16:32],
 * plan SHA-256[32:64], image SHA-256[64:96], header SHA-256[96:128],
 * zero padding. Slot 0 is immediately before PLAN; later slots descend
 * toward lower LBAs. Each slot is written at most once, flushed and read
 * back before the deliberate fault. A full or corrupt ring rejects new runs. */

/* EVENT: magic[0:8], version[8:12], kind=1 plan admitted[12:16],
 * run ID[16:32], plan SHA-256[32:64], image SHA-256[64:96], prior full
 * event-block SHA-256[96:128], header SHA-256[128:160], zero padding.
 * Slot 0 begins before the crash ring and later slots descend toward lower
 * LBAs. Each event is flushed and read back before the crash record. */

#endif
