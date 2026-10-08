/* Clef boot progress v1: diagnostic telemetry, never allocation authority.
 * Complete ASCII records on the existing native diagnostic transport:
 * [clef_native] CLEF_BOOT v=1 stage=<name> done=<u64> total=<u64>
 * Stages, in order: starting (0/1), block_ready (1/1), loading (bytes),
 * backbone (0..32/32), routing (1..2/2), joint (1..4/4), checking (0/1),
 * ready (1/1). "failed" (0/1) is terminal from any stage.
 * Loading includes exactly CLEF_MODEL_BYTES, excluding media padding.
 * Layer counts mean completed layers, never estimated elapsed time.
 * ready qualifies this fixed test only, not a general inference service.
 * Consumers must require the full ordered trace and numerical test PASS.
 * Core boot budgets remain deterministic throughout; progress grants no caps.
 */
#ifndef AOS_CLEF_BOOT_H
#define AOS_CLEF_BOOT_H
#define CLEF_BOOT_VERSION 1u
#define CLEF_BOOT_PREFIX "CLEF_BOOT"
#endif
