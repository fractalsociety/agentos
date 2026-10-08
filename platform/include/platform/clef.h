/* Bounded Clef-Flash text inference. No OS, device, allocation or IPC API. */
#ifndef AOS_CLEF_H
#define AOS_CLEF_H
#include <stddef.h>
#include <stdint.h>

#define CLEF_MAX_TOKENS 512u
#define CLEF_MAX_OPTIONS 4u
#define CLEF_MODEL_BYTES UINT64_C(6486448288)
#define CLEF_MODEL_VA UINT64_C(0x200000000)
#define CLEF_ARENA_VA (CLEF_MODEL_VA + UINT64_C(0x1c0000000))
#define CLEF_ARENA_BYTES UINT64_C(0x40000000)

typedef struct { uint32_t begin, end; } clef_span;
typedef struct {
    uint32_t count, options;
    uint32_t tokens[CLEF_MAX_TOKENS];
    clef_span question, option[CLEF_MAX_OPTIONS];
} clef_input;
typedef struct {
    float logits[CLEF_MAX_OPTIONS], probabilities[CLEF_MAX_OPTIONS];
    uint32_t choice;
} clef_result;
typedef void (*clef_progress)(void *context, const char *stage, unsigned layer);
_Static_assert(sizeof(clef_input) == 2096u, "Rust Input ABI");
_Static_assert(sizeof(clef_result) == 36u, "Rust Scores ABI");

/* Rust FFI. Caller provides disjoint valid regions for this entire call.
 * One call per native PD boot; the arena stays exclusively owned by Rust.
 * 0 success; 1 format; 2 shape; 3 input; 4 nonfinite; 5 heap initialization. */
uint32_t clef_rust_run(const uint8_t *, size_t, const clef_input *,
                      uint8_t *, size_t, clef_result *, clef_progress, void *);
#endif
