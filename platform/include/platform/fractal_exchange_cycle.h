/* Transport-neutral, bounded Fractal plan/result cycle. The caller must
 * validate the partition and enforce an LBA bound in every I/O callback. */
#ifndef AOS_PLATFORM_FRACTAL_EXCHANGE_CYCLE_H
#define AOS_PLATFORM_FRACTAL_EXCHANGE_CYCLE_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    void *context;
    uint8_t *block; /* exactly 4096 writable bytes */
    bool (*read_block)(void *context, uint64_t block_index, uint8_t *block);
    bool (*write_block)(void *context, uint64_t block_index,
                        const uint8_t *block);
    bool (*flush)(void *context);
} fractal_exchange_io_t;

/* capacity_blocks is the first block after the authorized partition extent.
 * AGENTOS_FRACTAL_PERSISTENT_MARKER reserves the terminal guard block before
 * applying exchange offsets. Legacy exchange builds use the original end.
 * Returns 2 on success, FRACTAL_XFER_PANIC_STEP after a verified crash
 * record, otherwise the exchange v1 rejection/error step. */
uint32_t fractal_exchange_cycle_run(const fractal_exchange_io_t *io,
                                    uint64_t capacity_blocks);

#endif
