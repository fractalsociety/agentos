/* Freestanding compile-only ABI probe for both supported target architectures. */
#include <stddef.h>
#include <stdint.h>

#include "../../kernel/fractalos-root-task/include/contracts/companion_export_contract.h"

_Static_assert(sizeof(companion_event_cursor_t) == 72u,
               "target cursor layout");
_Static_assert(offsetof(companion_event_cursor_t, position) == 32u,
               "target cursor position layout");
_Static_assert(sizeof(companion_reply_t) == 112u,
               "target reply layout");
_Static_assert(sizeof(companion_wire_bytes_t) == 8u,
               "target string slice layout");
_Static_assert(sizeof(companion_wire_list_t) == 16u,
               "target list slice layout");
_Static_assert(_Alignof(companion_wire_daily_root_t) == COMPANION_ABI_ALIGNMENT,
               "target result record alignment");
_Static_assert(_Alignof(companion_wire_health_adapter_summary_t) == COMPANION_ABI_ALIGNMENT,
               "target health record alignment");
_Static_assert(_Alignof(companion_wire_worker_memory_t) == COMPANION_ABI_ALIGNMENT,
               "target worker record alignment");
