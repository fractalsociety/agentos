/*
 * companion_export_test.c — contract-first tests for the companion gateway.
 *
 * These are intentionally red until the companion export PD exists.  They
 * exercise the complete request surface, authority denials, epoch/cursor
 * invalidation, result bounds, and schema negotiation through typed statuses.
 */

#include "../harness/test_framework.h"
#include "../../kernel/agentos-root-task/include/contracts/companion_export_contract.h"

static void companion_expect(microkit_channel ch,
                             uint64_t op,
                             uint64_t expected,
                             const char *name,
                             uint32_t words)
{
    microkit_mr_set(0, op);
    (void)microkit_ppcall(ch, microkit_msginfo_new(op, words));
    if (microkit_mr_get(0) == expected)
        _tf_ok(name);
    else
        _tf_fail_point(name, "companion gateway returned an unexpected typed status");
}

void run_companion_export_tests(microkit_channel ch)
{
    TEST_SECTION("companion_export");

    /* describe: a supported v1 client is accepted. */
    microkit_mr_set(1, COMPANION_SCHEMA_MAJOR);
    microkit_mr_set(2, COMPANION_SCHEMA_MINOR);
    companion_expect(ch, MSG_COMPANION_DESCRIBE, COMPANION_EXPORT_OK,
                     "companion: describe accepts compatible schema", 3);

    /* Major changes are never negotiated. */
    microkit_mr_set(1, COMPANION_SCHEMA_MAJOR + 1u);
    microkit_mr_set(2, COMPANION_SCHEMA_MINOR);
    companion_expect(ch, MSG_COMPANION_DESCRIBE,
                     COMPANION_EXPORT_ERR_UNSUPPORTED_SCHEMA,
                     "companion: describe rejects incompatible major", 3);

    /* Every projection request is denied without its explicit grant. */
    microkit_mr_set(1, 1u); /* authority epoch */
    companion_expect(ch, MSG_COMPANION_LIST_PROJECTS,
                     COMPANION_EXPORT_ERR_DENIED,
                     "companion: project export requires grant", 2);

    microkit_mr_set(1, 1u);
    companion_expect(ch, MSG_COMPANION_LIST_PROGRESS,
                     COMPANION_EXPORT_ERR_DENIED,
                     "companion: progress export requires grant", 2);

    microkit_mr_set(1, 1u);
    companion_expect(ch, MSG_COMPANION_GET_DAILY_ROOT,
                     COMPANION_EXPORT_ERR_DENIED,
                     "companion: daily-root export requires grant", 2);

    microkit_mr_set(1, 1u);
    companion_expect(ch, MSG_COMPANION_GET_HEALTH_ADAPTER,
                     COMPANION_EXPORT_ERR_DENIED,
                     "companion: health export requires grant", 2);

    microkit_mr_set(1, 1u);
    companion_expect(ch, MSG_COMPANION_LIST_WORKER_MEMORY,
                     COMPANION_EXPORT_ERR_DENIED,
                     "companion: worker-memory export requires grant", 2);

    /* A task intent is the sole mutation and has an independent grant. */
    microkit_mr_set(1, 1u); /* authority epoch in the bounded request */
    companion_expect(ch, MSG_COMPANION_SUBMIT_TASK_INTENT,
                     COMPANION_EXPORT_ERR_DENIED,
                     "companion: task intent requires grant", 2);

    /* A cursor minted before the current authority epoch is never resumed. */
    microkit_mr_set(1, 2u); /* current epoch */
    microkit_mr_set(2, 1u); /* has cursor */
    companion_expect(ch, MSG_COMPANION_LIST_PROJECTS,
                     COMPANION_EXPORT_ERR_STALE_CURSOR,
                     "companion: stale cursor is rejected", 3);

    /* A page over the negotiated result ceiling is rejected, not truncated. */
    microkit_mr_set(1, 2u);
    microkit_mr_set(2, COMPANION_MAX_PAGE_ITEMS + 1u);
    microkit_mr_set(3, COMPANION_MAX_RESULT_BYTES + 1u);
    companion_expect(ch, MSG_COMPANION_LIST_WORKER_MEMORY,
                     COMPANION_EXPORT_ERR_RESULT_TOO_LARGE,
                     "companion: oversized result is rejected", 4);
}

