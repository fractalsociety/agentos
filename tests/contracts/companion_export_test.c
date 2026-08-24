/* Companion export v1.1 contract and transport behavior tests. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../kernel/agentos-root-task/include/contracts/companion_export_contract.h"

struct companion_fixture {
    uint32_t grants;
    uint64_t epoch;
    uint32_t stream_id;
    companion_object_id_t root;
    uint64_t oldest_seq;
    uint64_t newest_seq;
    uint64_t max_position;
    uint8_t arena[COMPANION_RESULT_ARENA_BYTES];
};

static void bytes_zero(void *ptr, size_t len)
{
    uint8_t *out = (uint8_t *)ptr;
    for (size_t i = 0u; i < len; i++) out[i] = 0u;
}

static void bytes_copy(void *dst_ptr, const void *src_ptr, size_t len)
{
    uint8_t *dst = (uint8_t *)dst_ptr;
    const uint8_t *src = (const uint8_t *)src_ptr;
    for (size_t i = 0u; i < len; i++) dst[i] = src[i];
}

static companion_object_id_t object_id(uint8_t seed)
{
    companion_object_id_t id;
    for (uint32_t i = 0u; i < COMPANION_OBJECT_ID_BYTES; i++)
        id.bytes[i] = (uint8_t)(seed + i);
    return id;
}

static void fixture_init(struct companion_fixture *fixture, uint32_t grants)
{
    bytes_zero(fixture, sizeof(*fixture));
    fixture->grants = grants;
    fixture->epoch = 9u;
    fixture->stream_id = 4u;
    fixture->root = object_id(0x20u);
    fixture->oldest_seq = 10u;
    fixture->newest_seq = 90u;
    fixture->max_position = 20u;
}

static companion_request_header_t request_header(uint32_t bytes)
{
    companion_request_header_t header;
    bytes_zero(&header, sizeof(header));
    header.abi_major = COMPANION_SCHEMA_MAJOR;
    header.abi_minor = COMPANION_SCHEMA_MINOR;
    header.request_bytes = bytes;
    header.result.offset = 8u;
    header.result.capacity = COMPANION_MAX_RESULT_BYTES;
    return header;
}

static companion_event_cursor_t live_cursor(const struct companion_fixture *fixture,
                                            uint32_t projection)
{
    companion_event_cursor_t cursor;
    bytes_zero(&cursor, sizeof(cursor));
    cursor.event_seq = 42u;
    cursor.authority_epoch = fixture->epoch;
    cursor.stream_id = fixture->stream_id;
    cursor.schema_major = COMPANION_SCHEMA_MAJOR;
    cursor.schema_minor = COMPANION_SCHEMA_MINOR;
    cursor.projection = projection;
    cursor.position = 3u;
    cursor.root = fixture->root;
    return cursor;
}

static uint32_t required_grant(uint32_t opcode)
{
    switch (opcode) {
    case MSG_COMPANION_LIST_PROJECTS: return COMPANION_GRANT_PROJECT;
    case MSG_COMPANION_LIST_PROGRESS: return COMPANION_GRANT_PROGRESS;
    case MSG_COMPANION_GET_DAILY_ROOT: return COMPANION_GRANT_DAILY_ROOT;
    case MSG_COMPANION_GET_HEALTH_ADAPTER: return COMPANION_GRANT_HEALTH;
    case MSG_COMPANION_LIST_WORKER_MEMORY: return COMPANION_GRANT_WORKER_MEMORY;
    case MSG_COMPANION_SUBMIT_TASK_INTENT: return COMPANION_GRANT_TASK_INTENT;
    default: return 0u;
    }
}

static uint32_t projection_for(uint32_t opcode)
{
    switch (opcode) {
    case MSG_COMPANION_LIST_PROJECTS: return COMPANION_PROJECTION_PROJECT;
    case MSG_COMPANION_LIST_PROGRESS: return COMPANION_PROJECTION_PROGRESS;
    case MSG_COMPANION_GET_DAILY_ROOT: return COMPANION_PROJECTION_DAILY_ROOT;
    case MSG_COMPANION_GET_HEALTH_ADAPTER: return COMPANION_PROJECTION_HEALTH;
    case MSG_COMPANION_LIST_WORKER_MEMORY: return COMPANION_PROJECTION_WORKER_MEMORY;
    case MSG_COMPANION_SUBMIT_TASK_INTENT: return COMPANION_PROJECTION_TASK_INTENT;
    default: return 0u;
    }
}

static uint32_t record_type_for(uint32_t opcode)
{
    switch (opcode) {
    case MSG_COMPANION_DESCRIBE: return COMPANION_WIRE_SESSION;
    case MSG_COMPANION_LIST_PROJECTS: return COMPANION_WIRE_PROJECT_PAGE;
    case MSG_COMPANION_LIST_PROGRESS: return COMPANION_WIRE_PROGRESS_PAGE;
    case MSG_COMPANION_GET_DAILY_ROOT: return COMPANION_WIRE_DAILY_ROOT;
    case MSG_COMPANION_GET_HEALTH_ADAPTER: return COMPANION_WIRE_HEALTH_ADAPTER_SUMMARY;
    case MSG_COMPANION_LIST_WORKER_MEMORY: return COMPANION_WIRE_WORKER_MEMORY_PAGE;
    case MSG_COMPANION_SUBMIT_TASK_INTENT: return COMPANION_WIRE_TASK_INTENT_RECEIPT;
    default: return 0u;
    }
}

static uint32_t record_payload_bytes_for(uint32_t opcode)
{
    switch (opcode) {
    case MSG_COMPANION_DESCRIBE: return sizeof(companion_wire_session_t);
    case MSG_COMPANION_LIST_PROJECTS: return sizeof(companion_wire_project_page_t);
    case MSG_COMPANION_LIST_PROGRESS: return sizeof(companion_wire_progress_page_t);
    case MSG_COMPANION_GET_DAILY_ROOT: return sizeof(companion_wire_daily_root_t);
    case MSG_COMPANION_GET_HEALTH_ADAPTER: return sizeof(companion_wire_health_adapter_summary_t);
    case MSG_COMPANION_LIST_WORKER_MEMORY:
        return sizeof(companion_wire_worker_memory_page_t);
    case MSG_COMPANION_SUBMIT_TASK_INTENT:
        return sizeof(companion_wire_task_intent_receipt_t);
    default: return 0u;
    }
}

static uint32_t fixture_page_status(const companion_page_request_t *page,
                                    const companion_request_header_t *header)
{
    companion_limits_t limits;
    bytes_zero(&limits, sizeof(limits));
    limits.max_page_items = COMPANION_MAX_PAGE_ITEMS;
    limits.max_result_bytes = COMPANION_MAX_RESULT_BYTES;
    if (!companion_page_valid(page, &limits) || page->max_bytes > header->result.capacity)
        return COMPANION_EXPORT_ERR_RESULT_TOO_LARGE;
    return COMPANION_EXPORT_OK;
}

static uint32_t fixture_dispatch(struct companion_fixture *fixture,
                                 uint32_t opcode,
                                 uint32_t request_offset,
                                 uint32_t frame_bytes,
                                 companion_reply_t *reply)
{
    const void *frame;
    companion_request_header_t header;
    uint64_t epoch = fixture->epoch;
    companion_event_cursor_t cursor;
    bool has_cursor = false;
    bytes_zero(reply, sizeof(*reply));
    reply->abi_major = COMPANION_SCHEMA_MAJOR;
    reply->abi_minor = COMPANION_SCHEMA_MINOR;
    reply->authority_epoch = fixture->epoch;

    if ((request_offset & (COMPANION_ABI_ALIGNMENT - 1u)) != 0u
        || frame_bytes == 0u
        || frame_bytes > COMPANION_MAX_REQUEST_BYTES
        || request_offset > COMPANION_RESULT_ARENA_BYTES - frame_bytes) {
        reply->status = COMPANION_EXPORT_ERR_INVALID;
        return reply->status;
    }
    frame = &fixture->arena[request_offset];

    if (opcode == MSG_COMPANION_DESCRIBE
        && frame_bytes == sizeof(struct companion_req_describe_v1_0)) {
        struct companion_req_describe_v1_0 legacy;
        bytes_copy(&legacy, frame, sizeof(legacy));
        reply->status = companion_schema_supported(
            legacy.requested,
            (companion_schema_version_t){COMPANION_SCHEMA_MAJOR,
                                         COMPANION_SCHEMA_MINOR},
            COMPANION_SCHEMA_MIN_MINOR)
            ? COMPANION_EXPORT_OK
            : COMPANION_EXPORT_ERR_UNSUPPORTED_SCHEMA;
        return reply->status;
    }

    if (frame_bytes < sizeof(header)) {
        reply->status = COMPANION_EXPORT_ERR_INVALID;
        return reply->status;
    }
    bytes_copy(&header, frame, sizeof(header));
    if (header.abi_major != COMPANION_SCHEMA_MAJOR
        || header.abi_minor > COMPANION_SCHEMA_MINOR) {
        reply->status = COMPANION_EXPORT_ERR_UNSUPPORTED_SCHEMA;
        return reply->status;
    }
    if (header.request_bytes != frame_bytes
        || !companion_request_transport_valid(request_offset, frame_bytes,
                                              &header.result)) {
        reply->status = COMPANION_EXPORT_ERR_INVALID;
        return reply->status;
    }

    if (opcode == MSG_COMPANION_DESCRIBE) {
        struct companion_req_describe req;
        if (frame_bytes != sizeof(req)) goto invalid;
        bytes_copy(&req, frame, sizeof(req));
        if (!companion_schema_supported(
                req.requested,
                (companion_schema_version_t){COMPANION_SCHEMA_MAJOR,
                                             COMPANION_SCHEMA_MINOR},
                COMPANION_SCHEMA_MIN_MINOR)) {
            reply->status = COMPANION_EXPORT_ERR_UNSUPPORTED_SCHEMA;
            return reply->status;
        }
    } else if ((fixture->grants & required_grant(opcode)) == 0u) {
        reply->status = COMPANION_EXPORT_ERR_DENIED;
        return reply->status;
    } else {
        switch (opcode) {
        case MSG_COMPANION_LIST_PROJECTS: {
            struct companion_req_list_projects req;
            if (frame_bytes != sizeof(req)) goto invalid;
            bytes_copy(&req, frame, sizeof(req));
            if (fixture_page_status(&req.page, &req.header) != COMPANION_EXPORT_OK) {
                reply->status = COMPANION_EXPORT_ERR_RESULT_TOO_LARGE;
                return reply->status;
            }
            epoch = req.authority_epoch;
            has_cursor = req.page.has_cursor != 0u;
            cursor = req.page.cursor;
            break;
        }
        case MSG_COMPANION_LIST_PROGRESS: {
            struct companion_req_list_progress req;
            if (frame_bytes != sizeof(req)) goto invalid;
            bytes_copy(&req, frame, sizeof(req));
            if (fixture_page_status(&req.page, &req.header) != COMPANION_EXPORT_OK) {
                reply->status = COMPANION_EXPORT_ERR_RESULT_TOO_LARGE;
                return reply->status;
            }
            epoch = req.authority_epoch;
            has_cursor = req.page.has_cursor != 0u;
            cursor = req.page.cursor;
            break;
        }
        case MSG_COMPANION_GET_DAILY_ROOT: {
            struct companion_req_get_daily_root req;
            if (frame_bytes != sizeof(req)) goto invalid;
            bytes_copy(&req, frame, sizeof(req));
            epoch = req.authority_epoch;
            if (req.date_len != COMPANION_MAX_DATE_BYTES
                || req.timezone_len == 0u
                || req.timezone_len > COMPANION_MAX_TIMEZONE_BYTES)
                goto invalid;
            break;
        }
        case MSG_COMPANION_GET_HEALTH_ADAPTER: {
            struct companion_req_get_health_adapter req;
            if (frame_bytes != sizeof(req)) goto invalid;
            bytes_copy(&req, frame, sizeof(req));
            epoch = req.authority_epoch;
            break;
        }
        case MSG_COMPANION_LIST_WORKER_MEMORY: {
            struct companion_req_list_worker_memory req;
            if (frame_bytes != sizeof(req)) goto invalid;
            bytes_copy(&req, frame, sizeof(req));
            if (fixture_page_status(&req.page, &req.header) != COMPANION_EXPORT_OK) {
                reply->status = COMPANION_EXPORT_ERR_RESULT_TOO_LARGE;
                return reply->status;
            }
            epoch = req.authority_epoch;
            has_cursor = req.page.has_cursor != 0u;
            cursor = req.page.cursor;
            break;
        }
        case MSG_COMPANION_SUBMIT_TASK_INTENT: {
            struct companion_req_submit_task_intent req;
            if (frame_bytes != sizeof(req)) goto invalid;
            bytes_copy(&req, frame, sizeof(req));
            epoch = req.intent.authority_epoch;
            has_cursor = true;
            cursor = req.intent.cursor;
            if (req.intent.note_len > COMPANION_MAX_NOTE_BYTES) goto invalid;
            break;
        }
        default:
            goto invalid;
        }
    }

    if (epoch != fixture->epoch) {
        reply->status = COMPANION_EXPORT_ERR_STALE_AUTHORITY;
        return reply->status;
    }
    if (has_cursor) {
        companion_cursor_binding_t binding;
        bytes_zero(&binding, sizeof(binding));
        binding.schema.major = COMPANION_SCHEMA_MAJOR;
        binding.schema.minor = COMPANION_SCHEMA_MINOR;
        binding.projection = projection_for(opcode);
        binding.stream_id = fixture->stream_id;
        binding.root = fixture->root;
        binding.authority_epoch = fixture->epoch;
        binding.oldest_retained_seq = fixture->oldest_seq;
        binding.newest_seq = fixture->newest_seq;
        binding.max_position = fixture->max_position;
        reply->status = companion_cursor_validate(&cursor, &binding);
        if (reply->status != COMPANION_EXPORT_OK) return reply->status;
    }

    uint32_t payload_bytes = record_payload_bytes_for(opcode);
    uint32_t result_bytes = sizeof(companion_wire_record_t) + payload_bytes;
    if (payload_bytes == 0u || result_bytes > header.result.capacity) {
        reply->status = COMPANION_EXPORT_ERR_RESULT_TOO_LARGE;
        return reply->status;
    }
    companion_wire_record_t record = {
        .record_type = record_type_for(opcode),
        .record_bytes = result_bytes,
        .field_count = 0u,
        .reserved = 0u,
    };
    bytes_copy(&fixture->arena[header.result.offset], &record, sizeof(record));
    bytes_zero(&fixture->arena[header.result.offset + sizeof(record)], payload_bytes);
    reply->status = COMPANION_EXPORT_OK;
    reply->result_offset = header.result.offset;
    reply->result_bytes = result_bytes;
    reply->item_count = opcode == MSG_COMPANION_DESCRIBE ? 1u : 0u;
    return reply->status;

invalid:
    reply->status = COMPANION_EXPORT_ERR_INVALID;
    return reply->status;
}

typedef struct {
    uint32_t opcode;
    uint32_t offset;
    uint32_t bytes;
} marshalled_request_t;

static marshalled_request_t marshal(struct companion_fixture *fixture,
                                    uint32_t opcode, const void *request,
                                    uint32_t bytes)
{
    const uint32_t request_offset = 32768u;
    bytes_copy(&fixture->arena[request_offset], request, bytes);
    return (marshalled_request_t){opcode, request_offset, bytes};
}

#ifdef AGENTOS_TEST_HOST
#include <stdio.h>
static unsigned test_count;
static unsigned failures;
static void check(bool ok, const char *name)
{
    test_count++;
    printf("%s %u - %s\n", ok ? "ok" : "not ok", test_count, name);
    if (!ok) failures++;
}
#else
#include "../harness/test_framework.h"
static void check(bool ok, const char *name)
{
    if (ok) _tf_ok(name);
    else _tf_fail_point(name, "companion contract behavior drift");
}
#endif

static void run_suite(void)
{
    static struct companion_fixture fixture;
    companion_reply_t reply;
    fixture_init(&fixture, 0u);

    struct companion_req_describe describe;
    bytes_zero(&describe, sizeof(describe));
    describe.header = request_header(sizeof(describe));
    describe.requested = (companion_schema_version_t){1u, 1u};
    marshalled_request_t msg = marshal(&fixture, MSG_COMPANION_DESCRIBE,
                                      &describe, sizeof(describe));
    check(fixture_dispatch(&fixture, msg.opcode, msg.offset, msg.bytes, &reply)
              == COMPANION_EXPORT_OK
              && reply.result_bytes
                     == sizeof(companion_wire_record_t)
                        + sizeof(companion_wire_session_t),
          "v1.1 describe marshals into a checked result arena");

    struct companion_req_describe_v1_0 legacy = {
        .requested = {1u, 0u},
    };
    msg = marshal(&fixture, MSG_COMPANION_DESCRIBE, &legacy, sizeof(legacy));
    check(fixture_dispatch(&fixture, msg.opcode, msg.offset, msg.bytes, &reply)
              == COMPANION_EXPORT_OK,
          "v1.0 schema negotiation remains supported after the minor bump");

    describe.requested.major = 2u;
    msg = marshal(&fixture, MSG_COMPANION_DESCRIBE, &describe, sizeof(describe));
    check(fixture_dispatch(&fixture, msg.opcode, msg.offset, msg.bytes, &reply)
              == COMPANION_EXPORT_ERR_UNSUPPORTED_SCHEMA,
          "incompatible schema major is rejected");

    struct companion_req_list_projects projects;
    bytes_zero(&projects, sizeof(projects));
    projects.header = request_header(sizeof(projects));
    projects.authority_epoch = fixture.epoch;
    projects.page.max_items = 8u;
    projects.page.max_bytes = 1024u;
    projects.page.has_cursor = 1u;
    projects.page.cursor = live_cursor(&fixture, COMPANION_PROJECTION_PROJECT);

    struct companion_req_list_progress progress;
    bytes_zero(&progress, sizeof(progress));
    progress.header = request_header(sizeof(progress));
    progress.authority_epoch = fixture.epoch;
    progress.project_id = object_id(0x50u);
    progress.page = projects.page;
    progress.page.cursor.projection = COMPANION_PROJECTION_PROGRESS;

    struct companion_req_get_daily_root daily;
    bytes_zero(&daily, sizeof(daily));
    daily.header = request_header(sizeof(daily));
    daily.authority_epoch = fixture.epoch;
    daily.date_len = 10u;
    daily.timezone_len = 3u;
    bytes_copy(daily.date_key, "2026-08-24", 10u);
    bytes_copy(daily.timezone_key, "UTC", 3u);

    struct companion_req_get_health_adapter health;
    bytes_zero(&health, sizeof(health));
    health.header = request_header(sizeof(health));
    health.authority_epoch = fixture.epoch;

    struct companion_req_list_worker_memory workers;
    bytes_zero(&workers, sizeof(workers));
    workers.header = request_header(sizeof(workers));
    workers.authority_epoch = fixture.epoch;
    workers.page = projects.page;
    workers.page.cursor.projection = COMPANION_PROJECTION_WORKER_MEMORY;

    struct companion_req_submit_task_intent intent;
    bytes_zero(&intent, sizeof(intent));
    intent.header = request_header(sizeof(intent));
    intent.intent.schema = (companion_schema_version_t){1u, 1u};
    intent.intent.authority_epoch = fixture.epoch;
    intent.intent.cursor = live_cursor(&fixture, COMPANION_PROJECTION_TASK_INTENT);

#define DENIED_CASE(op, req, grant, label)                                      \
    do {                                                                         \
        companion_wire_record_t wire_record;                                    \
        msg = marshal(&fixture, (op), &(req), sizeof(req));                      \
        check(fixture_dispatch(&fixture, msg.opcode, msg.offset, msg.bytes, &reply)\
                  == COMPANION_EXPORT_ERR_DENIED,                               \
              "denied fixture rejects " label " without its grant");         \
        fixture.grants = (grant);                                                \
        uint32_t granted_status = fixture_dispatch(                              \
            &fixture, msg.opcode, msg.offset, msg.bytes, &reply);                \
        bytes_copy(&wire_record,                                                 \
                   &fixture.arena[(req).header.result.offset],                   \
                   sizeof(wire_record));                                         \
        check(granted_status                                                     \
                  == COMPANION_EXPORT_OK                                        \
                  && reply.result_offset == (req).header.result.offset          \
                  && reply.result_bytes <= (req).header.result.capacity          \
                  && wire_record.record_type == record_type_for(op)              \
                  && wire_record.record_bytes == reply.result_bytes,             \
              "granted fixture serves bounded " label " result");            \
        fixture.grants = 0u;                                                     \
    } while (0)

    DENIED_CASE(MSG_COMPANION_LIST_PROJECTS, projects,
                COMPANION_GRANT_PROJECT, "project");
    DENIED_CASE(MSG_COMPANION_LIST_PROGRESS, progress,
                COMPANION_GRANT_PROGRESS, "progress");
    DENIED_CASE(MSG_COMPANION_GET_DAILY_ROOT, daily,
                COMPANION_GRANT_DAILY_ROOT, "daily-root");
    DENIED_CASE(MSG_COMPANION_GET_HEALTH_ADAPTER, health,
                COMPANION_GRANT_HEALTH, "health");
    DENIED_CASE(MSG_COMPANION_LIST_WORKER_MEMORY, workers,
                COMPANION_GRANT_WORKER_MEMORY, "worker-memory");
    DENIED_CASE(MSG_COMPANION_SUBMIT_TASK_INTENT, intent,
                COMPANION_GRANT_TASK_INTENT, "task-intent");
#undef DENIED_CASE

    fixture.grants = COMPANION_GRANT_PROGRESS;
    companion_event_cursor_t original = progress.page.cursor;
#define STALE_CURSOR_CASE(field, value, label)                                  \
    do {                                                                         \
        progress.page.cursor = original;                                         \
        progress.page.cursor.field = (value);                                    \
        msg = marshal(&fixture, MSG_COMPANION_LIST_PROGRESS, &progress,          \
                      sizeof(progress));                                         \
        check(fixture_dispatch(&fixture, msg.opcode, msg.offset, msg.bytes, &reply)\
                  == COMPANION_EXPORT_ERR_STALE_CURSOR,                         \
              label);                                                            \
    } while (0)
    STALE_CURSOR_CASE(authority_epoch, fixture.epoch - 1u,
                      "stale authority epoch cursor is rejected");
    STALE_CURSOR_CASE(stream_id, fixture.stream_id + 1u,
                      "cross-stream cursor is rejected");
    STALE_CURSOR_CASE(schema_minor, 0u,
                      "cross-schema cursor is rejected");
    STALE_CURSOR_CASE(projection, COMPANION_PROJECTION_PROJECT,
                      "cross-projection cursor is rejected");
    STALE_CURSOR_CASE(event_seq, fixture.newest_seq + 1u,
                      "future sequence cursor is rejected");
    STALE_CURSOR_CASE(position, fixture.max_position + 1u,
                      "nonexistent deterministic progress position is rejected");
#undef STALE_CURSOR_CASE

    progress.page.cursor = original;
    progress.page.cursor.root = object_id(0xa0u);
    msg = marshal(&fixture, MSG_COMPANION_LIST_PROGRESS, &progress, sizeof(progress));
    check(fixture_dispatch(&fixture, msg.opcode, msg.offset, msg.bytes, &reply)
              == COMPANION_EXPORT_ERR_STALE_CURSOR,
          "cross-root cursor is rejected");

    workers.page.cursor = live_cursor(&fixture, COMPANION_PROJECTION_WORKER_MEMORY);
    workers.page.max_items = COMPANION_MAX_PAGE_ITEMS + 1u;
    fixture.grants = COMPANION_GRANT_WORKER_MEMORY;
    msg = marshal(&fixture, MSG_COMPANION_LIST_WORKER_MEMORY, &workers,
                  sizeof(workers));
    check(fixture_dispatch(&fixture, msg.opcode, msg.offset, msg.bytes, &reply)
              == COMPANION_EXPORT_ERR_RESULT_TOO_LARGE,
          "page above negotiated item limit is rejected, never truncated");

    workers.page.max_items = 1u;
    workers.page.max_bytes = COMPANION_MAX_RESULT_BYTES;
    workers.header.result.capacity = 512u;
    msg = marshal(&fixture, MSG_COMPANION_LIST_WORKER_MEMORY, &workers,
                  sizeof(workers));
    check(fixture_dispatch(&fixture, msg.opcode, msg.offset, msg.bytes, &reply)
              == COMPANION_EXPORT_ERR_RESULT_TOO_LARGE,
          "page cannot exceed its granted result slice capacity");

    projects.header.result.offset = 3u;
    fixture.grants = COMPANION_GRANT_PROJECT;
    msg = marshal(&fixture, MSG_COMPANION_LIST_PROJECTS, &projects, sizeof(projects));
    check(fixture_dispatch(&fixture, msg.opcode, msg.offset, msg.bytes, &reply)
              == COMPANION_EXPORT_ERR_INVALID,
          "unaligned result arena is rejected before projection");

    projects.header.result.offset = COMPANION_RESULT_ARENA_BYTES - 8u;
    projects.header.result.capacity = 16u;
    msg = marshal(&fixture, MSG_COMPANION_LIST_PROJECTS, &projects, sizeof(projects));
    check(fixture_dispatch(&fixture, msg.opcode, msg.offset, msg.bytes, &reply)
              == COMPANION_EXPORT_ERR_INVALID,
          "out-of-bounds result arena is rejected before projection");

    projects.header.result.offset = 8u;
    projects.header.result.capacity = COMPANION_MAX_RESULT_BYTES;
    msg = marshal(&fixture, MSG_COMPANION_LIST_PROJECTS, &projects, sizeof(projects));
    check(fixture_dispatch(&fixture, msg.opcode, msg.offset + 1u, msg.bytes, &reply)
              == COMPANION_EXPORT_ERR_INVALID,
          "unaligned marshalled request slice is rejected");

    projects.header.result.offset = 32768u;
    projects.header.result.capacity = 1024u;
    msg = marshal(&fixture, MSG_COMPANION_LIST_PROJECTS, &projects, sizeof(projects));
    check(fixture_dispatch(&fixture, msg.opcode, msg.offset, msg.bytes, &reply)
              == COMPANION_EXPORT_ERR_INVALID,
          "overlapping request and result slices are rejected");

    check(CH_COMPANION_EXPORT == 77u
              && CH_COMPANION_EXPORT != CH_GPU_SHMEM
              && CH_COMPANION_EXPORT != CH_DEBUG_BRIDGE
              && CH_COMPANION_EXPORT != CH_NET_ISOLATOR,
          "generated companion channel is unique in controller scope");
}

#ifdef AGENTOS_TEST_HOST
int main(void)
{
    puts("TAP version 14");
    run_suite();
    printf("1..%u\n", test_count);
    return failures == 0u ? 0 : 1;
}
#else
void run_companion_export_contract_tests(microkit_channel ch)
{
    (void)ch;
    TEST_SECTION("companion export v1.1 contract");
    run_suite();
}
#endif
