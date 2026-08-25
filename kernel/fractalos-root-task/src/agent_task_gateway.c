#include "contracts/agent_harness_contract.h"
#include "contracts/eventbus_contract.h"
#include "contracts/mesh_agent_contract.h"
#include "agent_task_gateway.h"

#include <stdbool.h>
#include <stddef.h>

#if defined(__GNUC__)
__attribute__((weak)) uint32_t fractalos_eventbus_record(
    struct eventbus_agent_event *event)
{
    (void)event;
    return EVENTBUS_AGENT_EVENT_OK;
}
#else
extern uint32_t fractalos_eventbus_record(struct eventbus_agent_event *event);
#endif

static struct {
    uint8_t *arena;
    uint32_t arena_size;
    agent_task_submit_fn submit;
    agent_task_metrics_fn metrics;
    agent_task_authority_fn authority;
    void *ctx;
    uint32_t next_task_id;
    uint32_t task_id;
    uint32_t required_caps;
    uint32_t task_flags;
    uint32_t max_steps;
    uint32_t prompt_len;
    uint32_t received_len;
    uint32_t result_capacity;
    uint32_t result_len;
    uint32_t available_caps;
    uint32_t authority_epoch;
    uint32_t harness_status;
    uint32_t state;
    bool active;
    bool ran;
    eventbus_event_hash_t scope_id;
    eventbus_event_hash_t event_head;
    struct harness_reply_result last_metrics;
} g_task;

struct fractal_gateway_state {
    bool program_valid;
    bool task_valid;
    struct agent_task_program_ref program_ref;
    struct agent_task_program_handle program;
    struct agent_task_handle task;
    struct agent_task_budget budget;
    struct agent_task_budget remaining;
    struct agent_task_worker_identity worker;
    uint32_t program_state;
    uint32_t state;
    uint32_t terminal_code;
    uint32_t result_kind;
    uint32_t verify_status;
    uint32_t evidence_sequence;
    uint32_t evidence_unconsumed; /* 1 while successful TASK_VERIFY may commit */
    uint32_t authority_epoch;
    uint32_t task_flags;
    uint32_t result_bytes;
    uint64_t owner_badge;
    struct agent_task_verify_evidence pending_evidence;
    eventbus_event_hash_t result_digest;
    eventbus_event_hash_t scope_id;
    eventbus_event_hash_t event_head;
};

static struct fractal_gateway_state g_fractal;
static agent_task_enqueue_fn g_enqueue;

static void bytes_zero(void *dst, uint32_t len)
{
    uint8_t *p = (uint8_t *)dst;
    for (uint32_t i = 0u; i < len; i++) p[i] = 0u;
}

static void bytes_copy(void *dst, const void *src, uint32_t len)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (uint32_t i = 0u; i < len; i++) d[i] = s[i];
}

static int bytes_equal(const void *a, const void *b, uint32_t len)
{
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    for (uint32_t i = 0u; i < len; i++)
        if (x[i] != y[i])
            return 0;
    return 1;
}

static bool bytes_nonzero(const uint8_t *bytes, uint32_t length)
{
    uint8_t value = 0u;
    uint32_t i;
    for (i = 0u; i < length; i++) value |= bytes[i];
    return value != 0u;
}

static bool fractal_badge(uint64_t badge)
{
    return (badge & AGENT_TASK_GATEWAY_RIGHT) != 0u;
}

static bool fractal_owner(uint64_t badge)
{
    return g_fractal.owner_badge != 0u && badge == g_fractal.owner_badge;
}

static uint32_t fractal_authority_epoch(void)
{
    uint32_t caps = 0u, epoch = 0u;
    if (g_task.authority != (agent_task_authority_fn)0)
        g_task.authority(&caps, &epoch, g_task.ctx);
    (void)caps;
    return epoch;
}

static bool fractal_epoch_ok(uint32_t supplied)
{
    return supplied != 0u && supplied == fractal_authority_epoch();
}

static bool fractal_budget_ok(const struct agent_task_budget *budget)
{
    return budget != (const struct agent_task_budget *)0
        && budget->cpu_quanta != 0u
        && budget->cpu_quanta <= AGENT_TASK_MAX_CPU_QUANTA
        && budget->memory_bytes != 0u
        && budget->memory_bytes <= AGENT_TASK_MAX_MEMORY_BYTES
        && budget->max_steps != 0u
        && budget->max_steps <= AGENT_TASK_MAX_STEPS
        && budget->max_result_bytes != 0u
        && budget->max_result_bytes <= AGENT_TASK_MAX_RESULT_BYTES;
}

static eventbus_event_hash_t fractal_budget_hash(
    const struct agent_task_budget *budget)
{
    uint8_t bytes[24];
    eventbus_event_hash_t hash = {{0}};
    uint32_t i;

    for (i = 0u; i < 8u; i++) {
        bytes[i] = (uint8_t)(budget->cpu_quanta >> (i * 8u));
        bytes[8u + i] = (uint8_t)(budget->memory_bytes >> (i * 8u));
    }
    for (i = 0u; i < 4u; i++) {
        bytes[16u + i] = (uint8_t)(budget->max_steps >> (i * 8u));
        bytes[20u + i] = (uint8_t)(budget->max_result_bytes >> (i * 8u));
    }
    eventbus_event_hash_bytes(bytes, sizeof(bytes), &hash);
    return hash;
}

static eventbus_event_hash_t fractal_scope_hash(
    const struct agent_task_program_ref *program,
    const struct agent_task_handle *task)
{
    uint8_t bytes[AGENT_TASK_DIGEST_BYTES + 8u];
    eventbus_event_hash_t hash = {{0}};
    uint32_t i;

    bytes_copy(bytes, program->digest, AGENT_TASK_DIGEST_BYTES);
    for (i = 0u; i < 2u; i++) {
        uint32_t value = i == 0u ? task->slot : task->generation;
        bytes[AGENT_TASK_DIGEST_BYTES + i * 4u] = (uint8_t)value;
        bytes[AGENT_TASK_DIGEST_BYTES + i * 4u + 1u] =
            (uint8_t)(value >> 8u);
        bytes[AGENT_TASK_DIGEST_BYTES + i * 4u + 2u] =
            (uint8_t)(value >> 16u);
        bytes[AGENT_TASK_DIGEST_BYTES + i * 4u + 3u] =
            (uint8_t)(value >> 24u);
    }
    eventbus_event_hash_bytes(bytes, sizeof(bytes), &hash);
    return hash;
}

static bool fractal_program_handle_ok(const struct agent_task_program_handle *h)
{
    return g_fractal.program_valid && h != (const struct agent_task_program_handle *)0
        && h->slot == g_fractal.program.slot
        && h->generation == g_fractal.program.generation;
}

static uint32_t fractal_task_handle_status(const struct agent_task_handle *h)
{
    if (h == (const struct agent_task_handle *)0
            || h->slot == 0u || h->generation == 0u)
        return AGENT_TASK_ERR_NOT_FOUND;
    return g_fractal.task_valid && h->slot == g_fractal.task.slot
        && h->generation == g_fractal.task.generation
        ? AGENT_TASK_OK : AGENT_TASK_ERR_STALE_HANDLE;
}

static eventbus_event_hash_t fractal_handle_hash(const void *opaque_handle)
{
    uint8_t bytes[8];
    eventbus_event_hash_t hash = {{0}};
    const uint32_t *handle = (const uint32_t *)opaque_handle;
    uint32_t values[2] = {handle[0], handle[1]};
    uint32_t i;
    for (i = 0u; i < 2u; i++) {
        bytes[i * 4u] = (uint8_t)values[i];
        bytes[i * 4u + 1u] = (uint8_t)(values[i] >> 8u);
        bytes[i * 4u + 2u] = (uint8_t)(values[i] >> 16u);
        bytes[i * 4u + 3u] = (uint8_t)(values[i] >> 24u);
    }
    eventbus_event_hash_bytes(bytes, sizeof(bytes), &hash);
    return hash;
}

static uint32_t fractal_emit(uint32_t event_type, uint32_t flags,
                             const eventbus_event_hash_t *payload,
                             const eventbus_event_hash_t *evidence,
                             int32_t budget_delta, uint64_t *position)
{
    struct eventbus_agent_event event = {0};
    uint32_t status;
    if (!g_fractal.task_valid) return AGENT_TASK_ERR_NOT_FOUND;
    event.event_type = event_type;
    event.authority_epoch = g_fractal.authority_epoch;
    event.budget_delta = budget_delta;
    event.flags = flags | EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE;
    event.scope_id = g_fractal.scope_id;
    event.task_id = fractal_handle_hash(&g_fractal.task);
    event.causal_parent = g_fractal.event_head;
    if (payload != (const eventbus_event_hash_t *)0) event.payload_root = *payload;
    if (evidence != (const eventbus_event_hash_t *)0) event.evidence_root = *evidence;
    status = fractalos_eventbus_record(&event);
    if (status == EVENTBUS_AGENT_EVENT_OK) {
        g_fractal.event_head = event.event_hash;
        if (position != (uint64_t *)0) *position = event.position;
    }
    return status;
}

static eventbus_event_hash_t gateway_task_hash(uint32_t task_id)
{
    uint8_t seed[8] = {'t', 'a', 's', 'k', 0u, 0u, 0u, 0u};
    eventbus_event_hash_t result = {{0}};
    seed[4] = (uint8_t)task_id;
    seed[5] = (uint8_t)(task_id >> 8u);
    seed[6] = (uint8_t)(task_id >> 16u);
    seed[7] = (uint8_t)(task_id >> 24u);
    eventbus_event_hash_bytes(seed, (uint32_t)sizeof(seed), &result);
    return result;
}

/* Hash fixed-width descriptors explicitly so the pinned context does not
 * depend on compiler padding or host endianness. */
static eventbus_event_hash_t gateway_descriptor_hash(
    uint32_t task_id, uint32_t required_caps, uint32_t task_flags,
    uint32_t max_steps, uint32_t prompt_len, uint32_t result_capacity)
{
    uint8_t descriptor[24];
    eventbus_event_hash_t result = {{0}};
    uint32_t values[6] = {task_id, required_caps, task_flags, max_steps,
                          prompt_len, result_capacity};
    uint32_t i;
    for (i = 0u; i < 6u; i++) {
        descriptor[i * 4u] = (uint8_t)values[i];
        descriptor[i * 4u + 1u] = (uint8_t)(values[i] >> 8u);
        descriptor[i * 4u + 2u] = (uint8_t)(values[i] >> 16u);
        descriptor[i * 4u + 3u] = (uint8_t)(values[i] >> 24u);
    }
    eventbus_event_hash_bytes(descriptor, (uint32_t)sizeof(descriptor),
                              &result);
    return result;
}

static eventbus_event_hash_t gateway_submit_hash(
    const struct harness_req_submit *submit)
{
    uint8_t descriptor[40];
    eventbus_event_hash_t result = {{0}};
    uint32_t values[10] = {
        submit->task_id, submit->harness_kind, submit->required_caps,
        submit->task_flags, submit->max_steps, submit->authority_epoch,
        submit->prompt_offset, submit->prompt_len, submit->result_offset,
        submit->result_capacity,
    };
    uint32_t i;
    for (i = 0u; i < 10u; i++) {
        descriptor[i * 4u] = (uint8_t)values[i];
        descriptor[i * 4u + 1u] = (uint8_t)(values[i] >> 8u);
        descriptor[i * 4u + 2u] = (uint8_t)(values[i] >> 16u);
        descriptor[i * 4u + 3u] = (uint8_t)(values[i] >> 24u);
    }
    eventbus_event_hash_bytes(descriptor, (uint32_t)sizeof(descriptor),
                              &result);
    return result;
}

static uint32_t gateway_emit(uint32_t event_type, uint32_t flags,
                             const eventbus_event_hash_t *payload_root,
                             const eventbus_event_hash_t *evidence_root,
                             int32_t budget_delta)
{
    struct eventbus_agent_event event;
    uint32_t status;

    /* The legacy host gateway can be tested without linking EventBus. */
    if (fractalos_eventbus_record == (void *)0)
        return EVENTBUS_AGENT_EVENT_OK;

    event = (struct eventbus_agent_event){0};
    event.event_type = event_type;
    event.authority_epoch = g_task.authority_epoch;
    event.budget_delta = budget_delta;
    event.flags = flags | EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE;
    event.scope_id = g_task.scope_id;
    event.task_id = gateway_task_hash(g_task.task_id);
    event.causal_parent = g_task.event_head;
    if (payload_root != (const eventbus_event_hash_t *)0)
        event.payload_root = *payload_root;
    if (evidence_root != (const eventbus_event_hash_t *)0)
        event.evidence_root = *evidence_root;

    status = fractalos_eventbus_record(&event);
    if (status == EVENTBUS_AGENT_EVENT_OK)
        g_task.event_head = event.event_hash;
    return status;
}

static uint32_t gateway_emit_bytes(uint32_t event_type, uint32_t flags,
                                   const uint8_t *bytes, uint32_t length)
{
    eventbus_event_hash_t payload = {{0}};
    eventbus_event_hash_bytes(bytes, length, &payload);
    return gateway_emit(event_type, flags, &payload,
                        (const eventbus_event_hash_t *)0, 0);
}

static bool gateway_ready(void)
{
    return g_task.arena != NULL && g_task.submit != NULL
        && g_task.metrics != NULL && g_task.authority != NULL
        && g_task.arena_size >= AGENT_TASK_RESULT_OFFSET
            + AGENT_TASK_RESULT_CAP;
}

void agent_task_gateway_init(uint8_t *arena, uint32_t arena_size,
                             agent_task_submit_fn submit,
                             agent_task_metrics_fn metrics,
                             agent_task_authority_fn authority, void *ctx)
{
    bytes_zero(&g_task, sizeof(g_task));
    g_task.arena = arena;
    g_task.arena_size = arena_size;
    g_task.submit = submit;
    g_task.metrics = metrics;
    g_task.authority = authority;
    g_task.ctx = ctx;
    g_task.next_task_id = 1u;
    bytes_zero(&g_fractal, sizeof(g_fractal));
    g_enqueue = (agent_task_enqueue_fn)0;
}

void agent_task_gateway_set_enqueue(agent_task_enqueue_fn enqueue)
{
    g_enqueue = enqueue;
}

uint32_t agent_task_gateway_program_open(
    uint64_t badge, const struct agent_task_req_program_open *req,
    struct agent_task_reply_program_open *reply)
{
    if (reply == (struct agent_task_reply_program_open *)0)
        return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!fractal_badge(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (!gateway_ready() || req == (const struct agent_task_req_program_open *)0
            || req->program.interface_version != AGENT_TASK_FRACTAL_V1_VERSION
            || req->program.program_version == 0u
            || !bytes_nonzero(req->program.digest, AGENT_TASK_DIGEST_BYTES)
            || !fractal_epoch_ok(req->authority_epoch)
            || req->nonblocking != AGENT_TASK_NONBLOCKING)
        return reply->status = !fractal_epoch_ok(req != (const struct agent_task_req_program_open *)0
                                                  ? req->authority_epoch : 0u)
            ? AGENT_TASK_ERR_AUTHORITY : AGENT_TASK_ERR_INVALID;
    if (g_fractal.program_valid)
        return reply->status = AGENT_TASK_ERR_BUSY;

    g_fractal.program_valid = true;
    g_fractal.program_ref = req->program;
    g_fractal.program = (struct agent_task_program_handle){1u, 1u};
    g_fractal.program_state = AGENT_TASK_PROGRAM_READY;
    g_fractal.owner_badge = badge;
    g_fractal.authority_epoch = req->authority_epoch;
    g_fractal.worker = (struct agent_task_worker_identity){
        AGENT_TASK_WORKER_NATIVE, 0u, 1u, 0u};
    reply->status = AGENT_TASK_OK;
    reply->program = g_fractal.program;
    reply->state = g_fractal.program_state;
    reply->authority_epoch = g_fractal.authority_epoch;
    reply->worker = g_fractal.worker;
    return AGENT_TASK_OK;
}

uint32_t agent_task_gateway_program_poll(
    uint64_t badge, const struct agent_task_req_program_poll *req,
    struct agent_task_reply_program_poll *reply)
{
    if (reply == (struct agent_task_reply_program_poll *)0)
        return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!fractal_badge(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (!fractal_owner(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (req == (const struct agent_task_req_program_poll *)0
            || req->nonblocking != AGENT_TASK_NONBLOCKING)
        return reply->status = AGENT_TASK_ERR_INVALID;
    if (!fractal_epoch_ok(req->authority_epoch))
        return reply->status = AGENT_TASK_ERR_AUTHORITY;
    if (!fractal_program_handle_ok(&req->program))
        return reply->status = AGENT_TASK_ERR_STALE_HANDLE;
    reply->status = AGENT_TASK_OK;
    reply->program = g_fractal.program;
    reply->state = g_fractal.program_state;
    reply->authority_epoch = req->authority_epoch;
    reply->worker = g_fractal.worker;
    return AGENT_TASK_OK;
}

uint32_t agent_task_gateway_submit(
    uint64_t badge, const struct agent_task_req_submit *req,
    struct agent_task_reply_submit *reply)
{
    eventbus_event_hash_t payload;
    uint32_t status;
    if (reply == (struct agent_task_reply_submit *)0)
        return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!fractal_badge(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (!fractal_owner(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (req == (const struct agent_task_req_submit *)0
            || req->nonblocking != AGENT_TASK_NONBLOCKING
            || req->reserved != 0u || !fractal_budget_ok(&req->budget))
        return reply->status = AGENT_TASK_ERR_INVALID;
    /* task_flags is a declaration, never a grant.  Reject unknown effect
     * bits so a caller cannot smuggle a capability outside the approved
     * AgentHarness subset through this boundary. */
    if ((req->task_flags
            & ~(HARNESS_TASK_ALLOW_PATCH | HARNESS_TASK_REQUIRE_TEST)) != 0u)
        return reply->status = AGENT_TASK_ERR_DENIED;
    if (!fractal_epoch_ok(req->authority_epoch))
        return reply->status = AGENT_TASK_ERR_AUTHORITY;
    if (!fractal_program_handle_ok(&req->program))
        return reply->status = AGENT_TASK_ERR_STALE_HANDLE;
    if (g_fractal.task_valid)
        return reply->status = AGENT_TASK_ERR_BUSY;

    g_fractal.task_valid = true;
    g_fractal.task = (struct agent_task_handle){1u, 1u};
    g_fractal.budget = req->budget;
    g_fractal.remaining = req->budget;
    g_fractal.task_flags = req->task_flags;
    g_fractal.state = AGENT_TASK_STATE_ACCEPTED;
    g_fractal.verify_status = AGENT_TASK_VERIFY_UNVERIFIED;
    g_fractal.evidence_sequence = 0u;
    g_fractal.evidence_unconsumed = 0u;
    bytes_zero(&g_fractal.pending_evidence, sizeof(g_fractal.pending_evidence));
    g_fractal.terminal_code = 0u;
    g_fractal.result_kind = AGENT_TASK_RESULT_NONE;
    g_fractal.result_bytes = 0u;
    g_fractal.owner_badge = badge;
    g_fractal.authority_epoch = req->authority_epoch;
    g_fractal.scope_id = fractal_scope_hash(&g_fractal.program_ref,
                                            &g_fractal.task);
    g_fractal.event_head = (eventbus_event_hash_t){{0}};
    payload = fractal_handle_hash(&g_fractal.program);
    status = fractal_emit(EVENTBUS_EVENT_NESTED_CALL,
                          EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE,
                          &payload, (const eventbus_event_hash_t *)0,
                          -(int32_t)req->budget.max_steps, (uint64_t *)0);
    if (status != EVENTBUS_AGENT_EVENT_OK) {
        g_fractal.task_valid = false;
        return reply->status = AGENT_TASK_ERR_HARNESS;
    }
    payload = fractal_budget_hash(&g_fractal.budget);
    status = fractal_emit(EVENTBUS_EVENT_BUDGET,
                          EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE,
                          &payload, (const eventbus_event_hash_t *)0,
                          -(int32_t)req->budget.max_steps, (uint64_t *)0);
    if (status != EVENTBUS_AGENT_EVENT_OK) {
        g_fractal.task_valid = false;
        return reply->status = AGENT_TASK_ERR_HARNESS;
    }
    if (g_enqueue != (agent_task_enqueue_fn)0) {
        status = g_enqueue(req, &g_fractal.task, g_task.ctx);
        if (status != AGENT_TASK_OK) {
            eventbus_event_hash_t failure;
            uint8_t failure_bytes[4];
            failure_bytes[0] = (uint8_t)status;
            failure_bytes[1] = (uint8_t)(status >> 8u);
            failure_bytes[2] = (uint8_t)(status >> 16u);
            failure_bytes[3] = (uint8_t)(status >> 24u);
            eventbus_event_hash_bytes(failure_bytes, sizeof(failure_bytes),
                                      &failure);
            g_fractal.state = AGENT_TASK_STATE_FAILED;
            g_fractal.terminal_code = status;
            g_fractal.result_kind = AGENT_TASK_RESULT_FAILURE;
            if (fractal_emit(EVENTBUS_EVENT_TASK,
                             EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE,
                             &failure, (const eventbus_event_hash_t *)0,
                             0, (uint64_t *)0) != EVENTBUS_AGENT_EVENT_OK)
                status = AGENT_TASK_ERR_HARNESS;
            reply->program = g_fractal.program;
            reply->task = g_fractal.task;
            reply->state = g_fractal.state;
            reply->authority_epoch = g_fractal.authority_epoch;
            reply->worker = g_fractal.worker;
            return reply->status = status;
        }
    }
    reply->status = AGENT_TASK_OK;
    reply->program = g_fractal.program;
    reply->task = g_fractal.task;
    reply->state = g_fractal.state;
    reply->authority_epoch = g_fractal.authority_epoch;
    reply->worker = g_fractal.worker;
    return AGENT_TASK_OK;
}

uint32_t agent_task_gateway_poll(
    uint64_t badge, const struct agent_task_req_poll *req,
    struct agent_task_reply_poll *reply)
{
    uint32_t status;
    if (reply == (struct agent_task_reply_poll *)0)
        return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!fractal_badge(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (!fractal_owner(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (req == (const struct agent_task_req_poll *)0
            || req->nonblocking != AGENT_TASK_NONBLOCKING)
        return reply->status = AGENT_TASK_ERR_INVALID;
    if (!fractal_epoch_ok(req->authority_epoch))
        return reply->status = AGENT_TASK_ERR_AUTHORITY;
    status = fractal_task_handle_status(&req->task);
    if (status != AGENT_TASK_OK) return reply->status = status;
    reply->status = AGENT_TASK_OK;
    reply->task = g_fractal.task;
    reply->state = g_fractal.state;
    reply->terminal_code = g_fractal.terminal_code;
    reply->authority_epoch = req->authority_epoch;
    reply->worker = g_fractal.worker;
    return AGENT_TASK_OK;
}

uint32_t agent_task_gateway_cancel(
    uint64_t badge, const struct agent_task_req_cancel *req,
    struct agent_task_reply_cancel *reply)
{
    eventbus_event_hash_t payload;
    uint32_t status;
    if (reply == (struct agent_task_reply_cancel *)0)
        return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!fractal_badge(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (!fractal_owner(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (req == (const struct agent_task_req_cancel *)0
            || req->nonblocking != AGENT_TASK_NONBLOCKING)
        return reply->status = AGENT_TASK_ERR_INVALID;
    if (!fractal_epoch_ok(req->authority_epoch))
        return reply->status = AGENT_TASK_ERR_AUTHORITY;
    status = fractal_task_handle_status(&req->task);
    if (status != AGENT_TASK_OK) return reply->status = status;
    if (g_fractal.state >= AGENT_TASK_STATE_COMPLETE)
        return reply->status = AGENT_TASK_ERR_TERMINAL;
    payload = fractal_handle_hash(&g_fractal.task);
    status = fractal_emit(EVENTBUS_EVENT_TASK,
                          EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE, &payload,
                          (const eventbus_event_hash_t *)0, 0, (uint64_t *)0);
    if (status != EVENTBUS_AGENT_EVENT_OK)
        return reply->status = AGENT_TASK_ERR_HARNESS;
    g_fractal.state = AGENT_TASK_STATE_CANCELLED;
    g_fractal.terminal_code = AGENT_TASK_ERR_CANCELLED;
    g_fractal.result_kind = AGENT_TASK_RESULT_FAILURE;
    reply->status = AGENT_TASK_OK;
    reply->task = g_fractal.task;
    reply->state = g_fractal.state;
    reply->authority_epoch = req->authority_epoch;
    return AGENT_TASK_OK;
}

uint32_t agent_task_gateway_budget(
    uint64_t badge, const struct agent_task_req_budget *req,
    struct agent_task_reply_budget *reply)
{
    uint32_t status;
    if (reply == (struct agent_task_reply_budget *)0)
        return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!fractal_badge(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (!fractal_owner(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (req == (const struct agent_task_req_budget *)0
            || req->nonblocking != AGENT_TASK_NONBLOCKING
            || !fractal_budget_ok(&req->budget))
        return reply->status = AGENT_TASK_ERR_INVALID;
    if (!fractal_epoch_ok(req->authority_epoch))
        return reply->status = AGENT_TASK_ERR_AUTHORITY;
    status = fractal_task_handle_status(&req->task);
    if (status != AGENT_TASK_OK) return reply->status = status;
    if (g_fractal.state >= AGENT_TASK_STATE_COMPLETE)
        return reply->status = AGENT_TASK_ERR_TERMINAL;
    eventbus_event_hash_t budget_root = fractal_budget_hash(&req->budget);
    int64_t budget_delta = (int64_t)req->budget.max_steps
        - (int64_t)g_fractal.budget.max_steps;
    if (budget_delta > INT32_MAX) budget_delta = INT32_MAX;
    if (budget_delta < INT32_MIN) budget_delta = INT32_MIN;
    status = fractal_emit(EVENTBUS_EVENT_BUDGET,
                          EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE,
                          &budget_root, (const eventbus_event_hash_t *)0,
                          (int32_t)budget_delta, (uint64_t *)0);
    if (status != EVENTBUS_AGENT_EVENT_OK)
        return reply->status = AGENT_TASK_ERR_HARNESS;
    g_fractal.budget = req->budget;
    g_fractal.remaining = req->budget;
    reply->status = AGENT_TASK_OK;
    reply->task = g_fractal.task;
    reply->remaining = g_fractal.remaining;
    reply->authority_epoch = req->authority_epoch;
    return AGENT_TASK_OK;
}

uint32_t agent_task_gateway_verify(
    uint64_t badge, const struct agent_task_req_verify *req,
    struct agent_task_reply_verify *reply)
{
    eventbus_event_hash_t evidence;
    uint32_t status;
    uint64_t position = 0u;
    if (reply == (struct agent_task_reply_verify *)0)
        return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!fractal_badge(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (!fractal_owner(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (req == (const struct agent_task_req_verify *)0
            || req->nonblocking != AGENT_TASK_NONBLOCKING)
        return reply->status = AGENT_TASK_ERR_INVALID;
    if (!fractal_epoch_ok(req->authority_epoch))
        return reply->status = AGENT_TASK_ERR_AUTHORITY;
    status = fractal_task_handle_status(&req->task);
    if (status != AGENT_TASK_OK) return reply->status = status;
    if (g_fractal.state != AGENT_TASK_STATE_COMPLETE)
        return reply->status = AGENT_TASK_ERR_VERIFY_REQUIRED;

    reply->task = g_fractal.task;
    reply->state = g_fractal.state;
    reply->authority_epoch = req->authority_epoch;

    /* v1 VERIFY is decode-only: never create commit/promotion authority. */
    if (req->evidence.evidence_version == AGENT_TASK_VERIFY_VERSION_V1) {
        reply->status = AGENT_TASK_ERR_PROMOTION_FORBIDDEN;
        reply->verify_status = AGENT_TASK_VERIFY_REJECTED;
        reply->feedback_code = AGENT_TASK_FEEDBACK_POLICY;
        return reply->status;
    }
    if (req->evidence.evidence_version != AGENT_TASK_VERIFY_VERSION_V2) {
        reply->status = AGENT_TASK_ERR_EVIDENCE_MISMATCH;
        reply->verify_status = AGENT_TASK_VERIFY_REJECTED;
        reply->feedback_code = AGENT_TASK_FEEDBACK_EVIDENCE_INCOMPLETE;
        return reply->status;
    }

    /* Repair-safe reject path: incomplete evidence never becomes commit fuel. */
    if (req->evidence.proof_level == AGENT_TASK_PROOF_NONE
            || req->evidence.test_count == 0u
            || !bytes_nonzero(req->evidence.commit_digest, AGENT_TASK_DIGEST_BYTES)
            || !bytes_nonzero(req->evidence.test_digest, AGENT_TASK_DIGEST_BYTES)
            || !bytes_nonzero(req->evidence.evidence_digest, AGENT_TASK_DIGEST_BYTES)) {
        reply->status = AGENT_TASK_OK;
        reply->verify_status = AGENT_TASK_VERIFY_REJECTED;
        reply->feedback_code = AGENT_TASK_FEEDBACK_EVIDENCE_INCOMPLETE;
        reply->evidence_sequence = 0u;
        g_fractal.verify_status = AGENT_TASK_VERIFY_REJECTED;
        g_fractal.evidence_unconsumed = 0u;
        return AGENT_TASK_OK;
    }

    eventbus_event_hash_bytes(req->evidence.commit_digest, AGENT_TASK_DIGEST_BYTES,
                              &evidence);
    status = fractal_emit(EVENTBUS_EVENT_TASK_VERIFY,
                          EVENTBUS_EVENT_FLAG_TASK_VERIFY_SUCCESS,
                          &evidence, &evidence, 0, &position);
    if (status != EVENTBUS_AGENT_EVENT_OK) {
        reply->status = AGENT_TASK_OK;
        reply->verify_status = AGENT_TASK_VERIFY_REJECTED;
        reply->feedback_code = AGENT_TASK_FEEDBACK_TESTS_FAILED;
        g_fractal.verify_status = AGENT_TASK_VERIFY_REJECTED;
        g_fractal.evidence_unconsumed = 0u;
        return AGENT_TASK_OK;
    }
    g_fractal.verify_status = AGENT_TASK_VERIFY_ACCEPTED;
    g_fractal.evidence_sequence = (uint32_t)position;
    g_fractal.evidence_unconsumed = 1u;
    g_fractal.pending_evidence = req->evidence;
    reply->status = AGENT_TASK_OK;
    reply->verify_status = AGENT_TASK_VERIFY_ACCEPTED;
    reply->evidence_sequence = g_fractal.evidence_sequence;
    reply->feedback_code = AGENT_TASK_FEEDBACK_NONE;
    return AGENT_TASK_OK;
}

uint32_t agent_task_gateway_commit(
    uint64_t badge, const struct agent_task_req_commit *req,
    struct agent_task_reply_commit *reply)
{
    uint32_t status;
    if (reply == (struct agent_task_reply_commit *)0)
        return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!fractal_badge(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (!fractal_owner(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (req == (const struct agent_task_req_commit *)0
            || req->nonblocking != AGENT_TASK_NONBLOCKING
            || !bytes_nonzero(req->candidate_root, AGENT_TASK_DIGEST_BYTES))
        return reply->status = AGENT_TASK_ERR_INVALID;
    if (!fractal_epoch_ok(req->authority_epoch))
        return reply->status = AGENT_TASK_ERR_AUTHORITY;
    status = fractal_task_handle_status(&req->task);
    if (status != AGENT_TASK_OK) return reply->status = status;
    if (g_fractal.state != AGENT_TASK_STATE_COMPLETE)
        return reply->status = AGENT_TASK_ERR_NOT_READY;
    if (g_fractal.verify_status != AGENT_TASK_VERIFY_ACCEPTED
            || g_fractal.evidence_unconsumed == 0u)
        return reply->status = AGENT_TASK_ERR_VERIFY_REQUIRED;
    if (req->evidence_sequence != g_fractal.evidence_sequence
            || !bytes_equal(req->candidate_root,
                            g_fractal.pending_evidence.commit_digest,
                            AGENT_TASK_DIGEST_BYTES))
        return reply->status = AGENT_TASK_ERR_EVIDENCE_MISMATCH;
    /* Successful matching evidence is single-use. */
    g_fractal.evidence_unconsumed = 0u;
    reply->status = AGENT_TASK_OK;
    reply->task = g_fractal.task;
    reply->state = g_fractal.state;
    reply->authority_epoch = req->authority_epoch;
    reply->evidence_sequence = g_fractal.evidence_sequence;
    reply->consumed = 1u;
    return AGENT_TASK_OK;
}

uint32_t agent_task_gateway_terminal_result(
    uint64_t badge, const struct agent_task_req_terminal_result *req,
    struct agent_task_reply_terminal_result *reply)
{
    uint32_t status;
    if (reply == (struct agent_task_reply_terminal_result *)0)
        return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!fractal_badge(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (!fractal_owner(badge)) return reply->status = AGENT_TASK_ERR_DENIED;
    if (req == (const struct agent_task_req_terminal_result *)0
            || req->nonblocking != AGENT_TASK_NONBLOCKING)
        return reply->status = AGENT_TASK_ERR_INVALID;
    if (!fractal_epoch_ok(req->authority_epoch))
        return reply->status = AGENT_TASK_ERR_AUTHORITY;
    status = fractal_task_handle_status(&req->task);
    if (status != AGENT_TASK_OK) return reply->status = status;
    if (g_fractal.state < AGENT_TASK_STATE_COMPLETE)
        return reply->status = AGENT_TASK_ERR_NOT_READY;
    reply->status = AGENT_TASK_OK;
    reply->task = g_fractal.task;
    reply->state = g_fractal.state;
    reply->result_kind = g_fractal.result_kind;
    reply->terminal_code = g_fractal.terminal_code;
    reply->result_bytes = g_fractal.result_bytes;
    reply->verify_status = g_fractal.verify_status;
    reply->worker = g_fractal.worker;
    bytes_copy(reply->result_digest, g_fractal.result_digest.bytes,
               AGENT_TASK_DIGEST_BYTES);
    return AGENT_TASK_OK;
}

void agent_task_gateway_authenticated_event(
    const struct eventbus_agent_event *event)
{
    eventbus_event_hash_t task_hash;
    eventbus_event_hash_t authenticated_hash;
    if (event == (const struct eventbus_agent_event *)0 || !g_fractal.task_valid)
        return;
    if (event->schema_version != EVENTBUS_AGENT_EVENT_SCHEMA_VERSION
            || !(event->flags & EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE)
            || (event->flags & EVENTBUS_EVENT_FLAG_PROMOTION_INTERNAL))
        return;
    eventbus_agent_event_hash(event, &authenticated_hash);
    if (!eventbus_event_hash_equal(&authenticated_hash, &event->event_hash))
        return;
    task_hash = fractal_handle_hash(&g_fractal.task);
    if (!eventbus_event_hash_equal(&task_hash, &event->task_id)
            || !eventbus_event_hash_equal(&g_fractal.scope_id,
                                          &event->scope_id))
        return;
    if (event->event_type == EVENTBUS_EVENT_AUTHORITY_CHANGE) {
        if (g_fractal.authority_epoch != UINT32_MAX
                && event->authority_epoch == g_fractal.authority_epoch + 1u) {
            g_fractal.authority_epoch = event->authority_epoch;
            g_fractal.state = AGENT_TASK_STATE_REVOKED;
            g_fractal.terminal_code = AGENT_TASK_ERR_REVOKED;
            g_fractal.result_kind = AGENT_TASK_RESULT_FAILURE;
        }
    } else if (event->authority_epoch != g_fractal.authority_epoch) {
        return;
    } else if (event->event_type == EVENTBUS_EVENT_TASK_VERIFY) {
        if (!(event->flags & EVENTBUS_EVENT_FLAG_TASK_VERIFY_SUCCESS)
                || eventbus_event_hash_zero(&event->payload_root)
                || eventbus_event_hash_zero(&event->evidence_root)
                || g_fractal.state != AGENT_TASK_STATE_COMPLETE
                || g_fractal.verify_status != AGENT_TASK_VERIFY_UNVERIFIED)
            return;
        g_fractal.verify_status = AGENT_TASK_VERIFY_ACCEPTED;
        g_fractal.evidence_sequence = (uint32_t)event->position;
    } else if (event->event_type == EVENTBUS_EVENT_EFFECT) {
        if (!(event->flags & EVENTBUS_EVENT_FLAG_EXTERNAL_EFFECT)
                || eventbus_event_hash_zero(&event->payload_root)
                || g_fractal.state >= AGENT_TASK_STATE_COMPLETE)
            return;
        g_fractal.state = AGENT_TASK_STATE_COMPLETE;
        g_fractal.result_kind = AGENT_TASK_RESULT_VALUE;
        g_fractal.result_digest = event->payload_root;
    } else if (event->event_type == EVENTBUS_EVENT_TASK) {
        /* The host adapter uses the task ObjectID as the authenticated
         * cancellation marker. Other task roots are failure evidence. */
        if (g_fractal.state >= AGENT_TASK_STATE_COMPLETE)
            return;
        if (eventbus_event_hash_equal(&event->payload_root, &task_hash)) {
            g_fractal.state = AGENT_TASK_STATE_CANCELLED;
            g_fractal.terminal_code = AGENT_TASK_ERR_CANCELLED;
            g_fractal.result_kind = AGENT_TASK_RESULT_FAILURE;
        } else if (!eventbus_event_hash_zero(&event->payload_root)) {
            g_fractal.state = AGENT_TASK_STATE_FAILED;
            g_fractal.terminal_code = AGENT_TASK_ERR_HARNESS;
            g_fractal.result_kind = AGENT_TASK_RESULT_FAILURE;
            g_fractal.result_digest = event->payload_root;
        }
    } else if (event->event_type == EVENTBUS_EVENT_AUTHORITY_CHANGE) {
        g_fractal.state = AGENT_TASK_STATE_REVOKED;
        g_fractal.terminal_code = AGENT_TASK_ERR_REVOKED;
        g_fractal.result_kind = AGENT_TASK_RESULT_FAILURE;
    }
}

uint32_t agent_task_gateway_begin(const struct agent_task_req_begin *req,
                                  struct agent_task_reply_begin *reply)
{
    if (reply == NULL) return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!gateway_ready() || req == NULL
        || req->interface_version != AGENT_TASK_INTERFACE_VERSION
        || req->prompt_len == 0u || req->prompt_len > AGENT_TASK_PROMPT_CAP
        || req->result_capacity < 2u
        || req->result_capacity > AGENT_TASK_RESULT_CAP
        || req->max_steps == 0u
        || (req->required_caps & ~HARNESS_CAP_KNOWN_MASK) != 0u) {
        reply->status = AGENT_TASK_ERR_INVALID;
        return reply->status;
    }

    uint32_t available_caps = 0u, authority_epoch = 0u;
    g_task.authority(&available_caps, &authority_epoch, g_task.ctx);
    uint32_t task_id = g_task.next_task_id++;
    if (task_id == 0u) task_id = g_task.next_task_id++;

    g_task.task_id = task_id;
    g_task.required_caps = req->required_caps;
    g_task.task_flags = req->task_flags;
    g_task.max_steps = req->max_steps;
    g_task.prompt_len = req->prompt_len;
    g_task.received_len = 0u;
    g_task.result_capacity = req->result_capacity;
    g_task.result_len = 0u;
    g_task.available_caps = available_caps;
    g_task.authority_epoch = authority_epoch;
    g_task.harness_status = HARNESS_OK;
    g_task.state = HARNESS_STATE_IDLE;
    g_task.active = true;
    g_task.ran = false;
    g_task.scope_id = gateway_task_hash(task_id);
    g_task.event_head = (eventbus_event_hash_t){{0}};
    bytes_zero(&g_task.last_metrics, sizeof(g_task.last_metrics));
    bytes_zero(g_task.arena + AGENT_TASK_PROMPT_OFFSET, req->prompt_len);
    bytes_zero(g_task.arena + AGENT_TASK_RESULT_OFFSET, req->result_capacity);

    eventbus_event_hash_t descriptor = gateway_descriptor_hash(
        task_id, req->required_caps, req->task_flags, req->max_steps,
        req->prompt_len, req->result_capacity);
    if (gateway_emit(EVENTBUS_EVENT_TASK,
                     EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE,
                     &descriptor,
                     (const eventbus_event_hash_t *)0, 0)
            != EVENTBUS_AGENT_EVENT_OK) {
        g_task.active = false;
        reply->status = AGENT_TASK_ERR_HARNESS;
        return reply->status;
    }

    reply->status = AGENT_TASK_OK;
    reply->task_id = task_id;
    reply->accepted_prompt_len = req->prompt_len;
    reply->result_capacity = req->result_capacity;
    reply->available_caps = available_caps;
    reply->authority_epoch = authority_epoch;
    return AGENT_TASK_OK;
}

uint32_t agent_task_gateway_write(const struct agent_task_req_write *req)
{
    if (!gateway_ready() || req == NULL || !g_task.active
        || req->task_id != g_task.task_id)
        return AGENT_TASK_ERR_NOT_FOUND;
    if (g_task.ran || req->len == 0u || req->len > AGENT_TASK_CHUNK_BYTES
        || req->offset != g_task.received_len
        || g_task.received_len > g_task.prompt_len
        || req->len > g_task.prompt_len - g_task.received_len)
        return AGENT_TASK_ERR_INVALID;
    bytes_copy(g_task.arena + AGENT_TASK_PROMPT_OFFSET + req->offset,
               req->data, req->len);
    g_task.received_len += req->len;
    if (gateway_emit_bytes(EVENTBUS_EVENT_TASK,
                            EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE,
                            req->data, req->len)
            != EVENTBUS_AGENT_EVENT_OK) {
        g_task.received_len -= req->len;
        bytes_zero(g_task.arena + AGENT_TASK_PROMPT_OFFSET + req->offset,
                   req->len);
        return AGENT_TASK_ERR_HARNESS;
    }
    /* The same bounded message is also an actor/mailbox transition. */
    if (gateway_emit_bytes(EVENTBUS_EVENT_MAILBOX,
                           EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE,
                           req->data, req->len)
            != EVENTBUS_AGENT_EVENT_OK) {
        g_task.received_len -= req->len;
        bytes_zero(g_task.arena + AGENT_TASK_PROMPT_OFFSET + req->offset,
                   req->len);
        return AGENT_TASK_ERR_HARNESS;
    }
    return AGENT_TASK_OK;
}

uint32_t agent_task_gateway_run(const struct agent_task_req_run *req,
                                struct agent_task_reply_run *reply)
{
    if (reply == NULL) return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!gateway_ready() || req == NULL || !g_task.active
        || req->task_id != g_task.task_id) {
        reply->status = AGENT_TASK_ERR_NOT_FOUND;
        return reply->status;
    }
    reply->task_id = g_task.task_id;
    if (g_task.ran) {
        reply->status = AGENT_TASK_ERR_BUSY;
        return reply->status;
    }
    if (g_task.received_len != g_task.prompt_len) {
        reply->status = AGENT_TASK_ERR_INCOMPLETE;
        return reply->status;
    }

    /* Refresh kernel-owned authority at the effect boundary. The caller never
     * supplies an epoch and task text cannot manufacture a grant. */
    uint32_t prior_epoch = g_task.authority_epoch;
    g_task.authority(&g_task.available_caps, &g_task.authority_epoch,
                     g_task.ctx);
    if (g_task.authority_epoch != prior_epoch) {
        if (gateway_emit(EVENTBUS_EVENT_AUTHORITY_CHANGE,
                         EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE,
                         (const eventbus_event_hash_t *)0,
                         (const eventbus_event_hash_t *)0, 0)
                != EVENTBUS_AGENT_EVENT_OK) {
            reply->status = AGENT_TASK_ERR_AUTHORITY;
            return reply->status;
        }
    }
    if (gateway_emit(EVENTBUS_EVENT_BUDGET,
                     EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE,
                     (const eventbus_event_hash_t *)0,
                     (const eventbus_event_hash_t *)0,
                     -(int32_t)g_task.max_steps)
            != EVENTBUS_AGENT_EVENT_OK) {
        reply->status = AGENT_TASK_ERR_HARNESS;
        return reply->status;
    }

    struct harness_req_submit submit;
    bytes_zero(&submit, sizeof(submit));
    submit.task_id = g_task.task_id;
    submit.harness_kind = HARNESS_KIND_CODEX;
    submit.required_caps = g_task.required_caps;
    submit.task_flags = g_task.task_flags;
    submit.max_steps = g_task.max_steps;
    submit.authority_epoch = g_task.authority_epoch;
    submit.prompt_offset = AGENT_TASK_PROMPT_OFFSET;
    submit.prompt_len = g_task.prompt_len;
    submit.result_offset = AGENT_TASK_RESULT_OFFSET;
    submit.result_capacity = g_task.result_capacity;

    eventbus_event_hash_t submit_root = gateway_submit_hash(&submit);
    if (gateway_emit(EVENTBUS_EVENT_NESTED_CALL,
                     EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE,
                     &submit_root, (const eventbus_event_hash_t *)0, 0)
            != EVENTBUS_AGENT_EVENT_OK) {
        reply->status = AGENT_TASK_ERR_HARNESS;
        return reply->status;
    }

    struct harness_reply_submit harness_reply;
    bytes_zero(&harness_reply, sizeof(harness_reply));
    uint32_t harness_status = g_task.submit(&submit, &harness_reply,
                                             g_task.ctx);
    g_task.ran = true;
    g_task.harness_status = harness_status;
    g_task.state = harness_reply.state;
    g_task.last_metrics.status = harness_status;
    g_task.last_metrics.task_id = g_task.task_id;
    g_task.last_metrics.state = harness_reply.state;

    eventbus_event_hash_t program_state_root = {{0}};
    eventbus_event_hash_bytes((const uint8_t *)&harness_reply,
                              (uint32_t)sizeof(harness_reply),
                              &program_state_root);
    if (gateway_emit(EVENTBUS_EVENT_TASK,
                     EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE,
                     &program_state_root,
                     (const eventbus_event_hash_t *)0, 0)
            != EVENTBUS_AGENT_EVENT_OK) {
        reply->status = AGENT_TASK_ERR_HARNESS;
        return reply->status;
    }

    if (harness_status == HARNESS_OK) {
        struct harness_reply_result metrics;
        bytes_zero(&metrics, sizeof(metrics));
        uint32_t metrics_status = g_task.metrics(g_task.task_id, &metrics,
                                                  g_task.ctx);
        if (metrics_status != HARNESS_OK
            || metrics.result_len > g_task.result_capacity
            || metrics.result_len > AGENT_TASK_RESULT_CAP) {
            reply->status = AGENT_TASK_ERR_HARNESS;
            reply->harness_status = metrics_status;
            reply->state = harness_reply.state;
            return reply->status;
        }
        g_task.last_metrics = metrics;
        g_task.result_len = metrics.result_len;
        g_task.state = metrics.state;

        eventbus_event_hash_t result_root = {{0}};
        eventbus_event_hash_t evidence_root = {{0}};
        eventbus_event_hash_bytes(
            g_task.arena + AGENT_TASK_RESULT_OFFSET, g_task.result_len,
            &result_root);
        eventbus_event_hash_bytes((const uint8_t *)&metrics,
                                  (uint32_t)sizeof(metrics), &evidence_root);
        if (gateway_emit(EVENTBUS_EVENT_EFFECT,
                         EVENTBUS_EVENT_FLAG_EXTERNAL_EFFECT
                             | EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE,
                         &result_root, (const eventbus_event_hash_t *)0, 0)
                != EVENTBUS_AGENT_EVENT_OK) {
            reply->status = AGENT_TASK_ERR_HARNESS;
            return reply->status;
        }
        if (metrics.verification_exit_code == 0) {
            if (gateway_emit(EVENTBUS_EVENT_TASK_VERIFY,
                             EVENTBUS_EVENT_FLAG_TASK_VERIFY_SUCCESS
                                 | EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE,
                             &result_root, &evidence_root, 0)
                    != EVENTBUS_AGENT_EVENT_OK
                || gateway_emit(EVENTBUS_EVENT_CHECKPOINT,
                                EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE,
                                &result_root, &evidence_root, 0)
                       != EVENTBUS_AGENT_EVENT_OK
                || gateway_emit(EVENTBUS_EVENT_COMMIT,
                                EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE,
                                &result_root, &evidence_root, 0)
                       != EVENTBUS_AGENT_EVENT_OK) {
                reply->status = AGENT_TASK_ERR_EVIDENCE_MISMATCH;
                return reply->status;
            }
        }
    }

    reply->status = AGENT_TASK_OK;
    reply->task_id = g_task.task_id;
    reply->harness_status = g_task.harness_status;
    reply->state = g_task.state;
    reply->result_len = g_task.result_len;
    reply->used_caps = g_task.last_metrics.used_caps;
    return AGENT_TASK_OK;
}

uint32_t agent_task_gateway_result(const struct agent_task_req_result *req,
                                   struct agent_task_reply_result *reply)
{
    if (reply == NULL) return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!gateway_ready() || req == NULL || !g_task.active
        || req->task_id != g_task.task_id) {
        reply->status = AGENT_TASK_ERR_NOT_FOUND;
        return reply->status;
    }
    reply->task_id = g_task.task_id;
    if (!g_task.ran) {
        reply->status = AGENT_TASK_ERR_INCOMPLETE;
        return reply->status;
    }
    if (req->offset > g_task.result_len || req->max_len == 0u
        || req->max_len > AGENT_TASK_RESULT_CHUNK_BYTES) {
        reply->status = AGENT_TASK_ERR_INVALID;
        return reply->status;
    }
    uint32_t len = g_task.result_len - req->offset;
    if (len > req->max_len) len = req->max_len;
    if (gateway_emit_bytes(EVENTBUS_EVENT_TASK,
                            EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE,
                            g_task.arena + AGENT_TASK_RESULT_OFFSET
                                + req->offset,
                            len) != EVENTBUS_AGENT_EVENT_OK) {
        reply->status = AGENT_TASK_ERR_HARNESS;
        return reply->status;
    }
    bytes_copy(reply->data,
               g_task.arena + AGENT_TASK_RESULT_OFFSET + req->offset, len);
    reply->status = AGENT_TASK_OK;
    reply->total_len = g_task.result_len;
    reply->chunk_offset = req->offset;
    reply->chunk_len = len;
    return AGENT_TASK_OK;
}

uint32_t agent_task_gateway_metrics(uint32_t task_id,
                                    struct harness_reply_result *reply)
{
    if (reply == NULL) return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!gateway_ready() || !g_task.active || !g_task.ran
        || task_id != g_task.task_id)
        return AGENT_TASK_ERR_NOT_FOUND;
    *reply = g_task.last_metrics;
    return AGENT_TASK_OK;
}

static uint32_t gateway_remote_emit_denial(
    const mesh_remote_authority_context_t *ctx, uint32_t status,
    const mesh_remote_grant_t *grant, const mesh_execution_lease_t *lease)
{
    if (ctx == NULL || ctx->emit_event == NULL) return MESH_AUTHZ_ERR_EVENT;
    return ctx->emit_event(EVENTBUS_EVENT_AUTHORITY_CHANGE,
                           MESH_AUTHZ_DECISION_DENY, status, grant, lease, 0u,
                           ctx->callback_ctx) == EVENTBUS_AGENT_EVENT_OK
        ? status : MESH_AUTHZ_ERR_EVENT;
}

uint32_t agent_task_gateway_remote_dispatch_recheck(
    const mesh_remote_authority_state_t *authority_state,
    const mesh_remote_grant_t *grant, const mesh_execution_lease_t *lease,
    const mesh_remote_authority_context_t *ctx, uint64_t admitted_local_badge,
    uint64_t *out_local_badge)
{
    if (out_local_badge != NULL) *out_local_badge = 0u;
    if (out_local_badge == NULL || admitted_local_badge == 0u)
        return gateway_remote_emit_denial(ctx, MESH_AUTHZ_ERR_BAD_ARG,
                                          grant, lease);

    uint64_t rechecked_badge = 0u;
    uint32_t status = mesh_agent_recheck_remote_grant(
        authority_state, grant, ctx, &rechecked_badge);
    if (status != MESH_AUTHZ_OK) return status;
    if (rechecked_badge != admitted_local_badge)
        return gateway_remote_emit_denial(ctx, MESH_AUTHZ_ERR_CAPBROKER,
                                          grant, lease);

    status = mesh_agent_validate_execution_lease(lease, grant, ctx);
    if (status != MESH_AUTHZ_OK) return status;
    *out_local_badge = rechecked_badge;
    return MESH_AUTHZ_OK;
}

uint32_t agent_task_gateway_remote_completion_recheck(
    const mesh_remote_authority_state_t *authority_state,
    const mesh_remote_grant_t *grant, const mesh_execution_lease_t *lease,
    const mesh_remote_authority_context_t *ctx, uint64_t admitted_local_badge,
    mesh_completion_guard_t *completion, uint64_t completion_sequence)
{
    if (completion == NULL)
        return gateway_remote_emit_denial(ctx, MESH_AUTHZ_ERR_BAD_ARG,
                                          grant, lease);
    uint64_t rechecked_badge = 0u;
    uint32_t status = agent_task_gateway_remote_dispatch_recheck(
        authority_state, grant, lease, ctx, admitted_local_badge,
        &rechecked_badge);
    if (status != MESH_AUTHZ_OK) return status;
    if (!mesh_completion_accept(completion, completion_sequence))
        return gateway_remote_emit_denial(
            ctx, MESH_AUTHZ_ERR_DUPLICATE_COMPLETION, grant, lease);
    return MESH_AUTHZ_OK;
}
