/*
 * Scoped actor handles, persistent mailboxes, and passivation
 * (fos-gz0.14.7.1 / fos-gz0.14.7.2).
 */

#include "actor_mailbox.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct actor_record {
    int used;
    uint32_t lifecycle; /* actor_lifecycle_state */
    uint64_t id;
    uint32_t generation;
    uint32_t authority_epoch;
    uint32_t scope;
    uint64_t parent_id;
    uint64_t cap_mask;
    uint64_t budget_units;
    uint64_t budget_remaining;
    uint64_t mailbox_head; /* last accepted sequence — preserved across dormancy */
    uint32_t mailbox_count;
    uint32_t mailbox_read;
    uint64_t resident_bytes;
    uint8_t checkpoint_root[32];
    int has_checkpoint;
    struct actor_mailbox_message mailbox[ACTOR_MAILBOX_DEPTH];
};

struct task_record {
    int used;
    uint64_t id;
    uint32_t generation;
    uint32_t authority_epoch;
    uint32_t scope;
    uint64_t agent_id;
    uint64_t cap_mask;
    uint64_t budget_units;
};

struct program_record {
    int used;
    uint64_t id;
    uint32_t generation;
    uint32_t authority_epoch;
    uint32_t scope;
};

static struct {
    uint32_t authority_epoch;
    uint64_t next_agent_id;
    uint64_t next_task_id;
    uint64_t next_program_id;
    struct actor_record agents[ACTOR_MAILBOX_MAX_AGENTS];
    struct task_record tasks[ACTOR_MAILBOX_MAX_TASKS];
    struct program_record programs[16];
} g_actors;

static void bytes_zero(void *dst, size_t n)
{
    uint8_t *p = (uint8_t *)dst;
    while (n--) *p++ = 0;
}

static int root_is_zero(const uint8_t root[32])
{
    for (uint32_t i = 0u; i < 32u; i++) {
        if (root[i] != 0u)
            return 0;
    }
    return 1;
}

static int root_equal(const uint8_t a[32], const uint8_t b[32])
{
    for (uint32_t i = 0u; i < 32u; i++) {
        if (a[i] != b[i])
            return 0;
    }
    return 1;
}

static int scope_ok_child(uint32_t parent_scope, uint32_t child_scope)
{
    /* Child lifetime must be narrower or equal (task < session < agent < global). */
    return child_scope <= parent_scope;
}

static int caps_subset(uint64_t parent, uint64_t child)
{
    return (child & parent) == child;
}

static struct actor_record *find_agent(uint64_t id)
{
    for (uint32_t i = 0u; i < ACTOR_MAILBOX_MAX_AGENTS; i++) {
        if (g_actors.agents[i].used && g_actors.agents[i].id == id)
            return &g_actors.agents[i];
    }
    return NULL;
}

static struct task_record *find_task(uint64_t id)
{
    for (uint32_t i = 0u; i < ACTOR_MAILBOX_MAX_TASKS; i++) {
        if (g_actors.tasks[i].used && g_actors.tasks[i].id == id)
            return &g_actors.tasks[i];
    }
    return NULL;
}

static struct actor_record *alloc_agent(void)
{
    for (uint32_t i = 0u; i < ACTOR_MAILBOX_MAX_AGENTS; i++) {
        if (!g_actors.agents[i].used) {
            bytes_zero(&g_actors.agents[i], sizeof(g_actors.agents[i]));
            g_actors.agents[i].used = 1;
            return &g_actors.agents[i];
        }
    }
    return NULL;
}

static struct task_record *alloc_task(void)
{
    for (uint32_t i = 0u; i < ACTOR_MAILBOX_MAX_TASKS; i++) {
        if (!g_actors.tasks[i].used) {
            bytes_zero(&g_actors.tasks[i], sizeof(g_actors.tasks[i]));
            g_actors.tasks[i].used = 1;
            return &g_actors.tasks[i];
        }
    }
    return NULL;
}

static uint32_t validate_agent_handle(const struct actor_agent_handle *h,
                                      struct actor_record **out)
{
    struct actor_record *rec;

    if (h == NULL || h->id == 0u)
        return ACTOR_MAILBOX_ERR_INVALID;
    rec = find_agent(h->id);
    if (rec == NULL)
        return ACTOR_MAILBOX_ERR_NOT_FOUND;
    if (h->generation != rec->generation || h->authority_epoch != rec->authority_epoch)
        return ACTOR_MAILBOX_ERR_STALE_HANDLE;
    if (h->scope != rec->scope)
        return ACTOR_MAILBOX_ERR_CROSS_SCOPE;
    if (out != NULL)
        *out = rec;
    return ACTOR_MAILBOX_OK;
}

static void release_resident_mailbox(struct actor_record *agent)
{
    bytes_zero(agent->mailbox, sizeof(agent->mailbox));
    agent->mailbox_count = 0u;
    agent->mailbox_read = 0u;
}

void actor_mailbox_reset(void)
{
    bytes_zero(&g_actors, sizeof(g_actors));
    g_actors.authority_epoch = 1u;
    g_actors.next_agent_id = 1u;
    g_actors.next_task_id = 1u;
    g_actors.next_program_id = 1u;
}

uint32_t actor_mailbox_spawn(const struct actor_req_spawn *req,
                             struct actor_reply_spawn *reply)
{
    struct actor_record *parent = NULL;
    struct actor_record *child;
    uint32_t parent_scope = ACTOR_SCOPE_GLOBAL;
    uint64_t parent_caps = ~(uint64_t)0;
    uint64_t parent_budget = ~(uint64_t)0;
    uint32_t status;

    if (reply == NULL)
        return ACTOR_MAILBOX_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL || req->interface_version != ACTOR_MAILBOX_INTERFACE_VERSION
        || req->scope > ACTOR_SCOPE_GLOBAL || req->budget_units == 0u) {
        reply->status = ACTOR_MAILBOX_ERR_INVALID;
        return reply->status;
    }

    if (req->parent.id != 0u) {
        status = validate_agent_handle(&req->parent, &parent);
        if (status != ACTOR_MAILBOX_OK) {
            reply->status = status;
            return status;
        }
        if (parent->lifecycle != ACTOR_STATE_ACTIVE) {
            reply->status = ACTOR_MAILBOX_ERR_NOT_ACTIVE;
            return reply->status;
        }
        parent_scope = parent->scope;
        parent_caps = parent->cap_mask;
        parent_budget = parent->budget_remaining;
    }

    if (!scope_ok_child(parent_scope, req->scope)) {
        reply->status = ACTOR_MAILBOX_ERR_CROSS_SCOPE;
        return reply->status;
    }
    if (!caps_subset(parent_caps, req->cap_mask)) {
        reply->status = ACTOR_MAILBOX_ERR_CAPS;
        return reply->status;
    }
    if (req->budget_units > parent_budget) {
        reply->status = ACTOR_MAILBOX_ERR_BUDGET;
        return reply->status;
    }

    child = alloc_agent();
    if (child == NULL) {
        reply->status = ACTOR_MAILBOX_ERR_EXHAUSTED;
        return reply->status;
    }

    child->id = g_actors.next_agent_id++;
    child->generation = 1u;
    child->authority_epoch = g_actors.authority_epoch;
    child->scope = req->scope;
    child->parent_id = req->parent.id;
    child->cap_mask = req->cap_mask;
    child->budget_units = req->budget_units;
    child->budget_remaining = req->budget_units;
    child->mailbox_head = 0u;
    child->lifecycle = ACTOR_STATE_ACTIVE;
    child->resident_bytes = ACTOR_ACTIVE_HARNESS_BYTES;
    child->has_checkpoint = 0;

    if (parent != NULL)
        parent->budget_remaining -= req->budget_units;

    /* Immediate return — no wait for completion. */
    reply->status = ACTOR_MAILBOX_OK;
    reply->agent.id = child->id;
    reply->agent.generation = child->generation;
    reply->agent.authority_epoch = child->authority_epoch;
    reply->agent.scope = child->scope;
    return ACTOR_MAILBOX_OK;
}

uint32_t actor_mailbox_delegate(const struct actor_req_delegate *req,
                                struct actor_reply_delegate *reply)
{
    struct actor_record *agent = NULL;
    struct task_record *task;
    uint32_t status;

    if (reply == NULL)
        return ACTOR_MAILBOX_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL || req->interface_version != ACTOR_MAILBOX_INTERFACE_VERSION
        || req->scope > ACTOR_SCOPE_GLOBAL || req->budget_units == 0u) {
        reply->status = ACTOR_MAILBOX_ERR_INVALID;
        return reply->status;
    }

    status = validate_agent_handle(&req->agent, &agent);
    if (status != ACTOR_MAILBOX_OK) {
        reply->status = status;
        return status;
    }
    if (agent->lifecycle != ACTOR_STATE_ACTIVE) {
        reply->status = ACTOR_MAILBOX_ERR_NOT_ACTIVE;
        return reply->status;
    }
    if (!scope_ok_child(agent->scope, req->scope)) {
        reply->status = ACTOR_MAILBOX_ERR_CROSS_SCOPE;
        return reply->status;
    }
    if (!caps_subset(agent->cap_mask, req->cap_mask)) {
        reply->status = ACTOR_MAILBOX_ERR_CAPS;
        return reply->status;
    }
    if (req->budget_units > agent->budget_remaining) {
        reply->status = ACTOR_MAILBOX_ERR_BUDGET;
        return reply->status;
    }

    task = alloc_task();
    if (task == NULL) {
        reply->status = ACTOR_MAILBOX_ERR_EXHAUSTED;
        return reply->status;
    }

    task->id = g_actors.next_task_id++;
    task->generation = 1u;
    task->authority_epoch = agent->authority_epoch;
    task->scope = req->scope;
    task->agent_id = agent->id;
    task->cap_mask = req->cap_mask;
    task->budget_units = req->budget_units;
    agent->budget_remaining -= req->budget_units;

    reply->status = ACTOR_MAILBOX_OK;
    reply->task.id = task->id;
    reply->task.generation = task->generation;
    reply->task.authority_epoch = task->authority_epoch;
    reply->task.scope = task->scope;
    reply->task.agent_id = task->agent_id;
    return ACTOR_MAILBOX_OK;
}

uint32_t actor_mailbox_deliver(const struct actor_req_mailbox_deliver *req,
                               struct actor_reply_mailbox_deliver *reply)
{
    struct actor_record *agent = NULL;
    uint32_t status;
    uint32_t slot;
    uint64_t expected;

    if (reply == NULL)
        return ACTOR_MAILBOX_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL || req->interface_version != ACTOR_MAILBOX_INTERFACE_VERSION) {
        reply->status = ACTOR_MAILBOX_ERR_INVALID;
        return reply->status;
    }

    status = validate_agent_handle(&req->agent, &agent);
    if (status != ACTOR_MAILBOX_OK) {
        reply->status = status;
        return status;
    }
    /* Authorized wake: causal deliver may reactivate a dormant actor. */
    if (agent->lifecycle == ACTOR_STATE_DORMANT) {
        if (!agent->has_checkpoint) {
            reply->status = ACTOR_MAILBOX_ERR_CHECKPOINT;
            return reply->status;
        }
        if (agent->budget_remaining == 0u) {
            reply->status = ACTOR_MAILBOX_ERR_QUOTA;
            return reply->status;
        }
        agent->lifecycle = ACTOR_STATE_ACTIVE;
        agent->resident_bytes = ACTOR_ACTIVE_HARNESS_BYTES;
    }
    if (req->message.scope != agent->scope) {
        reply->status = ACTOR_MAILBOX_ERR_CROSS_SCOPE;
        return reply->status;
    }

    expected = agent->mailbox_head + 1u;
    if (req->message.sequence != expected) {
        reply->status = ACTOR_MAILBOX_ERR_CAUSAL;
        return reply->status;
    }
    if (req->message.causal_parent != agent->mailbox_head) {
        reply->status = ACTOR_MAILBOX_ERR_CAUSAL;
        return reply->status;
    }
    if (agent->mailbox_count >= ACTOR_MAILBOX_DEPTH) {
        reply->status = ACTOR_MAILBOX_ERR_FULL;
        return reply->status;
    }

    slot = (agent->mailbox_read + agent->mailbox_count) % ACTOR_MAILBOX_DEPTH;
    agent->mailbox[slot] = req->message;
    agent->mailbox_count++;
    agent->mailbox_head = req->message.sequence;
    reply->status = ACTOR_MAILBOX_OK;
    reply->accepted_sequence = req->message.sequence;
    return ACTOR_MAILBOX_OK;
}

uint32_t actor_mailbox_poll(const struct actor_req_mailbox_poll *req,
                            struct actor_reply_mailbox_poll *reply)
{
    struct actor_record *agent = NULL;
    uint32_t status;

    if (reply == NULL)
        return ACTOR_MAILBOX_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL || req->interface_version != ACTOR_MAILBOX_INTERFACE_VERSION) {
        reply->status = ACTOR_MAILBOX_ERR_INVALID;
        return reply->status;
    }

    status = validate_agent_handle(&req->agent, &agent);
    if (status != ACTOR_MAILBOX_OK) {
        reply->status = status;
        return status;
    }
    if (agent->lifecycle != ACTOR_STATE_ACTIVE) {
        reply->status = ACTOR_MAILBOX_ERR_NOT_ACTIVE;
        return reply->status;
    }
    if (agent->mailbox_count == 0u) {
        reply->status = ACTOR_MAILBOX_ERR_EMPTY;
        return reply->status;
    }

    reply->message = agent->mailbox[agent->mailbox_read];
    agent->mailbox_read = (agent->mailbox_read + 1u) % ACTOR_MAILBOX_DEPTH;
    agent->mailbox_count--;
    reply->status = ACTOR_MAILBOX_OK;
    return ACTOR_MAILBOX_OK;
}

uint32_t actor_mailbox_resolve(const struct actor_req_handle_resolve *req,
                               struct actor_reply_handle_resolve *reply)
{
    struct actor_record *agent = NULL;
    struct task_record *task = NULL;
    uint32_t status;

    if (reply == NULL)
        return ACTOR_MAILBOX_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL || req->interface_version != ACTOR_MAILBOX_INTERFACE_VERSION) {
        reply->status = ACTOR_MAILBOX_ERR_INVALID;
        return reply->status;
    }

    if (req->kind == 0u) {
        status = validate_agent_handle(&req->agent, &agent);
        if (status != ACTOR_MAILBOX_OK) {
            reply->status = status;
            return status;
        }
        if (req->expected_scope != agent->scope) {
            reply->status = ACTOR_MAILBOX_ERR_CROSS_SCOPE;
            return reply->status;
        }
        reply->status = ACTOR_MAILBOX_OK;
        reply->scope = agent->scope;
        reply->cap_mask = agent->cap_mask;
        reply->budget_remaining = agent->budget_remaining;
        reply->mailbox_head = agent->mailbox_head;
        return ACTOR_MAILBOX_OK;
    }

    if (req->kind == 1u) {
        if (req->task.id == 0u) {
            reply->status = ACTOR_MAILBOX_ERR_INVALID;
            return reply->status;
        }
        task = find_task(req->task.id);
        if (task == NULL) {
            reply->status = ACTOR_MAILBOX_ERR_NOT_FOUND;
            return reply->status;
        }
        if (req->task.generation != task->generation
            || req->task.authority_epoch != task->authority_epoch) {
            reply->status = ACTOR_MAILBOX_ERR_STALE_HANDLE;
            return reply->status;
        }
        if (req->task.scope != task->scope
            || req->expected_scope != task->scope) {
            reply->status = ACTOR_MAILBOX_ERR_CROSS_SCOPE;
            return reply->status;
        }
        reply->status = ACTOR_MAILBOX_OK;
        reply->scope = task->scope;
        reply->cap_mask = task->cap_mask;
        reply->budget_remaining = task->budget_units;
        reply->mailbox_head = 0u;
        return ACTOR_MAILBOX_OK;
    }

    reply->status = ACTOR_MAILBOX_ERR_INVALID;
    return reply->status;
}

uint32_t actor_mailbox_passivate(const struct actor_req_passivate *req,
                                 struct actor_reply_passivate *reply)
{
    struct actor_record *agent = NULL;
    uint32_t status;
    uint64_t released;

    if (reply == NULL)
        return ACTOR_MAILBOX_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL || req->interface_version != ACTOR_MAILBOX_INTERFACE_VERSION) {
        reply->status = ACTOR_MAILBOX_ERR_INVALID;
        return reply->status;
    }
    if (root_is_zero(req->checkpoint_root)) {
        reply->status = ACTOR_MAILBOX_ERR_CHECKPOINT;
        return reply->status;
    }

    status = validate_agent_handle(&req->agent, &agent);
    if (status != ACTOR_MAILBOX_OK) {
        reply->status = status;
        return status;
    }
    if (agent->lifecycle != ACTOR_STATE_ACTIVE) {
        reply->status = ACTOR_MAILBOX_ERR_NOT_ACTIVE;
        return reply->status;
    }

    released = agent->resident_bytes;
    if (released > ACTOR_DORMANT_METADATA_BYTES)
        released -= ACTOR_DORMANT_METADATA_BYTES;
    else
        released = 0u;

    memcpy(agent->checkpoint_root, req->checkpoint_root, 32u);
    agent->has_checkpoint = 1;
    release_resident_mailbox(agent);
    agent->lifecycle = ACTOR_STATE_DORMANT;
    agent->resident_bytes = ACTOR_DORMANT_METADATA_BYTES;

    reply->status = ACTOR_MAILBOX_OK;
    reply->lifecycle = ACTOR_STATE_DORMANT;
    reply->mailbox_head = agent->mailbox_head;
    reply->resident_bytes_released = released;
    memcpy(reply->checkpoint_root, agent->checkpoint_root, 32u);
    return ACTOR_MAILBOX_OK;
}

uint32_t actor_mailbox_reactivate(const struct actor_req_reactivate *req,
                                  struct actor_reply_reactivate *reply)
{
    struct actor_record *agent = NULL;
    uint32_t status;

    if (reply == NULL)
        return ACTOR_MAILBOX_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL || req->interface_version != ACTOR_MAILBOX_INTERFACE_VERSION) {
        reply->status = ACTOR_MAILBOX_ERR_INVALID;
        return reply->status;
    }
    if (req->event_token == 0u) {
        reply->status = ACTOR_MAILBOX_ERR_DENIED;
        return reply->status;
    }

    status = validate_agent_handle(&req->agent, &agent);
    if (status != ACTOR_MAILBOX_OK) {
        reply->status = status;
        return status;
    }
    if (agent->lifecycle != ACTOR_STATE_DORMANT) {
        reply->status = ACTOR_MAILBOX_ERR_NOT_DORMANT;
        return reply->status;
    }
    if (!agent->has_checkpoint
        || !root_equal(agent->checkpoint_root, req->checkpoint_root)) {
        reply->status = ACTOR_MAILBOX_ERR_CHECKPOINT;
        return reply->status;
    }
    if (req->quota_units == 0u || req->quota_units > agent->budget_remaining) {
        reply->status = ACTOR_MAILBOX_ERR_QUOTA;
        return reply->status;
    }

    agent->lifecycle = ACTOR_STATE_ACTIVE;
    agent->resident_bytes = ACTOR_ACTIVE_HARNESS_BYTES;
    /* Lineage preserved: generation, authority_epoch, mailbox_head unchanged. */

    reply->status = ACTOR_MAILBOX_OK;
    reply->lifecycle = ACTOR_STATE_ACTIVE;
    reply->mailbox_head = agent->mailbox_head;
    reply->generation = agent->generation;
    reply->resident_bytes = agent->resident_bytes;
    return ACTOR_MAILBOX_OK;
}

uint32_t actor_mailbox_memory_stats(const struct actor_req_memory_stats *req,
                                    struct actor_reply_memory_stats *reply)
{
    uint32_t active = 0u;
    uint32_t dormant = 0u;
    uint64_t active_bytes = 0u;
    uint64_t dormant_bytes = 0u;

    if (reply == NULL)
        return ACTOR_MAILBOX_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL || req->interface_version != ACTOR_MAILBOX_INTERFACE_VERSION) {
        reply->status = ACTOR_MAILBOX_ERR_INVALID;
        return reply->status;
    }

    for (uint32_t i = 0u; i < ACTOR_MAILBOX_MAX_AGENTS; i++) {
        if (!g_actors.agents[i].used)
            continue;
        if (g_actors.agents[i].lifecycle == ACTOR_STATE_ACTIVE) {
            active++;
            active_bytes += g_actors.agents[i].resident_bytes;
        } else {
            dormant++;
            dormant_bytes += g_actors.agents[i].resident_bytes;
        }
    }

    reply->status = ACTOR_MAILBOX_OK;
    reply->active_count = active;
    reply->dormant_count = dormant;
    reply->active_resident_bytes = active_bytes;
    reply->dormant_metadata_bytes = dormant_bytes;
    reply->frontier_bytes = active_bytes + dormant_bytes;
    return ACTOR_MAILBOX_OK;
}

uint32_t actor_mailbox_bump_epoch(uint64_t agent_id)
{
    struct actor_record *agent = find_agent(agent_id);
    if (agent == NULL)
        return ACTOR_MAILBOX_ERR_NOT_FOUND;
    g_actors.authority_epoch++;
    agent->authority_epoch = g_actors.authority_epoch;
    agent->generation++;
    return ACTOR_MAILBOX_OK;
}

uint32_t actor_mailbox_agent_count(void)
{
    uint32_t n = 0u;
    for (uint32_t i = 0u; i < ACTOR_MAILBOX_MAX_AGENTS; i++)
        if (g_actors.agents[i].used)
            n++;
    return n;
}

uint32_t actor_mailbox_task_count(void)
{
    uint32_t n = 0u;
    for (uint32_t i = 0u; i < ACTOR_MAILBOX_MAX_TASKS; i++)
        if (g_actors.tasks[i].used)
            n++;
    return n;
}
