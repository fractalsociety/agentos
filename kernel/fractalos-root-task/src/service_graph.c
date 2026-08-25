/*
 * Immutable capability service graph host runtime (fos-gz0.14.9).
 */

#include "service_graph.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SERVICE_GRAPH_MAX_STORED   32u
#define SERVICE_GRAPH_MAX_ARTIFACTS 64u

struct stored_graph {
    int used;
    int published;
    struct service_graph_root root;
    struct service_graph_provider providers[SERVICE_GRAPH_MAX_PROVIDERS];
    struct service_graph_edge edges[SERVICE_GRAPH_MAX_EDGES];
};

static struct {
    struct service_graph_digest active_graph_id;
    uint64_t next_activation_generation;
    uint32_t artifact_count;
    struct service_graph_digest artifacts[SERVICE_GRAPH_MAX_ARTIFACTS];
    struct stored_graph graphs[SERVICE_GRAPH_MAX_STORED];
} g_sg;

static void bytes_zero(void *dst, size_t n)
{
    uint8_t *p = (uint8_t *)dst;
    while (n--)
        *p++ = 0;
}

static int digest_is_zero(const struct service_graph_digest *d)
{
    uint8_t combined = 0u;
    for (uint32_t i = 0u; i < SERVICE_GRAPH_DIGEST_BYTES; i++)
        combined |= d->bytes[i];
    return combined == 0u;
}

static int digest_eq(const struct service_graph_digest *a,
                     const struct service_graph_digest *b)
{
    uint8_t difference = 0u;
    for (uint32_t i = 0u; i < SERVICE_GRAPH_DIGEST_BYTES; i++)
        difference |= (uint8_t)(a->bytes[i] ^ b->bytes[i]);
    return difference == 0u;
}

static void digest_copy(struct service_graph_digest *dst,
                        const struct service_graph_digest *src)
{
    for (uint32_t i = 0u; i < SERVICE_GRAPH_DIGEST_BYTES; i++)
        dst->bytes[i] = src->bytes[i];
}

/* Host-proof content id: FNV-1a over providers + edges (not production SHA-256). */
static void hash_graph_contents(
    const struct service_graph_provider *providers, uint32_t provider_count,
    const struct service_graph_edge *edges, uint32_t edge_count,
    uint32_t max_resource_units, struct service_graph_digest *out)
{
    uint64_t hash = UINT64_C(0xcbf29ce484222325);
    const uint8_t *bytes;
    uint32_t i, j;

    bytes_zero(out, sizeof(*out));
    for (i = 0u; i < provider_count; i++) {
        bytes = (const uint8_t *)&providers[i];
        for (j = 0u; j < (uint32_t)sizeof(providers[i]); j++) {
            hash ^= bytes[j];
            hash *= UINT64_C(0x100000001b3);
        }
    }
    for (i = 0u; i < edge_count; i++) {
        bytes = (const uint8_t *)&edges[i];
        for (j = 0u; j < (uint32_t)sizeof(edges[i]); j++) {
            hash ^= bytes[j];
            hash *= UINT64_C(0x100000001b3);
        }
    }
    hash ^= max_resource_units;
    hash *= UINT64_C(0x100000001b3);
    for (i = 0u; i < 8u; i++)
        out->bytes[i] = (uint8_t)(hash >> (i * 8u));
    for (i = 8u; i < SERVICE_GRAPH_DIGEST_BYTES; i++)
        out->bytes[i] = (uint8_t)(0xA5u ^ out->bytes[i - 8u]);
}

static int artifact_known(const struct service_graph_digest *id)
{
    uint32_t i;
    if (digest_is_zero(id))
        return 0;
    for (i = 0u; i < g_sg.artifact_count; i++) {
        if (digest_eq(&g_sg.artifacts[i], id))
            return 1;
    }
    return 0;
}

static struct stored_graph *find_graph(const struct service_graph_digest *id)
{
    uint32_t i;
    if (digest_is_zero(id))
        return NULL;
    for (i = 0u; i < SERVICE_GRAPH_MAX_STORED; i++) {
        if (g_sg.graphs[i].used && digest_eq(&g_sg.graphs[i].root.graph_id, id))
            return &g_sg.graphs[i];
    }
    return NULL;
}

static struct stored_graph *alloc_graph(void)
{
    uint32_t i;
    for (i = 0u; i < SERVICE_GRAPH_MAX_STORED; i++) {
        if (!g_sg.graphs[i].used) {
            bytes_zero(&g_sg.graphs[i], sizeof(g_sg.graphs[i]));
            g_sg.graphs[i].used = 1;
            return &g_sg.graphs[i];
        }
    }
    return NULL;
}

static int find_provider_index(
    const struct service_graph_provider *providers, uint32_t count,
    const struct service_graph_digest *provider_id)
{
    uint32_t i;
    for (i = 0u; i < count; i++) {
        if (digest_eq(&providers[i].provider_id, provider_id))
            return (int)i;
    }
    return -1;
}

static int find_interface_provider(
    const struct service_graph_provider *providers, uint32_t count,
    const struct service_graph_digest *interface_hash)
{
    uint32_t i;
    for (i = 0u; i < count; i++) {
        if (digest_eq(&providers[i].interface_hash, interface_hash))
            return (int)i;
    }
    return -1;
}

static uint32_t detect_cycle(
    const struct service_graph_provider *providers, uint32_t provider_count,
    const struct service_graph_edge *edges, uint32_t edge_count)
{
    uint8_t adj[SERVICE_GRAPH_MAX_PROVIDERS][SERVICE_GRAPH_MAX_PROVIDERS];
    uint8_t state[SERVICE_GRAPH_MAX_PROVIDERS]; /* 0=unseen 1=active 2=done */
    uint32_t stack[SERVICE_GRAPH_MAX_PROVIDERS];
    uint32_t sp;
    uint32_t i, e;
    int from, to_iface, to;

    bytes_zero(adj, sizeof(adj));
    bytes_zero(state, sizeof(state));

    for (e = 0u; e < edge_count; e++) {
        from = find_provider_index(providers, provider_count,
                                   &edges[e].from_provider);
        if (from < 0)
            return SERVICE_GRAPH_ERR_FABRICATED_PROVIDER;
        to_iface = find_interface_provider(providers, provider_count,
                                           &edges[e].needs_interface);
        if (to_iface < 0)
            return SERVICE_GRAPH_ERR_MISSING_DEP;
        to = to_iface;
        if (from == to)
            return SERVICE_GRAPH_ERR_CYCLE;
        adj[from][to] = 1u;
    }

    for (i = 0u; i < provider_count; i++) {
        if (state[i] != 0u)
            continue;
        sp = 0u;
        stack[sp++] = i;
        state[i] = 1u;
        while (sp > 0u) {
            uint32_t node = stack[sp - 1u];
            uint32_t nxt;
            int advanced = 0;
            for (nxt = 0u; nxt < provider_count; nxt++) {
                if (!adj[node][nxt])
                    continue;
                if (state[nxt] == 1u)
                    return SERVICE_GRAPH_ERR_CYCLE;
                if (state[nxt] == 0u) {
                    state[nxt] = 1u;
                    stack[sp++] = nxt;
                    advanced = 1;
                    break;
                }
            }
            if (!advanced) {
                state[node] = 2u;
                sp--;
            }
        }
    }
    return SERVICE_GRAPH_OK;
}

static uint32_t validate_contents(
    const struct service_graph_provider *providers, uint32_t provider_count,
    const struct service_graph_edge *edges, uint32_t edge_count,
    uint32_t max_resource_units)
{
    uint32_t i;
    uint32_t total_resources = 0u;
    uint32_t status;

    if (providers == NULL || provider_count == 0u ||
        provider_count > SERVICE_GRAPH_MAX_PROVIDERS ||
        edge_count > SERVICE_GRAPH_MAX_EDGES ||
        (edge_count > 0u && edges == NULL) ||
        max_resource_units == 0u ||
        max_resource_units > SERVICE_GRAPH_MAX_RESOURCES)
        return SERVICE_GRAPH_ERR_INVALID;

    for (i = 0u; i < provider_count; i++) {
        if (digest_is_zero(&providers[i].provider_id) ||
            digest_is_zero(&providers[i].interface_hash) ||
            providers[i].interface_major == 0u ||
            providers[i].budget_units == 0u)
            return SERVICE_GRAPH_ERR_INVALID;
        if (!artifact_known(&providers[i].provider_id))
            return SERVICE_GRAPH_ERR_FABRICATED_PROVIDER;
        /* Duplicate provider ids fail closed. */
        if (find_provider_index(providers, i, &providers[i].provider_id) >= 0)
            return SERVICE_GRAPH_ERR_INVALID;
        /* One provider per interface in a graph version. */
        if (find_interface_provider(providers, i, &providers[i].interface_hash) >= 0)
            return SERVICE_GRAPH_ERR_INCOMPATIBLE_VERSION;
        if (total_resources > max_resource_units - providers[i].resource_units)
            return SERVICE_GRAPH_ERR_EXCESS_RESOURCE;
        total_resources += providers[i].resource_units;
    }

    for (i = 0u; i < edge_count; i++) {
        if (digest_is_zero(&edges[i].from_provider) ||
            digest_is_zero(&edges[i].needs_interface))
            return SERVICE_GRAPH_ERR_INVALID;
        if (find_provider_index(providers, provider_count,
                                &edges[i].from_provider) < 0)
            return SERVICE_GRAPH_ERR_FABRICATED_PROVIDER;
        if (find_interface_provider(providers, provider_count,
                                    &edges[i].needs_interface) < 0)
            return SERVICE_GRAPH_ERR_MISSING_DEP;
    }

    status = detect_cycle(providers, provider_count, edges, edge_count);
    if (status != SERVICE_GRAPH_OK)
        return status;
    return SERVICE_GRAPH_OK;
}

void service_graph_reset(void)
{
    bytes_zero(&g_sg, sizeof(g_sg));
    g_sg.next_activation_generation = 1u;
}

uint32_t service_graph_register_artifact(
    const struct service_graph_digest *provider_id)
{
    if (provider_id == NULL || digest_is_zero(provider_id))
        return SERVICE_GRAPH_ERR_INVALID;
    if (artifact_known(provider_id))
        return SERVICE_GRAPH_OK;
    if (g_sg.artifact_count >= SERVICE_GRAPH_MAX_ARTIFACTS)
        return SERVICE_GRAPH_ERR_FULL;
    digest_copy(&g_sg.artifacts[g_sg.artifact_count++], provider_id);
    return SERVICE_GRAPH_OK;
}

uint32_t service_graph_validate(
    const struct service_graph_req_validate *req,
    const struct service_graph_provider *providers,
    const struct service_graph_edge *edges,
    struct service_graph_reply_validate *reply)
{
    uint32_t status;
    struct stored_graph *slot;
    struct service_graph_digest graph_id;

    if (reply == NULL)
        return SERVICE_GRAPH_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != SERVICE_GRAPH_INTERFACE_VERSION) {
        reply->status = SERVICE_GRAPH_ERR_INVALID;
        return reply->status;
    }

    status = validate_contents(providers, req->provider_count, edges,
                               req->edge_count, req->max_resource_units);
    if (status != SERVICE_GRAPH_OK) {
        reply->status = status;
        return status;
    }

    hash_graph_contents(providers, req->provider_count, edges, req->edge_count,
                        req->max_resource_units, &graph_id);
    slot = find_graph(&graph_id);
    if (slot == NULL) {
        slot = alloc_graph();
        if (slot == NULL) {
            reply->status = SERVICE_GRAPH_ERR_FULL;
            return reply->status;
        }
        digest_copy(&slot->root.graph_id, &graph_id);
        slot->root.provider_count = req->provider_count;
        slot->root.edge_count = req->edge_count;
        slot->root.max_resource_units = req->max_resource_units;
        memcpy(slot->providers, providers,
               (size_t)req->provider_count * sizeof(*providers));
        if (req->edge_count > 0u)
            memcpy(slot->edges, edges,
                   (size_t)req->edge_count * sizeof(*edges));
    }

    digest_copy(&reply->graph_id, &graph_id);
    reply->status = SERVICE_GRAPH_OK;
    return SERVICE_GRAPH_OK;
}

uint32_t service_graph_publish(
    const struct service_graph_req_publish *req,
    struct service_graph_reply_publish *reply)
{
    struct stored_graph *slot;

    if (reply == NULL)
        return SERVICE_GRAPH_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != SERVICE_GRAPH_INTERFACE_VERSION) {
        reply->status = SERVICE_GRAPH_ERR_INVALID;
        return reply->status;
    }

    slot = find_graph(&req->graph_id);
    if (slot == NULL) {
        reply->status = SERVICE_GRAPH_ERR_NOT_FOUND;
        return reply->status;
    }

    if (digest_is_zero(&g_sg.active_graph_id)) {
        if (!digest_is_zero(&req->expected_prior_graph_id)) {
            reply->status = SERVICE_GRAPH_ERR_STALE_ROOT;
            return reply->status;
        }
    } else if (!digest_eq(&g_sg.active_graph_id, &req->expected_prior_graph_id)) {
        reply->status = SERVICE_GRAPH_ERR_STALE_ROOT;
        return reply->status;
    }

    digest_copy(&slot->root.prior_graph_id, &g_sg.active_graph_id);
    slot->root.activation_generation = g_sg.next_activation_generation++;
    slot->root.event_lineage_seq = req->event_lineage_seq;
    slot->published = 1;
    digest_copy(&g_sg.active_graph_id, &slot->root.graph_id);
    reply->root = slot->root;
    reply->status = SERVICE_GRAPH_OK;
    return SERVICE_GRAPH_OK;
}

uint32_t service_graph_bind(
    const struct service_graph_req_bind *req,
    struct service_graph_reply_bind *reply)
{
    struct stored_graph *slot;
    const struct service_graph_digest *graph_id;
    int idx;

    if (reply == NULL)
        return SERVICE_GRAPH_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != SERVICE_GRAPH_INTERFACE_VERSION ||
        digest_is_zero(&req->interface_hash) ||
        req->interface_major == 0u) {
        reply->status = SERVICE_GRAPH_ERR_INVALID;
        return reply->status;
    }

    graph_id = digest_is_zero(&req->graph_id) ? &g_sg.active_graph_id
                                              : &req->graph_id;
    slot = find_graph(graph_id);
    if (slot == NULL || !slot->published) {
        reply->status = SERVICE_GRAPH_ERR_NOT_FOUND;
        return reply->status;
    }

    idx = find_interface_provider(slot->providers, slot->root.provider_count,
                                  &req->interface_hash);
    if (idx < 0) {
        reply->status = SERVICE_GRAPH_ERR_NO_BINDING;
        return reply->status;
    }

    if (slot->providers[idx].interface_major != req->interface_major ||
        slot->providers[idx].interface_minor < req->interface_minor) {
        reply->status = SERVICE_GRAPH_ERR_INCOMPATIBLE_VERSION;
        return reply->status;
    }

    if ((req->requested_effect_mask & ~slot->providers[idx].effect_mask) != 0u) {
        reply->status = SERVICE_GRAPH_ERR_UNDECLARED_EFFECT;
        return reply->status;
    }
    if ((req->requested_cap_mask & ~slot->providers[idx].required_cap_mask) != 0u) {
        reply->status = SERVICE_GRAPH_ERR_UNDECLARED_CAP;
        return reply->status;
    }

    digest_copy(&reply->provider_id, &slot->providers[idx].provider_id);
    reply->provider_major = slot->providers[idx].interface_major;
    reply->provider_minor = slot->providers[idx].interface_minor;
    reply->granted_cap_mask = req->requested_cap_mask;
    reply->granted_effect_mask = req->requested_effect_mask;
    reply->resource_units = slot->providers[idx].resource_units;
    reply->status = SERVICE_GRAPH_OK;
    return SERVICE_GRAPH_OK;
}

uint32_t service_graph_swap(
    const struct service_graph_req_swap *req,
    struct service_graph_reply_swap *reply)
{
    struct stored_graph *current;
    struct stored_graph *fresh;
    struct service_graph_provider providers[SERVICE_GRAPH_MAX_PROVIDERS];
    struct service_graph_edge edges[SERVICE_GRAPH_MAX_EDGES];
    struct service_graph_req_validate vreq;
    struct service_graph_reply_validate vreply;
    struct service_graph_req_publish preq;
    struct service_graph_reply_publish preply;
    uint32_t status;
    uint32_t i;
    int replaced = 0;

    if (reply == NULL)
        return SERVICE_GRAPH_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != SERVICE_GRAPH_INTERFACE_VERSION ||
        digest_is_zero(&req->interface_hash)) {
        reply->status = SERVICE_GRAPH_ERR_INVALID;
        return reply->status;
    }

    current = find_graph(&req->current_graph_id);
    if (current == NULL || !current->published ||
        !digest_eq(&g_sg.active_graph_id, &req->current_graph_id)) {
        reply->status = SERVICE_GRAPH_ERR_STALE_ROOT;
        return reply->status;
    }

    if (!artifact_known(&req->new_provider.provider_id)) {
        reply->status = SERVICE_GRAPH_ERR_FABRICATED_PROVIDER;
        return reply->status;
    }
    if (!digest_eq(&req->new_provider.interface_hash, &req->interface_hash)) {
        reply->status = SERVICE_GRAPH_ERR_INVALID;
        return reply->status;
    }

    memcpy(providers, current->providers,
           (size_t)current->root.provider_count * sizeof(providers[0]));
    memcpy(edges, current->edges,
           (size_t)current->root.edge_count * sizeof(edges[0]));

    for (i = 0u; i < current->root.provider_count; i++) {
        if (digest_eq(&providers[i].interface_hash, &req->interface_hash)) {
            providers[i] = req->new_provider;
            replaced = 1;
            break;
        }
    }
    if (!replaced) {
        reply->status = SERVICE_GRAPH_ERR_NO_BINDING;
        return reply->status;
    }

    bytes_zero(&vreq, sizeof(vreq));
    vreq.interface_version = SERVICE_GRAPH_INTERFACE_VERSION;
    vreq.provider_count = current->root.provider_count;
    vreq.edge_count = current->root.edge_count;
    vreq.max_resource_units = current->root.max_resource_units;
    status = service_graph_validate(&vreq, providers, edges, &vreply);
    if (status != SERVICE_GRAPH_OK) {
        reply->status = status;
        return status;
    }

    /* Ensure the new graph is distinct from the prior ObjectID. */
    if (digest_eq(&vreply.graph_id, &current->root.graph_id)) {
        reply->status = SERVICE_GRAPH_ERR_INVALID;
        return reply->status;
    }

    bytes_zero(&preq, sizeof(preq));
    preq.interface_version = SERVICE_GRAPH_INTERFACE_VERSION;
    digest_copy(&preq.graph_id, &vreply.graph_id);
    digest_copy(&preq.expected_prior_graph_id, &current->root.graph_id);
    preq.event_lineage_seq = req->event_lineage_seq;
    status = service_graph_publish(&preq, &preply);
    if (status != SERVICE_GRAPH_OK) {
        reply->status = status;
        return status;
    }

    fresh = find_graph(&vreply.graph_id);
    if (fresh == NULL) {
        reply->status = SERVICE_GRAPH_ERR_NOT_FOUND;
        return reply->status;
    }
    reply->root = fresh->root;
    reply->status = SERVICE_GRAPH_OK;
    return SERVICE_GRAPH_OK;
}

uint32_t service_graph_rollback(
    const struct service_graph_req_rollback *req,
    struct service_graph_reply_rollback *reply)
{
    struct stored_graph *current;
    struct stored_graph *target;

    if (reply == NULL)
        return SERVICE_GRAPH_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != SERVICE_GRAPH_INTERFACE_VERSION) {
        reply->status = SERVICE_GRAPH_ERR_INVALID;
        return reply->status;
    }

    current = find_graph(&req->current_graph_id);
    target = find_graph(&req->target_graph_id);
    if (current == NULL || target == NULL || !current->published ||
        !target->published) {
        reply->status = SERVICE_GRAPH_ERR_NOT_FOUND;
        return reply->status;
    }
    if (!digest_eq(&g_sg.active_graph_id, &req->current_graph_id)) {
        reply->status = SERVICE_GRAPH_ERR_STALE_ROOT;
        return reply->status;
    }

    /* Target must be an ancestor (walk prior_graph_id chain). */
    {
        struct service_graph_digest cursor;
        int found = 0;
        digest_copy(&cursor, &current->root.prior_graph_id);
        while (!digest_is_zero(&cursor)) {
            struct stored_graph *step = find_graph(&cursor);
            if (step == NULL)
                break;
            if (digest_eq(&cursor, &req->target_graph_id)) {
                found = 1;
                break;
            }
            digest_copy(&cursor, &step->root.prior_graph_id);
        }
        if (!found) {
            reply->status = SERVICE_GRAPH_ERR_DENIED;
            return reply->status;
        }
    }

    /* Reactivate target: new activation generation, prior = current. */
    digest_copy(&target->root.prior_graph_id, &current->root.graph_id);
    target->root.activation_generation = g_sg.next_activation_generation++;
    target->root.event_lineage_seq = req->event_lineage_seq;
    digest_copy(&g_sg.active_graph_id, &target->root.graph_id);
    reply->root = target->root;
    reply->status = SERVICE_GRAPH_OK;
    return SERVICE_GRAPH_OK;
}

uint32_t service_graph_resolve(
    const struct service_graph_req_resolve *req,
    struct service_graph_reply_resolve *reply)
{
    struct stored_graph *slot;
    const struct service_graph_digest *id;

    if (reply == NULL)
        return SERVICE_GRAPH_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != SERVICE_GRAPH_INTERFACE_VERSION) {
        reply->status = SERVICE_GRAPH_ERR_INVALID;
        return reply->status;
    }

    id = digest_is_zero(&req->graph_id) ? &g_sg.active_graph_id : &req->graph_id;
    slot = find_graph(id);
    if (slot == NULL || !slot->published) {
        reply->status = SERVICE_GRAPH_ERR_NOT_FOUND;
        return reply->status;
    }
    reply->root = slot->root;
    reply->status = SERVICE_GRAPH_OK;
    return SERVICE_GRAPH_OK;
}

uint32_t service_graph_stored_count(void)
{
    uint32_t i, n = 0u;
    for (i = 0u; i < SERVICE_GRAPH_MAX_STORED; i++) {
        if (g_sg.graphs[i].used)
            n++;
    }
    return n;
}

uint32_t service_graph_artifact_count(void)
{
    return g_sg.artifact_count;
}
