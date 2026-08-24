#include "harness_composition.h"

#include "../include/contracts/agentfs_contract.h"
#include "../../../contracts/execsvc/interface.h"
#include "../../../contracts/toolsvc/interface.h"

#include <stddef.h>

#define KIB(n) ((uint32_t)(n) * 1024u)
#define HARNESS_COMPONENT_FLAG_MASK \
    (HARNESS_COMPONENT_PRIVATE | HARNESS_COMPONENT_SHARED_SERVICE | \
     HARNESS_COMPONENT_SINGLETON | HARNESS_COMPONENT_COMPATIBILITY)

static const struct harness_component_catalog_entry builtin_catalog[] = {
    {
        .component_id = HARNESS_COMPONENT_RUNNER_CORE,
        .version = HARNESS_COMPONENT_VERSION_1,
        .flags = HARNESS_COMPONENT_PRIVATE | HARNESS_COMPONENT_SINGLETON,
        .private_bytes = KIB(64),
    },
    {
        .component_id = HARNESS_COMPONENT_CODEX_PLANNER,
        .version = HARNESS_COMPONENT_VERSION_1,
        .flags = HARNESS_COMPONENT_PRIVATE | HARNESS_COMPONENT_SINGLETON,
        .requires_components =
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_RUNNER_CORE) |
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_CONTEXT) |
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_MODEL_CLIENT),
        .private_bytes = KIB(96),
    },
    {
        .component_id = HARNESS_COMPONENT_CONTEXT,
        .version = HARNESS_COMPONENT_VERSION_1,
        .flags = HARNESS_COMPONENT_PRIVATE | HARNESS_COMPONENT_SINGLETON,
        .requires_components =
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_RUNNER_CORE),
        .private_bytes = KIB(32),
    },
    {
        .component_id = HARNESS_COMPONENT_MODEL_CLIENT,
        .version = HARNESS_COMPONENT_VERSION_1,
        .flags = HARNESS_COMPONENT_PRIVATE |
                 HARNESS_COMPONENT_SHARED_SERVICE |
                 HARNESS_COMPONENT_SINGLETON,
        .requires_components =
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_RUNNER_CORE),
        .required_caps = HARNESS_CAP_MODEL,
        .private_bytes = KIB(4),
        .shared_mapped_bytes = TOOLSVC_CLIENT_ARENA_SIZE,
        .endpoint_mask = HARNESS_CAP_MODEL,
        .mapping_mask = HARNESS_CAP_MODEL,
        .shared_components = HARNESS_SHARED_MODELSVC,
    },
    {
        .component_id = HARNESS_COMPONENT_TOOL_CLIENT,
        .version = HARNESS_COMPONENT_VERSION_1,
        .flags = HARNESS_COMPONENT_PRIVATE |
                 HARNESS_COMPONENT_SHARED_SERVICE |
                 HARNESS_COMPONENT_SINGLETON,
        .requires_components =
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_RUNNER_CORE),
        .required_caps = HARNESS_CAP_TOOL,
        .private_bytes = KIB(4),
        .shared_mapped_bytes = AGENTFS_CLIENT_ARENA_SIZE,
        .endpoint_mask = HARNESS_CAP_TOOL,
        .mapping_mask = HARNESS_CAP_TOOL,
        .shared_components = HARNESS_SHARED_TOOL_MCP |
                             HARNESS_SHARED_REPO_INDEX,
    },
    {
        .component_id = HARNESS_COMPONENT_MEMORY_CLIENT,
        .version = HARNESS_COMPONENT_VERSION_1,
        .flags = HARNESS_COMPONENT_PRIVATE |
                 HARNESS_COMPONENT_SHARED_SERVICE |
                 HARNESS_COMPONENT_SINGLETON,
        .requires_components =
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_RUNNER_CORE),
        .required_caps = HARNESS_CAP_MEMORY,
        .private_bytes = KIB(4),
        .shared_mapped_bytes = EXECSVC_CLIENT_ARENA_SIZE,
        .endpoint_mask = HARNESS_CAP_MEMORY,
        .mapping_mask = HARNESS_CAP_MEMORY,
        .shared_components = HARNESS_SHARED_ARTIFACT_STORE,
    },
    {
        .component_id = HARNESS_COMPONENT_EXEC_CLIENT,
        .version = HARNESS_COMPONENT_VERSION_1,
        .flags = HARNESS_COMPONENT_PRIVATE |
                 HARNESS_COMPONENT_SHARED_SERVICE |
                 HARNESS_COMPONENT_SINGLETON,
        .requires_components =
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_RUNNER_CORE) |
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_MEMORY_CLIENT),
        .required_caps = HARNESS_CAP_EXEC,
        .private_bytes = KIB(4),
        .shared_mapped_bytes = MODELSVC_CLIENT_ARENA_SIZE,
        .endpoint_mask = HARNESS_CAP_EXEC,
        .mapping_mask = HARNESS_CAP_EXEC,
        .shared_components = HARNESS_SHARED_EXEC_GRAPH,
    },
    {
        .component_id = HARNESS_COMPONENT_NETWORK_CLIENT,
        .version = HARNESS_COMPONENT_VERSION_1,
        .flags = HARNESS_COMPONENT_PRIVATE |
                 HARNESS_COMPONENT_SHARED_SERVICE |
                 HARNESS_COMPONENT_SINGLETON,
        .requires_components =
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_RUNNER_CORE),
        .required_caps = HARNESS_CAP_NETWORK,
        .private_bytes = KIB(4),
        .endpoint_mask = HARNESS_CAP_NETWORK,
    },
    {
        .component_id = HARNESS_COMPONENT_CODEX_GUEST,
        .version = HARNESS_COMPONENT_VERSION_1,
        .flags = HARNESS_COMPONENT_PRIVATE |
                 HARNESS_COMPONENT_SINGLETON |
                 HARNESS_COMPONENT_COMPATIBILITY,
        .requires_components =
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_RUNNER_CORE),
        .conflicts_components =
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_CODEX_PLANNER) |
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_CONTEXT) |
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_MODEL_CLIENT) |
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_TOOL_CLIENT) |
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_MEMORY_CLIENT) |
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_EXEC_CLIENT) |
            HARNESS_COMPONENT_BIT(HARNESS_COMPONENT_NETWORK_CLIENT),
        /* Guest RAM is accounted by the VMM, not as runner-private state. */
        .private_bytes = KIB(4),
    },
};

static void zero_bytes(void *dst, uint32_t len)
{
    uint8_t *p = (uint8_t *)dst;
    for (uint32_t i = 0u; i < len; i++) p[i] = 0u;
}

static uint32_t fail(struct initagent_reply_compose *reply, uint32_t status,
                     uint32_t index)
{
    reply->status = status;
    reply->rejected_index = index;
    return status;
}

static const struct harness_component_catalog_entry *find_component(
    const struct harness_component_catalog_entry *catalog,
    uint32_t catalog_count, uint32_t component_id)
{
    for (uint32_t i = 0u; i < catalog_count; i++)
        if (catalog[i].component_id == component_id) return &catalog[i];
    return NULL;
}

static uint64_t fingerprint_refs(uint32_t *refs, uint32_t count)
{
    for (uint32_t i = 1u; i < count; i++) {
        uint32_t value = refs[i];
        uint32_t j = i;
        while (j > 0u && refs[j - 1u] > value) {
            refs[j] = refs[j - 1u];
            j--;
        }
        refs[j] = value;
    }

    uint64_t hash = UINT64_C(14695981039346656037);
    const uint64_t prime = UINT64_C(1099511628211);
    uint32_t header[2] = { HARNESS_COMPOSE_INTERFACE_VERSION, count };
    for (uint32_t h = 0u; h < 2u; h++)
        for (uint32_t b = 0u; b < 4u; b++) {
            hash ^= (uint8_t)(header[h] >> (b * 8u));
            hash *= prime;
        }
    for (uint32_t i = 0u; i < count; i++)
        for (uint32_t b = 0u; b < 4u; b++) {
            hash ^= (uint8_t)(refs[i] >> (b * 8u));
            hash *= prime;
        }
    return hash;
}

static uint32_t validate_catalog(
    const struct harness_component_catalog_entry *catalog,
    uint32_t catalog_count, uint32_t *catalog_mask)
{
    if (catalog == NULL || catalog_count == 0u || catalog_count > 32u)
        return HARNESS_COMPOSE_ERR_CATALOG;
    uint32_t known = 0u;
    for (uint32_t i = 0u; i < catalog_count; i++) {
        const struct harness_component_catalog_entry *entry = &catalog[i];
        if (entry->component_id == 0u || entry->component_id > 32u
            || entry->version == 0u
            || (entry->flags & ~HARNESS_COMPONENT_FLAG_MASK) != 0u
            || (entry->required_caps & ~HARNESS_CAP_KNOWN_MASK) != 0u
            || (entry->endpoint_mask & ~entry->required_caps) != 0u
            || (entry->mapping_mask & ~entry->endpoint_mask) != 0u
            || (entry->shared_components
                & ~HARNESS_SHARED_COMPONENT_MASK) != 0u)
            return HARNESS_COMPOSE_ERR_CATALOG;
        uint32_t bit = HARNESS_COMPONENT_BIT(entry->component_id);
        if ((known & bit) != 0u) return HARNESS_COMPOSE_ERR_CATALOG;
        known |= bit;
    }
    for (uint32_t i = 0u; i < catalog_count; i++)
        if (((catalog[i].requires_components
              | catalog[i].conflicts_components) & ~known) != 0u)
            return HARNESS_COMPOSE_ERR_CATALOG;
    *catalog_mask = known;
    return HARNESS_COMPOSE_OK;
}

uint32_t harness_compose_validate(
    const struct harness_component_catalog_entry *catalog,
    uint32_t catalog_count,
    const struct initagent_req_compose_validate *req,
    struct initagent_reply_compose *reply)
{
    if (reply == NULL) return HARNESS_COMPOSE_ERR_INVALID;
    zero_bytes(reply, sizeof(*reply));
    reply->rejected_index = UINT32_MAX;
    if (req == NULL || req->interface_version != HARNESS_COMPOSE_INTERFACE_VERSION
        || req->component_count == 0u
        || req->component_count > HARNESS_COMPOSE_MAX_COMPONENTS
        || (req->declared_caps & ~HARNESS_CAP_KNOWN_MASK) != 0u)
        return fail(reply, HARNESS_COMPOSE_ERR_INVALID, UINT32_MAX);

    uint32_t catalog_mask = 0u;
    uint32_t status = validate_catalog(catalog, catalog_count, &catalog_mask);
    if (status != HARNESS_COMPOSE_OK)
        return fail(reply, status, UINT32_MAX);

    uint32_t selected = 0u;
    uint32_t derived_caps = 0u;
    uint32_t private_bytes = 0u;
    uint32_t shared_bytes = 0u;
    uint32_t endpoint_mask = 0u;
    uint32_t mapping_mask = 0u;
    uint32_t shared_components = 0u;
    uint32_t canonical[HARNESS_COMPOSE_MAX_COMPONENTS];

    for (uint32_t i = 0u; i < req->component_count; i++) {
        uint32_t ref = req->component_refs[i];
        uint32_t id = HARNESS_COMPONENT_REF_ID(ref);
        uint32_t version = HARNESS_COMPONENT_REF_VERSION(ref);
        const struct harness_component_catalog_entry *entry =
            find_component(catalog, catalog_count, id);
        if (entry == NULL)
            return fail(reply, HARNESS_COMPOSE_ERR_UNKNOWN_COMPONENT, i);
        if (version != entry->version)
            return fail(reply, HARNESS_COMPOSE_ERR_VERSION, i);
        uint32_t bit = HARNESS_COMPONENT_BIT(id);
        if ((selected & bit) != 0u)
            return fail(reply, HARNESS_COMPOSE_ERR_DUPLICATE, i);
        selected |= bit;
        canonical[i] = ref;
        if (UINT32_MAX - private_bytes < entry->private_bytes
            || UINT32_MAX - shared_bytes < entry->shared_mapped_bytes)
            return fail(reply, HARNESS_COMPOSE_ERR_RESOURCE_LIMIT, i);
        private_bytes += entry->private_bytes;
        shared_bytes += entry->shared_mapped_bytes;
        derived_caps |= entry->required_caps;
        endpoint_mask |= entry->endpoint_mask;
        mapping_mask |= entry->mapping_mask;
        shared_components |= entry->shared_components;
    }

    for (uint32_t i = 0u; i < req->component_count; i++) {
        uint32_t id = HARNESS_COMPONENT_REF_ID(req->component_refs[i]);
        const struct harness_component_catalog_entry *entry =
            find_component(catalog, catalog_count, id);
        if ((entry->requires_components & selected)
                != entry->requires_components)
            return fail(reply, HARNESS_COMPOSE_ERR_DEPENDENCY, i);
        if ((entry->conflicts_components & selected) != 0u)
            return fail(reply, HARNESS_COMPOSE_ERR_CONFLICT, i);
    }

    uint32_t reach[32];
    for (uint32_t i = 0u; i < 32u; i++) reach[i] = 0u;
    for (uint32_t i = 0u; i < catalog_count; i++) {
        uint32_t id = catalog[i].component_id;
        if ((selected & HARNESS_COMPONENT_BIT(id)) != 0u)
            reach[id - 1u] = catalog[i].requires_components & selected;
    }
    for (uint32_t k = 0u; k < 32u; k++) {
        uint32_t kbit = 1u << k;
        if ((selected & kbit) == 0u) continue;
        for (uint32_t i = 0u; i < 32u; i++)
            if ((selected & (1u << i)) != 0u
                && (reach[i] & kbit) != 0u)
                reach[i] |= reach[k];
    }
    for (uint32_t i = 0u; i < 32u; i++)
        if ((selected & (1u << i)) != 0u
            && (reach[i] & (1u << i)) != 0u)
            return fail(reply, HARNESS_COMPOSE_ERR_CYCLE, UINT32_MAX);

    if (derived_caps != req->declared_caps)
        return fail(reply, HARNESS_COMPOSE_ERR_CAPABILITY, UINT32_MAX);
    uint32_t private_limit = req->private_limit_bytes == 0u
        ? HARNESS_COMPOSE_DEFAULT_LIMIT_BYTES : req->private_limit_bytes;
    if (private_limit > HARNESS_COMPOSE_MAX_PRIVATE_BYTES
        || private_bytes > private_limit)
        return fail(reply, HARNESS_COMPOSE_ERR_RESOURCE_LIMIT, UINT32_MAX);

    uint64_t fingerprint = fingerprint_refs(canonical, req->component_count);
    reply->status = HARNESS_COMPOSE_OK;
    reply->profile_id = req->profile_id;
    reply->fingerprint_lo = (uint32_t)fingerprint;
    reply->fingerprint_hi = (uint32_t)(fingerprint >> 32);
    reply->component_mask = selected;
    reply->required_caps = derived_caps;
    reply->private_committed_bytes = private_bytes;
    reply->shared_mapped_bytes = shared_bytes;
    reply->endpoint_mask = endpoint_mask;
    reply->mapping_mask = mapping_mask;
    reply->shared_components = shared_components;
    reply->rejected_index = UINT32_MAX;
    return HARNESS_COMPOSE_OK;
}

static uint32_t fill_profile(uint32_t profile_id, uint32_t private_limit,
                             struct initagent_req_compose_validate *manifest)
{
    zero_bytes(manifest, sizeof(*manifest));
    manifest->interface_version = HARNESS_COMPOSE_INTERFACE_VERSION;
    manifest->profile_id = profile_id;
    manifest->private_limit_bytes = private_limit;
    manifest->component_refs[0] = HARNESS_COMPONENT_REF(
        HARNESS_COMPONENT_RUNNER_CORE, HARNESS_COMPONENT_VERSION_1);
    if (profile_id == HARNESS_PROFILE_READ_ONLY
        || profile_id == HARNESS_PROFILE_CODING) {
        manifest->component_refs[1] = HARNESS_COMPONENT_REF(
            HARNESS_COMPONENT_CONTEXT, HARNESS_COMPONENT_VERSION_1);
        manifest->component_refs[2] = HARNESS_COMPONENT_REF(
            HARNESS_COMPONENT_MODEL_CLIENT, HARNESS_COMPONENT_VERSION_1);
        manifest->component_refs[3] = HARNESS_COMPONENT_REF(
            HARNESS_COMPONENT_CODEX_PLANNER, HARNESS_COMPONENT_VERSION_1);
        manifest->component_refs[4] = HARNESS_COMPONENT_REF(
            HARNESS_COMPONENT_TOOL_CLIENT, HARNESS_COMPONENT_VERSION_1);
        manifest->component_count = 5u;
        manifest->declared_caps = HARNESS_CAP_MODEL | HARNESS_CAP_TOOL;
        if (profile_id == HARNESS_PROFILE_CODING) {
            manifest->component_refs[5] = HARNESS_COMPONENT_REF(
                HARNESS_COMPONENT_MEMORY_CLIENT, HARNESS_COMPONENT_VERSION_1);
            manifest->component_refs[6] = HARNESS_COMPONENT_REF(
                HARNESS_COMPONENT_EXEC_CLIENT, HARNESS_COMPONENT_VERSION_1);
            manifest->component_count = 7u;
            manifest->declared_caps |= HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC;
        }
        return HARNESS_COMPOSE_OK;
    }
    if (profile_id == HARNESS_PROFILE_CODEX_COMPAT) {
        manifest->component_refs[1] = HARNESS_COMPONENT_REF(
            HARNESS_COMPONENT_CODEX_GUEST, HARNESS_COMPONENT_VERSION_1);
        manifest->component_count = 2u;
        return HARNESS_COMPOSE_OK;
    }
    return HARNESS_COMPOSE_ERR_UNKNOWN_PROFILE;
}

uint32_t harness_compose_validate_builtin(
    const struct initagent_req_compose_validate *req,
    struct initagent_reply_compose *reply)
{
    uint32_t status = harness_compose_validate(
        builtin_catalog,
        (uint32_t)(sizeof(builtin_catalog) / sizeof(builtin_catalog[0])),
        req, reply);
    if (status != HARNESS_COMPOSE_OK || req->profile_id == HARNESS_PROFILE_CUSTOM)
        return status;

    struct initagent_req_compose_validate expected;
    status = fill_profile(req->profile_id, req->private_limit_bytes, &expected);
    if (status != HARNESS_COMPOSE_OK)
        return fail(reply, status, UINT32_MAX);
    struct initagent_reply_compose expected_reply;
    status = harness_compose_validate(
        builtin_catalog,
        (uint32_t)(sizeof(builtin_catalog) / sizeof(builtin_catalog[0])),
        &expected, &expected_reply);
    if (status != HARNESS_COMPOSE_OK) return fail(reply, status, UINT32_MAX);
    if (reply->component_mask != expected_reply.component_mask
        || reply->required_caps != expected_reply.required_caps)
        return fail(reply, HARNESS_COMPOSE_ERR_INVALID, UINT32_MAX);
    return HARNESS_COMPOSE_OK;
}

uint32_t harness_compose_profile(
    const struct initagent_req_compose_profile *req,
    struct initagent_reply_compose *reply)
{
    if (reply == NULL) return HARNESS_COMPOSE_ERR_INVALID;
    zero_bytes(reply, sizeof(*reply));
    reply->rejected_index = UINT32_MAX;
    if (req == NULL || req->interface_version != HARNESS_COMPOSE_INTERFACE_VERSION
        || req->reserved != 0u)
        return fail(reply, HARNESS_COMPOSE_ERR_INVALID, UINT32_MAX);
    struct initagent_req_compose_validate manifest;
    uint32_t status = fill_profile(req->profile_id, req->private_limit_bytes,
                                   &manifest);
    if (status != HARNESS_COMPOSE_OK)
        return fail(reply, status, UINT32_MAX);
    return harness_compose_validate_builtin(&manifest, reply);
}

const struct harness_component_catalog_entry *
harness_compose_builtin_catalog(uint32_t *count)
{
    if (count != NULL)
        *count = (uint32_t)(sizeof(builtin_catalog) / sizeof(builtin_catalog[0]));
    return builtin_catalog;
}
