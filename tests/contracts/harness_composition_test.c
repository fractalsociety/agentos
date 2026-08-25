/* Contract and validator tests for launcher-owned AgentHarness composition. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../kernel/fractalos-root-task/include/harness_composition.h"

static unsigned tests;
static unsigned failures;

static void check(int condition, const char *name)
{
    tests++;
    if (condition) printf("ok %u - %s\n", tests, name);
    else {
        printf("not ok %u - %s\n", tests, name);
        failures++;
    }
}

static struct initagent_req_compose_validate request_for(
    const uint32_t *refs, uint32_t count, uint32_t caps)
{
    struct initagent_req_compose_validate req;
    memset(&req, 0, sizeof(req));
    req.interface_version = HARNESS_COMPOSE_INTERFACE_VERSION;
    req.component_count = count;
    req.declared_caps = caps;
    req.private_limit_bytes = HARNESS_COMPOSE_DEFAULT_LIMIT_BYTES;
    for (uint32_t i = 0u; i < count && i < HARNESS_COMPOSE_MAX_COMPONENTS; i++)
        req.component_refs[i] = refs[i];
    return req;
}

static void test_contract_layout(void)
{
    check(MSG_INITAGENT_COMPOSE_VALIDATE != MSG_INITAGENT_COMPOSE_PROFILE,
          "each composition opcode is unique");
    check(sizeof(struct initagent_req_compose_validate) == 48u,
          "validate manifest fits one seL4 payload");
    check(sizeof(struct initagent_reply_compose) == 48u,
          "composition reply fits one seL4 payload");
    check(HARNESS_COMPOSE_MAX_COMPONENTS == 7u,
          "bounded manifest has seven component slots");
}

static void test_builtin_profiles(void)
{
    struct initagent_req_compose_profile req = {
        .interface_version = HARNESS_COMPOSE_INTERFACE_VERSION,
        .profile_id = HARNESS_PROFILE_READ_ONLY,
        .private_limit_bytes = HARNESS_COMPOSE_DEFAULT_LIMIT_BYTES,
    };
    struct initagent_reply_compose read_only, coding;
    check(harness_compose_profile(&req, &read_only) == HARNESS_COMPOSE_OK,
          "read-only profile validates");
    req.profile_id = HARNESS_PROFILE_CODING;
    check(harness_compose_profile(&req, &coding) == HARNESS_COMPOSE_OK,
          "coding profile validates");
    check(read_only.fingerprint_lo != coding.fingerprint_lo
              || read_only.fingerprint_hi != coding.fingerprint_hi,
          "heterogeneous profiles have distinct graph fingerprints");
    check(read_only.private_committed_bytes < coding.private_committed_bytes,
          "read-only worker allocates less private component state");
    check(read_only.shared_mapped_bytes < coding.shared_mapped_bytes,
          "read-only worker maps fewer shared client arenas");
    check((read_only.endpoint_mask & (HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC)) == 0u
              && (read_only.mapping_mask
                  & (HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC)) == 0u,
          "read-only profile omits memory and execution endpoints and mappings");
    check((coding.endpoint_mask & (HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC))
              == (HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC),
          "coding profile selects memory and execution components");
}

static void test_manifest_rejections(void)
{
    struct initagent_reply_compose reply;
    const uint32_t base[] = {
        HARNESS_COMPONENT_REF(HARNESS_COMPONENT_RUNNER_CORE, 1u),
        HARNESS_COMPONENT_REF(HARNESS_COMPONENT_CONTEXT, 1u),
        HARNESS_COMPONENT_REF(HARNESS_COMPONENT_MODEL_CLIENT, 1u),
        HARNESS_COMPONENT_REF(HARNESS_COMPONENT_CODEX_PLANNER, 1u),
    };
    struct initagent_req_compose_validate req = request_for(
        base, 4u, HARNESS_CAP_MODEL);
    check(harness_compose_validate_builtin(&req, &reply) == HARNESS_COMPOSE_OK,
          "valid custom minimal planner graph is accepted");
    uint32_t first_lo = reply.fingerprint_lo;
    uint32_t first_hi = reply.fingerprint_hi;

    const uint32_t reordered[] = { base[3], base[2], base[0], base[1] };
    req = request_for(reordered, 4u, HARNESS_CAP_MODEL);
    check(harness_compose_validate_builtin(&req, &reply) == HARNESS_COMPOSE_OK
              && reply.fingerprint_lo == first_lo
              && reply.fingerprint_hi == first_hi,
          "graph fingerprint is independent of manifest ordering");

    uint32_t unknown[] = { HARNESS_COMPONENT_REF(99u, 1u) };
    req = request_for(unknown, 1u, 0u);
    check(harness_compose_validate_builtin(&req, &reply)
              == HARNESS_COMPOSE_ERR_UNKNOWN_COMPONENT
              && reply.rejected_index == 0u,
          "unknown component is rejected with its manifest index");

    uint32_t wrong_version[] = {
        HARNESS_COMPONENT_REF(HARNESS_COMPONENT_RUNNER_CORE, 2u)
    };
    req = request_for(wrong_version, 1u, 0u);
    check(harness_compose_validate_builtin(&req, &reply)
              == HARNESS_COMPOSE_ERR_VERSION,
          "incompatible component version is rejected");

    uint32_t duplicate[] = { base[0], base[0] };
    req = request_for(duplicate, 2u, 0u);
    check(harness_compose_validate_builtin(&req, &reply)
              == HARNESS_COMPOSE_ERR_DUPLICATE,
          "duplicate singleton component is rejected");

    uint32_t planner_only[] = { base[3] };
    req = request_for(planner_only, 1u, HARNESS_CAP_MODEL);
    check(harness_compose_validate_builtin(&req, &reply)
              == HARNESS_COMPOSE_ERR_DEPENDENCY,
          "missing component dependency is rejected");

    req = request_for(base, 4u, 0u);
    check(harness_compose_validate_builtin(&req, &reply)
              == HARNESS_COMPOSE_ERR_CAPABILITY,
          "undeclared required capability is rejected");
    req = request_for(base, 4u, HARNESS_CAP_MODEL | HARNESS_CAP_EXEC);
    check(harness_compose_validate_builtin(&req, &reply)
              == HARNESS_COMPOSE_ERR_CAPABILITY,
          "unneeded capability declaration is rejected");

    req = request_for(base, 4u, HARNESS_CAP_MODEL);
    req.private_limit_bytes = 1u;
    check(harness_compose_validate_builtin(&req, &reply)
              == HARNESS_COMPOSE_ERR_RESOURCE_LIMIT,
          "private component state must fit the requested limit");
}

static void test_catalog_graph_rejections(void)
{
    struct harness_component_catalog_entry cycle_catalog[] = {
        {
            .component_id = 1u, .version = 1u,
            .flags = HARNESS_COMPONENT_PRIVATE | HARNESS_COMPONENT_SINGLETON,
            .requires_components = HARNESS_COMPONENT_BIT(2u),
        },
        {
            .component_id = 2u, .version = 1u,
            .flags = HARNESS_COMPONENT_PRIVATE | HARNESS_COMPONENT_SINGLETON,
            .requires_components = HARNESS_COMPONENT_BIT(1u),
        },
    };
    uint32_t refs[] = {
        HARNESS_COMPONENT_REF(1u, 1u),
        HARNESS_COMPONENT_REF(2u, 1u),
    };
    struct initagent_req_compose_validate req = request_for(refs, 2u, 0u);
    struct initagent_reply_compose reply;
    check(harness_compose_validate(cycle_catalog, 2u, &req, &reply)
              == HARNESS_COMPOSE_ERR_CYCLE,
          "cyclic component graph is rejected");

    cycle_catalog[0].requires_components = 0u;
    cycle_catalog[0].conflicts_components = HARNESS_COMPONENT_BIT(2u);
    cycle_catalog[1].requires_components = 0u;
    check(harness_compose_validate(cycle_catalog, 2u, &req, &reply)
              == HARNESS_COMPOSE_ERR_CONFLICT,
          "conflicting components are rejected");

    cycle_catalog[0].conflicts_components = 0u;
    cycle_catalog[0].requires_components = HARNESS_COMPONENT_BIT(3u);
    check(harness_compose_validate(cycle_catalog, 2u, &req, &reply)
              == HARNESS_COMPOSE_ERR_CATALOG,
          "catalog dependency on an unknown component fails closed");
}

static void test_unknown_profile(void)
{
    struct initagent_req_compose_profile req = {
        .interface_version = HARNESS_COMPOSE_INTERFACE_VERSION,
        .profile_id = 0xfeedu,
        .private_limit_bytes = HARNESS_COMPOSE_DEFAULT_LIMIT_BYTES,
    };
    struct initagent_reply_compose reply;
    check(harness_compose_profile(&req, &reply)
              == HARNESS_COMPOSE_ERR_UNKNOWN_PROFILE,
          "unknown built-in profile is rejected");
}

int main(void)
{
    puts("TAP version 14");
    test_contract_layout();
    test_builtin_profiles();
    test_manifest_rejections();
    test_catalog_graph_rejections();
    test_unknown_profile();
    printf("1..%u\n", tests);
    return failures == 0u ? 0 : 1;
}
