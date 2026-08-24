/* Static AArch64 topology proof for the least-privilege AgentHarness PD. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/agentos-root-task/src/system_desc_aarch64.c"

static const pd_desc_t *find_pd(const char *name)
{
    for (uint32_t i = 0u; i < system_desc_aarch64.pd_count; i++) {
        if (strcmp(system_desc_aarch64.pds[i].name, name) == 0)
            return &system_desc_aarch64.pds[i];
    }
    return NULL;
}

static int has_service(const pd_desc_t *pd, uint16_t service_id)
{
    for (uint32_t i = 0u; i < pd->init_ep_count; i++)
        if (pd->init_eps[i].service_id == service_id) return 1;
    return 0;
}

int main(void)
{
    const pd_desc_t *harness = find_pd("codex_harness");
    const pd_desc_t *model = find_pd("model_svc");
    const pd_desc_t *controller = find_pd("controller");
    assert(harness != NULL);
    assert(model != NULL);
    assert(controller != NULL);

    assert(harness->self_svc_id == SVC_ID_AGENT_HARNESS);
    assert(harness->stack_size == 0x10000u);
    assert(harness->cnode_size_bits == 8u);
    assert(has_service(harness, SVC_ID_MODELSVC));
    assert(has_service(harness, SVC_ID_LOG_DRAIN));
    assert(!has_service(harness, SVC_ID_NET_SERVER));
    assert(!has_service(harness, SVC_ID_NET_PD));
    assert(!has_service(harness, SVC_ID_TOOLSVC));
    assert(!has_service(harness, SVC_ID_AGENTFS));
    assert(!has_service(harness, SVC_ID_EXEC_SERVER));

    /* Network belongs to ModelSvc, not to the worker. */
    assert(has_service(model, SVC_ID_NET_SERVER));
    assert(has_service(controller, SVC_ID_AGENT_HARNESS));

    puts("agent harness topology tests: ok");
    return 0;
}
