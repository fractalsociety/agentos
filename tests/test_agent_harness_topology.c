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

static uint32_t service_badge_data(const pd_desc_t *pd, uint16_t service_id)
{
    for (uint32_t i = 0u; i < pd->init_ep_count; i++)
        if (pd->init_eps[i].service_id == service_id)
            return pd->init_eps[i].badge_data;
    return 0u;
}

int main(void)
{
    const pd_desc_t *harness = find_pd("codex_harness");
    const pd_desc_t *model = find_pd("model_svc");
    const pd_desc_t *tools = find_pd("tool_svc");
    const pd_desc_t *memory = find_pd("agentfs");
    const pd_desc_t *exec = find_pd("exec_verify");
    const pd_desc_t *exec_transport = find_pd("exec_transport");
    const pd_desc_t *mcp_transport = find_pd("mcp_transport");
    const pd_desc_t *controller = find_pd("controller");
    const pd_desc_t *launcher = find_pd("init_agent");
    assert(harness != NULL);
    assert(model != NULL);
    assert(tools != NULL);
    assert(memory != NULL);
    assert(exec != NULL);
    assert(exec_transport != NULL);
    assert(mcp_transport != NULL);
    assert(controller != NULL);
    assert(launcher != NULL);

    assert(harness->self_svc_id == SVC_ID_AGENT_HARNESS);
    assert(harness->stack_size == 0x10000u);
    assert(harness->cnode_size_bits == 8u);
    assert(has_service(harness, SVC_ID_MODELSVC));
    assert(has_service(harness, SVC_ID_LOG_DRAIN));
    assert(!has_service(harness, SVC_ID_NET_SERVER));
    assert(!has_service(harness, SVC_ID_NET_PD));
    /* ToolCap is deliberately absent at boot and is minted into its canonical
     * slot by the restricted CapBroker authority manifest. */
    assert(!has_service(harness, SVC_ID_TOOLSVC));
    assert(has_service(harness, SVC_ID_AGENTFS));
    assert(has_service(harness, SVC_ID_EXEC_SERVER));
    assert(service_badge_data(harness, SVC_ID_EXEC_SERVER)
           == EXECSVC_RIGHT_ALL);
    assert(!has_service(harness, SVC_ID_EXEC_TRANSPORT));
    assert(!has_service(harness, SVC_ID_MCP_TRANSPORT));

    /* Network belongs to ModelSvc, not to the worker. */
    assert(has_service(model, SVC_ID_NET_SERVER));
    assert(tools->self_svc_id == SVC_ID_TOOLSVC);
    assert(!has_service(tools, SVC_ID_NET_SERVER));
    assert(!has_service(tools, SVC_ID_MODELSVC));
    assert(!has_service(tools, SVC_ID_AGENTFS));
    assert(!has_service(tools, SVC_ID_EXEC_TRANSPORT));
    assert(has_service(tools, SVC_ID_MCP_TRANSPORT));
    assert(has_service(tools, SVC_ID_EXEC_SERVER));
    assert(service_badge_data(tools, SVC_ID_EXEC_SERVER)
           == EXECSVC_RIGHT_AGENTOS_REPOSITORY);
    assert(memory->self_svc_id == SVC_ID_AGENTFS);
    assert(exec->self_svc_id == SVC_ID_EXEC_SERVER);
    assert(!has_service(exec, SVC_ID_MODELSVC));
    assert(!has_service(exec, SVC_ID_AGENTFS));
    assert(!has_service(exec, SVC_ID_TOOLSVC));
    assert(!has_service(exec, SVC_ID_NET_SERVER));
    assert(has_service(exec, SVC_ID_EXEC_TRANSPORT));
    assert(exec_transport->self_svc_id == SVC_ID_EXEC_TRANSPORT);
    assert(!has_service(exec_transport, SVC_ID_MODELSVC));
    assert(!has_service(exec_transport, SVC_ID_TOOLSVC));
    assert(!has_service(exec_transport, SVC_ID_AGENTFS));
    assert(!has_service(exec_transport, SVC_ID_EXEC_SERVER));
    assert(!has_service(exec_transport, SVC_ID_NET_SERVER));
    assert(mcp_transport->self_svc_id == SVC_ID_MCP_TRANSPORT);
    assert(!has_service(mcp_transport, SVC_ID_MODELSVC));
    assert(!has_service(mcp_transport, SVC_ID_TOOLSVC));
    assert(!has_service(mcp_transport, SVC_ID_AGENTFS));
    assert(!has_service(mcp_transport, SVC_ID_EXEC_SERVER));
    assert(!has_service(mcp_transport, SVC_ID_NET_SERVER));
    assert(has_service(controller, SVC_ID_AGENT_HARNESS));
    assert(has_service(launcher, SVC_ID_CONTROLLER));
    assert(service_badge_data(launcher, SVC_ID_CONTROLLER)
           == CONTROLLER_RIGHT_CAP_ADMIN);

    puts("agent harness topology tests: ok");
    return 0;
}
