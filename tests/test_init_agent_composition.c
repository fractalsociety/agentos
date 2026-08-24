/* Host dispatch proof for both InitAgent composition opcodes. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define AGENTOS_TEST_HOST 1
#include "../kernel/agentos-root-task/src/harness_composition.c"
#include "../kernel/agentos-root-task/src/init_agent.c"

static void dispatch(uint32_t opcode, const void *payload, uint32_t length,
                     struct initagent_reply_compose *reply)
{
    sel4_msg_t req = {0}, rep = {0};
    req.opcode = opcode;
    req.length = length;
    if (payload != NULL && length <= sizeof(req.data))
        memcpy(req.data, payload, length);
    assert(init_agent_dispatch_one(0u, &req, &rep) == SEL4_ERR_OK);
    assert(rep.length == sizeof(*reply));
    memcpy(reply, rep.data, sizeof(*reply));
}

int main(void)
{
    init_agent_test_init();
    struct initagent_req_compose_profile profile = {
        .interface_version = HARNESS_COMPOSE_INTERFACE_VERSION,
        .profile_id = HARNESS_PROFILE_READ_ONLY,
        .private_limit_bytes = HARNESS_COMPOSE_DEFAULT_LIMIT_BYTES,
    };
    struct initagent_reply_compose read_only, coding;
    dispatch(MSG_INITAGENT_COMPOSE_PROFILE, &profile, sizeof(profile),
             &read_only);
    assert(read_only.status == HARNESS_COMPOSE_OK);
    profile.profile_id = HARNESS_PROFILE_CODING;
    dispatch(MSG_INITAGENT_COMPOSE_PROFILE, &profile, sizeof(profile), &coding);
    assert(coding.status == HARNESS_COMPOSE_OK);
    assert(read_only.component_mask != coding.component_mask);
    assert((read_only.mapping_mask & (HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC))
           == 0u);

    struct initagent_req_compose_validate manifest = {
        .interface_version = HARNESS_COMPOSE_INTERFACE_VERSION,
        .component_count = 1u,
        .private_limit_bytes = HARNESS_COMPOSE_DEFAULT_LIMIT_BYTES,
        .component_refs = {
            HARNESS_COMPONENT_REF(HARNESS_COMPONENT_RUNNER_CORE, 1u),
        },
    };
    struct initagent_reply_compose custom;
    dispatch(MSG_INITAGENT_COMPOSE_VALIDATE, &manifest, sizeof(manifest),
             &custom);
    assert(custom.status == HARNESS_COMPOSE_OK);

    dispatch(MSG_INITAGENT_COMPOSE_VALIDATE, &manifest,
             sizeof(manifest) - 1u, &custom);
    assert(custom.status == HARNESS_COMPOSE_ERR_INVALID);

    puts("init agent composition dispatch tests: ok");
    return 0;
}
