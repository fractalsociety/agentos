/*
 * fos-gz0.14.9 — immutable capability service graph + governed provider swaps
 * (L2 host).
 *
 * Proves: consumers bind by interface hash only; two compatible providers work
 * unchanged for the consumer; cycles, incompatible versions, undeclared
 * effects/caps, missing deps, excess resources, and fabricated provider IDs
 * fail closed; swap/rollback preserve activation lineage.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/include/fractalos.h"
#include "../kernel/fractalos-root-task/include/service_graph.h"

static int g_failures;

static void expect_eq_u32(const char *name, uint32_t got, uint32_t want)
{
    if (got != want) {
        fprintf(stderr, "FAIL %s: got %u want %u\n", name, got, want);
        g_failures++;
    } else {
        printf("ok - %s\n", name);
    }
}

static void expect_true(const char *name, int cond)
{
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", name);
        g_failures++;
    } else {
        printf("ok - %s\n", name);
    }
}

static void digest_fill(struct service_graph_digest *d, uint8_t seed)
{
    uint32_t i;
    for (i = 0u; i < SERVICE_GRAPH_DIGEST_BYTES; i++)
        d->bytes[i] = (uint8_t)(seed + i);
}

static struct service_graph_provider make_provider(
    uint8_t id_seed, uint8_t iface_seed, uint32_t major, uint32_t minor,
    uint64_t caps, uint32_t effects, uint32_t resources)
{
    struct service_graph_provider p;
    memset(&p, 0, sizeof(p));
    digest_fill(&p.provider_id, id_seed);
    digest_fill(&p.interface_hash, iface_seed);
    p.interface_major = major;
    p.interface_minor = minor;
    p.required_cap_mask = caps;
    p.budget_units = 100u;
    p.effect_mask = effects;
    p.resource_units = resources;
    return p;
}

static void register_provider(const struct service_graph_provider *p)
{
    expect_eq_u32("register artifact",
                  service_graph_register_artifact(&p->provider_id),
                  SERVICE_GRAPH_OK);
}

static uint32_t publish_graph(const struct service_graph_provider *providers,
                              uint32_t provider_count,
                              const struct service_graph_edge *edges,
                              uint32_t edge_count, uint32_t max_resources,
                              const struct service_graph_digest *expected_prior,
                              uint64_t event_seq,
                              struct service_graph_root *out_root)
{
    struct service_graph_req_validate vreq;
    struct service_graph_reply_validate vreply;
    struct service_graph_req_publish preq;
    struct service_graph_reply_publish preply;
    uint32_t status;

    memset(&vreq, 0, sizeof(vreq));
    vreq.interface_version = SERVICE_GRAPH_INTERFACE_VERSION;
    vreq.provider_count = provider_count;
    vreq.edge_count = edge_count;
    vreq.max_resource_units = max_resources;
    status = service_graph_validate(&vreq, providers, edges, &vreply);
    if (status != SERVICE_GRAPH_OK)
        return status;

    memset(&preq, 0, sizeof(preq));
    preq.interface_version = SERVICE_GRAPH_INTERFACE_VERSION;
    preq.graph_id = vreply.graph_id;
    if (expected_prior != NULL)
        preq.expected_prior_graph_id = *expected_prior;
    preq.event_lineage_seq = event_seq;
    status = service_graph_publish(&preq, &preply);
    if (status == SERVICE_GRAPH_OK && out_root != NULL)
        *out_root = preply.root;
    return status;
}

static void test_opcodes(void)
{
    expect_eq_u32("MSG_SERVICE_GRAPH_VALIDATE", MSG_SERVICE_GRAPH_VALIDATE,
                  0x3201u);
    expect_eq_u32("MSG_SERVICE_GRAPH_PUBLISH", MSG_SERVICE_GRAPH_PUBLISH,
                  0x3202u);
    expect_eq_u32("MSG_SERVICE_GRAPH_BIND", MSG_SERVICE_GRAPH_BIND, 0x3203u);
    expect_eq_u32("MSG_SERVICE_GRAPH_SWAP", MSG_SERVICE_GRAPH_SWAP, 0x3204u);
    expect_eq_u32("MSG_SERVICE_GRAPH_ROLLBACK", MSG_SERVICE_GRAPH_ROLLBACK,
                  0x3205u);
    expect_eq_u32("MSG_SERVICE_GRAPH_RESOLVE", MSG_SERVICE_GRAPH_RESOLVE,
                  0x3206u);
    expect_eq_u32("interface version", SERVICE_GRAPH_INTERFACE_VERSION, 1u);
}

static void test_two_providers_same_consumer(void)
{
    struct service_graph_provider providers[1];
    struct service_graph_root root_a;
    struct service_graph_root root_b;
    struct service_graph_req_bind breq;
    struct service_graph_reply_bind breply_a;
    struct service_graph_reply_bind breply_b;
    struct service_graph_req_swap sreq;
    struct service_graph_reply_swap sreply;
    struct service_graph_provider alt;

    service_graph_reset();
    providers[0] = make_provider(0x10u, 0x20u, 1u, 2u, 0xFFu,
                                 SERVICE_GRAPH_EFFECT_ACTION, 10u);
    alt = make_provider(0x11u, 0x20u, 1u, 3u, 0xFFu, SERVICE_GRAPH_EFFECT_ACTION,
                        10u);
    register_provider(&providers[0]);
    register_provider(&alt);

    expect_eq_u32("publish provider A",
                  publish_graph(providers, 1u, NULL, 0u, 100u, NULL, 1u,
                                &root_a),
                  SERVICE_GRAPH_OK);

    memset(&breq, 0, sizeof(breq));
    breq.interface_version = SERVICE_GRAPH_INTERFACE_VERSION;
    digest_fill(&breq.interface_hash, 0x20u);
    breq.interface_major = 1u;
    breq.interface_minor = 1u;
    breq.requested_cap_mask = 0x0Fu;
    breq.requested_effect_mask = SERVICE_GRAPH_EFFECT_ACTION;
    expect_eq_u32("bind A", service_graph_bind(&breq, &breply_a),
                  SERVICE_GRAPH_OK);
    expect_true("bind A provider id",
                memcmp(breply_a.provider_id.bytes, providers[0].provider_id.bytes,
                       SERVICE_GRAPH_DIGEST_BYTES) == 0);

    memset(&sreq, 0, sizeof(sreq));
    sreq.interface_version = SERVICE_GRAPH_INTERFACE_VERSION;
    sreq.current_graph_id = root_a.graph_id;
    digest_fill(&sreq.interface_hash, 0x20u);
    sreq.new_provider = alt;
    sreq.event_lineage_seq = 2u;
    expect_eq_u32("swap to provider B", service_graph_swap(&sreq, &sreply),
                  SERVICE_GRAPH_OK);
    root_b = sreply.root;
    expect_true("swap minted new graph id",
                memcmp(root_a.graph_id.bytes, root_b.graph_id.bytes,
                       SERVICE_GRAPH_DIGEST_BYTES) != 0);
    expect_true("swap prior lineage",
                memcmp(root_b.prior_graph_id.bytes, root_a.graph_id.bytes,
                       SERVICE_GRAPH_DIGEST_BYTES) == 0);
    expect_true("swap activation advanced",
                root_b.activation_generation > root_a.activation_generation);

    /* Same consumer bind request (unchanged) against new provider. */
    expect_eq_u32("bind B with same consumer request",
                  service_graph_bind(&breq, &breply_b), SERVICE_GRAPH_OK);
    expect_true("bind B provider id",
                memcmp(breply_b.provider_id.bytes, alt.provider_id.bytes,
                       SERVICE_GRAPH_DIGEST_BYTES) == 0);
    expect_eq_u32("consumer major unchanged", breply_b.provider_major, 1u);
}

static void test_fail_closed_cases(void)
{
    struct service_graph_provider providers[2];
    struct service_graph_edge edges[2];
    struct service_graph_req_validate vreq;
    struct service_graph_reply_validate vreply;
    struct service_graph_root root;
    struct service_graph_req_bind breq;
    struct service_graph_reply_bind breply;
    struct service_graph_provider fabricated;

    service_graph_reset();
    providers[0] = make_provider(0x30u, 0x40u, 1u, 0u, 0x0Fu,
                                 SERVICE_GRAPH_EFFECT_OBJECT_READ, 50u);
    providers[1] = make_provider(0x31u, 0x41u, 1u, 0u, 0x0Fu,
                                 SERVICE_GRAPH_EFFECT_OBJECT_READ, 50u);
    register_provider(&providers[0]);
    register_provider(&providers[1]);

    /* Fabricated provider id (never registered). */
    fabricated = make_provider(0xEEu, 0x40u, 1u, 0u, 0x0Fu,
                               SERVICE_GRAPH_EFFECT_OBJECT_READ, 10u);
    memset(&vreq, 0, sizeof(vreq));
    vreq.interface_version = SERVICE_GRAPH_INTERFACE_VERSION;
    vreq.provider_count = 1u;
    vreq.max_resource_units = 100u;
    expect_eq_u32("fabricated provider denied",
                  service_graph_validate(&vreq, &fabricated, NULL, &vreply),
                  SERVICE_GRAPH_ERR_FABRICATED_PROVIDER);

    /* Excess resources. */
    vreq.provider_count = 2u;
    vreq.max_resource_units = 80u;
    expect_eq_u32("excess resources denied",
                  service_graph_validate(&vreq, providers, NULL, &vreply),
                  SERVICE_GRAPH_ERR_EXCESS_RESOURCE);

    /* Missing dependency. */
    memset(edges, 0, sizeof(edges));
    edges[0].from_provider = providers[0].provider_id;
    digest_fill(&edges[0].needs_interface, 0x99u); /* no provider */
    vreq.edge_count = 1u;
    vreq.max_resource_units = 200u;
    expect_eq_u32("missing dep denied",
                  service_graph_validate(&vreq, providers, edges, &vreply),
                  SERVICE_GRAPH_ERR_MISSING_DEP);

    /* Cycle A->B->A via interfaces. */
    edges[0].from_provider = providers[0].provider_id;
    edges[0].needs_interface = providers[1].interface_hash;
    edges[1].from_provider = providers[1].provider_id;
    edges[1].needs_interface = providers[0].interface_hash;
    vreq.edge_count = 2u;
    expect_eq_u32("cycle denied",
                  service_graph_validate(&vreq, providers, edges, &vreply),
                  SERVICE_GRAPH_ERR_CYCLE);

    /* Happy path then bind denials. */
    expect_eq_u32("publish valid graph",
                  publish_graph(providers, 2u, NULL, 0u, 200u, NULL, 1u, &root),
                  SERVICE_GRAPH_OK);

    memset(&breq, 0, sizeof(breq));
    breq.interface_version = SERVICE_GRAPH_INTERFACE_VERSION;
    digest_fill(&breq.interface_hash, 0x40u);
    breq.interface_major = 2u; /* wrong major */
    breq.interface_minor = 0u;
    breq.requested_cap_mask = 0x01u;
    breq.requested_effect_mask = SERVICE_GRAPH_EFFECT_OBJECT_READ;
    expect_eq_u32("incompatible major denied",
                  service_graph_bind(&breq, &breply),
                  SERVICE_GRAPH_ERR_INCOMPATIBLE_VERSION);

    breq.interface_major = 1u;
    breq.requested_effect_mask = SERVICE_GRAPH_EFFECT_ACTION; /* undeclared */
    expect_eq_u32("undeclared effect denied",
                  service_graph_bind(&breq, &breply),
                  SERVICE_GRAPH_ERR_UNDECLARED_EFFECT);

    breq.requested_effect_mask = SERVICE_GRAPH_EFFECT_OBJECT_READ;
    breq.requested_cap_mask = 0xF0u; /* outside declared envelope */
    expect_eq_u32("undeclared cap denied",
                  service_graph_bind(&breq, &breply),
                  SERVICE_GRAPH_ERR_UNDECLARED_CAP);
}

static void test_swap_rollback_lineage(void)
{
    struct service_graph_provider providers[1];
    struct service_graph_provider alt;
    struct service_graph_root root_a;
    struct service_graph_root root_b;
    struct service_graph_root root_rb;
    struct service_graph_req_swap sreq;
    struct service_graph_reply_swap sreply;
    struct service_graph_req_rollback rreq;
    struct service_graph_reply_rollback rreply;
    struct service_graph_req_resolve qreq;
    struct service_graph_reply_resolve qreply;

    service_graph_reset();
    providers[0] = make_provider(0x50u, 0x60u, 1u, 0u, 0xFFu,
                                 SERVICE_GRAPH_EFFECT_STATE_READ, 5u);
    alt = make_provider(0x51u, 0x60u, 1u, 1u, 0xFFu,
                        SERVICE_GRAPH_EFFECT_STATE_READ, 5u);
    register_provider(&providers[0]);
    register_provider(&alt);

    expect_eq_u32("lineage publish A",
                  publish_graph(providers, 1u, NULL, 0u, 50u, NULL, 10u,
                                &root_a),
                  SERVICE_GRAPH_OK);

    memset(&sreq, 0, sizeof(sreq));
    sreq.interface_version = SERVICE_GRAPH_INTERFACE_VERSION;
    sreq.current_graph_id = root_a.graph_id;
    digest_fill(&sreq.interface_hash, 0x60u);
    sreq.new_provider = alt;
    sreq.event_lineage_seq = 11u;
    expect_eq_u32("lineage swap", service_graph_swap(&sreq, &sreply),
                  SERVICE_GRAPH_OK);
    root_b = sreply.root;
    expect_eq_u32("swap event lineage", (uint32_t)root_b.event_lineage_seq,
                  11u);

    memset(&rreq, 0, sizeof(rreq));
    rreq.interface_version = SERVICE_GRAPH_INTERFACE_VERSION;
    rreq.current_graph_id = root_b.graph_id;
    rreq.target_graph_id = root_a.graph_id;
    rreq.event_lineage_seq = 12u;
    expect_eq_u32("rollback to A", service_graph_rollback(&rreq, &rreply),
                  SERVICE_GRAPH_OK);
    root_rb = rreply.root;
    expect_true("rollback active is A content",
                memcmp(root_rb.graph_id.bytes, root_a.graph_id.bytes,
                       SERVICE_GRAPH_DIGEST_BYTES) == 0);
    expect_true("rollback prior is B",
                memcmp(root_rb.prior_graph_id.bytes, root_b.graph_id.bytes,
                       SERVICE_GRAPH_DIGEST_BYTES) == 0);
    expect_eq_u32("rollback event lineage", (uint32_t)root_rb.event_lineage_seq,
                  12u);
    expect_true("rollback activation advanced",
                root_rb.activation_generation > root_b.activation_generation);

    memset(&qreq, 0, sizeof(qreq));
    qreq.interface_version = SERVICE_GRAPH_INTERFACE_VERSION;
    expect_eq_u32("resolve active", service_graph_resolve(&qreq, &qreply),
                  SERVICE_GRAPH_OK);
    expect_true("active after rollback is A",
                memcmp(qreply.root.graph_id.bytes, root_a.graph_id.bytes,
                       SERVICE_GRAPH_DIGEST_BYTES) == 0);
}

int main(void)
{
    g_failures = 0;
    test_opcodes();
    test_two_providers_same_consumer();
    test_fail_closed_cases();
    test_swap_rollback_lineage();

    if (g_failures != 0) {
        fprintf(stderr, "service graph suite: %d failure(s)\n", g_failures);
        return 1;
    }
    puts("service graph contract/security suite: ok");
    return 0;
}
