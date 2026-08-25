/*
 * Immutable Capability Service Graph Contract (fos-gz0.14.9)
 *
 * Interface-to-provider bindings, dependency edges, capability/effect classes,
 * budgets, versions, and component hashes as immutable validated graphs.
 * Consumers bind by interface hash/version only — never by provider name.
 * Provider presentation/manifest data never grants authority.
 *
 * Rebinding a provider creates a new graph ObjectID and preserves prior-root
 * lineage for rollback. Graph mutation does not mutate prior ObjectIDs.
 *
 * Channels: MSG_SERVICE_GRAPH_* (see fractalos.h)
 * Version: 1
 */

#pragma once

#include <stdint.h>

#define SERVICE_GRAPH_INTERFACE_VERSION 1u

#define SERVICE_GRAPH_DIGEST_BYTES     32u
#define SERVICE_GRAPH_MAX_PROVIDERS    16u
#define SERVICE_GRAPH_MAX_INTERFACES   16u
#define SERVICE_GRAPH_MAX_EDGES        64u
#define SERVICE_GRAPH_MAX_RESOURCES    1024u /* aggregate resource units ceiling */

/* Effect class bits — must be declared on the provider; undeclared use fails. */
#define SERVICE_GRAPH_EFFECT_OBJECT_READ   (1u << 0)
#define SERVICE_GRAPH_EFFECT_OBJECT_WRITE  (1u << 1)
#define SERVICE_GRAPH_EFFECT_INFERENCE     (1u << 2)
#define SERVICE_GRAPH_EFFECT_ACTION        (1u << 3)
#define SERVICE_GRAPH_EFFECT_TASK_VERIFY   (1u << 4)
#define SERVICE_GRAPH_EFFECT_EVENT_READ    (1u << 5)
#define SERVICE_GRAPH_EFFECT_EVENT_WRITE   (1u << 6)
#define SERVICE_GRAPH_EFFECT_ACTOR_CONTROL (1u << 7)
#define SERVICE_GRAPH_EFFECT_BUDGET_READ   (1u << 8)
#define SERVICE_GRAPH_EFFECT_BUDGET_WRITE  (1u << 9)
#define SERVICE_GRAPH_EFFECT_STATE_READ    (1u << 10)
#define SERVICE_GRAPH_EFFECT_STATE_WRITE   (1u << 11)

enum service_graph_error {
    SERVICE_GRAPH_OK                       = 0u,
    SERVICE_GRAPH_ERR_INVALID              = 1u,
    SERVICE_GRAPH_ERR_DENIED               = 2u,
    SERVICE_GRAPH_ERR_NOT_FOUND            = 3u,
    SERVICE_GRAPH_ERR_CYCLE                = 4u,
    SERVICE_GRAPH_ERR_INCOMPATIBLE_VERSION = 5u,
    SERVICE_GRAPH_ERR_UNDECLARED_EFFECT    = 6u,
    SERVICE_GRAPH_ERR_UNDECLARED_CAP       = 7u,
    SERVICE_GRAPH_ERR_MISSING_DEP          = 8u,
    SERVICE_GRAPH_ERR_EXCESS_RESOURCE      = 9u,
    SERVICE_GRAPH_ERR_FABRICATED_PROVIDER  = 10u,
    SERVICE_GRAPH_ERR_FULL                 = 11u,
    SERVICE_GRAPH_ERR_STALE_ROOT           = 12u,
    SERVICE_GRAPH_ERR_NO_BINDING           = 13u,
};

/* Content-addressed digest (SHA-256 wire identity). All-zero is absent. */
struct service_graph_digest {
    uint8_t bytes[SERVICE_GRAPH_DIGEST_BYTES];
} __attribute__((packed));

/*
 * One installed provider artifact. Consumers never see provider names —
 * only interface_hash + semver. provider_id is the artifact content hash.
 */
struct service_graph_provider {
    struct service_graph_digest provider_id;
    struct service_graph_digest interface_hash;
    uint32_t interface_major;
    uint32_t interface_minor;
    uint64_t required_cap_mask;
    uint64_t budget_units;
    uint32_t effect_mask;
    uint32_t resource_units;
} __attribute__((packed));

/*
 * Dependency edge: provider A requires some provider of interface B.
 * Edges never name concrete peer providers — only interface hashes.
 */
struct service_graph_edge {
    struct service_graph_digest from_provider;
    struct service_graph_digest needs_interface;
} __attribute__((packed));

/* Immutable graph root — prior_graph_id chains activation lineage. */
struct service_graph_root {
    struct service_graph_digest graph_id;
    struct service_graph_digest prior_graph_id;
    uint64_t activation_generation;
    uint64_t event_lineage_seq;
    uint32_t provider_count;
    uint32_t edge_count;
    uint32_t max_resource_units;
    uint32_t reserved;
} __attribute__((packed));

/* Consumer bind request: interface identity only (no provider locator). */
struct service_graph_req_bind {
    uint32_t interface_version;
    uint32_t reserved;
    struct service_graph_digest graph_id;
    struct service_graph_digest interface_hash;
    uint32_t interface_major;
    uint32_t interface_minor; /* consumer accepts providers with minor >= this */
    uint64_t requested_cap_mask;
    uint32_t requested_effect_mask;
    uint32_t reserved2;
} __attribute__((packed));

struct service_graph_reply_bind {
    uint32_t status;
    uint32_t reserved;
    struct service_graph_digest provider_id;
    uint32_t provider_major;
    uint32_t provider_minor;
    uint64_t granted_cap_mask;
    uint32_t granted_effect_mask;
    uint32_t resource_units;
} __attribute__((packed));

/* Validate a candidate graph (providers+edges) before activation. */
struct service_graph_req_validate {
    uint32_t interface_version;
    uint32_t provider_count;
    uint32_t edge_count;
    uint32_t max_resource_units;
    /* Followed in host arena / table slots: providers[] then edges[]. */
} __attribute__((packed));

struct service_graph_reply_validate {
    uint32_t status;
    uint32_t reserved;
    struct service_graph_digest graph_id;
} __attribute__((packed));

/* Publish a validated graph as the active root (mints lineage). */
struct service_graph_req_publish {
    uint32_t interface_version;
    uint32_t reserved;
    struct service_graph_digest graph_id;
    struct service_graph_digest expected_prior_graph_id; /* CAS; zero = first */
    uint64_t event_lineage_seq;
} __attribute__((packed));

struct service_graph_reply_publish {
    uint32_t status;
    uint32_t reserved;
    struct service_graph_root root;
} __attribute__((packed));

/*
 * Governed provider swap: replace the provider bound to an interface.
 * Creates a new graph ObjectID; does not mutate the prior graph.
 */
struct service_graph_req_swap {
    uint32_t interface_version;
    uint32_t reserved;
    struct service_graph_digest current_graph_id;
    struct service_graph_digest interface_hash;
    struct service_graph_provider new_provider;
    uint64_t event_lineage_seq;
} __attribute__((packed));

struct service_graph_reply_swap {
    uint32_t status;
    uint32_t reserved;
    struct service_graph_root root;
} __attribute__((packed));

/* Rollback to a prior graph ObjectID in the activation lineage. */
struct service_graph_req_rollback {
    uint32_t interface_version;
    uint32_t reserved;
    struct service_graph_digest current_graph_id;
    struct service_graph_digest target_graph_id;
    uint64_t event_lineage_seq;
} __attribute__((packed));

struct service_graph_reply_rollback {
    uint32_t status;
    uint32_t reserved;
    struct service_graph_root root;
} __attribute__((packed));

/* Resolve active root metadata (lineage / generation). */
struct service_graph_req_resolve {
    uint32_t interface_version;
    uint32_t reserved;
    struct service_graph_digest graph_id; /* zero = active root */
} __attribute__((packed));

struct service_graph_reply_resolve {
    uint32_t status;
    uint32_t reserved;
    struct service_graph_root root;
} __attribute__((packed));

_Static_assert(sizeof(struct service_graph_digest) == 32u,
               "service graph digest wire size");
_Static_assert(sizeof(struct service_graph_provider) == 96u,
               "service graph provider wire size");
_Static_assert(sizeof(struct service_graph_edge) == 64u,
               "service graph edge wire size");
_Static_assert(sizeof(struct service_graph_root) == 96u,
               "service graph root wire size");
_Static_assert(sizeof(struct service_graph_req_bind) == 96u,
               "service graph bind request wire size");
_Static_assert(sizeof(struct service_graph_reply_bind) == 64u,
               "service graph bind reply wire size");
