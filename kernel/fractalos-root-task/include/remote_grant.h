/*
 * Fractal Mesh remote-authority wire records.
 *
 * This file is a generated-schema-facing contract, not a serializer.  The
 * generated encoder owns byte order and length delimiting.  Field order in
 * the signing records below is normative; the signature field itself is not
 * part of the signed byte range.  No record contains a seL4 badge or any
 * other local capability handle.
 */

#pragma once

#include <stdint.h>

#include "fractalos.h"

#define MESH_CONTRACT_VERSION          1u
#define MESH_WIRE_SCHEMA_VERSION       1u
#define MESH_WIRE_ENCODING_GENERATED   1u
#define MESH_WIRE_LITTLE_ENDIAN        1u
#define MESH_WIRE_LENGTH_DELIMITED     1u

#define MESH_ID_BYTES                  32u
#define MESH_SIGNATURE_BYTES           64u
#define MESH_RESUME_TOKEN_BYTES        32u
#define MESH_NONCE_BYTES               32u
#define MESH_ENDPOINT_BYTES            64u

#define MESH_ADVERTISEMENT_SIGNATURE_DOMAIN "fractalos/fractal-service-ad/1"
#define MESH_REMOTE_GRANT_SIGNATURE_DOMAIN \
    "fractalos/fractal-remote-grant/1"
#define MESH_EXECUTION_LEASE_SIGNATURE_DOMAIN \
    "fractalos/fractal-execution-lease/1"

/* Canonical signing spans, excluding the trailing signature. */
#define MESH_SERVICE_ADVERTISEMENT_SIGNING_BYTES 184u
#define MESH_REMOTE_GRANT_SIGNING_BYTES          304u
#define MESH_EXECUTION_LEASE_SIGNING_BYTES      168u
#define MESH_SERVICE_ADVERTISEMENT_WIRE_BYTES \
    (MESH_SERVICE_ADVERTISEMENT_SIGNING_BYTES + MESH_SIGNATURE_BYTES)
#define MESH_REMOTE_GRANT_WIRE_BYTES \
    (MESH_REMOTE_GRANT_SIGNING_BYTES + MESH_SIGNATURE_BYTES)
#define MESH_EXECUTION_LEASE_WIRE_BYTES \
    (MESH_EXECUTION_LEASE_SIGNING_BYTES + MESH_SIGNATURE_BYTES)

/* A network message never contains a local endpoint badge. */
#define MESH_REMOTE_GRANT_HAS_LOCAL_BADGE 0u
#define MESH_REMOTE_WIRE_HAS_BADGE        0u

struct mesh_node_id {
    uint8_t bytes[MESH_ID_BYTES];
};
typedef struct mesh_node_id mesh_node_id_t;
typedef mesh_node_id_t NodeID;

struct mesh_service_id {
    uint8_t bytes[MESH_ID_BYTES];
};
typedef struct mesh_service_id mesh_service_id_t;
typedef mesh_service_id_t ServiceID;

struct mesh_space_id {
    uint8_t bytes[MESH_ID_BYTES];
};
typedef struct mesh_space_id mesh_space_id_t;
typedef mesh_space_id_t SpaceID;

struct mesh_object_id {
    uint8_t bytes[MESH_ID_BYTES];
};
typedef struct mesh_object_id mesh_object_id_t;

struct mesh_agent_id {
    uint8_t bytes[MESH_ID_BYTES];
};
typedef struct mesh_agent_id mesh_agent_id_t;

struct mesh_interface_hash {
    uint8_t bytes[MESH_ID_BYTES];
};
typedef struct mesh_interface_hash mesh_interface_hash_t;

struct mesh_remote_session_handle {
    uint64_t session_id;
    uint64_t generation;
};
typedef struct mesh_remote_session_handle mesh_remote_session_handle_t;
typedef mesh_remote_session_handle_t RemoteSessionHandle;

struct mesh_resume_token {
    uint8_t bytes[MESH_RESUME_TOKEN_BYTES];
};
typedef struct mesh_resume_token mesh_resume_token_t;

struct mesh_service_advertisement {
    ServiceID service_id;
    NodeID provider_node;
    mesh_interface_hash_t interface_hash;
    uint8_t endpoint[MESH_ENDPOINT_BYTES];
    uint64_t required_capability;
    uint64_t health_epoch;
    uint64_t expiry_unix_ms;
    uint8_t signature[MESH_SIGNATURE_BYTES];
};
typedef struct mesh_service_advertisement mesh_service_advertisement_t;
typedef mesh_service_advertisement_t ServiceAdvertisement;

enum mesh_effect_class {
    MESH_EFFECT_READ_ONLY = 0u,
    MESH_EFFECT_LOCAL      = 1u,
    MESH_EFFECT_SHARED     = 2u,
    MESH_EFFECT_EXTERNAL   = 3u,
};

#define MESH_GRANT_SCOPE_OBJECTS      (1u << 0)
#define MESH_GRANT_SCOPE_SPACE_ROOT  (1u << 1)
#define MESH_GRANT_SCOPE_MAILBOX     (1u << 2)
#define REMOTE_GRANT_SCOPE_OBJECTS   MESH_GRANT_SCOPE_OBJECTS
#define REMOTE_GRANT_SCOPE_SPACE_ROOT MESH_GRANT_SCOPE_SPACE_ROOT
#define REMOTE_GRANT_SCOPE_MAILBOX   MESH_GRANT_SCOPE_MAILBOX

struct mesh_remote_grant {
    NodeID issuer;
    NodeID subject_node;
    mesh_agent_id_t subject_agent;
    NodeID audience_node;
    SpaceID space_id;
    mesh_interface_hash_t interface_hash;
    mesh_object_id_t object_scope;
    uint64_t operation_mask;
    uint32_t scope_flags;
    uint32_t effect_class;
    uint64_t budget_units;
    uint64_t expiry_unix_ms;
    uint64_t authority_epoch;
    uint64_t revocation_epoch;
    uint8_t nonce[MESH_NONCE_BYTES];
    uint8_t signature[MESH_SIGNATURE_BYTES];
};
typedef struct mesh_remote_grant mesh_remote_grant_t;
typedef mesh_remote_grant_t RemoteGrant;
typedef mesh_remote_grant_t remote_grant_t;

struct mesh_revocation_epoch {
    uint64_t authority_epoch;
    uint64_t revocation_epoch;
};
typedef struct mesh_revocation_epoch mesh_revocation_epoch_t;
typedef mesh_revocation_epoch_t RevocationEpoch;

struct mesh_execution_lease {
    uint64_t lease_id;
    uint64_t fence_epoch;
    uint64_t expires_unix_ms;
    uint64_t authority_epoch;
    uint64_t revocation_epoch;
    NodeID holder_node;
    mesh_agent_id_t subject_agent;
    SpaceID space_id;
    uint8_t nonce[MESH_NONCE_BYTES];
    uint8_t signature[MESH_SIGNATURE_BYTES];
};
typedef struct mesh_execution_lease mesh_execution_lease_t;
typedef mesh_execution_lease_t ExecutionLease;
typedef mesh_execution_lease_t execution_lease_t;

_Static_assert(sizeof(mesh_node_id_t) == MESH_ID_BYTES, "NodeID wire size");
_Static_assert(sizeof(mesh_service_id_t) == MESH_ID_BYTES, "ServiceID wire size");
_Static_assert(sizeof(mesh_space_id_t) == MESH_ID_BYTES, "SpaceID wire size");
_Static_assert(sizeof(mesh_remote_session_handle_t) == 16u,
               "remote session handle wire size");
_Static_assert(MESH_SERVICE_ADVERTISEMENT_SIGNING_BYTES ==
                   (3u * MESH_ID_BYTES + MESH_ENDPOINT_BYTES + 3u * 8u),
               "ServiceAdvertisement canonical signing size");
_Static_assert(MESH_REMOTE_GRANT_SIGNING_BYTES ==
                   (7u * MESH_ID_BYTES + 5u * 8u + 2u * 4u +
                    MESH_NONCE_BYTES),
               "RemoteGrant canonical signing size");
_Static_assert(MESH_EXECUTION_LEASE_SIGNING_BYTES ==
                   (5u * 8u + 3u * MESH_ID_BYTES + MESH_NONCE_BYTES),
               "ExecutionLease canonical signing size");
_Static_assert(MESH_REMOTE_GRANT_HAS_LOCAL_BADGE == 0u,
               "remote grants never carry local badges");
_Static_assert(MESH_REMOTE_WIRE_HAS_BADGE == 0u,
               "wire records never carry remote badges");
