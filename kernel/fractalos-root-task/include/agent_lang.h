/* AgentLang v0: bounded model-facing DSL lowered to canonical Agent IR. */
#pragma once

#include <stdint.h>

#include "agent_ir.h"

#define AGENT_LANG_INTERFACE_VERSION 1u
#define AGENT_LANG_MAX_SOURCE_BYTES  4096u
#define AGENT_LANG_MAX_IDENTIFIER    24u
#define AGENT_LANG_MAX_PRELUDE_VALUES 16u
#define AGENT_LANG_MAX_SYMBOLS       32u
#define AGENT_LANG_MAX_NODES         32u
#define AGENT_LANG_MAX_PARALLELISM   8u

enum agent_lang_error {
    AGENT_LANG_OK = 0u,
    AGENT_LANG_ERR_INVALID = 1u,
    AGENT_LANG_ERR_VERSION = 2u,
    AGENT_LANG_ERR_SOURCE_TOO_LARGE = 3u,
    AGENT_LANG_ERR_TOKEN = 4u,
    AGENT_LANG_ERR_SYNTAX = 5u,
    AGENT_LANG_ERR_UNDECLARED = 6u,
    AGENT_LANG_ERR_DUPLICATE = 7u,
    AGENT_LANG_ERR_TYPE = 8u,
    AGENT_LANG_ERR_RESULT_REQUIRED = 9u,
    AGENT_LANG_ERR_CAPABILITY = 10u,
    AGENT_LANG_ERR_EFFECT = 11u,
    AGENT_LANG_ERR_BOUNDS = 12u,
    AGENT_LANG_ERR_FORBIDDEN = 13u,
    AGENT_LANG_ERR_LOWERING = 14u,
};

enum agent_lang_type {
    AGENT_LANG_TYPE_INVALID = 0u,
    AGENT_LANG_TYPE_OBJECT_ID = 1u,
    AGENT_LANG_TYPE_AGENT_HANDLE = 2u,
    AGENT_LANG_TYPE_TASK_HANDLE = 3u,
    AGENT_LANG_TYPE_VERIFICATION = 4u,
    AGENT_LANG_TYPE_RESULT_OBJECT_ID = 5u,
    AGENT_LANG_TYPE_RESULT_AGENT_HANDLE = 6u,
    AGENT_LANG_TYPE_RESULT_TASK_HANDLE = 7u,
    AGENT_LANG_TYPE_RESULT_VERIFICATION = 8u,
};

struct agent_lang_diagnostic_v0 {
    uint32_t status;
    uint32_t offset;
    uint32_t line;
    uint32_t column;
    uint32_t expected_type;
    uint32_t actual_type;
    uint32_t required_effect;
    uint32_t reserved;
};

struct agent_lang_prelude_value_v0 {
    char name[AGENT_LANG_MAX_IDENTIFIER];
    uint16_t type;
    uint16_t reserved;
    agent_object_id_t root;
};

/* installed_caps is launch authority. declared_effects is the narrower
 * compile-time effect row for this program. Neither field grants authority. */
struct agent_lang_prelude_v0 {
    uint16_t interface_version;
    uint16_t value_count;
    uint32_t installed_caps;
    uint32_t declared_effects;
    uint16_t max_nodes;
    uint16_t max_parallelism;
    uint32_t reserved;
    struct agent_lang_prelude_value_v0
        values[AGENT_LANG_MAX_PRELUDE_VALUES];
};

/* A step reuses the stable Agent IR node. parallel_group zero is sequential;
 * equal nonzero groups are siblings launched within one bounded scope. */
struct agent_lang_ir_step_v0 {
    struct agent_ir_node_v0 node;
    agent_object_id_t ir_node_root;
    agent_object_id_t result_root;
    agent_object_id_t auxiliary_root;
    uint16_t sequence;
    uint16_t parallel_group;
    uint16_t result_type;
    uint16_t reserved;
};

struct agent_lang_program_v0 {
    uint16_t interface_version;
    uint16_t node_count;
    uint16_t parallel_group_count;
    uint16_t reserved;
    uint32_t declared_effects;
    uint32_t required_effects;
    agent_object_id_t source_root;
    agent_object_id_t prelude_root;
    agent_object_id_t program_root;
    struct agent_lang_ir_step_v0 steps[AGENT_LANG_MAX_NODES];
};

uint32_t agent_lang_compile_v0(
    const char *source, uint32_t source_len,
    const struct agent_lang_prelude_v0 *prelude,
    struct agent_lang_program_v0 *program,
    struct agent_lang_diagnostic_v0 *diagnostic);

_Static_assert(sizeof(struct agent_lang_diagnostic_v0) == 32u,
               "AgentLang diagnostic ABI drift");
_Static_assert(sizeof(struct agent_lang_prelude_value_v0) == 44u,
               "AgentLang prelude value ABI drift");
_Static_assert(sizeof(struct agent_lang_ir_step_v0) == 136u,
               "AgentLang IR step ABI drift");
_Static_assert(sizeof(struct agent_lang_program_v0) == 4416u,
               "AgentLang program ABI drift");
