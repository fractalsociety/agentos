#include "agent_lang.h"

#include <stdbool.h>
#include <stddef.h>

enum token_kind {
    TOK_EOF = 0,
    TOK_IDENT,
    TOK_LET,
    TOK_PARALLEL,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_LBRACE,
    TOK_RBRACE,
    TOK_LBRACKET,
    TOK_RBRACKET,
    TOK_COMMA,
    TOK_EQUAL,
    TOK_QUESTION,
    TOK_SEMICOLON,
    TOK_FORBIDDEN,
    TOK_INVALID,
};

struct token {
    uint16_t kind;
    uint16_t length;
    uint32_t offset;
    uint32_t line;
    uint32_t column;
    char text[AGENT_LANG_MAX_IDENTIFIER];
};

struct symbol {
    char name[AGENT_LANG_MAX_IDENTIFIER];
    uint16_t type;
    uint16_t reserved;
    agent_object_id_t root;
    agent_object_id_t auxiliary_root;
};

struct pending_step {
    uint16_t operation;
    uint16_t result_type;
    uint16_t parallel_group;
    uint16_t reserved;
    uint32_t effect;
    agent_object_id_t subject;
    agent_object_id_t context;
    agent_object_id_t result;
    agent_object_id_t auxiliary;
};

struct parser {
    const char *source;
    uint32_t source_len;
    uint32_t cursor;
    uint32_t line;
    uint32_t column;
    struct token current;
    const struct agent_lang_prelude_v0 *prelude;
    struct agent_lang_diagnostic_v0 *diagnostic;
    struct symbol symbols[AGENT_LANG_MAX_SYMBOLS];
    uint16_t symbol_count;
    uint16_t step_count;
    uint16_t next_parallel_group;
    uint16_t active_parallel_group;
    uint16_t active_parallel_width;
    uint16_t reserved;
    uint32_t required_effects;
    struct pending_step pending[AGENT_LANG_MAX_NODES];
};

static void bytes_zero(void *ptr, uint32_t length)
{
    uint8_t *bytes = (uint8_t *)ptr;
    for (uint32_t i = 0u; i < length; i++) bytes[i] = 0u;
}

static void bytes_copy(void *destination, const void *source, uint32_t length)
{
    uint8_t *dst = (uint8_t *)destination;
    const uint8_t *src = (const uint8_t *)source;
    for (uint32_t i = 0u; i < length; i++) dst[i] = src[i];
}

static bool bytes_equal(const void *left, const void *right, uint32_t length)
{
    const uint8_t *a = (const uint8_t *)left;
    const uint8_t *b = (const uint8_t *)right;
    for (uint32_t i = 0u; i < length; i++) if (a[i] != b[i]) return false;
    return true;
}

static uint32_t string_length(const char *text, uint32_t maximum)
{
    uint32_t length = 0u;
    if (text == NULL) return 0u;
    while (length < maximum && text[length] != '\0') length++;
    return length;
}

static bool text_is(const char *text, uint16_t length, const char *literal)
{
    uint32_t literal_length = string_length(literal, AGENT_LANG_MAX_IDENTIFIER);
    return length == literal_length
        && bytes_equal(text, literal, literal_length);
}

static void id_copy(agent_object_id_t *destination,
                    const agent_object_id_t *source)
{
    bytes_copy(destination, source, sizeof(*destination));
}

static void id_zero(agent_object_id_t *id)
{
    bytes_zero(id, sizeof(*id));
}

static void put16(uint8_t *output, uint32_t *offset, uint16_t value)
{
    output[(*offset)++] = (uint8_t)value;
    output[(*offset)++] = (uint8_t)(value >> 8u);
}

static void put32(uint8_t *output, uint32_t *offset, uint32_t value)
{
    for (uint32_t i = 0u; i < 4u; i++)
        output[(*offset)++] = (uint8_t)(value >> (i * 8u));
}

static void put_id(uint8_t *output, uint32_t *offset,
                   const agent_object_id_t *id)
{
    for (uint32_t i = 0u; i < 4u; i++) put32(output, offset, id->word[i]);
}

static bool identifier_start(char character)
{
    return (character >= 'a' && character <= 'z')
        || (character >= 'A' && character <= 'Z') || character == '_';
}

static bool identifier_continue(char character)
{
    return identifier_start(character)
        || (character >= '0' && character <= '9');
}

static bool forbidden_identifier(const char *text, uint16_t length)
{
    static const char *const forbidden[] = {
        "import", "filesystem", "file", "read_file", "write_file",
        "shell", "bash", "http", "network", "socket", "tcp", "env",
        "clock", "reflect", "reflection", "while", "loop", "for", "fn",
        "recurse", "recursion", "alloc", "new", "package", "include",
    };
    for (uint32_t i = 0u; i < sizeof(forbidden) / sizeof(forbidden[0]); i++)
        if (text_is(text, length, forbidden[i])) return true;
    return false;
}

static void diagnose(struct parser *parser, uint32_t status,
                     const struct token *token, uint32_t expected,
                     uint32_t actual, uint32_t effect)
{
    if (parser->diagnostic->status != AGENT_LANG_OK) return;
    parser->diagnostic->status = status;
    parser->diagnostic->offset = token->offset;
    parser->diagnostic->line = token->line;
    parser->diagnostic->column = token->column;
    parser->diagnostic->expected_type = expected;
    parser->diagnostic->actual_type = actual;
    parser->diagnostic->required_effect = effect;
}

static void advance_position(struct parser *parser, char character)
{
    parser->cursor++;
    if (character == '\n') {
        parser->line++;
        parser->column = 1u;
    } else {
        parser->column++;
    }
}

static void next_token(struct parser *parser)
{
    while (parser->cursor < parser->source_len) {
        char character = parser->source[parser->cursor];
        if (character != ' ' && character != '\t' && character != '\r'
            && character != '\n') break;
        advance_position(parser, character);
    }
    struct token *token = &parser->current;
    bytes_zero(token, sizeof(*token));
    token->offset = parser->cursor;
    token->line = parser->line;
    token->column = parser->column;
    if (parser->cursor == parser->source_len) {
        token->kind = TOK_EOF;
        return;
    }
    char character = parser->source[parser->cursor];
    if (identifier_start(character)) {
        uint32_t start = parser->cursor;
        while (parser->cursor < parser->source_len
               && identifier_continue(parser->source[parser->cursor]))
            advance_position(parser, parser->source[parser->cursor]);
        uint32_t length = parser->cursor - start;
        if (length == 0u || length >= AGENT_LANG_MAX_IDENTIFIER) {
            token->kind = TOK_INVALID;
            return;
        }
        token->length = (uint16_t)length;
        bytes_copy(token->text, &parser->source[start], length);
        token->text[length] = '\0';
        if (text_is(token->text, token->length, "let")) token->kind = TOK_LET;
        else if (text_is(token->text, token->length, "parallel"))
            token->kind = TOK_PARALLEL;
        else if (forbidden_identifier(token->text, token->length))
            token->kind = TOK_FORBIDDEN;
        else token->kind = TOK_IDENT;
        return;
    }
    advance_position(parser, character);
    token->length = 1u;
    token->text[0] = character;
    switch (character) {
    case '(': token->kind = TOK_LPAREN; break;
    case ')': token->kind = TOK_RPAREN; break;
    case '{': token->kind = TOK_LBRACE; break;
    case '}': token->kind = TOK_RBRACE; break;
    case '[': token->kind = TOK_LBRACKET; break;
    case ']': token->kind = TOK_RBRACKET; break;
    case ',': token->kind = TOK_COMMA; break;
    case '=': token->kind = TOK_EQUAL; break;
    case '?': token->kind = TOK_QUESTION; break;
    case ';': token->kind = TOK_SEMICOLON; break;
    default: token->kind = TOK_INVALID; break;
    }
}

static bool accept(struct parser *parser, uint16_t kind)
{
    if (parser->current.kind != kind) return false;
    next_token(parser);
    return true;
}

static bool expect(struct parser *parser, uint16_t kind)
{
    if (parser->current.kind == TOK_FORBIDDEN) {
        diagnose(parser, AGENT_LANG_ERR_FORBIDDEN, &parser->current,
                 0u, 0u, 0u);
        return false;
    }
    if (parser->current.kind != kind) {
        diagnose(parser, parser->current.kind == TOK_INVALID
                     ? AGENT_LANG_ERR_TOKEN : AGENT_LANG_ERR_SYNTAX,
                 &parser->current, 0u, 0u, 0u);
        return false;
    }
    next_token(parser);
    return true;
}

static struct symbol *find_symbol(struct parser *parser,
                                  const struct token *identifier)
{
    for (uint16_t i = 0u; i < parser->symbol_count; i++) {
        uint32_t length = string_length(parser->symbols[i].name,
                                        AGENT_LANG_MAX_IDENTIFIER);
        if (length == identifier->length
            && bytes_equal(parser->symbols[i].name, identifier->text, length))
            return &parser->symbols[i];
    }
    return NULL;
}

static bool add_symbol(struct parser *parser, const struct token *identifier,
                       uint16_t type, const agent_object_id_t *root,
                       const agent_object_id_t *auxiliary)
{
    if (find_symbol(parser, identifier) != NULL) {
        diagnose(parser, AGENT_LANG_ERR_DUPLICATE, identifier, 0u, 0u, 0u);
        return false;
    }
    if (parser->symbol_count >= AGENT_LANG_MAX_SYMBOLS) {
        diagnose(parser, AGENT_LANG_ERR_BOUNDS, identifier, 0u, 0u, 0u);
        return false;
    }
    struct symbol *symbol = &parser->symbols[parser->symbol_count++];
    bytes_zero(symbol, sizeof(*symbol));
    bytes_copy(symbol->name, identifier->text, identifier->length);
    symbol->type = type;
    id_copy(&symbol->root, root);
    id_copy(&symbol->auxiliary_root, auxiliary);
    return true;
}

static uint16_t result_type(uint16_t value_type)
{
    switch (value_type) {
    case AGENT_LANG_TYPE_OBJECT_ID: return AGENT_LANG_TYPE_RESULT_OBJECT_ID;
    case AGENT_LANG_TYPE_AGENT_HANDLE:
        return AGENT_LANG_TYPE_RESULT_AGENT_HANDLE;
    case AGENT_LANG_TYPE_TASK_HANDLE:
        return AGENT_LANG_TYPE_RESULT_TASK_HANDLE;
    case AGENT_LANG_TYPE_VERIFICATION:
        return AGENT_LANG_TYPE_RESULT_VERIFICATION;
    default: return AGENT_LANG_TYPE_INVALID;
    }
}

static void derive_root(uint16_t operation, uint16_t type, uint16_t sequence,
                        uint16_t parallel_group,
                        const agent_object_id_t *subject,
                        const agent_object_id_t *context,
                        agent_object_id_t *root)
{
    uint8_t canonical[44];
    uint32_t offset = 0u;
    canonical[offset++] = 'A'; canonical[offset++] = 'L';
    canonical[offset++] = 'v'; canonical[offset++] = '0';
    canonical[offset++] = (uint8_t)operation;
    canonical[offset++] = (uint8_t)(operation >> 8u);
    canonical[offset++] = (uint8_t)type;
    canonical[offset++] = (uint8_t)(type >> 8u);
    canonical[offset++] = (uint8_t)sequence;
    canonical[offset++] = (uint8_t)(sequence >> 8u);
    canonical[offset++] = (uint8_t)parallel_group;
    canonical[offset++] = (uint8_t)(parallel_group >> 8u);
    bytes_copy(&canonical[offset], subject, sizeof(*subject));
    offset += sizeof(*subject);
    bytes_copy(&canonical[offset], context, sizeof(*context));
    offset += sizeof(*context);
    agent_isa_object_id_from_bytes(canonical, offset, root);
}

static bool require_effect(struct parser *parser, uint32_t effect,
                           const struct token *operation)
{
    if ((effect & ~parser->prelude->installed_caps) != 0u) {
        diagnose(parser, AGENT_LANG_ERR_CAPABILITY, operation,
                 0u, 0u, effect);
        return false;
    }
    if ((effect & ~parser->prelude->declared_effects) != 0u) {
        diagnose(parser, AGENT_LANG_ERR_EFFECT, operation, 0u, 0u, effect);
        return false;
    }
    parser->required_effects |= effect;
    return true;
}

static bool symbol_argument(struct parser *parser, uint16_t expected,
                            struct symbol **out)
{
    struct token identifier = parser->current;
    if (!expect(parser, TOK_IDENT)) return false;
    struct symbol *symbol = find_symbol(parser, &identifier);
    if (symbol == NULL) {
        diagnose(parser, AGENT_LANG_ERR_UNDECLARED, &identifier,
                 expected, AGENT_LANG_TYPE_INVALID, 0u);
        return false;
    }
    if (symbol->type != expected) {
        diagnose(parser, AGENT_LANG_ERR_TYPE, &identifier,
                 expected, symbol->type, 0u);
        return false;
    }
    *out = symbol;
    return true;
}

static bool append_step(struct parser *parser, const struct token *operation,
                        uint16_t isa_operation, uint16_t value_type,
                        uint32_t effect, const agent_object_id_t *subject,
                        const agent_object_id_t *context,
                        agent_object_id_t *result,
                        agent_object_id_t *auxiliary)
{
    uint16_t limit = parser->prelude->max_nodes;
    if (limit == 0u || limit > AGENT_LANG_MAX_NODES)
        limit = AGENT_LANG_MAX_NODES;
    if (parser->step_count >= limit
        || parser->step_count >= AGENT_LANG_MAX_NODES) {
        diagnose(parser, AGENT_LANG_ERR_BOUNDS, operation, 0u, 0u, 0u);
        return false;
    }
    if (!require_effect(parser, effect, operation)) return false;
    struct pending_step *step = &parser->pending[parser->step_count];
    bytes_zero(step, sizeof(*step));
    step->operation = isa_operation;
    step->result_type = value_type;
    step->parallel_group = parser->active_parallel_group;
    step->effect = effect;
    id_copy(&step->subject, subject);
    id_copy(&step->context, context);
    derive_root(isa_operation, value_type, parser->step_count + 1u,
                parser->active_parallel_group, subject, context,
                &step->result);
    if (value_type == AGENT_LANG_TYPE_VERIFICATION) {
        derive_root(isa_operation, AGENT_LANG_TYPE_RESULT_VERIFICATION,
                    parser->step_count + 1u, parser->active_parallel_group,
                    &step->result, context, &step->auxiliary);
    }
    id_copy(result, &step->result);
    id_copy(auxiliary, &step->auxiliary);
    parser->step_count++;
    if (parser->active_parallel_group != 0u) parser->active_parallel_width++;
    return true;
}

static bool parse_call(struct parser *parser, uint16_t *value_type,
                       agent_object_id_t *result, agent_object_id_t *auxiliary)
{
    struct token operation = parser->current;
    if (operation.kind == TOK_FORBIDDEN) {
        diagnose(parser, AGENT_LANG_ERR_FORBIDDEN, &operation, 0u, 0u, 0u);
        return false;
    }
    if (!expect(parser, TOK_IDENT)) return false;
    if (!expect(parser, TOK_LPAREN)) return false;
    agent_object_id_t zero;
    id_zero(&zero);
    struct symbol *first = NULL;
    struct symbol *second = NULL;
    uint16_t isa_operation;
    uint16_t output;
    uint32_t effect;
    agent_object_id_t subject;
    agent_object_id_t context;
    id_zero(&subject);
    id_zero(&context);

    if (text_is(operation.text, operation.length, "checkpoint")) {
        if (!symbol_argument(parser, AGENT_LANG_TYPE_OBJECT_ID, &first))
            return false;
        (void)first;
        isa_operation = AGENT_ISA_OP_CHECKPOINT;
        output = AGENT_LANG_TYPE_OBJECT_ID;
        effect = AGENT_ISA_CAP_OBJECT;
    } else if (text_is(operation.text, operation.length, "restore")) {
        if (!symbol_argument(parser, AGENT_LANG_TYPE_OBJECT_ID, &first))
            return false;
        id_copy(&subject, &first->root);
        isa_operation = AGENT_ISA_OP_RESTORE;
        output = AGENT_LANG_TYPE_OBJECT_ID;
        effect = AGENT_ISA_CAP_OBJECT;
    } else if (text_is(operation.text, operation.length, "spawn")) {
        if (!symbol_argument(parser, AGENT_LANG_TYPE_OBJECT_ID, &first)
            || !expect(parser, TOK_COMMA)
            || !symbol_argument(parser, AGENT_LANG_TYPE_OBJECT_ID, &second))
            return false;
        id_copy(&subject, &first->root);
        id_copy(&context, &second->root);
        isa_operation = AGENT_ISA_OP_SPAWN;
        output = AGENT_LANG_TYPE_AGENT_HANDLE;
        effect = AGENT_ISA_CAP_CONTROL;
    } else if (text_is(operation.text, operation.length, "delegate")) {
        if (!symbol_argument(parser, AGENT_LANG_TYPE_AGENT_HANDLE, &first)
            || !expect(parser, TOK_COMMA)
            || !symbol_argument(parser, AGENT_LANG_TYPE_OBJECT_ID, &second))
            return false;
        id_copy(&subject, &first->root);
        id_copy(&context, &second->root);
        isa_operation = AGENT_ISA_OP_DELEGATE;
        output = AGENT_LANG_TYPE_TASK_HANDLE;
        effect = AGENT_ISA_CAP_CONTROL;
    } else if (text_is(operation.text, operation.length, "wait")) {
        if (!symbol_argument(parser, AGENT_LANG_TYPE_TASK_HANDLE, &first))
            return false;
        id_copy(&subject, &first->root);
        isa_operation = AGENT_ISA_OP_WAIT;
        output = AGENT_LANG_TYPE_OBJECT_ID;
        effect = 0u;
    } else if (text_is(operation.text, operation.length, "task_verify")) {
        if (!expect(parser, TOK_LBRACKET)) return false;
        uint8_t aggregate[4u + AGENT_LANG_MAX_PARALLELISM * 16u];
        uint32_t aggregate_length = 4u;
        uint16_t count = 0u;
        bytes_zero(aggregate, sizeof(aggregate));
        do {
            if (count >= AGENT_LANG_MAX_PARALLELISM) {
                diagnose(parser, AGENT_LANG_ERR_BOUNDS, &operation,
                         0u, 0u, 0u);
                return false;
            }
            if (!symbol_argument(parser, AGENT_LANG_TYPE_TASK_HANDLE, &first))
                return false;
            bytes_copy(&aggregate[aggregate_length], &first->root,
                       sizeof(first->root));
            aggregate_length += sizeof(first->root);
            count++;
        } while (accept(parser, TOK_COMMA));
        if (count == 0u || !expect(parser, TOK_RBRACKET)) return false;
        aggregate[0] = (uint8_t)count;
        agent_isa_object_id_from_bytes(aggregate, aggregate_length, &subject);
        struct token verifier_token = operation;
        bytes_zero(verifier_token.text, sizeof(verifier_token.text));
        const char verifier_name[] = "task_verifier";
        bytes_copy(verifier_token.text, verifier_name,
                   sizeof(verifier_name));
        verifier_token.length = sizeof(verifier_name) - 1u;
        second = find_symbol(parser, &verifier_token);
        if (second == NULL) {
            diagnose(parser, AGENT_LANG_ERR_UNDECLARED, &operation,
                     AGENT_LANG_TYPE_OBJECT_ID, AGENT_LANG_TYPE_INVALID, 0u);
            return false;
        }
        if (second->type != AGENT_LANG_TYPE_OBJECT_ID) {
            diagnose(parser, AGENT_LANG_ERR_TYPE, &operation,
                     AGENT_LANG_TYPE_OBJECT_ID, second->type, 0u);
            return false;
        }
        id_copy(&context, &second->root);
        isa_operation = AGENT_ISA_OP_VERIFY;
        output = AGENT_LANG_TYPE_VERIFICATION;
        effect = AGENT_ISA_CAP_VERIFY;
    } else if (text_is(operation.text, operation.length, "commit")) {
        if (!symbol_argument(parser, AGENT_LANG_TYPE_VERIFICATION, &first))
            return false;
        id_copy(&subject, &first->root);
        id_copy(&context, &first->auxiliary_root);
        isa_operation = AGENT_ISA_OP_COMMIT;
        output = AGENT_LANG_TYPE_OBJECT_ID;
        effect = AGENT_ISA_CAP_COMMIT;
    } else {
        diagnose(parser, AGENT_LANG_ERR_UNDECLARED, &operation,
                 0u, 0u, 0u);
        return false;
    }
    if (!expect(parser, TOK_RPAREN)) return false;
    *value_type = result_type(output);
    if (!append_step(parser, &operation, isa_operation, output, effect,
                     &subject, &context, result, auxiliary)) return false;
    if (!accept(parser, TOK_QUESTION)) {
        diagnose(parser, AGENT_LANG_ERR_RESULT_REQUIRED, &operation,
                 output, *value_type, effect);
        return false;
    }
    *value_type = output;
    return true;
}

static bool parse_statement(struct parser *parser, bool in_parallel)
{
    if (parser->current.kind == TOK_FORBIDDEN) {
        diagnose(parser, AGENT_LANG_ERR_FORBIDDEN, &parser->current,
                 0u, 0u, 0u);
        return false;
    }
    if (accept(parser, TOK_LET)) {
        struct token name = parser->current;
        if (!expect(parser, TOK_IDENT) || !expect(parser, TOK_EQUAL))
            return false;
        uint16_t type;
        agent_object_id_t result;
        agent_object_id_t auxiliary;
        if (!parse_call(parser, &type, &result, &auxiliary)) return false;
        uint16_t operation = parser->pending[parser->step_count - 1u].operation;
        if (in_parallel && operation != AGENT_ISA_OP_SPAWN
            && operation != AGENT_ISA_OP_DELEGATE) {
            diagnose(parser, AGENT_LANG_ERR_SYNTAX, &name, 0u, 0u, 0u);
            return false;
        }
        if (!add_symbol(parser, &name, type, &result, &auxiliary)) return false;
    } else {
        uint16_t type;
        agent_object_id_t result;
        agent_object_id_t auxiliary;
        if (!parse_call(parser, &type, &result, &auxiliary)) return false;
        (void)type;
    }
    (void)accept(parser, TOK_SEMICOLON);
    return true;
}

static bool parse_program(struct parser *parser)
{
    next_token(parser);
    while (parser->current.kind != TOK_EOF) {
        if (parser->current.kind == TOK_FORBIDDEN) {
            diagnose(parser, AGENT_LANG_ERR_FORBIDDEN, &parser->current,
                     0u, 0u, 0u);
            return false;
        }
        if (accept(parser, TOK_PARALLEL)) {
            if (parser->active_parallel_group != 0u
                || !expect(parser, TOK_LBRACE)) return false;
            parser->active_parallel_group = ++parser->next_parallel_group;
            parser->active_parallel_width = 0u;
            while (parser->current.kind != TOK_RBRACE) {
                if (parser->current.kind == TOK_EOF
                    || !parse_statement(parser, true)) return false;
            }
            if (!expect(parser, TOK_RBRACE)) return false;
            uint16_t limit = parser->prelude->max_parallelism;
            if (limit == 0u || limit > AGENT_LANG_MAX_PARALLELISM)
                limit = AGENT_LANG_MAX_PARALLELISM;
            if (parser->active_parallel_width == 0u
                || parser->active_parallel_width > limit) {
                diagnose(parser, AGENT_LANG_ERR_BOUNDS, &parser->current,
                         0u, 0u, 0u);
                return false;
            }
            parser->active_parallel_group = 0u;
            parser->active_parallel_width = 0u;
            (void)accept(parser, TOK_SEMICOLON);
        } else if (!parse_statement(parser, false)) {
            return false;
        }
    }
    return parser->step_count != 0u;
}

static bool validate_prelude(const struct agent_lang_prelude_v0 *prelude)
{
    if (prelude == NULL
        || prelude->interface_version != AGENT_LANG_INTERFACE_VERSION
        || prelude->value_count > AGENT_LANG_MAX_PRELUDE_VALUES
        || (prelude->installed_caps & ~AGENT_ISA_CAP_KNOWN_MASK) != 0u
        || (prelude->declared_effects & ~AGENT_ISA_CAP_KNOWN_MASK) != 0u
        || prelude->max_nodes == 0u
        || prelude->max_nodes > AGENT_LANG_MAX_NODES
        || prelude->max_parallelism == 0u
        || prelude->max_parallelism > AGENT_LANG_MAX_PARALLELISM
        || prelude->reserved != 0u)
        return false;
    for (uint16_t i = 0u; i < prelude->value_count; i++) {
        const struct agent_lang_prelude_value_v0 *value = &prelude->values[i];
        uint32_t length = string_length(value->name, AGENT_LANG_MAX_IDENTIFIER);
        if (length == 0u || length == AGENT_LANG_MAX_IDENTIFIER
            || !identifier_start(value->name[0]) || value->reserved != 0u
            || (value->type != AGENT_LANG_TYPE_OBJECT_ID
                && value->type != AGENT_LANG_TYPE_AGENT_HANDLE
                && value->type != AGENT_LANG_TYPE_TASK_HANDLE)
            || agent_object_id_is_zero(&value->root)) return false;
        for (uint32_t character = 1u; character < length; character++)
            if (!identifier_continue(value->name[character])) return false;
        if (forbidden_identifier(value->name, (uint16_t)length)) return false;
        for (uint16_t j = 0u; j < i; j++) {
            uint32_t prior_length = string_length(prelude->values[j].name,
                                                   AGENT_LANG_MAX_IDENTIFIER);
            if (length == prior_length
                && bytes_equal(value->name, prelude->values[j].name, length))
                return false;
        }
    }
    return true;
}

static void hash_prelude(const struct agent_lang_prelude_v0 *prelude,
                         agent_object_id_t *root)
{
    uint8_t canonical[16u + AGENT_LANG_MAX_PRELUDE_VALUES
        * (AGENT_LANG_MAX_IDENTIFIER + 4u + 16u)];
    uint32_t offset = 0u;
    put16(canonical, &offset, prelude->interface_version);
    put16(canonical, &offset, prelude->value_count);
    put32(canonical, &offset, prelude->installed_caps);
    put32(canonical, &offset, prelude->declared_effects);
    put16(canonical, &offset, prelude->max_nodes);
    put16(canonical, &offset, prelude->max_parallelism);
    for (uint16_t i = 0u; i < prelude->value_count; i++) {
        const struct agent_lang_prelude_value_v0 *value = &prelude->values[i];
        bytes_copy(&canonical[offset], value->name,
                   AGENT_LANG_MAX_IDENTIFIER);
        offset += AGENT_LANG_MAX_IDENTIFIER;
        put16(canonical, &offset, value->type);
        put16(canonical, &offset, 0u);
        put_id(canonical, &offset, &value->root);
    }
    agent_isa_object_id_from_bytes(canonical, offset, root);
}

static void hash_program(struct agent_lang_program_v0 *program)
{
    uint8_t canonical[64u + AGENT_LANG_MAX_NODES * 136u];
    uint32_t offset = 0u;
    put16(canonical, &offset, program->interface_version);
    put16(canonical, &offset, program->node_count);
    put16(canonical, &offset, program->parallel_group_count);
    put16(canonical, &offset, 0u);
    put32(canonical, &offset, program->declared_effects);
    put32(canonical, &offset, program->required_effects);
    put_id(canonical, &offset, &program->source_root);
    put_id(canonical, &offset, &program->prelude_root);
    for (uint16_t i = 0u; i < program->node_count; i++) {
        const struct agent_lang_ir_step_v0 *step = &program->steps[i];
        const struct agent_ir_node_v0 *node = &step->node;
        put16(canonical, &offset, node->interface_version);
        put16(canonical, &offset, node->operation);
        put32(canonical, &offset, node->execution_flags);
        put32(canonical, &offset, node->declared_caps);
        put32(canonical, &offset, node->budget_units);
        put_id(canonical, &offset, &node->subject_root);
        put_id(canonical, &offset, &node->context_root);
        put_id(canonical, &offset, &node->success_continuation_root);
        put_id(canonical, &offset, &node->failure_continuation_root);
        put_id(canonical, &offset, &step->ir_node_root);
        put_id(canonical, &offset, &step->result_root);
        put_id(canonical, &offset, &step->auxiliary_root);
        put16(canonical, &offset, step->sequence);
        put16(canonical, &offset, step->parallel_group);
        put16(canonical, &offset, step->result_type);
        put16(canonical, &offset, 0u);
    }
    agent_isa_object_id_from_bytes(canonical, offset, &program->program_root);
}

static uint32_t lower_program(struct parser *parser,
                              struct agent_lang_program_v0 *program)
{
    program->interface_version = AGENT_LANG_INTERFACE_VERSION;
    program->node_count = parser->step_count;
    program->parallel_group_count = parser->next_parallel_group;
    program->declared_effects = parser->prelude->declared_effects;
    program->required_effects = parser->required_effects;

    agent_object_id_t next_root;
    id_zero(&next_root);
    uint16_t index = parser->step_count;
    while (index > 0u) {
        index--;
        struct pending_step *pending = &parser->pending[index];
        struct agent_lang_ir_step_v0 *step = &program->steps[index];
        step->sequence = index + 1u;
        step->parallel_group = pending->parallel_group;
        step->result_type = pending->result_type;
        id_copy(&step->result_root, &pending->result);
        id_copy(&step->auxiliary_root, &pending->auxiliary);
        step->node.interface_version = AGENT_IR_INTERFACE_VERSION;
        step->node.operation = pending->operation;
        step->node.execution_flags = agent_isa_operation_is_async(
            pending->operation) ? AGENT_ISA_FLAG_ASYNC : 0u;
        step->node.declared_caps = pending->effect;
        step->node.budget_units = 1u;
        id_copy(&step->node.subject_root, &pending->subject);
        id_copy(&step->node.context_root, &pending->context);
        id_copy(&step->node.success_continuation_root, &next_root);
        id_zero(&step->node.failure_continuation_root);
        uint32_t status = agent_ir_validate_v0(&step->node);
        if (status != AGENT_IR_OK) return AGENT_LANG_ERR_LOWERING;
        agent_ir_node_hash_v0(&step->node, &step->ir_node_root);

        if (pending->parallel_group != 0u) {
            uint16_t first = index;
            while (first > 0u
                   && parser->pending[first - 1u].parallel_group
                        == pending->parallel_group) first--;
            if (first == index) id_copy(&next_root, &step->ir_node_root);
        } else {
            id_copy(&next_root, &step->ir_node_root);
        }
    }

    /* Reverse lowering initially sees later parallel siblings as the next
     * edge. Canonicalize every sibling to the first node after its group. */
    for (uint16_t i = 0u; i < parser->step_count; i++) {
        uint16_t group = program->steps[i].parallel_group;
        if (group == 0u) continue;
        uint16_t after = i;
        while (after < parser->step_count
               && program->steps[after].parallel_group == group) after++;
        agent_object_id_t join;
        id_zero(&join);
        if (after < parser->step_count)
            id_copy(&join, &program->steps[after].ir_node_root);
        id_copy(&program->steps[i].node.success_continuation_root, &join);
        if (agent_ir_validate_v0(&program->steps[i].node) != AGENT_IR_OK)
            return AGENT_LANG_ERR_LOWERING;
        agent_ir_node_hash_v0(&program->steps[i].node,
                              &program->steps[i].ir_node_root);
    }
    /* Re-hash sequential predecessors now that group entry roots are final. */
    for (uint16_t i = parser->step_count; i > 0u; i--) {
        uint16_t at = i - 1u;
        if (program->steps[at].parallel_group != 0u) continue;
        uint16_t next = at + 1u;
        if (next < parser->step_count)
            id_copy(&program->steps[at].node.success_continuation_root,
                    &program->steps[next].ir_node_root);
        agent_ir_node_hash_v0(&program->steps[at].node,
                              &program->steps[at].ir_node_root);
    }
    hash_program(program);
    return AGENT_LANG_OK;
}

uint32_t agent_lang_compile_v0(
    const char *source, uint32_t source_len,
    const struct agent_lang_prelude_v0 *prelude,
    struct agent_lang_program_v0 *program,
    struct agent_lang_diagnostic_v0 *diagnostic)
{
    if (program != NULL) bytes_zero(program, sizeof(*program));
    if (diagnostic != NULL) bytes_zero(diagnostic, sizeof(*diagnostic));
    if (source == NULL || source_len == 0u || prelude == NULL
        || program == NULL || diagnostic == NULL) {
        if (diagnostic != NULL) diagnostic->status = AGENT_LANG_ERR_INVALID;
        return AGENT_LANG_ERR_INVALID;
    }
    if (source_len > AGENT_LANG_MAX_SOURCE_BYTES) {
        diagnostic->status = AGENT_LANG_ERR_SOURCE_TOO_LARGE;
        diagnostic->line = 1u;
        diagnostic->column = 1u;
        return diagnostic->status;
    }
    if (!validate_prelude(prelude)) {
        diagnostic->status = prelude->interface_version
                != AGENT_LANG_INTERFACE_VERSION
            ? AGENT_LANG_ERR_VERSION : AGENT_LANG_ERR_INVALID;
        diagnostic->line = 1u;
        diagnostic->column = 1u;
        return diagnostic->status;
    }

    struct parser parser;
    bytes_zero(&parser, sizeof(parser));
    parser.source = source;
    parser.source_len = source_len;
    parser.line = 1u;
    parser.column = 1u;
    parser.prelude = prelude;
    parser.diagnostic = diagnostic;
    for (uint16_t i = 0u; i < prelude->value_count; i++) {
        struct token name;
        bytes_zero(&name, sizeof(name));
        uint32_t length = string_length(prelude->values[i].name,
                                        AGENT_LANG_MAX_IDENTIFIER);
        name.length = (uint16_t)length;
        bytes_copy(name.text, prelude->values[i].name, length + 1u);
        agent_object_id_t zero;
        id_zero(&zero);
        if (!add_symbol(&parser, &name, prelude->values[i].type,
                        &prelude->values[i].root, &zero))
            return diagnostic->status;
    }
    if (!parse_program(&parser)) {
        if (diagnostic->status == AGENT_LANG_OK) {
            diagnostic->status = AGENT_LANG_ERR_SYNTAX;
            diagnostic->line = parser.current.line;
            diagnostic->column = parser.current.column;
            diagnostic->offset = parser.current.offset;
        }
        return diagnostic->status;
    }
    agent_isa_object_id_from_bytes(source, source_len, &program->source_root);
    hash_prelude(prelude, &program->prelude_root);
    uint32_t status = lower_program(&parser, program);
    if (status != AGENT_LANG_OK) {
        bytes_zero(program, sizeof(*program));
        diagnostic->status = status;
        diagnostic->line = 1u;
        diagnostic->column = 1u;
        return status;
    }
    diagnostic->status = AGENT_LANG_OK;
    return AGENT_LANG_OK;
}
