# AgentLang v0 Language and Canonical Lowering Specification

Status: executable bootstrap specification
Issue: `agentos-gz0.14.6.1`

AgentLang v0 is the bounded, statically typed model-facing language above
Fractal Agent IR. It is deliberately not a general-purpose language. Its v0
compiler is freestanding C, performs no allocation, and only produces an
immutable program record; execution and WASM generation are separate work.

## Authority and effect model

The launcher supplies a versioned prelude containing immutable named values,
installed semantic capability classes, the program's declared effect row, and
resource limits. Prelude entries are the only external values visible to a
program. Valid entry types are `ObjectID`, `AgentHandle`, and `TaskHandle`.

Every capability call is checked twice conceptually:

1. The compiler requires its effect in both the declared effect row and the
   installed capability set.
2. A later runtime must independently authorize the lowered operation at the
   dispatch boundary.

The first check improves diagnostics and rejects accidental authority use. It
does not grant authority. Presentation is never authorization.

AgentLang v0 exposes no path, command, URL, socket, file descriptor, package,
environment, clock, reflection, or dynamic import. The tokens `import`,
`filesystem`, `file`, `read_file`, `write_file`, `shell`, `bash`, `http`,
`network`, `socket`, `tcp`, `env`, `clock`, `reflect`, `reflection`,
`package`, and `include` are rejected as forbidden constructs rather than
being resolved as names.

## Lexical grammar

Source is UTF-8 bytes restricted by the v0 grammar to ASCII identifiers and
punctuation. Whitespace separates tokens. Identifiers match
`[A-Za-z_][A-Za-z0-9_]*`, are at most 23 bytes, and are case-sensitive.
Comments and literals are intentionally absent in v0: immutable inputs arrive
through the capability-derived prelude.

```text
program       = statement+ EOF
statement     = binding [";"] | call "?" [";"] | parallel [";"]
binding       = "let" identifier "=" call "?"
parallel      = "parallel" "{" parallel-binding+ "}"
parallel-binding = "let" identifier "=" async-call "?" [";"]

call          = checkpoint | restore | spawn | delegate | wait
              | task-verify | commit
checkpoint    = "checkpoint" "(" object-id ")"
restore       = "restore" "(" object-id ")"
spawn         = "spawn" "(" object-id "," object-id ")"
delegate      = "delegate" "(" agent-handle "," object-id ")"
wait          = "wait" "(" task-handle ")"
task-verify   = "task_verify" "(" "[" task-handle
                ("," task-handle)* "]" ")"
commit        = "commit" "(" verification ")"
async-call    = spawn | delegate
```

`while`, `loop`, `for`, `fn`, `recurse`, `recursion`, `alloc`, and `new`
are forbidden. Therefore v0 has no recursion, user-defined functions,
unbounded loops, or dynamic allocation. Conditionals, detached children,
mutable bindings, exception handlers, and nested parallel scopes are also not
part of v0; future versions must add them with explicit static bounds and
canonical lowering rules.

## Static types and results

The value types are:

```text
ObjectID
AgentHandle
TaskHandle
Verification
Result<ObjectID>
Result<AgentHandle>
Result<TaskHandle>
Result<Verification>
```

Capability calls first type as `Result<T>`. The postfix `?` is mandatory and
deterministically propagates failure to the enclosing program scope, yielding
`T` on the success path. V0 intentionally has no implicit success coercion and
no way to discard an unchecked `Result`. This keeps ordinary source compact
while retaining explicit error propagation.

| Expression | Static result | Effect | Agent ISA lowering |
|---|---|---|---|
| `checkpoint(ObjectID)?` | `ObjectID` | `OBJECT` | `CHECKPOINT` |
| `restore(ObjectID)?` | `ObjectID` | `OBJECT` | `RESTORE` |
| `spawn(ObjectID, ObjectID)?` | `AgentHandle` | `CONTROL` | `SPAWN` |
| `delegate(AgentHandle, ObjectID)?` | `TaskHandle` | `CONTROL` | `DELEGATE` |
| `wait(TaskHandle)?` | `ObjectID` | none | `WAIT` |
| `task_verify([TaskHandle...])?` | `Verification` | `VERIFY` | `VERIFY` (`TASK_VERIFY`) |
| `commit(Verification)?` | `ObjectID` | `COMMIT` | `COMMIT` |

`task_verify` also requires a prelude value named `task_verifier` of type
`ObjectID`. A `Verification` is compiler-tracked as the candidate root plus a
distinct evidence root so `commit` lowers into the existing verified-only
two-ObjectID ISA shape. It is not interchangeable with either ObjectID.

Bindings are immutable, duplicate names are errors, and unresolved names are
errors. Local inference is complete because every prelude value and builtin
has a fixed type. AgentLang v0 contains no type casts or dynamic values.

## Structured concurrency

A `parallel` block contains only `spawn` and `delegate` bindings. All siblings
receive the same nonzero `parallel_group`; sequential steps have group zero.
Every sibling's success edge points to the same first step after the group.
The compiler rejects empty, nested, non-async, or over-width groups.

The program record is a plan, not a scheduler. A conforming runtime must launch
one group's siblings within one task scope, carve their budgets from the
parent, propagate cancellation, and prevent the scope from completing while a
required sibling remains unresolved. V0 compilation never detaches a child.

## Bounds

The wire-independent compiler limits are:

- source: 4096 bytes;
- prelude values: 16;
- symbols: 32;
- lowered nodes: 32, further restricted by `prelude.max_nodes`;
- parallel siblings: 8, further restricted by
  `prelude.max_parallelism`;
- identifier: 23 bytes plus terminator.

There is no heap allocation. Exceeding any static limit returns
`AGENT_LANG_ERR_BOUNDS` (or `AGENT_LANG_ERR_SOURCE_TOO_LARGE` for source).
Runtime fuel, bytes, wall deadline, and provider concurrency limits remain
mandatory later dispatch checks and are not claimed by this compiler.

## Canonical Agent IR

Each call lowers to one existing `agent_ir_node_v0`. The compiler derives:

- the exact ISA operation and required semantic capability class;
- the ISA async flag from the operation, never source text;
- a unit abstract compile-time budget placeholder;
- immutable subject/context roots from typed arguments;
- a deterministic result root domain-separated by AgentLang version,
  operation, result type, source sequence, parallel group, and arguments;
- success continuations, with all parallel siblings joining at the same node;
- zero failure continuation, representing program-level `?` propagation.

Async nodes must have a later success continuation in v0. An async call cannot
be the last program node. The compiler validates every output node using
`agent_ir_validate_v0` and hashes it with `agent_ir_node_hash_v0`.

`agent_lang_program_v0` records source, prelude, node/parallel counts, declared
and actually required effects, every reused Agent IR node, its root, derived
result roots, sequence, result type, and structured-concurrency group. Unused
storage and reserved fields are zero. Prelude and program ObjectIDs use an
explicit little-endian field encoding, not native structure layout or padding.
This makes byte comparison a valid deterministic-lowering test for pinned
source and prelude values across supported architectures.

This representation is deliberately an executable compiler artifact rather
than the future WASM module. IR-to-WASM compilation, validation, execution,
event recording, cancellation, and dispatch authorization belong to the
`RUN_PROGRAM` runtime work and must not be inferred from successful v0
front-end compilation.

## Stable diagnostics

The compiler returns one deterministic first-error diagnostic:

```text
status, byte offset, one-based line, one-based column,
expected type, actual type, required effect
```

Diagnostic status classes distinguish invalid API/prelude input, version,
source size, token, syntax, undeclared or duplicate name, type mismatch,
missing `?`, absent capability, undeclared effect, bounds, forbidden construct,
and impossible IR lowering. Diagnostic fields not relevant to an error are
zero. Pinned invalid source and prelude bytes must yield a byte-identical
diagnostic.

## Example

```text
let w = checkpoint(workspace)?
let worker = spawn(role, workspace)?

parallel {
    let a = delegate(worker, objective)?
    let b = delegate(coder, objective)?
}

let best = task_verify([a, b])?
commit(best)?
```

Python, TypeScript, shell, filesystem paths, and provider-specific tool names
do not appear in this source or its canonical IR.
