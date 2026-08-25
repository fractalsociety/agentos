# ExecSvc

ExecSvc is the capability-gated validation boundary for native FractalOS
workers. A caller must possess a minted `SVC_ID_EXEC_SERVER` endpoint cap, and
the cap's immutable badge selects one 48 KiB window in the service arena and
contains the exact profile-right mask. Holding compile-only authority does not
authorize repository tests or exact verification.

The interface has two operations:

- `EXECSVC_OP_VERIFY_EXACT` compares two bounded snapshots in the caller's
  window.
- `EXECSVC_OP_RUN_PROFILE` validates one immutable execution profile ID plus
  bounded source/output offsets. It never accepts a shell command or argv.

`EXECSVC_PROFILE_C11_COMPILE` performs a
compile-only C11 validation with fixed flags through the shared
`exec_transport` PD. The worker has no transport endpoint, device frame, host
socket, compiler process, ModelCap, or NetCap.

`EXECSVC_PROFILE_FRACTALOS_REPO_TEST` accepts a badge-owned AgentFS overlay bundle
containing at most 64 relative-path files within the common 24 KiB input bound,
snapshots the administrator-selected Git `HEAD` into a temporary workspace,
and runs the administrator-built shared `xtask test` binary. The worker cannot
choose a repository root, executable, command, argument, host path, or network
endpoint. The temporary workspace is executed without network access and with
host filesystem writes restricted to that workspace; Linux production requires
bubblewrap and macOS development uses `sandbox-exec`. The earlier single-file
bundle remains accepted by the proxy for wire compatibility.

Current limits are 24 KiB for the complete multi-file change set and 16 KiB of
diagnostics. Artifact retention and larger descriptor-streamed change sets
remain future extensions; neither requires adding an ambient shell to workers.
