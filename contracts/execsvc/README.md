# ExecSvc

ExecSvc is the capability-gated validation boundary for native AgentOS
workers. A caller must possess a minted `SVC_ID_EXEC_SERVER` endpoint cap, and
the cap's immutable badge selects one 48 KiB window in the service arena.

The interface has two operations:

- `EXECSVC_OP_VERIFY_EXACT` compares two bounded snapshots in the caller's
  window.
- `EXECSVC_OP_RUN_PROFILE` validates one immutable execution profile ID plus
  bounded source/output offsets. It never accepts a shell command or argv.

The first execution profile is `EXECSVC_PROFILE_C11_COMPILE`. It performs a
compile-only C11 validation with fixed flags through the shared
`exec_transport` PD. The worker has no transport endpoint, device frame, host
socket, compiler process, ModelCap, or NetCap.

Current limits are 24 KiB of source and 16 KiB of diagnostics. This profile is
not repository build/test execution: it accepts one translation unit, disables
includes and other preprocessor directives, and emits compiler diagnostics
only. A future managed execution guest can add separately identified profiles
for repository builds and tests without granting workers an ambient shell.
