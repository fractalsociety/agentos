# Target performance gates

agentOS performance claims are backed by measurements emitted from a booted
seL4 target. Host-side mocks are useful for correctness checks but are not
accepted as performance evidence.

`make perf-gate` builds the target contract image, boots it under QEMU, measures
each `PERF_BATCH_BEGIN`/`PERF_BATCH_END` serial window with the harness monotonic
clock, applies `thresholds.json`, and writes normalized JSON reports under
`build/perf/`. Targets may also emit a complete `PERF_JSON:` record when they
have a safe local counter.

Every record contains:

- `metric`: stable machine-readable metric name;
- `unit`: measurement unit (`ns/op` for harness-timed batches);
- `samples`: number of independent measured batches after warmup;
- `counter_hz`: timing frequency (`1000000000` for the monotonic nanosecond clock);
- `min`, `p50`, `p95`, `p99`, and `max`;
- `errors`: failed operations observed during the sample window.

The initial metric, `sel4_ipc_eventbus_status`, measures complete synchronous
calls from the target contract-runner PD into the live EventBus PD. It collects
12 independent batches of 1,024 calls after warmup, then reports the
distribution of per-call batch averages. The gate requires at least nine
intact batches because unrelated PDs currently share an unlocked debug UART
and can interleave an early boundary marker. AArch64 PDs cannot read `CNTVCT_EL0`
under seL4, so timing at serial batch boundaries preserves kernel isolation and
avoids a privileged counter dependency.

`modelsvc_cached_query` measures the complete target fast path: a badged seL4
call, compact request decoding, model routing, exact-result cache lookup, shared
arena response write, and reply. It collects 12 batches of 256 calls after an
unmeasured cache-prime request and fails if any reply is not a cache hit.

The reduced x86_64 topology does not launch service PDs yet. Its
`sel4_yield` metric measures kernel scheduling/yield throughput from the live
root task, proving that the same JSON and threshold pipeline works on both
architectures without misrepresenting it as cross-PD IPC.

Thresholds are intentionally board-specific. Tighten them from collected CI
history rather than copying values between QEMU and physical hardware. A
missing metric, malformed record, operation error, insufficient sample count,
or exceeded threshold fails the gate.
