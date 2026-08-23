# =============================================================================
# mk/target-tests.mk — target/QEMU-backed test gates (agentos-0h4, agentos-45b)
#
# These targets run REAL seL4 IPC under QEMU, as opposed to the host-only mock
# suite (`make test-integration`, which uses the tests/microkit.h stub).
#
# To enable them, the Makefile owner adds exactly ONE line to the root Makefile
# (see tests/TARGET_TESTS.md for the full wiring note):
#
#     include mk/target-tests.mk
#
# Targets defined here:
#   test-target              — build the seL4 test image and run the target
#                              contract TAP suite (EventBus, CC-PD, serial_pd,
#                              log_drain, guest lifecycle) for the current BOARD.
#   test-target-aarch64      — same, pinned to TARGET_ARCH=aarch64 GUEST_OS=none.
#   test-target-x86_64       — same, pinned to TARGET_ARCH=x86_64  GUEST_OS=none.
#   test-target-all          — both arches.
#   perf-gate                — real target performance gates on both arches.
#   test-cc-virtio-timeout   — QEMU proof of the CC-PD VirtIO bounded-wait
#                              timeout error path (agentos-45b).
#
# All of these reuse the existing infrastructure already in the root Makefile
# (`sel4-test-image`) and xtask (`run-tests`, cmd_run_tests.rs); they do not
# introduce a parallel framework.
# =============================================================================

.PHONY: test-target test-target-aarch64 test-target-x86_64 test-target-all \
        test-cc-virtio-timeout perf-gate perf-gate-aarch64 perf-gate-x86_64

# Run the on-target contract TAP suite for the current BOARD.
# `run-tests` builds build/$(BOARD)-test/agentos.img via `sel4-test-image`,
# boots it in QEMU, and waits for the TAP_DONE sentinel emitted by the
# target_contract_runner PD (tests/harness/target_contract_runner.c).
test-target:
	@echo ""
	@echo "╔══════════════════════════════════════════════╗"
	@echo "║  agentOS — target contract TAP (real seL4)    ║"
	@echo "╚══════════════════════════════════════════════╝"
	@echo ""
	@echo "[target-tests] BOARD=$(BOARD) — building image + running real-IPC TAP"
	@$(MAKE) run-tests BOARD=$(BOARD)

test-target-aarch64:
	@$(MAKE) test-target TARGET_ARCH=aarch64 GUEST_OS=none

test-target-x86_64:
	@$(MAKE) test-target TARGET_ARCH=x86_64 GUEST_OS=none

test-target-all: test-target-aarch64 test-target-x86_64
	@echo "[target-tests] both target arches reported"

# Run the real-IPC benchmark embedded in the target contract runner, require
# its machine-readable record, apply board-specific regression thresholds,
# and retain a normalized JSON result for CI or release artifacts.
perf-gate-aarch64:
	@cargo xtask run-tests \
		--board qemu_virt_aarch64 \
		--timeout-secs $(QEMU_TEST_TIMEOUT) \
		--require-perf \
		--perf-thresholds performance/thresholds.json \
		--perf-output build/perf/qemu_virt_aarch64.json

perf-gate-x86_64:
	@cargo xtask run-tests \
		--board x86_64_generic \
		--timeout-secs $(QEMU_TEST_TIMEOUT) \
		--require-perf \
		--perf-thresholds performance/thresholds.json \
		--perf-output build/perf/x86_64_generic.json

perf-gate: perf-gate-aarch64 perf-gate-x86_64
	@echo "[target-perf] configured target performance gates passed"

# agentos-45b: QEMU proof of the CC-PD VirtIO used-ring bounded-wait timeout.
# Builds the seL4 test image for BOARD (idempotent), then drives the wedge
# script which stalls the CC-PD virtconsole ring and verifies the timeout
# error path is observable and non-fatal.
test-cc-virtio-timeout:
	@echo ""
	@echo "╔══════════════════════════════════════════════╗"
	@echo "║  agentOS — CC-PD VirtIO timeout proof (QEMU)  ║"
	@echo "╚══════════════════════════════════════════════╝"
	@echo ""
	@$(MAKE) sel4-test-image BOARD=$(BOARD)
	@chmod +x tests/harness/cc_virtio_timeout_test.sh
	@BOARD=$(BOARD) bash tests/harness/cc_virtio_timeout_test.sh
