# Experimental native CPU inference. Weights remain outside the repository.
CLEF_CACHE ?= $(if $(XDG_CACHE_HOME),$(XDG_CACHE_HOME),$(HOME)/.cache)/agentos/clef-flash
CLEF_MODEL ?= $(CLEF_CACHE)/Clef-Flash-Q4_K_M.gguf
CLEF_SOURCES := $(wildcard platform/clef/src/*.rs) platform/clef/Cargo.toml
CLEF_HEADERS := platform/include/platform/clef.h tests/fixtures/clef-resource-choice.h
CLEF_CFLAGS := -std=c11 -O3 -Wall -Wextra -Werror -ffp-contract=off -Iplatform/include -I.
CLEF_SDK ?= $(HOME)/.cache/agentos/microkit-sdk-2.3.0
.PHONY: clef-fetch clef-fixture clef-host-check clef-build clef-native-test test-clef-unit clef-toolchain
clef-fetch:
	cargo run --release -q -p xtask -- clef fetch
clef-fixture:
	cargo run -q -p xtask -- clef fixture
build/clef/host-check: tests/clef/host.c $(CLEF_SOURCES) $(CLEF_HEADERS)
	@mkdir -p $(@D)
	cargo build -p agentos-clef --release
	$(CC) $(CLEF_CFLAGS) tests/clef/host.c target/release/libagentos_clef.a -o $@ -lm -lpthread -ldl
clef-host-check: build/clef/host-check
	$< "$(CLEF_MODEL)"
test-clef-unit:
	cargo test -p agentos-clef --lib
test-host: test-clef-unit
clef-toolchain:
	cargo run -q -p xtask -- clef toolchain
clef-build: clef-toolchain
	$(MAKE) build BUILD_DIR=$(abspath build/clef-native) AGENTOS_BOARD=x86_64_generic_vtx AGENTOS_ARCH=x86_64 \
		GUEST_OS=none BOARD_NAME=qemu-x86_64-vtx BOARD_NATIVE=0 BOARD_UART_PHYS=0x3F8 BOARD_UART_SIZE=0x8 BOARD_UART_TYPE=ns16550 \
		X86_FIRMWARE_RESET=1 X86_SECONDARY_BLOCK=1 FRACTAL_NATIVE_PROBE=1 FRACTAL_EXCHANGE_CYCLE=1 FRACTAL_NATIVE_ONLY=1 \
		FRACTAL_CLEF_TEST=1 SEL4_SDK_VERSION=2.3.0 SEL4_SDK="$(CLEF_SDK)" SEL4_PROFILE=debug \
		CLEF_RUST_SYSROOT="$(CLEF_CACHE)/rust-sysroot"
clef-native-test: clef-build
	SEL4_SDK="$(CLEF_SDK)" cargo run --release -q -p xtask -- clef native
