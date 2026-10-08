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

BOOT_KERNEL_BUILD ?= $(abspath ../fractal-lab/x2apic-diagnostic/build-xapic)
CLEF_FIRMWARE_SDK ?= $(CLEF_CACHE)/firmware-sdk
.PHONY: clef-boot-screen-test clef-firmware-sdk test-clef-boot-status
# Assemble headers from the already-built lab kernel; never configure, patch
# or rebuild seL4. Its generated invocation headers must match its ELF.
clef-firmware-sdk:
	test -f "$(BOOT_KERNEL_BUILD)/kernel32.elf"
	cmake --install "$(BOOT_KERNEL_BUILD)" --prefix "$(CLEF_CACHE)/firmware-kernel-install"
	mkdir -p "$(CLEF_FIRMWARE_SDK)/board/x86_64_generic_vtx/debug/elf"
	cp -a "$(CLEF_CACHE)/firmware-kernel-install/libsel4/include" "$(CLEF_FIRMWARE_SDK)/board/x86_64_generic_vtx/debug/"
	cp "$(BOOT_KERNEL_BUILD)/kernel.elf" "$(CLEF_FIRMWARE_SDK)/board/x86_64_generic_vtx/debug/elf/sel4.elf"
	cp "$(BOOT_KERNEL_BUILD)/kernel32.elf" "$(CLEF_FIRMWARE_SDK)/board/x86_64_generic_vtx/debug/elf/sel4_32.elf"
clef-boot-screen-test: clef-firmware-sdk
	$(MAKE) clef-build GUEST_OS=none BOOT_DISPLAY=1 CLEF_SDK="$(CLEF_FIRMWARE_SDK)"
	SEL4_SDK="$(CLEF_FIRMWARE_SDK)" cargo run --release -q -p xtask -- clef native --firmware-display $(CLEF_TEST_ARGS)
test-clef-boot-status:
	cargo test -p xtask --lib clef
test-host: test-clef-boot-status
.PHONY: test-boot-display-host
test-boot-display-host:
	@mkdir -p build/tests
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -Iplatform/include tests/platform/test_boot_display.c platform/display/boot_fb.c -o build/tests/test-boot-display
	build/tests/test-boot-display
test-host: test-boot-display-host

# Build/stage only: never writes the live ESP or changes BootNext.
BOOT_PHYSICAL_SDK ?= $(abspath ../fractal-lab/microkit-source/release/microkit-sdk-2.3.0)
BOOT_PHYSICAL_BUILD ?= $(abspath build/boot-screen-physical)
.PHONY: boot-screen-physical-build boot-screen-physical-stage
boot-screen-physical-build: clef-toolchain
	$(MAKE) build BUILD_DIR="$(BOOT_PHYSICAL_BUILD)" AGENTOS_BOARD=x86_64_generic_vtx AGENTOS_ARCH=x86_64 \
		GUEST_OS=none BOARD_NAME=qemu-x86_64-vtx BOARD_NATIVE=0 BOARD_UART_PHYS=0x3F8 BOARD_UART_SIZE=0x8 BOARD_UART_TYPE=ns16550 \
		X86_FIRMWARE_RESET=1 FRACTAL_NATIVE_ONLY=1 FRACTAL_NVME_PROBE=1 FRACTAL_NVME_ONLY=1 \
		FRACTAL_NVME_TARGET=samsung-bus81 FRACTAL_NVME_WRITE_PROBE=0 FRACTAL_NVME_EXCHANGE=0 \
		BOOT_DISPLAY=1 SEL4_SDK_VERSION=2.3.0 SEL4_SDK="$(BOOT_PHYSICAL_SDK)" SEL4_PROFILE=release \
		CLEF_RUST_SYSROOT="$(CLEF_CACHE)/rust-sysroot"
boot-screen-physical-stage: boot-screen-physical-build
	cargo run --release -q -p xtask -- clef stage --build-dir "$(BOOT_PHYSICAL_BUILD)" --firmware-display \
		--firmware-kernel "$(BOOT_PHYSICAL_SDK)/board/x86_64_generic_vtx/release/elf/sel4_32.elf"
