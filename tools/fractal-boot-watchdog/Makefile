ROOT := $(abspath ../..)
BUILD ?= $(ROOT)/build/fractal-boot-watchdog
STAGE ?= $(BUILD)/stage
OVMF ?= /usr/share/edk2/x64
QEMU ?= qemu-system-x86_64
CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror
EFI_FLAGS := -I/usr/include/efi -I/usr/include/efi/x86_64 -DEFI_FUNCTION_WRAPPER -fpic -fshort-wchar -mno-red-zone -ffreestanding -fno-stack-protector

.PHONY: all test
all: $(BUILD)/BOOTX64.EFI
$(BUILD):
	mkdir -p $@
$(BUILD)/%.o: %.c tco.h | $(BUILD)
	$(CC) $(CFLAGS) $(EFI_FLAGS) -c $< -o $@
$(BUILD)/loader.so: $(BUILD)/loader.o $(BUILD)/tco.o
	ld -nostdlib -znocombreloc -T /usr/lib/elf_x86_64_efi.lds -shared -Bsymbolic /usr/lib/crt0-efi-x86_64.o $^ -L/usr/lib -lefi -lgnuefi -o $@
$(BUILD)/BOOTX64.EFI: $(BUILD)/loader.so
	objcopy -j .text -j .sdata -j .data -j .rodata -j .dynamic -j .dynsym -j .rel -j .rela -j .reloc -O pei-x86-64 --subsystem 10 $< $@
$(BUILD)/test-tco: test.c tco.c tco.h | $(BUILD)
	$(CC) $(CFLAGS) test.c tco.c -o $@
test: $(BUILD)/test-tco
	$<

# Caller supplies qualified images. Staging never mounts the live ESP or
# changes firmware variables. Limine's countdown is inside the 120s budget.
.PHONY: stage test-firmware-refusal
stage: all
	test -f "$(KERNEL)" && test -f "$(ROOT_ELF)"
	mkdir -p $(STAGE)/EFI/FractalWatchdog
	install -m 0644 $(BUILD)/BOOTX64.EFI $(STAGE)/EFI/FractalWatchdog/BOOTX64.EFI
	install -m 0644 /usr/share/limine/BOOTX64.EFI $(STAGE)/EFI/FractalWatchdog/LIMINE.EFI
	install -m 0644 $(KERNEL) $(STAGE)/EFI/FractalWatchdog/sel4_32.elf
	install -m 0644 $(ROOT_ELF) $(STAGE)/EFI/FractalWatchdog/root_task.elf
	install -m 0644 limine.conf $(STAGE)/EFI/FractalWatchdog/limine.conf
	cd $(STAGE) && sha256sum EFI/FractalWatchdog/* > sha256.txt

# Stock q35 is not this PC's TCO v6: production firmware must refuse it.
test-firmware-refusal: all
	mkdir -p $(BUILD)/refusal
	truncate -s 64M $(BUILD)/refusal/esp.img
	mkfs.vfat -F 32 $(BUILD)/refusal/esp.img >/dev/null
	mmd -i $(BUILD)/refusal/esp.img ::/EFI ::/EFI/BOOT
	mcopy -i $(BUILD)/refusal/esp.img $(BUILD)/BOOTX64.EFI ::/EFI/BOOT/BOOTX64.EFI
	cp $(OVMF)/OVMF_VARS.4m.fd $(BUILD)/refusal/vars.fd
	@status=0; timeout 15s $(QEMU) -machine q35,accel=kvm -m 1G -cpu host \
	 -drive if=pflash,format=raw,readonly=on,file=$(OVMF)/OVMF_CODE.4m.fd \
	 -drive if=pflash,format=raw,file=$(BUILD)/refusal/vars.fd \
	 -drive if=ide,format=raw,file=$(BUILD)/refusal/esp.img \
	 -serial file:$(BUILD)/refusal/serial.log -display none -no-reboot \
	 >$(BUILD)/refusal/qemu.log 2>&1 || status=$$?; test "$$status" = 124
	rg -F 'Fractal: supported hardware watchdog unavailable; boot refused.' $(BUILD)/refusal/serial.log
