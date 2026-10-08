# Native Fractal boot display

The optional boot screen runs in native seL4 user space and writes through
a dedicated firmware-framebuffer driver. Its Rust renderer is maintained
outside this repository in
[fractal-boot-screen](https://github.com/fractalsociety/fractal-boot-screen).
It uses no Linux guest, desktop window or hosted inference service.

The Clef composition shows model bytes loaded, completed backbone and head
layers, first-decision checking, completion and failure. Progress measures
work within each stage; it is not an estimated countdown or a total boot
percentage. The existing deterministic boot allocations remain in force
while the model loads. Model output is still advisory for the fixed test.

The [retained UEFI/QEMU run](evidence/2026-10-07-boot-display/native.json)
passed the full inference test and framebuffer checks in 180.1 seconds
from QEMU launch. A [negative run](evidence/2026-10-07-boot-display/failure.json)
refused writable model media before inference and displayed the failure
state. The host suite and full repository gate passed. The
[physical build receipt](evidence/2026-10-07-boot-display/physical-build.json)
records a staged artifact, not physical-PC boot acceptance.
The tested renderer source is
[`1a1aa5bc`](https://github.com/fractalsociety/fractal-boot-screen/commit/1a1aa5bc9031d341150fd9f0750272f56da52354);
the receipts also record both display ELF hashes.

The separate physical-PC diagnostic composition shows native storage
initialization. It explicitly says that Clef has not started once storage
qualification finishes. Physical model loading from NVMe and a general
resource-allocation service are not implemented by this display change.

## Build and test

### Check out both repositories

```bash
git clone https://github.com/fractalsociety/agentos.git fractal-agentos
git clone https://github.com/fractalsociety/fractal-boot-screen.git fractal-boot-screen
cd fractal-agentos
```

Keep these checkouts as siblings, or pass
`BOOT_SCREEN_SOURCE=/absolute/path/to/fractal-boot-screen` to the agentOS
Make command. The renderer is an external source dependency, not a submodule
or an independently bootable OS. `BOOT_DISPLAY=1` builds its Rust static
library and links it into the agentOS `boot_screen.elf` client.

With Make, a C compiler and Rust/Cargo installed, the small host checks are:

```bash
make -C ../fractal-boot-screen test
make test-boot-display-host test-clef-boot-status GUEST_OS=none
```

They require neither the model download nor a seL4 kernel build.

### Prepare the native screen test

The tested host is Linux x86_64 with access to `/dev/kvm`. Allow at least
16 GiB available RAM and 15 GiB disk space for the model experiment, plus
space for toolchains and build outputs. The model alone is 6,486,448,288
bytes; a disposable copy is also staged for QEMU. Install Make, a C compiler,
Clang/LLVM, LLD, Rust/Cargo, curl, tar, CMake, QEMU x86_64, Limine, OVMF,
mtools, dosfstools and sfdisk. See the [host tools guide](QUICKSTART.md#1-host-packages)
for the general compiler tools and [Clef experiment](CLEF_NATIVE_TEST.md#reproduce)
for model details.

The current launcher expects firmware at these exact paths (the layout
used on the Omarchy/Arch test host):

```text
/usr/share/limine/BOOTX64.EFI
/usr/share/limine/limine-bios.sys
/usr/share/edk2/x64/OVMF_CODE.4m.fd
/usr/share/edk2/x64/OVMF_VARS.4m.fd
```

Other distributions may install those files elsewhere; the launcher does
not currently discover alternate paths.

The screen test also needs an existing kernel build. It defaults to
`../fractal-lab/x2apic-diagnostic/build-xapic`. `BOOT_KERNEL_BUILD` can select
another existing UEFI-compatible x86 MCS build with printing enabled,
`kernel.elf`, `kernel32.elf` and CMake install metadata for the matching
generated libsel4 headers. **This lab build is not included in either
repository or fetched by these commands.** Without it, the host checks and
the [stock-SDK headless Clef test](CLEF_NATIVE_TEST.md#reproduce) remain
available, but the native screen test cannot run.

`clef-firmware-sdk` installs the existing build's already-generated
headers into the user cache and copies its existing kernel artifacts. It
never configures, edits or rebuilds seL4. Kernel and generated invocation
headers must come from the same build.

This requirement matters on the current host: stock SDK seL4 loads across
OVMF's reserved low-memory firmware region. The lab's existing kernel was
previously relocated to 16 MiB; the screen test reuses that artifact. Its
SHA-256 is recorded in the receipt. The ordinary headless `clef-native-test`
continues to use the stock SDK. This display work makes no kernel changes.

### Run and inspect results

From `fractal-agentos`, after satisfying those prerequisites:

```bash
make clef-fetch GUEST_OS=none
make clef-boot-screen-test GUEST_OS=none \
    BOOT_KERNEL_BUILD=/absolute/path/to/existing-compatible-kernel-build
```

On the original lab host, omit `BOOT_KERNEL_BUILD` to use its default.
The build downloads the pinned native Rust toolchain into the user cache
and compiles both repositories. Use the tested renderer commit linked above
when reproducing the retained evidence.

The test creates a disposable FAT image and starts UEFI/Limine in QEMU/KVM.
QEMU runs without a desktop window; QMP captures `loading.ppm` and
`ready.ppm` under `build/clef-native`. The harness checks actual framebuffer pixels as well
as the native layer/probability trace and renderer completion marker.
`CLEF_TEST_ARGS='--expect-model-failure'` exercises refusal of writable
disposable model media and captures `failure.ppm`. The model cache remains
unchanged. Each run replaces the prior logs and receipt in that build directory.

Inspect `build/clef-native/receipt.json` for the result and artifact hashes,
`serial.log` for native diagnostics, and `boot-status.json` plus
`boot-events.jsonl` for progress. A passing full run ends with
`CLEF_NATIVE_PASS`; the failure test intentionally produces an
`EXPECTED_FAILURE` receipt.

Repository regression checks use the stock SDK separately:

```bash
make sdk SEL4_SDK_VERSION=2.3.0
make test-host SEL4_SDK_VERSION=2.3.0
make gate SEL4_SDK_VERSION=2.3.0
```

## Physical PC artifact

```
make boot-screen-physical-stage GUEST_OS=none
```

This builds the existing read-only Samsung `81:00.0` diagnostic with the
display driver and renderer, then stages `build/boot-screen-physical/boot-esp.img`.
`BOOT_PHYSICAL_SDK` selects the existing lab SDK and `BOOT_PHYSICAL_BUILD`
selects an isolated output directory. The target does not mount or alter the
live EFI partition, set BootNext, enable NVMe writes or reboot the PC.
Hardware acceptance requires a separately authorized physical boot. The
artifact is a diagnostic image, not a complete physical Clef machine.

## Contracts and failure behavior

`platform/include/platform/boot_display.h` defines the read-only progress
snapshot and validated framebuffer metadata. Root grants the framebuffer
mapping exclusively to `boot_display`, and only that driver maps its two
private staging banks. The renderer reads a consistent atomic progress
snapshot and submits complete frames through `platform/display/service.c`.
It cannot reach device registers, IRQs, the model arena or scheduling controls.
Both display PDs have fixed 1 ms / 10 ms CPU budgets. Unsupported framebuffer
formats or failed grants refuse startup of the display composition.

Firmware must supply a page-aligned, 32-bit direct-color framebuffer,
640–4096 pixels wide and 320–2160 high, with a validated pitch and at most
64 MiB. The scene is centered at 640×320. Grayscale avoids relying on RGB
channel masks, which the [seL4 framebuffer BootInfo payload](https://github.com/seL4/seL4/blob/master/include/arch/x86/arch/kernel/multiboot2.h)
does not retain. This is a firmware scanout path, not a GPU modesetting driver.

`platform/include/platform/clef_boot.h` defines complete ASCII diagnostic
records. The Rust launcher validates stage order, byte bounds and every layer,
and waits for numerical PASS before publishing `state=ready`. Atomic
`boot-status.json` snapshots and timestamped `boot-events.jsonl` records
include a unique run ID, phase, completed/total counts, units and errors.
Early launch failures and timeouts publish a failed state. No progress
record can authorize an allocation. Abrupt process termination may leave
the last snapshot; consumers must also observe process liveness.

The screen starts after root provisions the display PDs. Firmware/kernel
failures before that point cannot be rendered by this client. Model errors
and panics that return through its adapter publish an unavailable state;
the screen does not implement kernel-fault recovery or an independent
watchdog for a stalled model.
