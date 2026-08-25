#!/usr/bin/env bash
# tools/bootstrap-guest.sh — Create FractalOS E2E guest disk images from ISO files
#
# Automates guest OS installation from installer ISOs, producing raw disk images
# suitable for use as FractalOS VMM guest disks in E2E tests.
#
# Usage:
#   tools/bootstrap-guest.sh <os>
#   tools/bootstrap-guest.sh <os> <output-image>
#
# Supported OS targets:
#   ubuntu-amd64    Ubuntu 26.04 LTS x86_64 desktop (qemu_virt x86_64 guests)
#   ubuntu-arm64    Ubuntu 26.04 ARM64 desktop       (qemu_virt_aarch64 guests)
#   nixos           NixOS 25.11 x86_64 minimal       (qemu_virt x86_64 guests)
#   freebsd15       FreeBSD 15.0 AMD64               (qemu_virt x86_64 guests)
#
# Environment:
#   ISO_DIR         directory containing/caching ISO files
#                   (default: ${XDG_CACHE_HOME:-$HOME/.cache}/fractalos/isos)
#   GUEST_IMG_DIR   output directory (default: build/guest-images/)
#   TMP_ROOT        host scratch directory (default: build/tmp/)
#   E2E_SSH_PUBKEY  path to test SSH public key (default: tests/e2e/id_ed25519.pub)
#   DISK_SIZE_GB    guest disk image size in GB (default: 20)
#   QEMU_MEM_MB     RAM to give installer VM in MB (default: 2048)
#
# ISO filenames cached/looked up in ISO_DIR (auto-downloaded from the
# vendor's site if missing):
#   ubuntu-amd64:  ubuntu-26.04-desktop-amd64.iso
#                  (https://cdimage.ubuntu.com/releases/26.04/release/)
#   ubuntu-arm64:  ubuntu-26.04-desktop-arm64.iso
#                  (https://cdimage.ubuntu.com/releases/26.04/release/)
#   nixos:         nixos-minimal-25.11-x86_64-linux.iso
#                  (https://channels.nixos.org/nixos-25.11/latest-nixos-minimal-x86_64-linux.iso)
#   freebsd15:     FreeBSD-15.0-RELEASE-amd64-disc1.iso (or -bootonly)
#                  (https://download.freebsd.org/releases/amd64/amd64/ISO-IMAGES/15.0/)
#
# Prerequisites:
#   All:           qemu-system-{x86_64,aarch64}
#   ubuntu-*:      mkisofs OR hdiutil (macOS built-in)
#   nixos:         /usr/bin/expect (macOS built-in; brew install expect on Linux)
#   freebsd15:     /usr/bin/expect  (or: curl to download VM image instead)
#
# Notes:
#   - The NixOS and FreeBSD installers require ~15-30 minutes in QEMU without KVM.
#   - Pass E2E_SKIP_ISO_INSTALL=1 to download pre-built cloud images instead
#     (faster; requires internet; bypasses the local ISOs).

set -euo pipefail

# ── Helpers ────────────────────────────────────────────────────────────────────

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; RESET='\033[0m'
info()  { printf "${BOLD}[bootstrap]${RESET} %s\n" "$*"; }
ok()    { printf "${GREEN}[ok]${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}[warn]${RESET} %s\n" "$*"; }
die()   { printf "${RED}[error]${RESET} %s\n" "$*" >&2; exit 1; }

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# ── Configuration ──────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ISO_DIR="${ISO_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/fractalos/isos}"
GUEST_IMG_DIR="${GUEST_IMG_DIR:-${REPO_ROOT}/build/guest-images}"
TMP_ROOT="${TMP_ROOT:-${REPO_ROOT}/build/tmp}"
E2E_SSH_PUBKEY="${E2E_SSH_PUBKEY:-${REPO_ROOT}/tests/e2e/id_ed25519.pub}"
DISK_SIZE_GB="${DISK_SIZE_GB:-20}"
QEMU_MEM_MB="${QEMU_MEM_MB:-2048}"
E2E_SKIP_ISO_INSTALL="${E2E_SKIP_ISO_INSTALL:-0}"

OS="${1:-}"
[ -z "${OS}" ] && die "Usage: bootstrap-guest.sh <ubuntu-amd64|ubuntu-arm64|nixos|freebsd15> [output-image]"

OUTPUT_IMG="${2:-}"

mkdir -p "${GUEST_IMG_DIR}" "${TMP_ROOT}"

# ── SSH key ────────────────────────────────────────────────────────────────────

ensure_ssh_key() {
    local key_path="${REPO_ROOT}/tests/e2e/id_ed25519"
    if [ ! -f "${key_path}" ]; then
        info "Generating test SSH key..."
        ssh-keygen -t ed25519 -N "" -f "${key_path}" -C "fractalos-e2e-test" >/dev/null
        chmod 600 "${key_path}"
    fi
    E2E_SSH_PUBKEY="${key_path}.pub"
    [ -f "${E2E_SSH_PUBKEY}" ] || die "SSH public key not found: ${E2E_SSH_PUBKEY}"
    SSH_PUBKEY_CONTENT="$(cat "${E2E_SSH_PUBKEY}")"
}

# ── Seed ISO creation (Ubuntu cloud-init CIDATA) ───────────────────────────────

# Creates a CIDATA seed ISO from a directory of cloud-init files.
# On macOS uses hdiutil; on Linux uses mkisofs/genisoimage.
make_cidata_iso() {
    local seed_dir="$1"
    local out_iso="$2"

    if command -v hdiutil >/dev/null 2>&1; then
        # macOS
        hdiutil makehybrid \
            -o "${out_iso}" \
            -ov \
            -joliet \
            -iso \
            -default-volume-name CIDATA \
            "${seed_dir}" >/dev/null 2>&1
    elif command -v mkisofs >/dev/null 2>&1; then
        mkisofs -output "${out_iso}" \
            -volid CIDATA -joliet -rock "${seed_dir}" >/dev/null 2>&1
    elif command -v genisoimage >/dev/null 2>&1; then
        genisoimage -output "${out_iso}" \
            -volid CIDATA -joliet -rock "${seed_dir}" >/dev/null 2>&1
    else
        die "Cannot create seed ISO: install hdiutil (macOS) or mkisofs/genisoimage (Linux)"
    fi
}

# ── Vendor ISO download / cache ───────────────────────────────────────────────
#
# Ensures the named ISO is present in ISO_DIR, downloading it from the
# vendor's official site on cache miss. Echoes the cached path on success.

ensure_iso() {
    local iso_name="$1"
    local url="$2"
    local expected_sha="${3:-}"
    local cached="${ISO_DIR}/${iso_name}"

    mkdir -p "${ISO_DIR}"
    if [ -s "${cached}" ]; then
        if [ -n "$expected_sha" ] && [ "$(sha256_file "$cached")" != "$expected_sha" ]; then
            die "Cached ISO checksum mismatch: ${cached}"
        fi
        printf '%s\n' "${cached}"
        return 0
    fi

    info "Downloading ${url}" >&2
    info "  -> ${cached}" >&2
    local tmp="${cached}.part"
    if command -v aria2c >/dev/null 2>&1; then
        aria2c --continue=true --max-connection-per-server=8 --split=8 \
            --min-split-size=4M --file-allocation=none \
            --dir "${ISO_DIR}" --out "${iso_name}.part" "${url}" \
            || die "Download failed: ${url}"
    else
        curl --fail --location --continue-at - --progress-bar \
            -o "${tmp}" "${url}" || die "Download failed: ${url}"
    fi
    [ -s "${tmp}" ] || die "Downloaded ISO is empty: ${url}"
    if [ -n "$expected_sha" ] && [ "$(sha256_file "$tmp")" != "$expected_sha" ]; then
        die "Downloaded ISO checksum mismatch: ${url}"
    fi
    mv "${tmp}" "${cached}"
    printf '%s\n' "${cached}"
}

# ── Download fallback (cloud images) ──────────────────────────────────────────

download_nixos_cloud_image() {
    local out="$1"
    local ver="25.11"
    # NixOS provides minimal QCOW2 images via the hydra build system
    local base="https://channels.nixos.org/nixos-${ver}"
    info "Fetching NixOS ${ver} QCOW2 cloud image from nixos.org..."
    local fname="nixos-${ver}-x86_64-linux.qcow2.zst"
    local url="${base}/nixos-${ver}-x86_64-linux.qcow2.zst"
    local tmp="${out}.qcow2.zst"
    curl -L --progress-bar -o "${tmp}" "${url}" || die "Download failed: ${url}"
    if command -v zstd >/dev/null 2>&1; then
        zstd -d "${tmp}" -o "${out}.qcow2"
    else
        die "zstd not found — install it or use ISO mode (unset E2E_SKIP_ISO_INSTALL)"
    fi
    qemu-img convert -f qcow2 -O raw "${out}.qcow2" "${out}"
    rm -f "${tmp}" "${out}.qcow2"
}

download_freebsd15_vm_image() {
    local out="$1"
    local base="https://download.freebsd.org/releases/VM-IMAGES/15.0-RELEASE/amd64/Latest"
    local fname="FreeBSD-15.0-RELEASE-amd64-ufs.raw.xz"
    info "Fetching FreeBSD 15.0 VM image from freebsd.org..."
    local tmp="${out}.raw.xz"
    curl -L --progress-bar -o "${tmp}" "${base}/${fname}" || die "Download failed"
    xz -d "${tmp}"   # produces ${out%.raw.xz}.raw — rename
    mv "${tmp%.xz}" "${out}"
}

# ── Expect runner ─────────────────────────────────────────────────────────────

EXPECT_BIN=""
find_expect() {
    for p in /usr/bin/expect /usr/local/bin/expect /opt/homebrew/bin/expect; do
        [ -x "${p}" ] && EXPECT_BIN="${p}" && return 0
    done
    command -v expect >/dev/null 2>&1 && EXPECT_BIN="$(command -v expect)" && return 0
    return 1
}

# ── Ubuntu AMD64 bootstrap ─────────────────────────────────────────────────────
#
# Ubuntu 26.04 desktop ISO supports cloud-init "autoinstall" natively.
# We create a CIDATA seed ISO with user-data (autoinstall.yaml) and mount it
# alongside the Ubuntu installer ISO.  The installer runs completely unattended.

bootstrap_ubuntu_amd64() {
    local out="${OUTPUT_IMG:-${GUEST_IMG_DIR}/ubuntu-amd64.img}"
    local qemu="qemu-system-x86_64"

    command -v "${qemu}" >/dev/null 2>&1 || die "qemu-system-x86_64 not found"
    local iso
    iso="$(ensure_iso \
        "ubuntu-26.04-desktop-amd64.iso" \
        "https://cdimage.ubuntu.com/releases/26.04/release/ubuntu-26.04-desktop-amd64.iso")"

    ensure_ssh_key

    info "Bootstrapping Ubuntu 26.04 amd64 → ${out}"
    qemu-img create -f raw "${out}" "${DISK_SIZE_GB}G"

    # Build cloud-init seed directory
    local seed_dir
    seed_dir="$(mktemp -d "${TMP_ROOT}/fractalos-ubuntu-amd64-seed.XXXXXX")"
    trap 'rm -rf "${seed_dir}"' EXIT INT TERM

    # meta-data (minimal)
    cat > "${seed_dir}/meta-data" << 'META'
instance-id: fractalos-e2e
local-hostname: fractalos-guest
META

    # user-data (Ubuntu autoinstall — subiquity format)
    cat > "${seed_dir}/user-data" << AUTOINSTALL
#cloud-config
autoinstall:
  version: 1
  identity:
    hostname: fractalos-guest
    username: root
    password: '!'
  ssh:
    install-server: true
    allow-pw: false
    authorized-keys:
      - '${SSH_PUBKEY_CONTENT}'
  storage:
    layout:
      name: direct
  late-commands:
    - 'echo "PermitRootLogin yes" >> /target/etc/ssh/sshd_config'
    - 'mkdir -p /target/root/.ssh'
    - 'echo "${SSH_PUBKEY_CONTENT}" > /target/root/.ssh/authorized_keys'
    - 'chmod 700 /target/root/.ssh && chmod 600 /target/root/.ssh/authorized_keys'
  shutdown: poweroff
AUTOINSTALL

    local seed_iso="${seed_dir}/seed.iso"
    make_cidata_iso "${seed_dir}" "${seed_iso}"

    info "Launching Ubuntu installer in QEMU (headless — this takes ~10-20 min)..."
    local install_log="${TMP_ROOT}/ubuntu-install-$$.log"
    info "Serial log: ${install_log}"

    # Ubuntu autoinstall: pass ds=nocloud;seedfrom via kernel cmdline
    "${qemu}" \
        -machine q35 -m "${QEMU_MEM_MB}M" \
        -cpu host 2>/dev/null || true
    "${qemu}" \
        -machine q35 -m "${QEMU_MEM_MB}M" \
        -drive "file=${iso},readonly=on,media=cdrom,format=raw" \
        -drive "file=${seed_iso},readonly=on,media=cdrom,format=raw,index=1" \
        -drive "file=${out},if=virtio,format=raw" \
        -nographic \
        -serial "file:${install_log}" \
        -no-reboot 2>/dev/null &
    local qemu_pid=$!

    info "Waiting for Ubuntu autoinstall to complete (poweroff signal)..."
    local waited=0
    while kill -0 "${qemu_pid}" 2>/dev/null; do
        sleep 10
        waited=$(( waited + 10 ))
        if grep -qF "Installation complete" "${install_log}" 2>/dev/null; then
            info "Autoinstall complete (${waited}s)"
        fi
        if [ "${waited}" -ge 2400 ]; then
            kill "${qemu_pid}" 2>/dev/null || true
            die "Ubuntu install did not complete within 40 min"
        fi
    done

    rm -f "${install_log}"
    ok "Ubuntu amd64 image ready: ${out}"
}

# ── Ubuntu ARM64 bootstrap ─────────────────────────────────────────────────────

bootstrap_ubuntu_arm64() {
    local out="${OUTPUT_IMG:-${GUEST_IMG_DIR}/ubuntu-arm64.img}"
    local qemu="qemu-system-aarch64"
    local firmware="${GUEST_IMG_DIR}/edk2-aarch64-code.fd"

    command -v "${qemu}" >/dev/null 2>&1 || die "qemu-system-aarch64 not found"
    [ -f "${firmware}" ] || die "UEFI firmware not found: ${firmware} (run: make fetch-guest)"
    local iso
    iso="$(ensure_iso \
        "ubuntu-26.04-desktop-arm64.iso" \
        "https://cdimage.ubuntu.com/releases/26.04/release/ubuntu-26.04-desktop-arm64.iso")"

    ensure_ssh_key

    info "Bootstrapping Ubuntu 26.04 arm64 → ${out}"
    qemu-img create -f raw "${out}" "${DISK_SIZE_GB}G"

    local seed_dir
    seed_dir="$(mktemp -d "${TMP_ROOT}/fractalos-ubuntu-arm64-seed.XXXXXX")"
    trap 'rm -rf "${seed_dir}"' EXIT INT TERM

    cat > "${seed_dir}/meta-data" << 'META'
instance-id: fractalos-e2e-arm64
local-hostname: fractalos-guest-arm64
META

    cat > "${seed_dir}/user-data" << AUTOINSTALL
#cloud-config
autoinstall:
  version: 1
  identity:
    hostname: fractalos-guest-arm64
    username: root
    password: '!'
  ssh:
    install-server: true
    allow-pw: false
    authorized-keys:
      - '${SSH_PUBKEY_CONTENT}'
  storage:
    layout:
      name: direct
  late-commands:
    - 'echo "PermitRootLogin yes" >> /target/etc/ssh/sshd_config'
    - 'mkdir -p /target/root/.ssh'
    - 'echo "${SSH_PUBKEY_CONTENT}" > /target/root/.ssh/authorized_keys'
    - 'chmod 700 /target/root/.ssh && chmod 600 /target/root/.ssh/authorized_keys'
  shutdown: poweroff
AUTOINSTALL

    local seed_iso="${seed_dir}/seed.iso"
    make_cidata_iso "${seed_dir}" "${seed_iso}"

    info "Launching Ubuntu ARM64 installer in QEMU (headless)..."
    "${qemu}" \
        -machine virt,virtualization=on \
        -cpu cortex-a57 -m "${QEMU_MEM_MB}M" \
        -drive "if=pflash,format=raw,file=${firmware},readonly=on" \
        -drive "file=${iso},readonly=on,media=cdrom,format=raw" \
        -drive "file=${seed_iso},readonly=on,media=cdrom,format=raw,index=1" \
        -drive "file=${out},if=virtio,format=raw" \
        -nographic \
        -serial "file:${TMP_ROOT}/ubuntu-arm64-install-$$.log" \
        -no-reboot 2>/dev/null &
    local qemu_pid=$!

    info "Waiting for Ubuntu ARM64 autoinstall to complete..."
    local waited=0
    while kill -0 "${qemu_pid}" 2>/dev/null; do
        sleep 15
        waited=$(( waited + 15 ))
        [ "${waited}" -ge 3600 ] && kill "${qemu_pid}" 2>/dev/null || true && \
            die "Ubuntu ARM64 install did not complete within 60 min"
    done

    rm -f "${TMP_ROOT}/ubuntu-arm64-install-$$.log"
    ok "Ubuntu arm64 image ready: ${out}"
}

# ── NixOS bootstrap ────────────────────────────────────────────────────────────
#
# NixOS minimal ISO boots directly to a root shell on the serial console
# (no login prompt — it auto-logs in as root).  We drive the installation
# with expect: partition, format, mount, write configuration.nix, install.

bootstrap_nixos() {
    local out="${OUTPUT_IMG:-${GUEST_IMG_DIR}/nixos.img}"
    local qemu="qemu-system-x86_64"

    if [ "${E2E_SKIP_ISO_INSTALL}" = "1" ]; then
        download_nixos_cloud_image "${out}"
        return 0
    fi

    command -v "${qemu}" >/dev/null 2>&1 || die "qemu-system-x86_64 not found"
    find_expect || die "expect not found — install it (brew install expect) or set E2E_SKIP_ISO_INSTALL=1"
    local iso
    iso="$(ensure_iso \
        "nixos-minimal-25.11-x86_64-linux.iso" \
        "https://channels.nixos.org/nixos-25.11/latest-nixos-minimal-x86_64-linux.iso")"

    ensure_ssh_key

    info "Bootstrapping NixOS 25.11 → ${out}"
    qemu-img create -f raw "${out}" "${DISK_SIZE_GB}G"

    local serial_sock="${TMP_ROOT}/nixos-install-$$.sock"

    # Write the expect script to a temp file
    local expect_script
    expect_script="$(mktemp "${TMP_ROOT}/nixos-install-XXXXXX.exp")"
    cat > "${expect_script}" << EXPECT_SCRIPT
#!/usr/bin/expect -f

set timeout 600
set out  [lindex \$argv 0]
set iso  [lindex \$argv 1]
set key  [lindex \$argv 2]

# Launch QEMU
spawn qemu-system-x86_64 \\
    -machine q35 -m ${QEMU_MEM_MB} \\
    -drive "file=\$iso,readonly=on,media=cdrom,format=raw" \\
    -drive "file=\$out,if=virtio,format=raw" \\
    -nographic

# NixOS minimal boots to a root shell automatically — wait for prompt
# The prompt looks like: [root@nixos:~]#
puts "Waiting for NixOS to boot (up to 10 min)..."
expect {
    timeout         { puts "ERROR: NixOS did not boot"; exit 1 }
    "root@nixos"    { }
}
# Wait for the shell to be fully ready
sleep 3

# Partition the disk (GPT: EFI + root)
send "parted -s /dev/vda mklabel gpt \
    mkpart ESP fat32 1MiB 512MiB set 1 esp on \
    mkpart primary ext4 512MiB 100%\r"
expect "# "

send "mkfs.fat -F 32 -n boot /dev/vda1 && mkfs.ext4 -L nixos /dev/vda2\r"
expect "# "

send "mount /dev/disk/by-label/nixos /mnt && mkdir -p /mnt/boot && mount /dev/vda1 /mnt/boot\r"
expect "# "

send "nixos-generate-config --root /mnt\r"
expect "# "

# Write configuration.nix — use printf to avoid heredoc quoting issues in expect
send "printf '%s\\n' '{ config, pkgs, ... }:' > /mnt/etc/nixos/configuration.nix\r"
expect "# "
send "printf '%s\\n' '{ imports = \[ ./hardware-configuration.nix \];' >> /mnt/etc/nixos/configuration.nix\r"
expect "# "
send "printf '%s\\n' '  boot.loader.systemd-boot.enable = true;' >> /mnt/etc/nixos/configuration.nix\r"
expect "# "
send "printf '%s\\n' '  boot.loader.efi.canTouchEfiVariables = true;' >> /mnt/etc/nixos/configuration.nix\r"
expect "# "
send "printf '%s\\n' '  services.openssh.enable = true;' >> /mnt/etc/nixos/configuration.nix\r"
expect "# "
send "printf '%s\\n' '  services.openssh.settings.PermitRootLogin = \"yes\";' >> /mnt/etc/nixos/configuration.nix\r"
expect "# "
send "printf '%s\\n' '  services.openssh.settings.PasswordAuthentication = false;' >> /mnt/etc/nixos/configuration.nix\r"
expect "# "
send "printf '%s\\n' '  users.users.root.openssh.authorizedKeys.keys = \[ \"\$key\" \];' >> /mnt/etc/nixos/configuration.nix\r"
expect "# "
send "printf '%s\\n' '  networking.firewall.enable = false;' >> /mnt/etc/nixos/configuration.nix\r"
expect "# "
send "printf '%s\\n' '  environment.systemPackages = with pkgs; \[ vim curl wget \];' >> /mnt/etc/nixos/configuration.nix\r"
expect "# "
send "printf '%s\\n' '  system.stateVersion = \"25.11\";' >> /mnt/etc/nixos/configuration.nix\r"
expect "# "
send "printf '%s\\n' '}' >> /mnt/etc/nixos/configuration.nix\r"
expect "# "

puts "Running nixos-install (this takes 10-20 min)..."
send "nixos-install --no-root-passwd 2>&1 | tee /tmp/nixos-install.log\r"
set timeout 1800
expect {
    timeout              { puts "ERROR: nixos-install timed out"; exit 1 }
    "Installation finished" { }
    "installation finished" { }
    "error:"             { puts "ERROR: nixos-install failed"; exit 1 }
}
expect "# "

send "poweroff\r"
puts "NixOS installation complete."
expect eof
exit 0
EXPECT_SCRIPT
    chmod +x "${expect_script}"

    info "Running NixOS automated install via expect (15-25 min)..."
    "${EXPECT_BIN}" "${expect_script}" "${out}" "${iso}" "${SSH_PUBKEY_CONTENT}" || {
        rm -f "${expect_script}"
        die "NixOS installation failed — check QEMU output above"
    }
    rm -f "${expect_script}"

    ok "NixOS image ready: ${out}"
}

# ── FreeBSD 15 bootstrap ───────────────────────────────────────────────────────
#
# FreeBSD 15.0 bootonly ISO requires network access to fetch packages.
# Default: download the official VM image directly from freebsd.org.
# With E2E_SKIP_ISO_INSTALL=0 and a disc1 ISO: use expect + bsdinstall.

bootstrap_freebsd15() {
    local out="${OUTPUT_IMG:-${GUEST_IMG_DIR}/freebsd15-amd64.img}"
    local qemu="qemu-system-x86_64"

    if [ "${E2E_SKIP_ISO_INSTALL}" != "0" ]; then
        info "E2E_SKIP_ISO_INSTALL=${E2E_SKIP_ISO_INSTALL} — using FreeBSD VM image instead of installer ISO"
        download_freebsd15_vm_image "${out}"
        return 0
    fi

    local iso
    iso="$(ensure_iso \
        "FreeBSD-15.0-RELEASE-amd64-disc1.iso" \
        "https://download.freebsd.org/releases/amd64/amd64/ISO-IMAGES/15.0/FreeBSD-15.0-RELEASE-amd64-disc1.iso" \
        "cc73a14d4b1cfada880b78deb0b94ae0f439167418c32a6708f68f79563cb50c")"

    command -v "${qemu}" >/dev/null 2>&1 || die "qemu-system-x86_64 not found"
    find_expect || die "expect not found — install it or set E2E_SKIP_ISO_INSTALL=1 to download instead"
    local firmware=""
    for candidate in \
        /opt/homebrew/share/qemu/edk2-x86_64-code.fd \
        /usr/local/share/qemu/edk2-x86_64-code.fd \
        /usr/share/qemu/edk2-x86_64-code.fd; do
        if [ -f "$candidate" ]; then firmware="$candidate"; break; fi
    done
    [ -n "$firmware" ] || die "x86_64 EDK2 firmware not found"

    ensure_ssh_key

    info "Bootstrapping FreeBSD 15.0 amd64 → ${out}"
    qemu-img create -f raw "${out}" "${DISK_SIZE_GB}G"

    local role_iso="${TMP_ROOT}/fractalos-mesh-controller-role.iso"
    make_cidata_iso "${REPO_ROOT}/guest/roles/mesh-controller" "${role_iso}"

    local expect_script
    expect_script="$(mktemp "${TMP_ROOT}/freebsd-install-XXXXXX.exp")"
    cat > "${expect_script}" << EXPECT_SCRIPT
#!/usr/bin/expect -f

set timeout 600
set out  [lindex \$argv 0]
set iso  [lindex \$argv 1]
set role [lindex \$argv 2]
set key  [lindex \$argv 3]
set firmware [lindex \$argv 4]

spawn qemu-system-x86_64 \\
    -machine q35 -m ${QEMU_MEM_MB} \\
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=\$firmware" \\
    -drive "file=\$iso,readonly=on,media=cdrom,format=raw" \\
    -drive "file=\$role,readonly=on,media=cdrom,format=raw,index=1" \\
    -drive "file=\$out,if=virtio,format=raw" \\
    -netdev user,id=net0 \\
    -device virtio-net-pci,netdev=net0 \\
    -display none -monitor none -serial stdio

# Wait for the FreeBSD boot menu
expect {
    timeout                     { puts "ERROR: FreeBSD did not boot"; exit 1 }
    "Welcome to FreeBSD"        { }
    "Booting FreeBSD"           { }
}
# Let autoboot timer expire (10s) or press Enter to boot immediately
sleep 12

# The serial installer asks for a terminal type before launching bsdinstall.
expect {
    timeout                     { puts "ERROR: console type prompt did not appear"; exit 1 }
    "Console type"              { send "\r" }
}

# Wait for bsdinstall main menu
expect {
    timeout                     { puts "ERROR: bsdinstall did not appear"; exit 1 }
    eof                         { puts "ERROR: FreeBSD exited before bsdinstall appeared"; exit 1 }
    -re {\x1b\[6n}              { send "\033\[24;80R"; exp_continue }
    "ive System"                { }
}

# Select the underlined Shell hotkey to drive installation programmatically.
sleep 1
send "s"
expect {
    "# "    { }
    eof     { puts "ERROR: FreeBSD exited before the installer shell opened"; exit 1 }
    timeout { puts "ERROR: Shell prompt not reached"; exit 1 }
}

# Run bsdinstall in scripted mode
send "set -x\r"
expect "# "
send "stty -echo\r"
expect "# "

# Partition with gpart
send "gpart create -s gpt vtbd0\r"
expect "# "
send "gpart add -t efi -s 100m vtbd0\r"
expect "# "
send "gpart add -t freebsd-swap -s 512m vtbd0\r"
expect "# "
send "gpart add -t freebsd-ufs vtbd0\r"
expect "# "

send "newfs_msdos -F 32 -c 1 /dev/vtbd0p1\r"
expect "# "
send "newfs -U /dev/vtbd0p3\r"
expect "# "

send "mount /dev/vtbd0p3 /mnt\r"
expect "# "
send "mkdir -p /mnt/boot/efi && mount_msdosfs /dev/vtbd0p1 /mnt/boot/efi\r"
expect "# "

# FreeBSD 15 release media ships pkgbase packages instead of base.txz/kernel.txz.
# Install from the disc's signed, offline repository into the mounted target.
puts "Installing FreeBSD pkgbase system..."
send "pkg --rootdir /mnt --repo-conf-dir /usr/freebsd-packages/repos -o IGNORE_OSVERSION=yes update && pkg --rootdir /mnt --repo-conf-dir /usr/freebsd-packages/repos -o IGNORE_OSVERSION=yes install -U -y -r FreeBSD-base FreeBSD-set-minimal FreeBSD-set-base pkg FreeBSD-kernel-generic && echo __FRACTALOS_PKGBASE_OK__\r"
set timeout 1200
expect {
    timeout                         { puts "ERROR: pkgbase installation timed out"; exit 1 }
    "__FRACTALOS_PKGBASE_OK__"        { expect "# " }
    "# "                            { puts "ERROR: pkgbase installation failed"; exit 1 }
}
set timeout 600
send "mkdir -p /mnt/usr/local/etc/pkg/repos && echo 'FreeBSD-base: { enabled: yes }' > /mnt/usr/local/etc/pkg/repos/FreeBSD.conf\r"
expect "# "

# Configure the installed system
send "echo 'hostname=\"freebsd-guest\"' > /mnt/etc/rc.conf\r"
expect "# "
send "echo 'sshd_enable=\"YES\"' >> /mnt/etc/rc.conf\r"
expect "# "
send "echo 'ifconfig_vtnet0=\"DHCP\"' >> /mnt/etc/rc.conf\r"
expect "# "
send "echo 'fractalos_mesh_firstboot_enable=\"YES\"' >> /mnt/etc/rc.conf\r"
expect "# "

# SSH configuration
send "echo 'PermitRootLogin yes' >> /mnt/etc/ssh/sshd_config\r"
expect "# "
send "echo 'PasswordAuthentication no' >> /mnt/etc/ssh/sshd_config\r"
expect "# "

# Inject SSH public key
send "mkdir -p /mnt/root/.ssh && chmod 700 /mnt/root/.ssh\r"
expect "# "
send "echo '\$key' > /mnt/root/.ssh/authorized_keys && chmod 600 /mnt/root/.ssh/authorized_keys\r"
expect "# "

# Stage the role now; its network-dependent installer runs once on first boot.
# The release medium is read-only, so use its memory-backed /tmp as mountpoint.
send "mkdir -p /tmp/fractalos-role /mnt/usr/local/share/fractalos/roles/mesh-controller /mnt/usr/local/etc/rc.d && mount_cd9660 /dev/cd1 /tmp/fractalos-role && cp -R /tmp/fractalos-role/. /mnt/usr/local/share/fractalos/roles/mesh-controller/ && install -m 0555 /tmp/fractalos-role/files/fractalos_mesh_firstboot.rc /mnt/usr/local/etc/rc.d/fractalos_mesh_firstboot && chmod 0555 /mnt/usr/local/share/fractalos/roles/mesh-controller/install.sh && umount /tmp/fractalos-role && echo __FRACTALOS_ROLE_STAGED_OK__\r"
expect {
    timeout                         { puts "ERROR: mesh-controller role staging timed out"; exit 1 }
    "__FRACTALOS_ROLE_STAGED_OK__"    { expect "# " }
    "# "                            { puts "ERROR: mesh-controller role staging failed"; exit 1 }
}

# Install the UEFI loader at both the FreeBSD and architecture fallback paths.
# The fallback path boots even when firmware NVRAM cannot be persisted by QEMU.
send "mkdir -p /mnt/boot/efi/efi/freebsd /mnt/boot/efi/efi/boot\r"
expect "# "
send "cp /mnt/boot/loader.efi /mnt/boot/efi/efi/freebsd/loader.efi && cp /mnt/boot/loader.efi /mnt/boot/efi/efi/boot/bootx64.efi && echo __FRACTALOS_BOOTLOADER_OK__\r"
expect {
    timeout                         { puts "ERROR: UEFI bootloader installation timed out"; exit 1 }
    "__FRACTALOS_BOOTLOADER_OK__"     { expect "# " }
    "# "                            { puts "ERROR: UEFI bootloader installation failed"; exit 1 }
}

# fstab
send "echo '/dev/vtbd0p3 / ufs rw 1 1' > /mnt/etc/fstab\r"
expect "# "
send "echo '/dev/vtbd0p2 none swap sw 0 0' >> /mnt/etc/fstab\r"
expect "# "
send "echo 'proc /proc procfs rw 0 0' >> /mnt/etc/fstab\r"
expect "# "

send "sync && umount /mnt/boot/efi /mnt\r"
expect "# "

send "poweroff\r"
puts "FreeBSD installation complete."
expect eof
exit 0
EXPECT_SCRIPT
    chmod +x "${expect_script}"

    info "Running FreeBSD automated install via expect (10-20 min)..."
    local install_attempt=1
    while ! "${EXPECT_BIN}" "${expect_script}" "${out}" "${iso}" "${role_iso}" "${SSH_PUBKEY_CONTENT}" "${firmware}"; do
        if [ "${install_attempt}" -ge 3 ]; then
            rm -f "${expect_script}"
            die "FreeBSD installation failed after ${install_attempt} attempts"
        fi
        install_attempt=$((install_attempt + 1))
        warn "FreeBSD installer attempt failed before completion; retrying (${install_attempt}/3)"
        qemu-img create -f raw "${out}" "${DISK_SIZE_GB}G"
    done
    rm -f "${expect_script}"

    ok "FreeBSD 15 image ready: ${out}"
}

# ── Dispatch ───────────────────────────────────────────────────────────────────

case "${OS}" in
    ubuntu-amd64)   bootstrap_ubuntu_amd64 ;;
    ubuntu-arm64)   bootstrap_ubuntu_arm64 ;;
    nixos)          bootstrap_nixos ;;
    freebsd15)      bootstrap_freebsd15 ;;
    *)
        die "Unknown OS target '${OS}'. Valid: ubuntu-amd64 ubuntu-arm64 nixos freebsd15"
        ;;
esac
