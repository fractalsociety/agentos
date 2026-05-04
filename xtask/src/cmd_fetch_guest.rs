use crate::{FetchGuestArgs, GuestOs};
use anyhow::Context;
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::Stdio;

const ISO_DIR_ENV: &str = "AGENTOS_ISO_DIR";
const COPY_ISOS_ENV: &str = "AGENTOS_COPY_ISOS";

const UBUNTU_VERSION: &str = "26.04";
const UBUNTU_ISO_NAME: &str = "ubuntu-26.04-desktop-arm64.iso";
const UBUNTU_ISO_URL: &str =
    "https://cdimage.ubuntu.com/releases/26.04/release/ubuntu-26.04-desktop-arm64.iso";
const UBUNTU_IMAGE_NAME: &str = "ubuntu-26.04-aarch64.iso";
const UBUNTU_KERNEL_NAME: &str = "ubuntu-26.04-aarch64-Image";
const UBUNTU_INITRD_NAME: &str = "ubuntu-26.04-aarch64-initrd";

const FREEBSD_VERSION: &str = "15.0";
const FREEBSD_ISO_NAME: &str = "FreeBSD-15.0-RELEASE-arm64-aarch64-dvd1.iso";
const FREEBSD_ISO_URL: &str =
    "https://download.freebsd.org/releases/arm64/aarch64/ISO-IMAGES/15.0/FreeBSD-15.0-RELEASE-arm64-aarch64-dvd1.iso";
const FREEBSD_IMAGE_NAME: &str = "freebsd-15.0-aarch64.iso";
const FREEBSD_KERNEL_NAME: &str = "freebsd-15.0-aarch64-kernel";

fn repo_root() -> anyhow::Result<PathBuf> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("failed to run git rev-parse")?;
    anyhow::ensure!(out.status.success(), "not in a git repository");
    let root = String::from_utf8(out.stdout)
        .context("git output not utf-8")?
        .trim()
        .to_string();
    Ok(PathBuf::from(root))
}

fn default_image_dir() -> anyhow::Result<PathBuf> {
    Ok(repo_root()?.join("build/guest-images"))
}

fn build_tmp_dir() -> anyhow::Result<PathBuf> {
    let dir = repo_root()?.join("build/tmp");
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    Ok(dir)
}

fn iso_dir_from_env(
    agentos_iso_dir: Option<OsString>,
    xdg_cache_home: Option<OsString>,
    home: Option<OsString>,
) -> PathBuf {
    if let Some(d) = agentos_iso_dir {
        return PathBuf::from(d);
    }
    let cache_root = xdg_cache_home
        .map(PathBuf::from)
        .or_else(|| home.map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    cache_root.join("agentos").join("isos")
}

fn iso_dir() -> PathBuf {
    iso_dir_from_env(
        std::env::var_os(ISO_DIR_ENV),
        std::env::var_os("XDG_CACHE_HOME"),
        std::env::var_os("HOME"),
    )
}

fn ensure_cached_iso(iso_name: &str, url: &str) -> anyhow::Result<PathBuf> {
    let cache = iso_dir();
    fs::create_dir_all(&cache)
        .with_context(|| format!("failed to create ISO cache dir: {}", cache.display()))?;
    let cached = cache.join(iso_name);
    if cached.exists() && fs::metadata(&cached).map(|m| m.len()).unwrap_or(0) > 0 {
        return Ok(cached);
    }

    let curl = find_tool(&["curl", "/opt/homebrew/bin/curl", "/usr/bin/curl"])?;
    let tmp = cached.with_extension("part");
    let _ = fs::remove_file(&tmp);
    println!("[fetch-guest] Downloading {} -> {}", url, cached.display());
    let status = std::process::Command::new(&curl)
        .arg("--fail")
        .arg("--location")
        .arg("--progress-bar")
        .arg("--output")
        .arg(&tmp)
        .arg(url)
        .status()
        .with_context(|| format!("failed to run {}", curl.display()))?;
    anyhow::ensure!(status.success(), "ISO download failed: {}", url);
    anyhow::ensure!(
        fs::metadata(&tmp).map(|m| m.len()).unwrap_or(0) > 0,
        "downloaded ISO is empty: {}",
        url
    );
    fs::rename(&tmp, &cached)
        .with_context(|| format!("failed to move {} to {}", tmp.display(), cached.display()))?;
    Ok(cached)
}

pub fn run(args: &FetchGuestArgs) -> anyhow::Result<()> {
    let output_dir = match &args.output_dir {
        Some(d) => PathBuf::from(d),
        None => default_image_dir()?,
    };
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed to create output dir: {}", output_dir.display()))?;

    match args.os {
        GuestOs::Ubuntu => fetch_ubuntu(&output_dir),
        GuestOs::Freebsd => fetch_freebsd(&output_dir),
    }
}

fn fetch_ubuntu(output_dir: &Path) -> anyhow::Result<()> {
    let iso = stage_local_iso(
        output_dir,
        UBUNTU_ISO_NAME,
        UBUNTU_IMAGE_NAME,
        UBUNTU_ISO_URL,
    )?;
    extract_ubuntu_initrd(&iso, &output_dir.join(UBUNTU_INITRD_NAME))?;
    extract_ubuntu_kernel(&iso, &output_dir.join(UBUNTU_KERNEL_NAME))?;
    println!(
        "[fetch-guest] Ubuntu {} assets ready under {}",
        UBUNTU_VERSION,
        output_dir.display()
    );
    Ok(())
}

fn extract_ubuntu_initrd(iso: &Path, initrd_dest: &Path) -> anyhow::Result<()> {
    if initrd_dest.exists() && fs::metadata(initrd_dest).map(|m| m.len()).unwrap_or(0) > 0 {
        println!(
            "[fetch-guest] Ubuntu E2E initrd already staged: {}",
            initrd_dest.display()
        );
        return Ok(());
    }

    let tmp_root = build_tmp_dir()?;
    let tmp_dir = tempfile::Builder::new()
        .prefix("agentos-ubuntu-initrd-")
        .tempdir_in(&tmp_root)
        .context("failed to create Ubuntu initrd tempdir under build/tmp")?;
    let full_initrd = tmp_dir.path().join("initrd.full");
    extract_iso_file(iso, "casper/initrd", &full_initrd)?;

    let full = fs::read(&full_initrd)
        .with_context(|| format!("failed to read {}", full_initrd.display()))?;
    let trailer =
        find_subslice(&full, b"TRAILER!!!").context("Ubuntu initrd missing first CPIO trailer")?;
    let tail_start = find_subslice_from(&full, b"\x28\xb5\x2f\xfd", trailer)
        .context("Ubuntu initrd missing zstd userspace payload")?;

    let minmods_dir = tmp_dir.path().join("minmods");
    fs::create_dir_all(&minmods_dir)
        .with_context(|| format!("failed to create {}", minmods_dir.display()))?;
    let entries = archive_entries(&full_initrd)?;
    let required_suffixes = [
        "kernel/fs/isofs/isofs.ko.zst",
        "kernel/fs/nls/nls_iso8859-1.ko.zst",
        "kernel/fs/overlayfs/overlay.ko.zst",
    ];
    for suffix in required_suffixes {
        let entry = entries
            .iter()
            .find(|entry| entry.ends_with(suffix))
            .with_context(|| format!("Ubuntu initrd missing required module {suffix}"))?;
        extract_archive_file(&full_initrd, entry, &minmods_dir.join(entry))?;
    }

    let minmods_cpio = tmp_dir.path().join("minmods.cpio");
    create_newc_archive(&minmods_dir, &minmods_cpio)?;

    let mut out = fs::read(&minmods_cpio)
        .with_context(|| format!("failed to read {}", minmods_cpio.display()))?;
    out.extend_from_slice(&full[tail_start..]);
    write_output(initrd_dest, &out)?;
    println!(
        "[fetch-guest] Built Ubuntu {} E2E initrd -> {}",
        UBUNTU_VERSION,
        initrd_dest.display()
    );
    Ok(())
}

fn fetch_freebsd(output_dir: &Path) -> anyhow::Result<()> {
    let iso = stage_local_iso(
        output_dir,
        FREEBSD_ISO_NAME,
        FREEBSD_IMAGE_NAME,
        FREEBSD_ISO_URL,
    )?;
    extract_freebsd_kernel(&iso, &output_dir.join(FREEBSD_KERNEL_NAME))?;
    println!(
        "[fetch-guest] FreeBSD {} assets ready under {}",
        FREEBSD_VERSION,
        output_dir.display()
    );
    Ok(())
}

fn archive_entries(archive: &Path) -> anyhow::Result<Vec<String>> {
    let out = std::process::Command::new("bsdtar")
        .arg("-tf")
        .arg(archive)
        .output()
        .context("failed to run bsdtar")?;
    anyhow::ensure!(
        out.status.success(),
        "bsdtar failed listing {}",
        archive.display()
    );
    let stdout = String::from_utf8(out.stdout).context("bsdtar listing was not utf-8")?;
    Ok(stdout.lines().map(|line| line.to_string()).collect())
}

fn extract_archive_file(archive: &Path, entry: &str, dest: &Path) -> anyhow::Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let out =
        fs::File::create(dest).with_context(|| format!("failed to create {}", dest.display()))?;
    let status = std::process::Command::new("bsdtar")
        .arg("-xOf")
        .arg(archive)
        .arg(entry)
        .stdout(Stdio::from(out))
        .status()
        .context("failed to run bsdtar")?;
    anyhow::ensure!(status.success(), "bsdtar failed extracting {entry}");
    Ok(())
}

fn create_newc_archive(input_dir: &Path, dest: &Path) -> anyhow::Result<()> {
    let out =
        fs::File::create(dest).with_context(|| format!("failed to create {}", dest.display()))?;
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg("find . | LC_ALL=C sort | cpio -o -H newc --quiet")
        .current_dir(input_dir)
        .stdout(Stdio::from(out))
        .status()
        .context("failed to run cpio")?;
    anyhow::ensure!(status.success(), "cpio failed creating {}", dest.display());
    Ok(())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    find_subslice_from(haystack, needle, 0)
}

fn find_subslice_from(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|idx| start + idx)
}

fn extract_freebsd_kernel(iso: &Path, kernel_dest: &Path) -> anyhow::Result<()> {
    if kernel_dest.exists() && fs::metadata(kernel_dest).map(|m| m.len()).unwrap_or(0) > 0 {
        println!(
            "[fetch-guest] FreeBSD kernel already extracted: {}",
            kernel_dest.display()
        );
        return Ok(());
    }

    let tmp_root = build_tmp_dir()?;
    let tmp_dir = tempfile::Builder::new()
        .prefix("agentos-freebsd-kernel-")
        .tempdir_in(&tmp_root)
        .context("failed to create FreeBSD kernel tempdir under build/tmp")?;
    let elf = tmp_dir.path().join("kernel.elf");
    let payload = tmp_dir.path().join("kernel.payload");
    extract_iso_file(iso, "boot/kernel/kernel", &elf)?;

    let objcopy = find_tool(&[
        "llvm-objcopy",
        "/opt/homebrew/opt/llvm/bin/llvm-objcopy",
        "/opt/homebrew/opt/llvm@22/bin/llvm-objcopy",
        "/opt/homebrew/opt/llvm@21/bin/llvm-objcopy",
        "/usr/local/opt/llvm/bin/llvm-objcopy",
        "/usr/bin/llvm-objcopy",
    ])?;
    let status = std::process::Command::new(&objcopy)
        .args(["-O", "binary"])
        .arg(&elf)
        .arg(&payload)
        .status()
        .with_context(|| format!("failed to run {}", objcopy.display()))?;
    anyhow::ensure!(status.success(), "{} failed", objcopy.display());

    let image_size = freebsd_arm64_image_size(&elf)?;
    let payload =
        fs::read(&payload).with_context(|| format!("failed to read {}", payload.display()))?;
    let mut image = vec![0u8; 0x800];
    wr32(&mut image, 0x00, 0x14000200); /* branch to first instruction at +0x800 */
    wr32(&mut image, 0x04, 0);
    wr64(&mut image, 0x08, 0); /* text_offset: loader places at RAM base */
    wr64(&mut image, 0x10, image_size);
    wr64(&mut image, 0x18, 0x8); /* flags used by FreeBSD arm64 kernel.bin */
    image[0x38..0x3c].copy_from_slice(b"ARMd");
    image.extend_from_slice(&payload);
    write_output(kernel_dest, &image)?;
    println!(
        "[fetch-guest] Built FreeBSD arm64 kernel.bin image -> {}",
        kernel_dest.display()
    );
    Ok(())
}

fn stage_local_iso(
    output_dir: &Path,
    source_name: &str,
    dest_name: &str,
    source_url: &str,
) -> anyhow::Result<PathBuf> {
    let dest = output_dir.join(dest_name);
    if staged_iso_ready(&dest)? {
        println!("[fetch-guest] ISO already staged: {}", dest.display());
        return Ok(dest);
    }

    let src = ensure_cached_iso(source_name, source_url)?;

    fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;

    if std::env::var(COPY_ISOS_ENV).ok().as_deref() == Some("1") {
        println!(
            "[fetch-guest] Copying {} -> {}",
            src.display(),
            dest.display()
        );
        fs::copy(&src, &dest)
            .with_context(|| format!("failed to copy {} to {}", src.display(), dest.display()))?;
    } else {
        println!(
            "[fetch-guest] Staging ISO symlink {} -> {}",
            dest.display(),
            src.display()
        );
        symlink_file(&src, &dest).with_context(|| {
            format!("failed to symlink {} to {}", dest.display(), src.display())
        })?;
    }

    Ok(dest)
}

fn staged_iso_ready(dest: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(dest) {
        Ok(_) => {
            if fs::metadata(dest).map(|m| m.len()).unwrap_or(0) > 0 {
                return Ok(true);
            }
            fs::remove_file(dest)
                .with_context(|| format!("failed to remove stale ISO stage {}", dest.display()))?;
            Ok(false)
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => {
            Err(err).with_context(|| format!("failed to inspect staged ISO {}", dest.display()))
        }
    }
}

#[cfg(unix)]
fn symlink_file(src: &Path, dest: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(src, dest)
}

#[cfg(not(unix))]
fn symlink_file(src: &Path, dest: &Path) -> std::io::Result<()> {
    fs::copy(src, dest).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_dir_prefers_explicit_agentos_iso_dir() {
        let dir = iso_dir_from_env(
            Some(OsString::from("/tmp/agentos-isos")),
            Some(OsString::from("/tmp/xdg-cache")),
            Some(OsString::from("/tmp/home")),
        );
        assert_eq!(dir, PathBuf::from("/tmp/agentos-isos"));
    }

    #[test]
    fn iso_dir_defaults_to_xdg_cache() {
        let dir = iso_dir_from_env(
            None,
            Some(OsString::from("/tmp/xdg-cache")),
            Some(OsString::from("/tmp/home")),
        );
        assert_eq!(dir, PathBuf::from("/tmp/xdg-cache/agentos/isos"));
    }

    #[test]
    fn iso_dir_defaults_to_home_cache_without_xdg() {
        let dir = iso_dir_from_env(None, None, Some(OsString::from("/tmp/home")));
        assert_eq!(dir, PathBuf::from("/tmp/home/.cache/agentos/isos"));
    }
}

fn extract_iso_file(iso: &Path, entry: &str, dest: &Path) -> anyhow::Result<()> {
    if dest.exists() && fs::metadata(dest).map(|m| m.len()).unwrap_or(0) > 0 {
        println!(
            "[fetch-guest] ISO member already extracted: {}",
            dest.display()
        );
        return Ok(());
    }

    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let tmp = dest.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let out =
        fs::File::create(&tmp).with_context(|| format!("failed to create {}", tmp.display()))?;

    println!("[fetch-guest] Extracting {} from {}", entry, iso.display());
    let status = std::process::Command::new("bsdtar")
        .arg("-xOf")
        .arg(iso)
        .arg(entry)
        .stdout(Stdio::from(out))
        .status()
        .context("failed to run bsdtar")?;
    anyhow::ensure!(status.success(), "bsdtar failed extracting {}", entry);
    anyhow::ensure!(
        fs::metadata(&tmp).map(|m| m.len()).unwrap_or(0) > 0,
        "extracted {} was empty",
        entry
    );
    fs::rename(&tmp, dest)
        .with_context(|| format!("failed to move {} to {}", tmp.display(), dest.display()))?;
    Ok(())
}

fn extract_ubuntu_kernel(iso: &Path, kernel_dest: &Path) -> anyhow::Result<()> {
    if kernel_dest.exists() && fs::metadata(kernel_dest).map(|m| m.len()).unwrap_or(0) > 0 {
        println!(
            "[fetch-guest] Ubuntu kernel already extracted: {}",
            kernel_dest.display()
        );
        return Ok(());
    }

    let tmp_root = build_tmp_dir()?;
    let tmp_dir = tempfile::Builder::new()
        .prefix("agentos-ubuntu-kernel-")
        .tempdir_in(&tmp_root)
        .context("failed to create Ubuntu kernel tempdir under build/tmp")?;
    let vmlinuz = tmp_dir.path().join("vmlinuz");
    extract_iso_file(iso, "casper/vmlinuz", &vmlinuz)?;
    decode_arm64_kernel(&vmlinuz, kernel_dest, tmp_dir.path())
}

fn decode_arm64_kernel(vmlinuz: &Path, kernel_dest: &Path, work_dir: &Path) -> anyhow::Result<()> {
    let bytes =
        fs::read(vmlinuz).with_context(|| format!("failed to read {}", vmlinuz.display()))?;

    if is_raw_arm64_image(&bytes) {
        write_output(kernel_dest, &bytes)?;
        println!(
            "[fetch-guest] Copied raw arm64 kernel Image -> {}",
            kernel_dest.display()
        );
        return Ok(());
    }

    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut gz = flate2::read::GzDecoder::new(&bytes[..]);
        let mut raw = Vec::new();
        gz.read_to_end(&mut raw)
            .context("failed to decompress gzip vmlinuz")?;
        anyhow::ensure!(
            is_raw_arm64_image(&raw),
            "gzip payload is not an arm64 Image"
        );
        write_output(kernel_dest, &raw)?;
        println!(
            "[fetch-guest] Decompressed gzip arm64 kernel Image -> {}",
            kernel_dest.display()
        );
        return Ok(());
    }

    if bytes.starts_with(b"MZ") {
        let linux_section = work_dir.join("vmlinuz.linux");
        let objcopy = find_tool(&[
            "llvm-objcopy",
            "/opt/homebrew/opt/llvm/bin/llvm-objcopy",
            "/opt/homebrew/opt/llvm@22/bin/llvm-objcopy",
            "/opt/homebrew/opt/llvm@21/bin/llvm-objcopy",
            "/usr/local/opt/llvm/bin/llvm-objcopy",
            "/usr/bin/llvm-objcopy",
        ])?;
        let status = std::process::Command::new(&objcopy)
            .arg("--dump-section")
            .arg(format!(".linux={}", linux_section.display()))
            .arg(vmlinuz)
            .status()
            .with_context(|| format!("failed to run {}", objcopy.display()))?;
        anyhow::ensure!(status.success(), "{} failed", objcopy.display());
        decode_zboot_payload(&linux_section, kernel_dest, work_dir)?;
        println!(
            "[fetch-guest] Extracted PE/zboot arm64 kernel Image -> {}",
            kernel_dest.display()
        );
        return Ok(());
    }

    anyhow::bail!(
        "{} is not a raw, gzip, or PE/zboot arm64 kernel",
        vmlinuz.display()
    );
}

fn decode_zboot_payload(
    section_path: &Path,
    kernel_dest: &Path,
    work_dir: &Path,
) -> anyhow::Result<()> {
    let section = fs::read(section_path)
        .with_context(|| format!("failed to read {}", section_path.display()))?;
    anyhow::ensure!(section.len() >= 32, "zboot section is too small");
    anyhow::ensure!(&section[4..8] == b"zimg", "missing arm64 zboot magic");

    let payload_off = u32::from_le_bytes(section[8..12].try_into().unwrap()) as usize;
    let payload_size = u32::from_le_bytes(section[12..16].try_into().unwrap()) as usize;
    let comp = &section[24..28];
    let payload_end = payload_off
        .checked_add(payload_size)
        .context("zboot payload size overflow")?;
    anyhow::ensure!(
        payload_end <= section.len(),
        "zboot payload exceeds section length"
    );
    let payload = &section[payload_off..payload_end];

    if comp == b"gzip" {
        let mut gz = flate2::read::GzDecoder::new(payload);
        let mut raw = Vec::new();
        gz.read_to_end(&mut raw)
            .context("failed to decompress zboot gzip payload")?;
        anyhow::ensure!(
            is_raw_arm64_image(&raw),
            "zboot gzip payload is not an arm64 Image"
        );
        write_output(kernel_dest, &raw)
    } else if comp == b"zstd" {
        let payload_path = work_dir.join("vmlinuz.linux.zst");
        fs::write(&payload_path, payload)
            .with_context(|| format!("failed to write {}", payload_path.display()))?;
        let tmp = kernel_dest.with_extension("tmp");
        let out = fs::File::create(&tmp)
            .with_context(|| format!("failed to create {}", tmp.display()))?;
        let zstd = find_tool(&[
            "zstd",
            "/opt/homebrew/bin/zstd",
            "/usr/local/bin/zstd",
            "/usr/bin/zstd",
        ])?;
        let status = std::process::Command::new(&zstd)
            .arg("-dc")
            .arg(&payload_path)
            .stdout(Stdio::from(out))
            .status()
            .with_context(|| format!("failed to run {}", zstd.display()))?;
        anyhow::ensure!(status.success(), "{} failed", zstd.display());
        let raw = fs::read(&tmp).with_context(|| format!("failed to read {}", tmp.display()))?;
        anyhow::ensure!(
            is_raw_arm64_image(&raw),
            "zboot zstd payload is not an arm64 Image"
        );
        fs::rename(&tmp, kernel_dest).with_context(|| {
            format!(
                "failed to move {} to {}",
                tmp.display(),
                kernel_dest.display()
            )
        })
    } else if comp == [0, 0, 0, 0] {
        write_output(kernel_dest, payload)
    } else {
        anyhow::bail!(
            "unsupported arm64 zboot compression tag {:?}",
            String::from_utf8_lossy(comp)
        );
    }
}

fn is_raw_arm64_image(bytes: &[u8]) -> bool {
    bytes.len() > 0x3c && &bytes[0x38..0x3c] == b"ARMd"
}

fn write_output(dest: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let tmp = dest.with_extension("tmp");
    fs::write(&tmp, bytes).with_context(|| format!("failed to write {}", tmp.display()))?;
    fs::rename(&tmp, dest)
        .with_context(|| format!("failed to move {} to {}", tmp.display(), dest.display()))?;
    Ok(())
}

fn freebsd_arm64_image_size(elf_path: &Path) -> anyhow::Result<u64> {
    let elf =
        fs::read(elf_path).with_context(|| format!("failed to read {}", elf_path.display()))?;
    anyhow::ensure!(elf.len() >= 64, "FreeBSD kernel ELF is too small");
    anyhow::ensure!(
        &elf[0..4] == b"\x7fELF",
        "FreeBSD kernel is not an ELF file"
    );
    anyhow::ensure!(
        elf[4] == 2 && elf[5] == 1,
        "FreeBSD kernel is not ELF64 little-endian"
    );

    let phoff = rd64(&elf, 32)? as usize;
    let phentsize = rd16(&elf, 54)? as usize;
    let phnum = rd16(&elf, 56)? as usize;
    anyhow::ensure!(phentsize >= 56, "unexpected ELF program header size");

    let mut base = u64::MAX;
    let mut end = 0u64;
    for idx in 0..phnum {
        let off = phoff
            .checked_add(
                idx.checked_mul(phentsize)
                    .context("ELF phdr offset overflow")?,
            )
            .context("ELF phdr offset overflow")?;
        anyhow::ensure!(
            off + phentsize <= elf.len(),
            "ELF program header is truncated"
        );
        let p_type = rd32(&elf, off)?;
        if p_type != 1 {
            continue;
        }
        let vaddr = rd64(&elf, off + 16)?;
        let memsz = rd64(&elf, off + 40)?;
        base = base.min(vaddr);
        end = end.max(vaddr.checked_add(memsz).context("ELF LOAD end overflow")?);
    }

    anyhow::ensure!(
        base != u64::MAX && end > base,
        "FreeBSD ELF has no LOAD segments"
    );
    Ok(align_up(end - base, 0x1000))
}

fn rd16(buf: &[u8], off: usize) -> anyhow::Result<u16> {
    anyhow::ensure!(off + 2 <= buf.len(), "read past end of buffer");
    Ok(u16::from_le_bytes(buf[off..off + 2].try_into().unwrap()))
}

fn rd32(buf: &[u8], off: usize) -> anyhow::Result<u32> {
    anyhow::ensure!(off + 4 <= buf.len(), "read past end of buffer");
    Ok(u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()))
}

fn rd64(buf: &[u8], off: usize) -> anyhow::Result<u64> {
    anyhow::ensure!(off + 8 <= buf.len(), "read past end of buffer");
    Ok(u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()))
}

fn wr32(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn wr64(buf: &mut [u8], off: usize, value: u64) {
    buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

fn find_tool(candidates: &[&str]) -> anyhow::Result<PathBuf> {
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.is_absolute() && path.exists() {
            return Ok(path);
        }

        if !candidate.contains('/') {
            let out = std::process::Command::new("sh")
                .args(["-c", &format!("command -v {}", candidate)])
                .output()
                .with_context(|| format!("failed to search for {}", candidate))?;
            if out.status.success() {
                let found = String::from_utf8(out.stdout)
                    .context("command -v output was not utf-8")?
                    .trim()
                    .to_string();
                if !found.is_empty() {
                    return Ok(PathBuf::from(found));
                }
            }
        }
    }

    anyhow::bail!("required tool not found; tried {:?}", candidates);
}
