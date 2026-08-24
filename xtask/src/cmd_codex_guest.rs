//! Reproducible Linux initramfs containing the official OpenAI Codex CLI.
//!
//! The image intentionally contains no credential. Authentication is supplied
//! only at runtime after the guest networking and secret-broker paths exist.

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const CODEX_VERSION: &str = "0.149.1";
pub const OUTPUT_INITRD: &str = "agentos-codex-0.149.1-aarch64-initrd.cpio.gz";
pub const OUTPUT_MANIFEST: &str = "agentos-codex-0.149.1-aarch64.json";
const RECIPE_REVISION: u64 = 1;

const CODEX_PACKAGE_URL: &str =
    "https://registry.npmjs.org/@openai/codex/-/codex-0.149.1-linux-arm64.tgz";
const CODEX_PACKAGE_SHA256: &str =
    "81f6deb8a444e0b661bef85d5de894509efad76fc1dec4e82267659e145ff131";
const CODEX_BINARY_PATH: &str = "package/vendor/aarch64-unknown-linux-musl/bin/codex";
const CODEX_BINARY_SHA256: &str =
    "2447e3fef519401ff6d6e90759ab1bf66082da48966fc6e4fe9a77108f9c20d8";

const ROOTFS_ID: &str = "6dcd1debf64e6d69b178cd0f46b8c4ae7cebe2a5-rootfs.cpio.gz";
const ROOTFS_URL: &str =
    "https://trustworthy.systems/Downloads/libvmm/images/6dcd1debf64e6d69b178cd0f46b8c4ae7cebe2a5-rootfs.cpio.gz.tar.gz";
const ROOTFS_ARCHIVE_SHA256: &str =
    "aaba19854ba7b274e2dbe0e209b6e8430f3463ae429b0d79ff7ce80479abf1d9";

const CA_BUNDLE_URL: &str = "https://curl.se/ca/cacert-2025-12-02.pem";
const CA_BUNDLE_SHA256: &str = "f1407d974c5ed87d544bd931a278232e13925177e239fca370619aba63c757b4";

const CODEX_PACKAGE_ENV: &str = "AGENTOS_CODEX_PACKAGE";
const ROOTFS_ARCHIVE_ENV: &str = "AGENTOS_CODEX_BASE_ROOTFS";
const CA_BUNDLE_ENV: &str = "AGENTOS_CODEX_CA_BUNDLE";

#[derive(Serialize)]
struct Artifact<'a> {
    source: &'a str,
    sha256: &'a str,
}

#[derive(Serialize)]
struct OutputArtifact {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Serialize)]
struct Manifest<'a> {
    schema: &'a str,
    recipe_revision: u64,
    architecture: &'a str,
    codex_version: &'a str,
    codex_package: Artifact<'a>,
    codex_binary_sha256: &'a str,
    base_rootfs: Artifact<'a>,
    ca_bundle: Artifact<'a>,
    credential_policy: &'a str,
    workspace: &'a str,
    preflight_marker: &'a str,
    output: OutputArtifact,
}

pub fn fetch(output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;
    if std::env::var_os("AGENTOS_CODEX_REBUILD").is_none() && existing_output_ready(output_dir)? {
        println!(
            "[codex-guest] official Codex {} image already verified: {}",
            CODEX_VERSION,
            output_dir.join(OUTPUT_INITRD).display()
        );
        return Ok(());
    }
    let cache = output_dir.join(".codex-cache");
    fs::create_dir_all(&cache).with_context(|| format!("failed to create {}", cache.display()))?;

    let package = obtain_verified(
        CODEX_PACKAGE_ENV,
        CODEX_PACKAGE_URL,
        CODEX_PACKAGE_SHA256,
        &cache.join(format!("openai-codex-{CODEX_VERSION}-linux-arm64.tgz")),
    )?;
    let rootfs_archive = obtain_verified(
        ROOTFS_ARCHIVE_ENV,
        ROOTFS_URL,
        ROOTFS_ARCHIVE_SHA256,
        &cache.join(format!("{ROOTFS_ID}.tar.gz")),
    )?;
    let ca_bundle = obtain_verified(
        CA_BUNDLE_ENV,
        CA_BUNDLE_URL,
        CA_BUNDLE_SHA256,
        &cache.join("cacert-2025-12-02.pem"),
    )?;

    let codex = extract_tar_gz_member(&package, CODEX_BINARY_PATH)?;
    verify_bytes("Codex binary", &codex, CODEX_BINARY_SHA256)?;
    ensure_aarch64_static_elf(&codex)?;

    let base_rootfs = extract_tar_gz_suffix(&rootfs_archive, "/rootfs.cpio.gz")?;
    anyhow::ensure!(
        base_rootfs.starts_with(&[0x1f, 0x8b]),
        "base rootfs member is not gzip compressed"
    );
    let ca =
        fs::read(&ca_bundle).with_context(|| format!("failed to read {}", ca_bundle.display()))?;

    let overlay = build_overlay(&codex, &ca)?;
    let mut initrd = base_rootfs;
    initrd.extend_from_slice(&gzip_deterministic(&overlay)?);
    // The VMM reserves 0x50000000..0x5f000000 for initrd data.
    anyhow::ensure!(
        initrd.len() < 0x0f000000,
        "Codex initrd is too large for the 512 MiB guest layout: {} bytes",
        initrd.len()
    );

    let initrd_path = output_dir.join(OUTPUT_INITRD);
    write_atomic(&initrd_path, &initrd)?;
    let output_hash = sha256_bytes(&initrd);
    let manifest = Manifest {
        schema: "agentos.codex-guest.v1",
        recipe_revision: RECIPE_REVISION,
        architecture: "aarch64-linux-musl",
        codex_version: CODEX_VERSION,
        codex_package: Artifact {
            source: CODEX_PACKAGE_URL,
            sha256: CODEX_PACKAGE_SHA256,
        },
        codex_binary_sha256: CODEX_BINARY_SHA256,
        base_rootfs: Artifact {
            source: ROOTFS_URL,
            sha256: ROOTFS_ARCHIVE_SHA256,
        },
        ca_bundle: Artifact {
            source: CA_BUNDLE_URL,
            sha256: CA_BUNDLE_SHA256,
        },
        credential_policy: "runtime-only; no credential is stored in this image",
        workspace: "/workspace",
        preflight_marker: "AGENTOS_CODEX_PREFLIGHT",
        output: OutputArtifact {
            path: OUTPUT_INITRD.to_string(),
            sha256: output_hash,
            bytes: initrd.len() as u64,
        },
    };
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    manifest_bytes.push(b'\n');
    write_atomic(&output_dir.join(OUTPUT_MANIFEST), &manifest_bytes)?;

    println!(
        "[codex-guest] official Codex {} image ready: {} ({} bytes)",
        CODEX_VERSION,
        initrd_path.display(),
        initrd.len()
    );
    println!("[codex-guest] sha256={}", manifest.output.sha256);
    println!("[codex-guest] credential_policy=runtime-only");
    Ok(())
}

fn existing_output_ready(output_dir: &Path) -> Result<bool> {
    let initrd_path = output_dir.join(OUTPUT_INITRD);
    let manifest_path = output_dir.join(OUTPUT_MANIFEST);
    if !initrd_path.is_file() || !manifest_path.is_file() {
        return Ok(false);
    }
    let manifest: serde_json::Value = match fs::read(&manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))
        .and_then(|bytes| serde_json::from_slice(&bytes).context("invalid Codex guest manifest"))
    {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    if manifest.get("schema").and_then(|v| v.as_str()) != Some("agentos.codex-guest.v1")
        || manifest.get("recipe_revision").and_then(|v| v.as_u64()) != Some(RECIPE_REVISION)
        || manifest.get("codex_version").and_then(|v| v.as_str()) != Some(CODEX_VERSION)
        || manifest.get("codex_binary_sha256").and_then(|v| v.as_str()) != Some(CODEX_BINARY_SHA256)
    {
        return Ok(false);
    }
    let expected = manifest
        .pointer("/output/sha256")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if expected.len() != 64 {
        return Ok(false);
    }
    let bytes = fs::read(&initrd_path)
        .with_context(|| format!("failed to read {}", initrd_path.display()))?;
    Ok(sha256_bytes(&bytes) == expected)
}

fn obtain_verified(env_name: &str, url: &str, expected: &str, cache: &Path) -> Result<PathBuf> {
    if let Some(source) = std::env::var_os(env_name) {
        let path = PathBuf::from(source);
        verify_file(env_name, &path, expected)?;
        return Ok(path);
    }
    if cache.exists() && verify_file("cached artifact", cache, expected).is_ok() {
        return Ok(cache.to_path_buf());
    }

    println!("[codex-guest] downloading {url}");
    let response = reqwest::blocking::Client::builder()
        .user_agent("agentos-xtask/codex-guest-v1")
        .build()?
        .get(url)
        .send()
        .with_context(|| format!("failed to download {url}"))?
        .error_for_status()
        .with_context(|| format!("download returned an error for {url}"))?;
    let bytes = response.bytes()?.to_vec();
    verify_bytes(url, &bytes, expected)?;
    write_atomic(cache, &bytes)?;
    Ok(cache.to_path_buf())
}

fn verify_file(label: &str, path: &Path, expected: &str) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    verify_bytes(label, &bytes, expected)
}

fn verify_bytes(label: &str, bytes: &[u8], expected: &str) -> Result<()> {
    let actual = sha256_bytes(bytes);
    anyhow::ensure!(
        actual == expected,
        "{label} SHA-256 mismatch: expected {expected}, got {actual}"
    );
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn extract_tar_gz_member(archive_path: &Path, wanted: &str) -> Result<Vec<u8>> {
    let file = fs::File::open(archive_path)
        .with_context(|| format!("failed to open {}", archive_path.display()))?;
    let mut archive = tar::Archive::new(GzDecoder::new(file));
    for entry in archive.entries().context("failed to read tar entries")? {
        let mut entry = entry?;
        if entry.path()?.to_string_lossy() == wanted {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            return Ok(bytes);
        }
    }
    anyhow::bail!("missing {wanted} in {}", archive_path.display())
}

fn extract_tar_gz_suffix(archive_path: &Path, suffix: &str) -> Result<Vec<u8>> {
    let file = fs::File::open(archive_path)
        .with_context(|| format!("failed to open {}", archive_path.display()))?;
    let mut archive = tar::Archive::new(GzDecoder::new(file));
    for entry in archive.entries().context("failed to read tar entries")? {
        let mut entry = entry?;
        if entry.path()?.to_string_lossy().ends_with(suffix) {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            return Ok(bytes);
        }
    }
    anyhow::bail!("missing *{suffix} in {}", archive_path.display())
}

fn ensure_aarch64_static_elf(bytes: &[u8]) -> Result<()> {
    anyhow::ensure!(
        bytes.len() > 0x40 && &bytes[..4] == b"\x7fELF",
        "Codex is not ELF"
    );
    anyhow::ensure!(
        bytes[4] == 2 && bytes[5] == 1,
        "Codex is not ELF64 little-endian"
    );
    // e_machine is little-endian at ELF header offset 18; 183 is AArch64.
    anyhow::ensure!(
        u16::from_le_bytes([bytes[18], bytes[19]]) == 183,
        "Codex is not AArch64"
    );
    // A musl-static executable has no PT_INTERP. Parse the ELF64 program table.
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    anyhow::ensure!(phentsize >= 56, "Codex has an invalid ELF program table");
    for index in 0..phnum {
        let offset = phoff.saturating_add(index.saturating_mul(phentsize));
        anyhow::ensure!(
            offset + 4 <= bytes.len(),
            "Codex ELF program table is truncated"
        );
        let kind = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        anyhow::ensure!(
            kind != 3,
            "Codex unexpectedly requires a dynamic interpreter"
        );
    }
    Ok(())
}

fn build_overlay(codex: &[u8], ca_bundle: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(codex.len() + ca_bundle.len() + 16 * 1024);
    let mut ino = 1u32;
    for dir in [
        ".",
        "usr",
        "usr/local",
        "usr/local/bin",
        "etc",
        "etc/ssl",
        "etc/ssl/certs",
        "etc/network",
        "etc/init.d",
        "root",
        "workspace",
    ] {
        append_newc(&mut out, dir, ino, 0o040755, 2, &[])?;
        ino += 1;
    }
    append_newc(&mut out, "usr/local/bin/codex", ino, 0o100755, 1, codex)?;
    ino += 1;
    append_newc(
        &mut out,
        "etc/ssl/certs/ca-certificates.crt",
        ino,
        0o100444,
        1,
        ca_bundle,
    )?;
    ino += 1;
    append_newc(
        &mut out,
        "etc/network/interfaces",
        ino,
        0o100644,
        1,
        NETWORK_INTERFACES.as_bytes(),
    )?;
    ino += 1;
    append_newc(
        &mut out,
        "etc/init.d/S99codex-worker",
        ino,
        0o100755,
        1,
        PREFLIGHT_SCRIPT.as_bytes(),
    )?;
    ino += 1;
    append_newc(
        &mut out,
        "root/.profile",
        ino,
        0o100600,
        1,
        PROFILE.as_bytes(),
    )?;
    ino += 1;
    append_newc(
        &mut out,
        "workspace/AGENTS.md",
        ino,
        0o100644,
        1,
        WORKSPACE_AGENTS.as_bytes(),
    )?;
    ino += 1;
    append_newc(
        &mut out,
        "workspace/agent_health.sh",
        ino,
        0o100755,
        1,
        WORKSPACE_FIXTURE.as_bytes(),
    )?;
    ino += 1;
    append_newc(
        &mut out,
        "workspace/test.sh",
        ino,
        0o100755,
        1,
        WORKSPACE_TEST.as_bytes(),
    )?;
    ino += 1;
    append_newc(&mut out, "TRAILER!!!", ino, 0, 1, &[])?;
    Ok(out)
}

fn append_newc(
    out: &mut Vec<u8>,
    name: &str,
    ino: u32,
    mode: u32,
    nlink: u32,
    data: &[u8],
) -> Result<()> {
    let namesize = name.len() + 1;
    let filesize = u32::try_from(data.len()).context("initramfs entry too large")?;
    let header = format!(
        "070701{ino:08x}{mode:08x}{uid:08x}{gid:08x}{nlink:08x}{mtime:08x}{filesize:08x}{devmajor:08x}{devminor:08x}{rdevmajor:08x}{rdevminor:08x}{namesize:08x}{check:08x}",
        uid = 0u32,
        gid = 0u32,
        mtime = 0u32,
        devmajor = 0u32,
        devminor = 0u32,
        rdevmajor = 0u32,
        rdevminor = 0u32,
        check = 0u32,
    );
    anyhow::ensure!(header.len() == 110, "newc header length mismatch");
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    pad4(out);
    out.extend_from_slice(data);
    pad4(out);
    Ok(())
}

fn pad4(out: &mut Vec<u8>) {
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn gzip_deterministic(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("output path has no parent")?;
    fs::create_dir_all(parent)?;
    let tmp = path.with_extension("part");
    fs::write(&tmp, bytes).with_context(|| format!("failed to write {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("failed to move {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

const NETWORK_INTERFACES: &str = r#"auto lo
iface lo inet loopback

# Activated by the AgentOS network broker once virtio-net mediation is ready.
iface eth0 inet dhcp
"#;

const PROFILE: &str = r#"export HOME=/root
export CODEX_HOME=/run/codex
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
cd /workspace
"#;

const PREFLIGHT_SCRIPT: &str = r#"#!/bin/sh
export HOME=/root
export CODEX_HOME=/run/codex
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
mkdir -p /run/codex /workspace
chmod 0700 /run/codex
before="$(cut -d. -f1 /proc/uptime 2>/dev/null)"
version="$(/usr/local/bin/codex --version 2>&1)"
status=$?
after="$(cut -d. -f1 /proc/uptime 2>/dev/null)"
ram_kib="$(sed -n 's/^MemTotal:[[:space:]]*\([0-9]*\).*/\1/p' /proc/meminfo)"
printf 'AGENTOS_CODEX_PREFLIGHT status=%s version="%s" uptime_before_s=%s uptime_after_s=%s ram_kib=%s workspace=/workspace auth=runtime-only\n' "$status" "$version" "$before" "$after" "$ram_kib"
"#;

const WORKSPACE_AGENTS: &str = r#"# AgentOS guest fixture

Keep changes inside `/workspace`. Run `./test.sh` after modifying the fixture.
"#;

const WORKSPACE_FIXTURE: &str = r#"#!/bin/sh
# Deliberately incomplete fixture for the first live in-guest Codex task.
printf '{"agent":"codex","healthy":false}\n'
"#;

const WORKSPACE_TEST: &str = r#"#!/bin/sh
set -eu
./agent_health.sh | grep -q '"healthy":true'
printf 'PASS agent_health\n'
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_aarch64_elf_validation_rejects_non_elf() {
        assert!(ensure_aarch64_static_elf(b"not an elf").is_err());
    }

    #[test]
    fn overlay_is_deterministic_and_contains_no_credentials() {
        let codex = b"test-codex";
        let ca = b"test-ca";
        let one = build_overlay(codex, ca).unwrap();
        let two = build_overlay(codex, ca).unwrap();
        assert_eq!(one, two);
        assert!(one.windows(codex.len()).any(|window| window == codex));
        assert!(one
            .windows(b"AGENTOS_CODEX_PREFLIGHT".len())
            .any(|window| window == b"AGENTOS_CODEX_PREFLIGHT"));
        for forbidden in [b"OPENAI_API_KEY".as_slice(), b"auth.json", b"sk-"] {
            assert!(!one
                .windows(forbidden.len())
                .any(|window| window == forbidden));
        }
    }

    #[test]
    fn gzip_output_is_repeatable() {
        assert_eq!(
            gzip_deterministic(b"hello").unwrap(),
            gzip_deterministic(b"hello").unwrap()
        );
    }
}
