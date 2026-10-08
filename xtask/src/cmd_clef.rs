use crate::clef_boot::Monitor;
use anyhow::{ensure, Context, Result};
use clap::Args;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::PathBuf, process::Command, time::Duration};

const REV: &str = "4a192915ef971886004b5b13294f2b4c7a7fc39d";
const NAME: &str = "Clef-Flash-Q4_K_M.gguf";
const SHA: &str = "fd3e90605e8103307dca37cb5a8cdb036267e2fe3cb2d908d80a8ceb9ec0638c";
const SIZE: u64 = 6_486_448_288;

#[derive(Args)]
pub struct ClefArgs {
    #[arg(value_parser = ["fetch", "fixture", "native", "toolchain", "stage"])]
    pub action: String,
    #[arg(long, default_value = "http://127.0.0.1:18081")]
    pub oracle: String,
    #[arg(long, default_value = "build/clef-native")]
    pub build_dir: PathBuf,
    #[arg(long, default_value_t = 3600)]
    pub timeout_secs: u64,
    /// Boot through UEFI/Limine and require the native framebuffer screen.
    #[arg(long)]
    pub firmware_display: bool,
    /// Existing UEFI-compatible kernel artifact; never patched by this tool.
    #[arg(long, requires = "firmware_display")]
    pub firmware_kernel: Option<PathBuf>,
    /// Negative display test: writable disposable model media must be refused.
    #[arg(long, requires = "firmware_display")]
    pub expect_model_failure: bool,
}
fn cache() -> Result<PathBuf> {
    Ok(std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or(PathBuf::from(std::env::var_os("HOME").context("HOME not set")?).join(".cache"))
        .join("agentos/clef-flash"))
}
fn verify(path: &std::path::Path) -> Result<()> {
    println!("Checking model size and SHA256: {}", path.display());
    let mut file = fs::File::open(path)?;
    ensure!(file.metadata()?.len() == SIZE, "Clef model size mismatch");
    let mut sha = Sha256::new();
    let mut buf = vec![0; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sha.update(&buf[..n]);
    }
    ensure!(
        format!("{:x}", sha.finalize()) == SHA,
        "Clef model SHA256 mismatch"
    );
    Ok(())
}
fn toolchain() -> Result<()> {
    let dir = cache()?;
    fs::create_dir_all(&dir)?;
    let sysroot = dir.join("rust-sysroot");
    let compiler = sysroot.join("bin/rustc");
    let target = sysroot.join("lib/rustlib/x86_64-unknown-linux-gnu/lib");
    let sources = sysroot.join("lib/rustlib/src/rust/library/Cargo.toml");
    if compiler.is_file() && target.is_dir() && sources.is_file() {
        let version = Command::new(&compiler).arg("--version").output()?;
        ensure!(
            version.status.success()
                && String::from_utf8(version.stdout)?.starts_with("rustc 1.98.1 "),
            "unexpected native compiler"
        );
        return Ok(());
    }
    for (name, sha, component) in [
        (
            "rustc-1.98.1-x86_64-unknown-linux-gnu",
            "e974f036b28565f37c0f3bd92ddefa809bee16c04f9dcf07b9ed96e05aaaf7c4",
            "rustc",
        ),
        (
            "rust-std-1.98.1-x86_64-unknown-linux-gnu",
            "fa3ff450172a16c026944030230c5069947af93c728d9179971d44e5e0cfb561",
            "rust-std-x86_64-unknown-linux-gnu",
        ),
        (
            "rust-src-1.98.1",
            "5c846ebcebcc7e2e0777a4cdaa12051691593f16a7e94edbae5e6241cc62d98c",
            "rust-src",
        ),
    ] {
        let archive = dir.join(format!("{name}.tar.xz"));
        if !archive.exists() {
            let part = dir.join(format!("{name}.download"));
            let file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&part)?;
            let status = Command::new("curl")
                .args(["--fail", "--location", "--retry", "3"])
                .arg(format!("https://static.rust-lang.org/dist/{name}.tar.xz"))
                .stdout(file)
                .status()?;
            ensure!(status.success(), "toolchain download failed");
            fs::rename(part, &archive)?;
        }
        ensure!(
            format!("{:x}", Sha256::digest(fs::read(&archive)?)) == sha,
            "toolchain archive checksum mismatch"
        );
        fs::create_dir_all(&sysroot)?;
        let mut cmd = Command::new("tar");
        cmd.arg("-xf")
            .arg(&archive)
            .arg("-C")
            .arg(&sysroot)
            .arg("--strip-components=2");
        cmd.arg(format!("{name}/{component}/lib"));
        if component == "rustc" {
            cmd.arg(format!("{name}/{component}/bin"));
        }
        ensure!(cmd.status()?.success(), "toolchain extraction failed");
    }
    println!("Native Rust 1.98.1 installed in {}", sysroot.display());
    Ok(())
}
fn fetch() -> Result<PathBuf> {
    let dir = cache()?;
    fs::create_dir_all(&dir)?;
    let path = dir.join(NAME);
    if !path.exists() {
        let part = dir.join(format!("{NAME}.download"));
        // create_new prevents concurrent writers and never overwrites a prior attempt.
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part)?;
        let status = Command::new("curl")
            .args(["--fail", "--location", "--retry", "3"])
            .arg(format!(
                "https://huggingface.co/ggml-org/Clef-Flash-GGUF/resolve/{REV}/{NAME}"
            ))
            .stdout(file)
            .status()?;
        ensure!(status.success(), "Clef download failed: {}", part.display());
        verify(&part)?;
        fs::rename(part, &path)?;
    } else {
        verify(&path)?;
    }
    println!("Verified {} SHA256={SHA}", path.display());
    Ok(path)
}
fn fixture(a: &ClefArgs) -> Result<()> {
    ensure!(
        a.oracle.starts_with("http://127.0.0.1:"),
        "oracle must be loopback"
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(600))
        .build()?;
    let state =
        "Available memory: 256 MiB. A task requests 512 MiB. Never exceed available memory.";
    let instruction = "Should the allocator grant or defer the request?";
    let options = [
        ("defer", "Wait for enough memory."),
        ("grant", "Allocate 512 MiB now."),
    ];
    let request = json!({"state":state,"questions":{"allocation":{"type":"choice","instructions":instruction,
        "criteria":{"defer":options[0].1,"grant":options[1].1}}}});
    let answer: Value = serde_json::from_str(
        &client
            .post(format!("{}/v1/systemone", a.oracle))
            .header("Content-Type", "application/json")
            .body(request.to_string())
            .send()?
            .error_for_status()?
            .text()?,
    )?;
    ensure!(
        answer["answers"]["allocation"]["choice"] == "defer",
        "reference did not defer oversized request: {answer}"
    );
    let mut tokens = Vec::<u32>::new();
    let mut append = |text: &str| -> Result<(usize, usize)> {
        let data: Value = serde_json::from_str(
            &client
                .post(format!("{}/tokenize", a.oracle))
                .header("Content-Type", "application/json")
                .body(json!({"content":text,"add_special":false,"parse_special":true}).to_string())
                .send()?
                .error_for_status()?
                .text()?,
        )?;
        let start = tokens.len();
        for v in data["tokens"].as_array().context("missing tokens")? {
            let t = v.as_u64().context("noninteger token")?;
            ensure!(t < 248320, "token out of range");
            tokens.push(t as u32);
        }
        Ok((start, tokens.len()))
    };
    append("<|im_start|>system\nRead the complete state and schema. Decide every field jointly. Each answer must be exactly one of that field's allowed options.<|im_end|>\n<|im_start|>user\nSTATE:\n")?;
    append(state)?;
    append("\n\nSCHEMA FIELDS:\n")?;
    append("\nFIELD 1\nID: allocation\nTYPE: choice\nINSTRUCTION: ")?;
    let q = append(instruction)?;
    append("\nALLOWED OPTIONS:\n")?;
    let mut spans = Vec::new();
    for (i, (id, description)) in options.iter().enumerate() {
        append(&format!("OPTION {}: ", i + 1))?;
        spans.push(append(&serde_json::to_string(
            &json!({"description":description,"option_id":id}),
        )?)?);
        append("\n")?;
    }
    append("END FIELD\n")?;
    append("\n<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\nJOINT SCHEMA DECISIONS:")?;
    ensure!(tokens.len() <= 512, "fixture exceeds native bound");
    ensure!(
        answer["usage"]["input_tokens"].as_u64() == Some(tokens.len() as u64),
        "reference prompt/token count differs: {} vs {}",
        answer["usage"],
        tokens.len()
    );
    let probabilities: Vec<f64> = options
        .iter()
        .map(|(id, _)| {
            answer["answers"]["allocation"]["probabilities"][id]
                .as_f64()
                .context("missing probability")
        })
        .collect::<Result<_>>()?;
    fs::create_dir_all("tests/fixtures")?;
    let mut header=format!("/* Generated by make clef-fixture using llama.cpp b11476; see JSON provenance. */\n#ifndef CLEF_RESOURCE_FIXTURE_H\n#define CLEF_RESOURCE_FIXTURE_H\n#include <platform/clef.h>\nstatic const clef_input clef_resource_input = {{\n .count={}, .options=2,\n .question={{{},{}}},\n .option={{{{{},{}}},{{{},{}}}}},\n .tokens={{\n",tokens.len(),q.0,q.1,spans[0].0,spans[0].1,spans[1].0,spans[1].1);
    for chunk in tokens.chunks(12) {
        header.push_str("  ");
        for t in chunk {
            header.push_str(&format!("{t},"));
        }
        header.push('\n');
    }
    header.push_str(&format!(" }}\n}};\nstatic const float clef_reference_probabilities[2] = {{{:.9}f,{:.9}f}};\n#endif\n",probabilities[0],probabilities[1]));
    fs::write("tests/fixtures/clef-resource-choice.h", header)?;
    fs::write(
        "tests/fixtures/clef-resource-choice.json",
        serde_json::to_string_pretty(&json!({
        "model_revision":REV,"model_sha256":SHA,"oracle":"ggml-org/llama.cpp b11476 CPU",
        "request":request,"reference_response":answer,"tokens":tokens,"question_span":q,"option_spans":spans,
        "absolute_probability_tolerance":0.02,"native_scope":"fixed text tokens; full 32-layer backbone and 6-layer joint head"}))?
            + "\n",
    )?;
    println!(
        "Wrote {}-token fixture; reference probabilities={probabilities:?}",
        tokens.len()
    );
    Ok(())
}
fn stage_firmware(build: &std::path::Path, kernel: &std::path::Path) -> Result<()> {
    let esp = build.join("boot-esp.img");
    fs::File::create(&esp)?.set_len(64 * 1024 * 1024)?;
    use std::io::Write;
    let mut partition = Command::new("sfdisk")
        .arg(&esp)
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    partition
        .stdin
        .take()
        .context("partition stdin")?
        .write_all(b"label: dos\nstart=2048, type=ef, bootable\n")?;
    ensure!(
        partition.wait()?.success(),
        "partition disposable boot image"
    );
    let fat = format!("{}@@1048576", esp.display());
    ensure!(
        Command::new("mkfs.vfat")
            .args(["-F", "32", "--offset", "2048"])
            .arg(&esp)
            .status()?
            .success(),
        "format disposable boot image"
    );
    ensure!(
        Command::new("mmd")
            .arg("-i")
            .arg(&fat)
            .args(["::/EFI", "::/EFI/BOOT"])
            .status()?
            .success(),
        "create boot directories"
    );
    let config = build.join("limine.conf");
    fs::write(&config,"timeout: 0\n/Fractal native boot\n    protocol: multiboot2\n    resolution: 1024x768x32\n    path: boot():/sel4.elf\n    module_path: boot():/root_task.elf\n")?;
    for (source, dest) in [
        (
            std::path::Path::new("/usr/share/limine/BOOTX64.EFI"),
            "::/EFI/BOOT/BOOTX64.EFI",
        ),
        (kernel, "::/sel4.elf"),
        (
            std::path::Path::new("/usr/share/limine/limine-bios.sys"),
            "::/limine-bios.sys",
        ),
        (build.join("root_task.elf").as_path(), "::/root_task.elf"),
        (config.as_path(), "::/limine.conf"),
    ] {
        ensure!(
            Command::new("mcopy")
                .arg("-i")
                .arg(&fat)
                .arg(source)
                .arg(dest)
                .status()?
                .success(),
            "stage boot file {dest}"
        );
    }
    fs::copy("/usr/share/edk2/x64/OVMF_VARS.4m.fd", build.join("vars.fd"))?;
    ensure!(
        Command::new("limine")
            .arg("bios-install")
            .arg(&esp)
            .status()?
            .success(),
        "install disposable boot sector"
    );
    Ok(())
}
fn capture_screen(build: &std::path::Path, name: &str) -> Result<()> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let mut socket = UnixStream::connect(build.join("display.qmp"))?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    fn receive(s: &mut UnixStream) -> Result<Value> {
        let mut bytes = Vec::new();
        loop {
            ensure!(bytes.len() < 65536, "oversized QMP reply");
            let mut b = [0];
            s.read_exact(&mut b)?;
            if b[0] == b'\n' {
                return Ok(serde_json::from_slice(&bytes)?);
            }
            bytes.push(b[0]);
        }
    }
    ensure!(
        receive(&mut socket)?.get("QMP").is_some(),
        "missing QMP greeting"
    );
    for (id, mut request) in [
        json!({"execute":"qmp_capabilities"}),
        json!({"execute":"screendump","arguments":{"filename":build.join(name)}}),
    ]
    .into_iter()
    .enumerate()
    {
        request["id"] = json!(id);
        writeln!(socket, "{request}")?;
        let mut completed = false;
        for _ in 0..32 {
            let reply = receive(&mut socket)?;
            if reply.get("event").is_some() {
                continue;
            }
            ensure!(
                reply["id"] == id && reply.get("return").is_some(),
                "QMP failed: {reply}"
            );
            completed = true;
            break;
        }
        ensure!(completed, "QMP event limit");
    }
    validate_screen_ppm(&fs::read(build.join(name))?, name == "ready.ppm")?;
    Ok(())
}
fn validate_screen_ppm(bytes: &[u8], ready: bool) -> Result<()> {
    let mut parts = bytes.splitn(4, |b| *b == b'\n');
    ensure!(parts.next() == Some(b"P6".as_slice()), "screen is not P6");
    let dimensions = std::str::from_utf8(parts.next().context("missing screen dimensions")?)?;
    let dims: Vec<usize> = dimensions
        .split_ascii_whitespace()
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        dims.len() == 2 && (640..=4096).contains(&dims[0]) && (320..=2160).contains(&dims[1]),
        "screen bounds"
    );
    ensure!(
        parts.next() == Some(b"255".as_slice()),
        "screen channel depth"
    );
    let data = parts.next().context("missing screen pixels")?;
    let (width, height) = (dims[0], dims[1]);
    ensure!(data.len() == width * height * 3, "screen byte count");
    let pixel = |x: usize, y: usize| {
        let at = (((height - 320) / 2 + y) * width + (width - 640) / 2 + x) * 3;
        &data[at..at + 3]
    };
    ensure!(
        pixel(298, 18) == [190; 3] && pixel(305, 25) == [190; 3] && pixel(312, 32) == [190; 3],
        "native emblem not visible"
    );
    if ready {
        ensure!(
            pixel(64, 190) == [230; 3] && pixel(575, 190) == [230; 3],
            "ready progress bar incomplete"
        );
    }
    Ok(())
}
fn native(a: &ClefArgs) -> Result<()> {
    let build = fs::canonicalize(&a.build_dir)?;
    let run_lock = build.join("native.lock");
    let _lock_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&run_lock)
        .context("native test already running (or remove stale native.lock after checking QEMU)")?;
    struct Lock(PathBuf);
    impl Drop for Lock {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let _lock = Lock(run_lock);
    let mut monitor = Monitor::new(&build)?;
    let receipt = build.join("receipt.json");
    if receipt.exists() {
        fs::remove_file(receipt)?;
    }
    let result = native_inner(a, &build, &mut monitor);
    if let Err(error) = &result {
        monitor.fail(&format!("{error:#}"))?;
    }
    result
}
fn native_inner(a: &ClefArgs, build: &std::path::Path, monitor: &mut Monitor) -> Result<()> {
    monitor.phase("verifying_model")?;
    let model = fetch()?;
    let sdk = std::env::var_os("SEL4_SDK")
        .map(PathBuf::from)
        .unwrap_or(cache()?.parent().unwrap().join("microkit-sdk-2.3.0"));
    let kernel = a
        .firmware_kernel
        .clone()
        .unwrap_or_else(|| sdk.join("board/x86_64_generic_vtx/debug/elf/sel4_32.elf"));
    ensure!(
        kernel.is_file(),
        "missing debug kernel {}",
        kernel.display()
    );
    let scratch = build.join("primary.img");
    monitor.phase("staging_media")?;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&scratch)?
        .set_len(128 * 1024 * 1024)?;
    // The verified immutable model is attached read-only. Round media using a
    // disposable sparse copy: virtio block capacity is measured in 512B units.
    let media = build.join("model.img");
    fs::copy(&model, &media)?;
    fs::OpenOptions::new()
        .write(true)
        .open(&media)?
        .set_len((SIZE + 4095) & !4095)?;
    let serial = build.join("serial.log");
    fs::File::create(&serial)?;
    let receipt = build.join("receipt.json");
    if receipt.exists() {
        fs::remove_file(&receipt)?;
    }
    let root_sha = format!(
        "{:x}",
        Sha256::digest(fs::read(build.join("root_task.elf"))?)
    );
    let pd_sha = format!(
        "{:x}",
        Sha256::digest(fs::read(build.join("fractal_native_probe.elf"))?)
    );
    let kernel_sha = format!("{:x}", Sha256::digest(fs::read(&kernel)?));
    let log = fs::File::create(build.join("qemu.log"))?;
    let mut command = Command::new("qemu-system-x86_64");
    command
        .args([
            "-machine",
            "q35",
            "-accel",
            "kvm",
            "-cpu",
            "host,invtsc=on,tsc-freq=2880000000",
            "-m",
            "12G",
            "-smp",
            "1",
            "-display",
            "none",
            "-monitor",
            "none",
            "-no-reboot",
        ])
        .arg("-serial")
        .arg(format!("file:{}", serial.display()))
        .arg("-serial")
        .arg(format!("file:{}", build.join("com2.log").display()))
        .arg("-drive")
        .arg(format!(
            "if=none,id=primary,format=raw,file={}",
            scratch.display()
        ))
        .args([
            "-device",
            "virtio-blk-pci,drive=primary,addr=0x5,disable-legacy=on",
            "-netdev",
            "user,id=net0,restrict=on",
            "-device",
            "virtio-net-pci,netdev=net0,addr=0x6,disable-legacy=on",
            "-device",
            "virtio-serial-pci,addr=0x7,disable-legacy=on",
        ])
        .arg("-drive")
        .arg(format!(
            "if=none,id=clef,format=raw,readonly={},file={}",
            if a.expect_model_failure { "off" } else { "on" },
            media.display()
        ))
        .args([
            "-device",
            "virtio-blk-pci,drive=clef,addr=0x8,disable-legacy=on",
        ])
        .stdout(log.try_clone()?)
        .stderr(log);
    if a.firmware_display {
        stage_firmware(build, &kernel)?;
        command
            .arg("-drive")
            .arg(format!(
                "if=pflash,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd"
            ))
            .arg("-drive")
            .arg(format!(
                "if=pflash,format=raw,file={}",
                build.join("vars.fd").display()
            ));
        command
            .arg("-drive")
            .arg(format!(
                "if=ide,format=raw,file={}",
                build.join("boot-esp.img").display()
            ))
            .arg("-qmp")
            .arg(format!(
                "unix:{},server=on,wait=off",
                build.join("display.qmp").display()
            ));
    } else {
        command
            .arg("-kernel")
            .arg(&kernel)
            .arg("-initrd")
            .arg(build.join("root_task.elf"));
    }
    monitor.phase("booting")?;
    let mut child = command.spawn()?;
    let start = std::time::Instant::now();
    let mut printed = 0;
    let mut captured_loading = false;
    let result = (|| -> Result<()> {
        loop {
            // PD debug output can interleave individual UTF-8 bytes during
            // boot. Keep raw byte offsets and decode lossily so one damaged
            // banner never hides the later ASCII inference result.
            let bytes = fs::read(&serial).unwrap_or_default();
            let output = String::from_utf8_lossy(&bytes);
            let progress = monitor.ingest(&bytes);
            if a.expect_model_failure && output.contains("CLEF_NATIVE_FAIL") {
                ensure!(
                    output.contains("CLEF_NATIVE_FAIL: expected read-only model media"),
                    "unexpected native failure"
                );
                ensure!(
                    !output.contains("CLEF_NATIVE_PASS") && !output.contains("CLEF backbone"),
                    "failed media reached inference"
                );
                if output.contains("BOOT_SCREEN_FAILURE_PRESENTED") {
                    capture_screen(build, "failure.ppm")?;
                    monitor.fail("expected refusal of writable model media")?;
                    return Ok(());
                }
            } else {
                progress?;
            }
            if bytes.len() > printed {
                print!("{}", String::from_utf8_lossy(&bytes[printed..]));
                printed = bytes.len();
            }
            ensure!(
                a.expect_model_failure || !output.contains("CLEF_NATIVE_FAIL"),
                "native Clef test failed"
            );
            ensure!(
                !output.contains("BOOT_DISPLAY_FAIL"),
                "native boot display failed"
            );
            if a.firmware_display
                && !captured_loading
                && output.contains("BOOT_DISPLAY_PRESENT")
                && output.contains("stage=backbone done=0")
            {
                capture_screen(build, "loading.ppm")?;
                captured_loading = true;
            }
            if !a.expect_model_failure
                && output.contains("CLEF_NATIVE_PASS")
                && (!a.firmware_display || output.contains("BOOT_SCREEN_READY_PRESENTED"))
            {
                validate_native_log(&output)?;
                if a.firmware_display {
                    capture_screen(build, "ready.ppm")?;
                }
                return Ok(());
            }
            ensure!(
                child.try_wait()?.is_none(),
                "QEMU exited before native inference passed"
            );
            ensure!(
                start.elapsed() < Duration::from_secs(a.timeout_secs),
                "native Clef timeout"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    })();
    let _ = child.kill();
    let _ = child.wait();
    result?;
    if !a.expect_model_failure {
        monitor.ready()?;
    }
    fs::write(
        receipt,
        serde_json::to_string_pretty(
            &json!({"status": if a.expect_model_failure { "EXPECTED_FAILURE" } else { "PASS" },
        "execution":"native seL4 EL0 PD on x86_64 QEMU/KVM; no guest","model_sha256":SHA,
        "engine":"Rust no_std, SSE2","root_task_sha256":root_sha,"inference_pd_sha256":pd_sha,"kernel_sha256":kernel_sha,
        "elapsed_seconds":start.elapsed().as_secs_f64(),"serial_log":serial,
        "firmware_display":a.firmware_display,"boot_status":monitor.summary(),
        "boot_display_sha256": if a.firmware_display { Some(format!("{:x}",Sha256::digest(fs::read(build.join("boot_display.elf"))?))) } else { None },
        "boot_renderer_sha256": if a.firmware_display { Some(format!("{:x}",Sha256::digest(fs::read(build.join("boot_screen.elf"))?))) } else { None },
        "scope":"fixed resource-choice prompt, full backbone and decision head; advisory only"}),
        )? + "\n",
    )?;
    Ok(())
}
fn validate_native_log(log: &str) -> Result<()> {
    crate::clef_boot::validate(log)?;
    ensure!(
        log.contains("CLEF_NATIVE_BEGIN: Rust no_std x86_64"),
        "missing Rust native start"
    );
    ensure!(!log.contains("CLEF_NATIVE_FAIL"), "native failure in log");
    for (stage, count) in [("backbone", 32), ("routing", 2), ("joint", 4)] {
        for i in 0..count {
            ensure!(
                log.lines()
                    .any(|line| line.trim_end() == format!("[clef_native] CLEF {stage} {i}")),
                "missing native {stage} layer {i}"
            );
        }
    }
    ensure!(
        log.contains("CLEF option=0 probability_ppm=")
            && log.contains("CLEF option=1 probability_ppm="),
        "missing native probabilities"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blank_or_truncated_capture_is_not_a_display_proof() {
        assert!(validate_screen_ppm(b"P6\n1024 768\n255\n", true).is_err());
        let mut image = b"P6\n640 320\n255\n".to_vec();
        image.resize(image.len() + 640 * 320 * 3, 0);
        assert!(validate_screen_ppm(&image, true).is_err());
    }
    #[test]
    fn rejects_marker_without_inference() {
        assert!(validate_native_log("CLEF_NATIVE_PASS").is_err());
        let mut log = String::from("CLEF_NATIVE_BEGIN: Rust no_std x86_64\n");
        log += &crate::clef_boot::tests::valid_trace();
        for (stage, n) in [("backbone", 32), ("routing", 2), ("joint", 4)] {
            for i in 0..n {
                log += &format!("[clef_native] CLEF {stage} {i}\r\n");
            }
        }
        log += "CLEF option=0 probability_ppm=904456\nCLEF option=1 probability_ppm=95543\n";
        assert!(validate_native_log(&log).is_ok());
        let mut interleaved = vec![0xe2, 0x95, b'\n'];
        interleaved.extend_from_slice(log.as_bytes());
        assert!(validate_native_log(&String::from_utf8_lossy(&interleaved)).is_ok());
        assert!(validate_native_log(&log.replace("CLEF backbone 17", "missing")).is_err());
        log += "CLEF_NATIVE_FAIL";
        assert!(validate_native_log(&log).is_err());
    }
}
pub fn run(a: &ClefArgs) -> Result<()> {
    match a.action.as_str() {
        "fetch" => fetch().map(|_| ()),
        "fixture" => fixture(a),
        "native" => native(a),
        "toolchain" => toolchain(),
        "stage" => stage_firmware(
            &fs::canonicalize(&a.build_dir)?,
            a.firmware_kernel
                .as_deref()
                .context("stage requires --firmware-kernel")?,
        ),
        _ => unreachable!(),
    }
}
