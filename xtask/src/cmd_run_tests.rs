use crate::RunTestsArgs;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapStatus {
    Pass,
    Fail(i32),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TargetPerfRecord {
    pub schema: u32,
    pub metric: String,
    pub unit: String,
    pub samples: u64,
    pub counter_hz: u64,
    pub min: u64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub max: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AgentResourceRecord {
    pub schema: u32,
    pub worker: String,
    pub private_committed_bytes: u64,
    pub private_limit_bytes: u64,
    pub shared_mapped_bytes: u64,
    pub target_low_bytes: u64,
    pub target_high_bytes: u64,
    pub shared_components: u64,
}

#[derive(Debug, Serialize)]
struct TargetPerfReport<'a> {
    schema: u32,
    board: &'a str,
    source: &'static str,
    metrics: &'a [TargetPerfRecord],
    resources: &'a [AgentResourceRecord],
}

#[derive(Debug, Deserialize)]
struct PerfThresholds {
    schema: u32,
    boards: BTreeMap<String, BTreeMap<String, MetricThreshold>>,
}

#[derive(Debug, Deserialize)]
struct MetricThreshold {
    #[serde(default)]
    min_samples: Option<u64>,
    #[serde(default)]
    p50_max: Option<u64>,
    #[serde(default)]
    p95_max: Option<u64>,
    #[serde(default)]
    p99_max: Option<u64>,
    #[serde(default)]
    max_max: Option<u64>,
}

#[derive(Debug)]
struct SerialEvent {
    line: String,
    received_at: Instant,
}

struct QemuTestProcess {
    child: std::process::Child,
    model_proxy: Option<std::process::Child>,
    exec_proxy: Option<std::process::Child>,
    mcp_proxy: Option<std::process::Child>,
    serial_events: Receiver<SerialEvent>,
    serial_reader: JoinHandle<()>,
    network_injector: Option<JoinHandle<()>>,
    network_injector_stop: Option<Arc<AtomicBool>>,
    network_wg_seen: Option<Arc<AtomicBool>>,
    network_frames_seen: Option<Arc<AtomicU64>>,
    network_last_frame: Option<Arc<Mutex<Vec<u8>>>>,
}

fn is_wireguard_ipv4_udp_frame(received: &[u8]) -> bool {
    if received.len() < 46 {
        return false;
    }
    let max_prefix = received.len().saturating_sub(46).min(16);
    (0..=max_prefix).any(|prefix| {
        received[prefix + 12..prefix + 14] == [0x08, 0x00]
            && received[prefix + 23] == 17
            && (received[prefix + 34..prefix + 36] == [0xca, 0x6c]
                || received[prefix + 36..prefix + 38] == [0xca, 0x6c])
            && matches!(received[prefix + 42], 1 | 2 | 4)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PerfBatchMarker {
    Begin {
        metric: String,
        calls: u64,
    },
    End {
        metric: String,
        calls: u64,
        errors: u64,
    },
}

#[derive(Default)]
struct PerfBatchTracker {
    active: BTreeMap<String, (Instant, u64)>,
    samples: BTreeMap<String, Vec<u64>>,
    errors: BTreeMap<String, u64>,
}

pub fn run(args: &RunTestsArgs) -> Result<()> {
    if let Some(input_log) = &args.input_log {
        let text = std::fs::read_to_string(input_log)
            .with_context(|| format!("failed to read {}", input_log.display()))?;
        if args.board == "qemu_virt_aarch64" {
            validate_boot_health(&text)?;
        }
        report_tap_result(&text, &args.board)?;
        return process_perf_records(&text, args, Vec::new());
    }

    let repo_root = repo_root()?;
    if !args.no_build {
        crate::cmd_test::run_make(
            &["sel4-test-image", &format!("BOARD={}", args.board)],
            &repo_root,
        )
        .context("seL4-target test image build failed")?;
    }

    let log_file = tempfile::NamedTempFile::new().context("failed to create temp log file")?;
    let log_path = log_file.path().to_path_buf();

    let mut qemu = spawn_qemu_test_image(&args.board, &repo_root, &log_path)
        .with_context(|| format!("failed to launch seL4-target TAP image for {}", args.board))?;

    let wait = wait_for_tap_done(
        Duration::from_secs(args.timeout_secs),
        &mut qemu.child,
        &qemu.serial_events,
    );

    let _ = qemu.child.kill();
    let _ = qemu.child.wait();
    if let Some(mut proxy) = qemu.model_proxy.take() {
        let _ = proxy.kill();
        let _ = proxy.wait();
    }
    if let Some(mut proxy) = qemu.exec_proxy.take() {
        let _ = proxy.kill();
        let _ = proxy.wait();
    }
    if let Some(mut proxy) = qemu.mcp_proxy.take() {
        let _ = proxy.kill();
        let _ = proxy.wait();
    }
    if let Some(stop) = qemu.network_injector_stop.take() {
        stop.store(true, Ordering::Release);
    }
    if let Some(injector) = qemu.network_injector.take() {
        let _ = injector.join();
    }
    let mut network_wg_seen = qemu
        .network_wg_seen
        .as_ref()
        .map(|seen| seen.load(Ordering::Acquire));
    let network_frames_seen = qemu
        .network_frames_seen
        .as_ref()
        .map(|count| count.load(Ordering::Acquire));
    let network_last_frame = qemu.network_last_frame.as_ref().and_then(|frame| {
        frame.lock().ok().map(|bytes| {
            if is_wireguard_ipv4_udp_frame(&bytes) {
                network_wg_seen = Some(true);
            }
            bytes
                .iter()
                .take(64)
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join("")
        })
    });
    let _ = qemu.serial_reader.join();

    let text = std::fs::read_to_string(&log_path).unwrap_or_default();
    println!("\n=== Serial output ===");
    print!("{}", text);
    println!("=====================\n");

    let measured_records = wait?;
    if args.board == "qemu_virt_aarch64" {
        anyhow::ensure!(
            network_wg_seen == Some(true),
            "target fixture observed no outbound WireGuard IPv4/UDP frame ({} total Ethernet datagrams received; last={})",
            network_frames_seen.unwrap_or(0),
            network_last_frame.as_deref().unwrap_or("none")
        );
    }
    if args.board == "qemu_virt_aarch64" {
        validate_boot_health(&text)?;
    }
    report_tap_result(&text, &args.board)?;
    process_perf_records(&text, args, measured_records)
}

pub fn validate_boot_health(output: &str) -> Result<()> {
    anyhow::ensure!(
        !output.contains("[rt] FAULT"),
        "target emitted an unexpected root-task fault report"
    );
    anyhow::ensure!(
        !output.contains("ns_register: nameserver not found"),
        "controller could not reach its boot-provided NameServer capability"
    );

    let marker = output
        .lines()
        .find_map(|line| {
            line.find("FRACTALOS_BOOT_HEALTH ")
                .map(|start| &line[start + "FRACTALOS_BOOT_HEALTH ".len()..])
        })
        .context("target emitted no FRACTALOS_BOOT_HEALTH record")?;
    let mut registered = None;
    let mut disabled = None;
    let mut failed = None;
    for field in marker.split_whitespace() {
        if let Some(value) = field.strip_prefix("ns_registered=") {
            registered = value.parse::<u32>().ok();
        } else if let Some(value) = field.strip_prefix("ns_disabled=") {
            disabled = value.parse::<u32>().ok();
        } else if let Some(value) = field.strip_prefix("ns_failed=") {
            failed = value.parse::<u32>().ok();
        }
    }
    let registered = registered.context("boot health omitted ns_registered")?;
    let _disabled = disabled.context("boot health omitted ns_disabled")?;
    let failed = failed.context("boot health omitted ns_failed")?;
    anyhow::ensure!(registered > 0u32, "boot health registered no services");
    anyhow::ensure!(
        failed == 0u32,
        "boot health reported {failed} failed registrations"
    );
    Ok(())
}

pub fn parse_perf_records(output: &str) -> Result<Vec<TargetPerfRecord>> {
    output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("PERF_JSON:"))
        .map(|json| serde_json::from_str(json).context("invalid PERF_JSON record"))
        .collect()
}

pub fn parse_agent_resource_records(output: &str) -> Result<Vec<AgentResourceRecord>> {
    output
        .lines()
        // Several protection domains share the debug UART. A concurrent writer
        // can prefix a valid record before the resource marker reaches the host,
        // so locate the self-delimiting marker instead of requiring column zero.
        .filter_map(|line| {
            line.find("AGENT_RESOURCE_JSON:")
                .map(|start| &line[start + 20..])
        })
        .map(|json| serde_json::from_str(json).context("invalid AGENT_RESOURCE_JSON record"))
        .collect()
}

fn process_perf_records(
    output: &str,
    args: &RunTestsArgs,
    mut measured_records: Vec<TargetPerfRecord>,
) -> Result<()> {
    let mut records = parse_perf_records(output)?;
    let resources = parse_agent_resource_records(output)?;
    records.append(&mut measured_records);
    if args.require_perf {
        anyhow::ensure!(!records.is_empty(), "target emitted no PERF_JSON records");
    }
    for record in &records {
        anyhow::ensure!(
            record.schema == 1,
            "unsupported PERF_JSON schema {}",
            record.schema
        );
        anyhow::ensure!(
            record.errors == 0,
            "{} reported {} errors",
            record.metric,
            record.errors
        );
    }
    for resource in &resources {
        anyhow::ensure!(
            resource.schema == 1,
            "unsupported AGENT_RESOURCE_JSON schema {}",
            resource.schema
        );
        anyhow::ensure!(
            resource.private_committed_bytes <= resource.private_limit_bytes,
            "{} private memory {} exceeds limit {}",
            resource.worker,
            resource.private_committed_bytes,
            resource.private_limit_bytes
        );
        anyhow::ensure!(
            resource.private_limit_bytes <= resource.target_high_bytes,
            "{} private limit {} exceeds target ceiling {}",
            resource.worker,
            resource.private_limit_bytes,
            resource.target_high_bytes
        );
    }

    if let Some(path) = &args.perf_thresholds {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read performance thresholds {}", path.display()))?;
        let thresholds: PerfThresholds = serde_json::from_str(&text)
            .with_context(|| format!("invalid performance thresholds {}", path.display()))?;
        apply_thresholds(&records, &args.board, &thresholds)?;
    }

    if let Some(path) = &args.perf_output {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let report = TargetPerfReport {
            schema: 1,
            board: &args.board,
            source: "sel4-target-qemu",
            metrics: &records,
            resources: &resources,
        };
        std::fs::write(path, serde_json::to_vec_pretty(&report)?)
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "[xtask:run-tests] wrote target performance report: {}",
            path.display()
        );
    }
    Ok(())
}

fn apply_thresholds(
    records: &[TargetPerfRecord],
    board: &str,
    thresholds: &PerfThresholds,
) -> Result<()> {
    anyhow::ensure!(
        thresholds.schema == 1,
        "unsupported threshold schema {}",
        thresholds.schema
    );
    let board_thresholds = thresholds
        .boards
        .get(board)
        .with_context(|| format!("no performance thresholds configured for board {board}"))?;
    for (metric, threshold) in board_thresholds {
        let record = records
            .iter()
            .find(|record| &record.metric == metric)
            .with_context(|| format!("target did not emit required metric {metric}"))?;
        if let Some(minimum) = threshold.min_samples {
            anyhow::ensure!(
                record.samples >= minimum,
                "{metric} samples {} below minimum {minimum}",
                record.samples
            );
        }
        for (name, actual, limit) in [
            ("p50", record.p50, threshold.p50_max),
            ("p95", record.p95, threshold.p95_max),
            ("p99", record.p99, threshold.p99_max),
            ("max", record.max, threshold.max_max),
        ] {
            if let Some(limit) = limit {
                anyhow::ensure!(
                    actual <= limit,
                    "{metric} {name} regression: {actual} {} exceeds {limit}",
                    record.unit
                );
            }
        }
    }
    Ok(())
}

fn parse_perf_batch_marker(line: &str) -> Result<Option<PerfBatchMarker>> {
    let line = line.trim();
    if let Some(rest) = line.strip_prefix("PERF_BATCH_BEGIN:") {
        let Some((metric, calls)) = rest.rsplit_once(':') else {
            return Ok(None);
        };
        anyhow::ensure!(!metric.is_empty(), "empty performance metric name");
        let Ok(calls) = calls.parse() else {
            return Ok(None);
        };
        return Ok(Some(PerfBatchMarker::Begin {
            metric: metric.to_string(),
            calls,
        }));
    }
    if let Some(rest) = line.strip_prefix("PERF_BATCH_END:") {
        let mut fields = rest.rsplitn(3, ':');
        let (Some(errors), Some(calls), Some(metric)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return Ok(None);
        };
        anyhow::ensure!(!metric.is_empty(), "empty performance metric name");
        let (Ok(calls), Ok(errors)) = (calls.parse(), errors.parse()) else {
            return Ok(None);
        };
        return Ok(Some(PerfBatchMarker::End {
            metric: metric.to_string(),
            calls,
            errors,
        }));
    }
    Ok(None)
}

impl PerfBatchTracker {
    fn observe(&mut self, marker: PerfBatchMarker, at: Instant) -> Result<()> {
        match marker {
            PerfBatchMarker::Begin { metric, calls } => {
                anyhow::ensure!(calls > 0, "{metric} performance batch has zero calls");
                // A shared debug UART can splice another PD's output into a
                // marker. A new intact BEGIN supersedes any partial batch.
                self.active.insert(metric, (at, calls));
            }
            PerfBatchMarker::End {
                metric,
                calls,
                errors,
            } => {
                let Some((started_at, started_calls)) = self.active.remove(&metric) else {
                    // Its BEGIN marker was interleaved. The minimum-sample
                    // threshold still prevents a noisy run from passing.
                    return Ok(());
                };
                anyhow::ensure!(
                    calls == started_calls,
                    "{metric} batch call count changed from {started_calls} to {calls}"
                );
                let elapsed_ns = at.saturating_duration_since(started_at).as_nanos();
                anyhow::ensure!(elapsed_ns > 0, "{metric} batch duration was zero");
                let ns_per_call = u64::try_from(elapsed_ns / u128::from(calls))
                    .context("performance batch duration overflow")?;
                self.samples
                    .entry(metric.clone())
                    .or_default()
                    .push(ns_per_call);
                *self.errors.entry(metric).or_default() += errors;
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<TargetPerfRecord>> {
        // A final partial marker is treated like any other UART-corrupted
        // batch; per-board min_samples determines whether evidence suffices.
        let mut records = Vec::with_capacity(self.samples.len());
        for (metric, values) in &mut self.samples {
            values.sort_unstable();
            let percentile = |percent: usize| {
                let rank = (values.len() * percent).div_ceil(100).max(1);
                values[rank - 1]
            };
            records.push(TargetPerfRecord {
                schema: 1,
                metric: metric.clone(),
                unit: "ns/op".to_string(),
                samples: values.len() as u64,
                counter_hz: 1_000_000_000,
                min: values[0],
                p50: percentile(50),
                p95: percentile(95),
                p99: percentile(99),
                max: *values.last().expect("non-empty performance samples"),
                errors: self.errors.get(metric).copied().unwrap_or_default(),
            });
        }
        Ok(records)
    }
}

fn repo_root() -> Result<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("failed to run git rev-parse")?;
    anyhow::ensure!(output.status.success(), "not in a git repository");
    let root = String::from_utf8(output.stdout)
        .context("git output is not utf-8")?
        .trim()
        .to_string();
    Ok(PathBuf::from(root))
}

fn spawn_qemu_test_image(
    board: &str,
    repo_root: &Path,
    log_path: &Path,
) -> Result<QemuTestProcess> {
    let log_file = std::fs::File::create(log_path).context("failed to create QEMU log file")?;
    let build_dir = repo_root.join("build").join(format!("{board}-test"));
    let model_socket_path = log_path.with_extension("model.sock");
    let exec_socket_path = log_path.with_extension("exec.sock");
    let mcp_socket_path = log_path.with_extension("mcp.sock");
    let mut network_fixture = None;

    let mut cmd = match board {
        "qemu_virt_aarch64" => {
            let injector = std::net::UdpSocket::bind("127.0.0.1:0")
                .context("failed to bind target-test Ethernet injector")?;
            let injector_port = injector
                .local_addr()
                .context("failed to inspect target-test injector address")?
                .port();
            let qemu_port_probe = std::net::UdpSocket::bind("127.0.0.1:0")
                .context("failed to reserve target-test QEMU network port")?;
            let qemu_port = qemu_port_probe
                .local_addr()
                .context("failed to inspect target-test QEMU network address")?
                .port();
            drop(qemu_port_probe);
            network_fixture = Some((injector, qemu_port));
            let mut c = std::process::Command::new("qemu-system-aarch64");
            c.arg("-machine")
                .arg("virt,virtualization=on,highmem=off,secure=off")
                .arg("-cpu")
                .arg("cortex-a57")
                .arg("-m")
                .arg("2G")
                .arg("-display")
                .arg("none")
                .arg("-monitor")
                .arg("none")
                .arg("-serial")
                .arg("stdio")
                .arg("-global")
                .arg("virtio-mmio.force-legacy=off")
                .arg("-device")
                .arg(format!(
                    "loader,file={},cpu-num=0",
                    build_dir.join("loader.elf").display()
                ))
                .arg("-device")
                .arg(format!(
                    "loader,file={},addr=0x48000000",
                    build_dir.join("fractalos.img").display()
                ))
                .arg("-netdev")
                .arg(format!(
                    "socket,id=fractalos_test_net,udp=127.0.0.1:{injector_port},localaddr=127.0.0.1:{qemu_port}"
                ))
                .arg("-device")
                .arg("virtio-net-device,netdev=fractalos_test_net,bus=virtio-mmio-bus.0,ctrl_vq=off,ctrl_rx=off,ctrl_vlan=off,guest_announce=off,mq=off,ctrl_mac_addr=off,ctrl_guest_offloads=off");
            if std::env::var_os("FRACTALOS_LIVE_MODEL_TEST").is_some() {
                c.arg("-chardev")
                    .arg(format!(
                        "socket,id=model_pd_char,path={},server=on,wait=off",
                        model_socket_path.display()
                    ))
                    .arg("-device")
                    .arg("virtio-serial-device,bus=virtio-mmio-bus.3,id=vser_model")
                    .arg("-device")
                    .arg("virtconsole,bus=vser_model.0,chardev=model_pd_char,name=model.0");
                c.arg("-chardev")
                    .arg(format!(
                        "socket,id=exec_pd_char,path={},server=on,wait=off",
                        exec_socket_path.display()
                    ))
                    .arg("-device")
                    .arg("virtio-serial-device,bus=virtio-mmio-bus.8,id=vser_exec")
                    .arg("-device")
                    .arg("virtconsole,bus=vser_exec.0,chardev=exec_pd_char,name=exec.0");
            }
            c.arg("-chardev")
                .arg(format!(
                    "socket,id=mcp_pd_char,path={},server=on,wait=off",
                    mcp_socket_path.display()
                ))
                .arg("-device")
                .arg("virtio-serial-device,bus=virtio-mmio-bus.16,id=vser_mcp")
                .arg("-device")
                .arg("virtconsole,bus=vser_mcp.0,chardev=mcp_pd_char,name=mcp.0");
            c
        }
        "x86_64_generic" => {
            let kernel =
                repo_root.join("microkit-sdk-2.1.0/board/x86_64_generic/release/elf/sel4_32.elf");
            let mut c = std::process::Command::new("qemu-system-x86_64");
            c.arg("-machine")
                .arg("q35")
                .arg("-cpu")
                .arg("max")
                .arg("-m")
                .arg("2G")
                .arg("-display")
                .arg("none")
                .arg("-monitor")
                .arg("none")
                .arg("-serial")
                .arg("stdio")
                .arg("-kernel")
                .arg(kernel)
                .arg("-initrd")
                .arg(build_dir.join("root_task.elf"));
            c
        }
        other => anyhow::bail!(
            "unknown board: {} -- add QEMU invocation to cmd_run_tests.rs",
            other
        ),
    };

    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(log_file)
        .process_group(0)
        .spawn()
        .context("failed to spawn QEMU")?;
    println!("[xtask:run-tests] QEMU pid={}", child.id());
    let network_injector_stop = network_fixture
        .as_ref()
        .map(|_| Arc::new(AtomicBool::new(false)));
    let network_wg_seen = network_fixture
        .as_ref()
        .map(|_| Arc::new(AtomicBool::new(false)));
    let network_frames_seen = network_fixture
        .as_ref()
        .map(|_| Arc::new(AtomicU64::new(0)));
    let network_last_frame = network_fixture
        .as_ref()
        .map(|_| Arc::new(Mutex::new(Vec::new())));
    let network_injector = network_fixture.map(|(socket, qemu_port)| {
        let stop = Arc::clone(network_injector_stop.as_ref().expect("stop flag"));
        let wg_seen = Arc::clone(network_wg_seen.as_ref().expect("WG observation flag"));
        let frames_seen = Arc::clone(
            network_frames_seen
                .as_ref()
                .expect("Ethernet observation counter"),
        );
        let last_frame = Arc::clone(
            network_last_frame
                .as_ref()
                .expect("Ethernet observation sample"),
        );
        std::thread::spawn(move || {
            let destination = (std::net::Ipv4Addr::LOCALHOST, qemu_port);
            let mut frame = [0u8; 60];
            frame[..6].fill(0xff);
            frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x7f]);
            frame[12..14].copy_from_slice(&[0x88, 0xb5]);
            let _ = socket.set_nonblocking(true);
            let mut received = [0u8; 2048];
            loop {
                if !stop.load(Ordering::Acquire) {
                    let _ = socket.send_to(&frame, destination);
                }
                while let Ok((len, _)) = socket.recv_from(&mut received) {
                    frames_seen.fetch_add(1, Ordering::Relaxed);
                    if let Ok(mut sample) = last_frame.lock() {
                        sample.clear();
                        sample.extend_from_slice(&received[..len]);
                    }
                    if is_wireguard_ipv4_udp_frame(&received[..len]) {
                        wg_seen.store(true, Ordering::Release);
                    }
                }
                if stop.load(Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })
    });
    let model_proxy = if std::env::var_os("FRACTALOS_LIVE_MODEL_TEST").is_some() {
        let bridge_url = std::env::var("FRACTALOS_MODEL_BRIDGE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8790/v1/chat/completions".to_string());
        let mut command = std::process::Command::new("python3");
        command
            .arg(repo_root.join("tools/model_transport_proxy.py"))
            .arg("--socket")
            .arg(&model_socket_path)
            .arg("--bridge-url")
            .arg(bridge_url)
            .stdout(Stdio::null());
        if std::env::var_os("FRACTALOS_MODEL_TRANSPORT_TRACE").is_some() {
            command.arg("--trace");
        }
        let proxy = command
            .spawn()
            .context("failed to spawn native model transport proxy")?;
        println!("[xtask:run-tests] model transport proxy pid={}", proxy.id());
        Some(proxy)
    } else {
        None
    };
    let exec_proxy = if std::env::var_os("FRACTALOS_LIVE_MODEL_TEST").is_some() {
        let mut command = std::process::Command::new("python3");
        command
            .arg(repo_root.join("tools/exec_transport_proxy.py"))
            .arg("--socket")
            .arg(&exec_socket_path)
            .arg("--repository-root")
            .arg(repo_root)
            .stdout(Stdio::null());
        if std::env::var_os("FRACTALOS_EXEC_TRANSPORT_TRACE").is_some() {
            command.arg("--trace");
        }
        let proxy = command
            .spawn()
            .context("failed to spawn native execution transport proxy")?;
        println!(
            "[xtask:run-tests] execution transport proxy pid={}",
            proxy.id()
        );
        Some(proxy)
    } else {
        None
    };
    let mcp_proxy = if board == "qemu_virt_aarch64" {
        let mut command = std::process::Command::new("python3");
        command
            .arg(repo_root.join("tools/mcp_transport_proxy.py"))
            .arg("--socket")
            .arg(&mcp_socket_path)
            .stdout(Stdio::null());
        if let Ok(server) = std::env::var("FRACTALOS_MCP_SERVER_COMMAND_JSON") {
            command.arg("--server-command-json").arg(server);
        }
        if let Ok(server_env) = std::env::var("FRACTALOS_MCP_SERVER_ENV_JSON") {
            command.arg("--server-env-json").arg(server_env);
        }
        if std::env::var_os("FRACTALOS_MCP_TRANSPORT_TRACE").is_some() {
            command.arg("--trace");
        }
        let proxy = command
            .spawn()
            .context("failed to spawn native MCP transport proxy")?;
        println!("[xtask:run-tests] MCP transport proxy pid={}", proxy.id());
        Some(proxy)
    } else {
        None
    };
    let stdout = child
        .stdout
        .take()
        .context("QEMU stdout pipe unavailable")?;
    let mut serial_log = std::fs::OpenOptions::new()
        .append(true)
        .open(log_path)
        .context("failed to open QEMU serial log")?;
    let (sender, serial_events) = mpsc::channel();
    let serial_reader = std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut bytes = Vec::new();
        loop {
            bytes.clear();
            match reader.read_until(b'\n', &mut bytes) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let received_at = Instant::now();
                    if serial_log.write_all(&bytes).is_err() {
                        break;
                    }
                    let line = String::from_utf8_lossy(&bytes).into_owned();
                    if sender.send(SerialEvent { line, received_at }).is_err() {
                        break;
                    }
                }
            }
        }
    });
    Ok(QemuTestProcess {
        child,
        model_proxy,
        exec_proxy,
        mcp_proxy,
        serial_events,
        serial_reader,
        network_injector,
        network_injector_stop,
        network_wg_seen,
        network_frames_seen,
        network_last_frame,
    })
}

fn wait_for_tap_done(
    timeout: Duration,
    qemu: &mut std::process::Child,
    serial_events: &Receiver<SerialEvent>,
) -> Result<Vec<TargetPerfRecord>> {
    let start = Instant::now();
    let mut perf = PerfBatchTracker::default();
    let mut boot_ready_ns = None;

    loop {
        if start.elapsed() >= timeout {
            anyhow::bail!("timeout after {}s waiting for TAP_DONE", timeout.as_secs());
        }
        if let Some(status) = qemu.try_wait().context("failed to poll QEMU")? {
            anyhow::bail!("QEMU exited with status {status} before TAP_DONE");
        }

        let remaining = timeout.saturating_sub(start.elapsed());
        match serial_events.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(event) => {
                if boot_ready_ns.is_none() && event.line.contains("[rt] boot complete") {
                    boot_ready_ns = Some(
                        event
                            .received_at
                            .saturating_duration_since(start)
                            .as_nanos() as u64,
                    );
                }
                if let Some(marker) = parse_perf_batch_marker(&event.line)? {
                    perf.observe(marker, event.received_at)?;
                }
                if parse_tap_done(&event.line).is_some() {
                    let mut records = perf.finish()?;
                    if let Some(elapsed) = boot_ready_ns {
                        records.push(TargetPerfRecord {
                            schema: 1,
                            metric: "qemu_spawn_to_fractalos_ready".to_string(),
                            unit: "ns/boot".to_string(),
                            samples: 1,
                            counter_hz: 1_000_000_000,
                            min: elapsed,
                            p50: elapsed,
                            p95: elapsed,
                            p99: elapsed,
                            max: elapsed,
                            errors: 0,
                        });
                    }
                    return Ok(records);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("QEMU serial stream closed before TAP_DONE")
            }
        }
    }
}

pub fn parse_tap_done(output: &str) -> Option<TapStatus> {
    for line in output.lines() {
        let Some(rest) = line.trim().strip_prefix("TAP_DONE:") else {
            continue;
        };
        let code = rest.trim().parse::<i32>().ok()?;
        return Some(if code == 0 {
            TapStatus::Pass
        } else {
            TapStatus::Fail(code)
        });
    }
    None
}

fn report_tap_result(output: &str, board: &str) -> Result<()> {
    match parse_tap_done(output) {
        Some(TapStatus::Pass) => {
            println!("PASS [board={}]: TAP_DONE:0", board);
            Ok(())
        }
        Some(TapStatus::Fail(code)) => {
            anyhow::bail!("FAIL [board={}]: TAP_DONE:{}", board, code)
        }
        None => anyhow::bail!("FAIL [board={}]: no TAP_DONE sentinel found", board),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_accepts_success_sentinel() {
        assert_eq!(
            parse_tap_done("TAP version 14\nok 1 - boot\n1..1\nTAP_DONE:0\n"),
            Some(TapStatus::Pass)
        );
    }

    #[test]
    fn parser_reports_failure_code() {
        assert_eq!(
            parse_tap_done("not ok 1 - boot\nTAP_DONE:2\n"),
            Some(TapStatus::Fail(2))
        );
    }

    #[test]
    fn parser_reports_missing_sentinel_as_incomplete() {
        assert_eq!(
            parse_tap_done("TAP version 14\nok 1 - still running\n"),
            None
        );
    }

    #[test]
    fn boot_health_rejects_root_faults_and_registration_failures() {
        assert!(validate_boot_health(concat!(
            "FRACTALOS_BOOT_HEALTH ns_registered=3 ns_disabled=3 ns_failed=0\n",
            "FractalOS boot complete\n",
        ))
        .is_ok());
        assert!(validate_boot_health(concat!(
            "[rt] FAULT label=0x6 badge=0x17 pd=fault_handler\n",
            "FRACTALOS_BOOT_HEALTH ns_registered=3 ns_disabled=3 ns_failed=0\n",
            "FractalOS boot complete\n",
        ))
        .is_err());
        assert!(validate_boot_health(concat!(
            "FRACTALOS_BOOT_HEALTH ns_registered=0 ns_disabled=3 ns_failed=3\n",
            "FractalOS boot complete\n",
        ))
        .is_err());
        assert!(validate_boot_health("FractalOS boot complete\n").is_err());
    }

    #[test]
    fn parser_accepts_target_perf_json() {
        let records = parse_perf_records(concat!(
            "noise\n",
            "PERF_JSON:{\"schema\":1,\"metric\":\"ipc\",\"unit\":\"cycles\",",
            "\"samples\":256,\"counter_hz\":62500000,\"min\":10,\"p50\":20,",
            "\"p95\":30,\"p99\":40,\"max\":50,\"errors\":0}\n",
        ))
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].metric, "ipc");
        assert_eq!(records[0].p99, 40);
    }

    #[test]
    fn parser_rejects_malformed_target_perf_json() {
        assert!(parse_perf_records("PERF_JSON:{bad}\n").is_err());
    }

    #[test]
    fn parser_accepts_agent_resource_json() {
        let resources = parse_agent_resource_records(concat!(
            "AGENT_RESOURCE_JSON:{\"schema\":1,\"worker\":\"codex_harness\",",
            "\"private_committed_bytes\":241664,\"private_limit_bytes\":67108864,",
            "\"shared_mapped_bytes\":49152,\"target_low_bytes\":20971520,",
            "\"target_high_bytes\":157286400,\"shared_components\":1}\n",
        ))
        .unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].worker, "codex_harness");
        assert_eq!(resources[0].private_committed_bytes, 241_664);
        assert_eq!(resources[0].shared_mapped_bytes, 49_152);
    }

    #[test]
    fn parser_accepts_agent_resource_json_after_concurrent_uart_prefix() {
        let resources = parse_agent_resource_records(concat!(
            "[cc_pd] partial output AGENT_RESOURCE_JSON:",
            "{\"schema\":1,\"worker\":\"codex_harness\",",
            "\"private_committed_bytes\":274432,\"private_limit_bytes\":67108864,",
            "\"shared_mapped_bytes\":196608,\"target_low_bytes\":20971520,",
            "\"target_high_bytes\":157286400,\"shared_components\":55}\n",
        ))
        .unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].private_committed_bytes, 274_432);
        assert_eq!(resources[0].shared_components, 55);
    }

    #[test]
    fn parser_rejects_malformed_agent_resource_json() {
        assert!(parse_agent_resource_records("AGENT_RESOURCE_JSON:{bad}\n").is_err());
    }

    #[test]
    fn parser_accepts_perf_batch_markers() {
        assert_eq!(
            parse_perf_batch_marker("PERF_BATCH_BEGIN:ipc:1024\r\n").unwrap(),
            Some(PerfBatchMarker::Begin {
                metric: "ipc".to_string(),
                calls: 1024,
            })
        );
        assert_eq!(
            parse_perf_batch_marker("PERF_BATCH_END:ipc:1024:3\n").unwrap(),
            Some(PerfBatchMarker::End {
                metric: "ipc".to_string(),
                calls: 1024,
                errors: 3,
            })
        );
    }

    #[test]
    fn batch_tracker_builds_ns_per_operation_record() {
        let start = Instant::now();
        let mut tracker = PerfBatchTracker::default();
        tracker
            .observe(
                PerfBatchMarker::Begin {
                    metric: "ipc".to_string(),
                    calls: 100,
                },
                start,
            )
            .unwrap();
        tracker
            .observe(
                PerfBatchMarker::End {
                    metric: "ipc".to_string(),
                    calls: 100,
                    errors: 0,
                },
                start + Duration::from_micros(250),
            )
            .unwrap();
        let records = tracker.finish().unwrap();
        assert_eq!(records[0].samples, 1);
        assert_eq!(records[0].unit, "ns/op");
        assert_eq!(records[0].p50, 2500);
    }

    fn sample_record() -> TargetPerfRecord {
        TargetPerfRecord {
            schema: 1,
            metric: "ipc".to_string(),
            unit: "cycles".to_string(),
            samples: 256,
            counter_hz: 62_500_000,
            min: 10,
            p50: 20,
            p95: 30,
            p99: 40,
            max: 50,
            errors: 0,
        }
    }

    #[test]
    fn thresholds_accept_record_within_limits() {
        let thresholds: PerfThresholds = serde_json::from_str(
            r#"{"schema":1,"boards":{"qemu":{"ipc":{"min_samples":256,"p99_max":40}}}}"#,
        )
        .unwrap();
        apply_thresholds(&[sample_record()], "qemu", &thresholds).unwrap();
    }

    #[test]
    fn thresholds_reject_regression() {
        let thresholds: PerfThresholds =
            serde_json::from_str(r#"{"schema":1,"boards":{"qemu":{"ipc":{"p99_max":39}}}}"#)
                .unwrap();
        let error = apply_thresholds(&[sample_record()], "qemu", &thresholds).unwrap_err();
        assert!(error.to_string().contains("p99 regression"));
    }
}
