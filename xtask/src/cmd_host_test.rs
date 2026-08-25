//! `cargo xtask test` — compile and run FractalOS host-side test suites.
//!
//! Compiles every test suite under `tests/api/` and `tests/integration/`
//! using the system C compiler with `-DFRACTALOS_TEST_HOST`.  Each suite is
//! compiled into a standalone binary, executed, and its TAP output parsed.
//!
//! Exit code:
//!   0  — all suites passed (or no suites were found/requested)
//!   1  — one or more suites failed or a compile error occurred
//!
//! Flags:
//!   --suite <name>       Run only the named suite
//!   --compiler <path>    Override the C compiler (default: value of CC or "cc")
//!   --verbose / -v       Print full TAP output for every suite, not just failures
//!   --hardware           Also run the QEMU-backed hardware test suite (disabled by default)

use crate::HostTestArgs;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Suite definitions
// ---------------------------------------------------------------------------

/// A host-compilable test suite.
struct Suite {
    /// Short name used for `--suite <name>` selection and result reporting.
    name: &'static str,
    /// Source files, relative to the repo root.  The first entry is the
    /// primary test file; remaining entries are implementation files pulled in
    /// alongside it.
    sources: &'static [&'static str],
    /// Extra compiler arguments for this suite (e.g. a `-include` host shim
    /// needed when a real kernel source pulls in the Microkit IPC layer).
    extra_args: &'static [&'static str],
}

/// All known host-side test suites.
///
/// Only suites whose primary source file actually exists on disk are compiled
/// and run; the remainder are silently skipped.  This lets the list stay
/// stable as new test files are added incrementally.
const SUITES: &[Suite] = &[
    Suite {
        // fos-pkh: RemoteGrant validation and execution-lease fencing.
        name: "test_remote_authority",
        sources: &[
            "tests/security/test_remote_authority.c",
            "kernel/fractalos-root-task/src/auth_server.c",
            "kernel/fractalos-root-task/src/cap_broker.c",
            "kernel/fractalos-root-task/src/mesh_agent.c",
            "kernel/fractalos-root-task/src/agent_task_gateway.c",
        ],
        extra_args: &["-DFRACTALOS_REMOTE_AUTHORITY_HOST_TEST"],
    },
    Suite {
        // fos-2th: generated mesh frames and RemoteGrant rejection cases.
        name: "test_remote_grants",
        sources: &[
            "tests/security/test_remote_grants.c",
            "kernel/fractalos-root-task/src/auth_server.c",
            "kernel/fractalos-root-task/src/cap_broker.c",
            "kernel/fractalos-root-task/src/mesh_agent.c",
        ],
        extra_args: &["-DFRACTALOS_REMOTE_AUTHORITY_HOST_TEST"],
    },
    Suite {
        // fos-d02: companion v1.1 ABI, marshalling, grant, and cursor contract.
        name: "test_companion_export_contract",
        sources: &["tests/contracts/companion_export_test.c"],
        extra_args: &[],
    },
    Suite {
        name: "test_agent_task_gateway",
        sources: &[
            "tests/test_agent_task_gateway.c",
            "kernel/fractalos-root-task/src/agent_task_gateway.c",
            "kernel/fractalos-root-task/src/mesh_agent.c",
        ],
        extra_args: &["-DFRACTALOS_REMOTE_AUTHORITY_HOST_TEST"],
    },
    Suite {
        // fos-gz0.14.11: FractalOS capabilities v1 contract boundary.
        name: "test_agent_task_contract",
        sources: &["tests/contracts/agent_task_test.c"],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.14.5: canonical append-only Agent event stream.
        name: "test_agent_event_stream",
        sources: &["tests/test_agent_event_stream.c"],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.14.7.1: scoped actor handles + causal mailboxes.
        name: "test_actor_mailbox",
        sources: &[
            "tests/test_actor_mailbox.c",
            "kernel/fractalos-root-task/src/actor_mailbox.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.14.9: immutable capability service graph + provider swaps.
        name: "test_service_graph",
        sources: &[
            "tests/test_service_graph.c",
            "kernel/fractalos-root-task/src/service_graph.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.14.10.3: immutable shared-space replication + verified merge.
        name: "test_shared_space_replication",
        sources: &[
            "tests/test_shared_space_replication.c",
            "kernel/fractalos-root-task/src/shared_space.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.14.10.5: external Local Gateway fence (daily + intent + revoke).
        name: "test_local_gateway",
        sources: &[
            "tests/test_local_gateway.c",
            "kernel/fractalos-root-task/src/local_gateway.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.14.17: companion gateway projection boundary (no UI/HTTP).
        name: "test_companion_gateway",
        sources: &[
            "tests/test_companion_gateway.c",
            "kernel/fractalos-root-task/src/companion_gateway.c",
            "kernel/fractalos-root-task/src/local_gateway.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.14.8: continual harness E1 snapshot/promote/rollback (no WASM).
        name: "test_continual_harness",
        sources: &[
            "tests/test_continual_harness.c",
            "kernel/fractalos-root-task/src/continual_harness.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.14 / recovered: Agent ISA v0 semantic contract.
        name: "test_agent_isa_contract",
        sources: &["tests/contracts/agent_isa_test.c"],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.14: futures, execution DAG, rollback, and authority.
        name: "test_agent_isa_runtime",
        sources: &[
            "tests/test_agent_isa_runtime.c",
            "kernel/fractalos-root-task/src/agent_isa.c",
            "kernel/fractalos-root-task/src/sha256_mini.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.14: immutable Agent IR graph nodes lower to Agent ISA.
        name: "test_agent_ir",
        sources: &[
            "tests/test_agent_ir.c",
            "kernel/fractalos-root-task/src/agent_ir.c",
            "kernel/fractalos-root-task/src/agent_isa.c",
            "kernel/fractalos-root-task/src/sha256_mini.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.14.1.1: authenticated asynchronous dispatch contract.
        name: "test_agent_isa_dispatch_contract",
        sources: &["tests/contracts/agent_isa_dispatch_test.c"],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.14.1.1: queue, completion, cancellation, and revocation.
        name: "test_agent_isa_dispatch",
        sources: &[
            "tests/test_agent_isa_dispatch.c",
            "kernel/fractalos-root-task/src/agent_isa_dispatch.c",
            "kernel/fractalos-root-task/src/agent_event_emit.c",
            "kernel/fractalos-root-task/src/agent_isa.c",
            "kernel/fractalos-root-task/src/sha256_mini.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.14.1.2: capability-selected semantic adapters (no provider names).
        name: "test_agent_isa_semantic_adapter",
        sources: &[
            "tests/test_agent_isa_semantic_adapter.c",
            "kernel/fractalos-root-task/src/agent_isa_semantic_adapter.c",
            "kernel/fractalos-root-task/src/agent_event_emit.c",
            "kernel/fractalos-root-task/src/agent_isa.c",
            "kernel/fractalos-root-task/src/sha256_mini.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.14.1.3: dispatcher topology + async CHECKPOINT..COMMIT flow.
        name: "test_agent_isa_topology",
        sources: &[
            "tests/test_agent_isa_topology.c",
            "kernel/fractalos-root-task/src/agent_isa_topology.c",
            "kernel/fractalos-root-task/src/agent_isa_semantic_adapter.c",
            "kernel/fractalos-root-task/src/agent_isa_dispatch.c",
            "kernel/fractalos-root-task/src/agent_event_emit.c",
            "kernel/fractalos-root-task/src/agent_isa.c",
            "kernel/fractalos-root-task/src/sha256_mini.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.14.5.3: AgentFS descriptors + ISA emit + IPC RECORD/SEAL/REPLAY.
        name: "test_agent_event_integration",
        sources: &[
            "tests/test_agent_event_integration.c",
            "kernel/fractalos-root-task/src/agent_isa_semantic_adapter.c",
            "kernel/fractalos-root-task/src/agent_event_emit.c",
            "kernel/fractalos-root-task/src/agent_isa.c",
            "kernel/fractalos-root-task/src/sha256_mini.c",
            "services/agentfs/descriptor_store.c",
        ],
        extra_args: &["-DFRACTALOS_TEST_HOST"],
    },
    Suite {
        // fos-gz0.14.6.1: AgentLang parser/type/effect/canonical lowering.
        name: "test_agent_lang",
        sources: &[
            "tests/test_agent_lang.c",
            "kernel/fractalos-root-task/src/agent_lang.c",
            "kernel/fractalos-root-task/src/agent_ir.c",
            "kernel/fractalos-root-task/src/agent_isa.c",
            "kernel/fractalos-root-task/src/sha256_mini.c",
        ],
        extra_args: &[],
    },
    Suite {
        name: "test_controller",
        sources: &[
            "tests/api/test_controller.c",
            "kernel/fractalos-root-task/src/agent_task_gateway.c",
            "kernel/fractalos-root-task/src/mesh_agent.c",
        ],
        extra_args: &["-DFRACTALOS_REMOTE_AUTHORITY_HOST_TEST"],
    },
    Suite {
        name: "test_cc_contract",
        sources: &["tests/test_cc_contract.c"],
        extra_args: &[],
    },
    Suite {
        name: "test_repo_agent_task",
        sources: &[
            "tests/test_repo_agent_task.c",
            "tests/fixtures/repo_agent/answer.c",
        ],
        extra_args: &[],
    },
    Suite {
        name: "test_exec_verify",
        sources: &["tests/test_exec_verify.c"],
        extra_args: &[],
    },
    Suite {
        name: "test_model_svc",
        sources: &["tests/test_model_svc.c"],
        extra_args: &[],
    },
    Suite {
        name: "test_agentfs_workspace",
        sources: &["tests/test_agentfs_workspace.c"],
        extra_args: &[],
    },
    Suite {
        name: "test_tool_svc",
        sources: &["tests/test_tool_svc.c"],
        extra_args: &[],
    },
    Suite {
        name: "test_agent_harness_pd",
        sources: &["tests/test_agent_harness_pd.c"],
        extra_args: &[],
    },
    Suite {
        name: "test_agent_harness_topology",
        sources: &["tests/test_agent_harness_topology.c"],
        extra_args: &[],
    },
    Suite {
        name: "test_agent_harness_contract",
        sources: &["tests/contracts/agent_harness_test.c"],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.13.1: launcher-validated composable harness graphs.
        name: "test_harness_composition_contract",
        sources: &[
            "tests/contracts/harness_composition_test.c",
            "kernel/fractalos-root-task/src/harness_composition.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.13.1: InitAgent owns composition IPC dispatch.
        name: "test_init_agent_composition",
        sources: &["tests/test_init_agent_composition.c"],
        extra_args: &[],
    },
    Suite {
        name: "test_msgbus",
        sources: &["tests/api/test_msgbus.c"],
        extra_args: &[],
    },
    Suite {
        name: "test_capstore",
        sources: &["tests/api/test_capstore.c"],
        extra_args: &[],
    },
    Suite {
        name: "test_memfs",
        sources: &["tests/api/test_memfs.c"],
        extra_args: &[],
    },
    Suite {
        name: "test_logsvc",
        sources: &["tests/api/test_logsvc.c"],
        extra_args: &[],
    },
    Suite {
        name: "test_vibeos",
        sources: &["tests/api/test_vibeos.c"],
        extra_args: &[],
    },
    Suite {
        // fos-3ev: parameterized-PD startup-record contract.
        name: "test_pd_startup_record",
        sources: &["tests/test_pd_startup_record.c"],
        extra_args: &[],
    },
    Suite {
        // fos-c7i: Ed25519 + fatal cryptographic selftest gate.
        name: "test_crypto_selftest",
        sources: &[
            "tests/test_crypto_selftest.c",
            "kernel/fractalos-root-task/src/verify.c",
            "kernel/fractalos-root-task/src/ed25519_verify.c",
            "kernel/fractalos-root-task/src/monocypher.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.5: WireGuard's RFC 8439 transport AEAD primitive.
        name: "test_wireguard_crypto",
        sources: &[
            "tests/test_wireguard_crypto.c",
            "kernel/fractalos-root-task/src/monocypher.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.5: nonce uniqueness and authenticated RX replay window.
        name: "test_wireguard_counter",
        sources: &["tests/test_wireguard_counter.c"],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.5: canonical Noise BLAKE2s transcript and KDF vectors.
        name: "test_wireguard_noise",
        sources: &[
            "tests/test_wireguard_noise.c",
            "kernel/fractalos-root-task/src/wireguard_noise.c",
            "kernel/fractalos-root-task/src/monocypher.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.5: wg_net fail-closed handshake/session integration.
        name: "test_wg_net_sessions",
        sources: &[
            "tests/test_wg_net_sessions.c",
            "kernel/fractalos-root-task/src/wireguard_noise.c",
            "kernel/fractalos-root-task/src/wireguard_derp.c",
            "kernel/fractalos-root-task/src/monocypher.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.5: Headscale-style netmap apply + rekey-after-time.
        name: "test_wg_netmap",
        sources: &[
            "tests/test_wg_netmap.c",
            "kernel/fractalos-root-task/src/wireguard_noise.c",
            "kernel/fractalos-root-task/src/wireguard_derp.c",
            "kernel/fractalos-root-task/src/monocypher.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.5: cookie reply + under-load mac2 gate.
        name: "test_wg_cookies",
        sources: &[
            "tests/test_wg_cookies.c",
            "kernel/fractalos-root-task/src/wireguard_noise.c",
            "kernel/fractalos-root-task/src/wireguard_derp.c",
            "kernel/fractalos-root-task/src/monocypher.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.5: entropy-backed ephemeral + handshake index.
        name: "test_wg_entropy",
        sources: &[
            "tests/test_wg_entropy.c",
            "kernel/fractalos-root-task/src/wireguard_noise.c",
            "kernel/fractalos-root-task/src/wireguard_derp.c",
            "kernel/fractalos-root-task/src/monocypher.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.5: DERP Send/Recv framing around opaque WG ciphertext.
        name: "test_wg_derp",
        sources: &[
            "tests/test_wg_derp.c",
            "kernel/fractalos-root-task/src/wireguard_noise.c",
            "kernel/fractalos-root-task/src/monocypher.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.5: multi-peer UDP/DERP path + roam + timer rekey under traffic.
        name: "test_wg_dataplane",
        sources: &[
            "tests/test_wg_dataplane.c",
            "kernel/fractalos-root-task/src/wireguard_noise.c",
            "kernel/fractalos-root-task/src/monocypher.c",
        ],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.5: packet-only mapping and immutable NetServer WG right.
        name: "test_net_wg_handoff",
        sources: &["tests/test_net_wg_handoff.c"],
        extra_args: &[],
    },
    Suite {
        // fos-gz0.4: multi-queue ownership rings + TX chain DMA contract.
        name: "test_net_fastpath",
        sources: &["tests/test_net_fastpath.c"],
        extra_args: &[],
    },
    Suite {
        // fos-681 / fos-vsi: CC-PD polecat occupancy + log-slot model.
        // agent_pool.c pulls in the Microkit IPC layer, so force-include the
        // host shim that stubs microkit_mr_get/set.
        name: "test_cc_pd_metrics",
        sources: &[
            "tests/test_cc_pd_metrics.c",
            "kernel/fractalos-root-task/src/agent_pool.c",
        ],
        extra_args: &["-include", "tests/microkit.h"],
    },
    // NOTE: tests/integration/ suites include harness/test_framework.h which
    // depends on <microkit.h> from the Microkit SDK.  Those suites are
    // on-target only and are NOT compiled by the host-side runner.
    // They run via the QEMU boot path (xtask qemu-test) or the CI
    // contract-tests job which provisions the Microkit SDK.
];

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn run(args: &HostTestArgs) -> Result<()> {
    let repo_root = repo_root()?;

    // Resolve C compiler: CLI flag > CC env var > "cc".
    let cc = args
        .compiler
        .clone()
        .or_else(|| std::env::var("CC").ok())
        .unwrap_or_else(|| "cc".to_string());

    // Build a temporary output directory for compiled binaries.
    let build_dir = repo_root.join("target").join("test-bins");
    std::fs::create_dir_all(&build_dir).context("failed to create test binary output directory")?;

    println!("[xtask:test] compiler : {}", cc);
    println!("[xtask:test] repo root: {}", repo_root.display());
    println!("[xtask:test] bin dir  : {}", build_dir.display());
    if let Some(ref suite) = args.suite {
        println!("[xtask:test] suite    : {}", suite);
    }
    println!();

    // Collect suites to run, filtered by --suite if given.
    let selected: Vec<&Suite> = SUITES
        .iter()
        .filter(|s| {
            args.suite
                .as_deref()
                .map(|wanted| s.name == wanted)
                .unwrap_or(true)
        })
        .collect();

    if selected.is_empty() {
        if let Some(ref name) = args.suite {
            bail!(
                "unknown suite {:?} — available suites: {}",
                name,
                SUITES.iter().map(|s| s.name).collect::<Vec<_>>().join(", ")
            );
        }
        println!("[xtask:test] no suites found");
        return Ok(());
    }

    // ---------------------------------------------------------------------------
    // Compile & run each suite
    // ---------------------------------------------------------------------------

    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;

    // Include paths always passed to the compiler.
    let include_root = repo_root
        .join("kernel")
        .join("fractalos-root-task")
        .join("include");
    let include_harness = repo_root.join("tests").join("harness");
    let include_api = repo_root.join("tests").join("api");

    for suite in &selected {
        let primary_src = repo_root.join(suite.sources[0]);

        // Skip suites whose primary source file does not exist yet.
        if !primary_src.exists() {
            println!(
                "[xtask:test] SKIP  {} — source not found: {}",
                suite.name,
                primary_src.display()
            );
            skipped += 1;
            continue;
        }

        let bin = build_dir.join(suite.name);

        // ── Compile ──────────────────────────────────────────────────────────
        let mut cmd = std::process::Command::new(&cc);
        // Run from the repo root so relative extra args (e.g. `-include
        // tests/microkit.h`) resolve consistently regardless of invocation cwd.
        cmd.current_dir(&repo_root);
        cmd.args([
            "-DFRACTALOS_TEST_HOST",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-o",
            bin.to_str().unwrap(),
        ]);

        // Include paths
        cmd.arg(format!("-I{}", include_root.display()));
        cmd.arg(format!("-I{}", include_harness.display()));
        cmd.arg(format!("-I{}", include_api.display()));

        // Per-suite extra compiler args (e.g. a `-include` host shim).
        for &arg in suite.extra_args {
            cmd.arg(arg);
        }

        // Source files (primary + any kernel implementation files)
        for &src in suite.sources {
            let p = repo_root.join(src);
            if p.exists() {
                cmd.arg(p.to_str().unwrap());
            }
        }

        let compile_out = cmd
            .output()
            .with_context(|| format!("failed to invoke C compiler for suite {}", suite.name))?;

        if !compile_out.status.success() {
            eprintln!("[xtask:test] COMPILE ERROR: {}", suite.name);
            if !compile_out.stderr.is_empty() {
                eprintln!("{}", String::from_utf8_lossy(&compile_out.stderr));
            }
            errors += 1;
            println!("[xtask:test] FAIL  {} (compile error)", suite.name);
            println!();
            continue;
        }

        // ── Run ──────────────────────────────────────────────────────────────
        let run_out = std::process::Command::new(&bin)
            .output()
            .with_context(|| format!("failed to execute test binary for suite {}", suite.name))?;

        let stdout = String::from_utf8_lossy(&run_out.stdout);
        let stderr = String::from_utf8_lossy(&run_out.stderr);

        // Count TAP results.
        let ok_count: usize = stdout
            .lines()
            .filter(|l| l.starts_with("ok ") && !l.contains("# TODO"))
            .count();
        let not_ok_count: usize = stdout.lines().filter(|l| l.starts_with("not ok ")).count();
        let todo_count: usize = stdout.lines().filter(|l| l.contains("# TODO")).count();

        let suite_passed = run_out.status.success() && not_ok_count == 0;

        // Print output based on verbosity / failure.
        if args.verbose || !suite_passed {
            for line in stdout.lines() {
                println!("  {}", line);
            }
            if !stderr.is_empty() {
                for line in stderr.lines() {
                    eprintln!("  {}", line);
                }
            }
        } else {
            // Quiet mode: only print diagnostic (comment) lines.
            for line in stdout.lines() {
                if line.starts_with('#') {
                    println!("  {}", line);
                }
            }
        }

        let todo_note = if todo_count > 0 {
            format!("  ({} TODO)", todo_count)
        } else {
            String::new()
        };

        if suite_passed {
            println!(
                "[xtask:test] PASS  {} — {} ok, {} not-ok{}",
                suite.name, ok_count, not_ok_count, todo_note
            );
            passed += 1;
        } else {
            println!(
                "[xtask:test] FAIL  {} — {} ok, {} not-ok{}",
                suite.name, ok_count, not_ok_count, todo_note
            );
            failed += 1;
        }
        println!();
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────
    // Leave binaries in place for debugging; CI can wipe target/ separately.

    // ── Summary table ─────────────────────────────────────────────────────────
    let total = selected.len();
    println!("┌─────────────────────────────────────────────────────┐");
    println!("│  FractalOS host-side test results                     │");
    println!("├─────────────────────────────────────────────────────┤");
    println!(
        "│  Total suites:   {:>3}                               │",
        total
    );
    println!(
        "│  Passed:         {:>3}                               │",
        passed
    );
    println!(
        "│  Failed:         {:>3}                               │",
        failed
    );
    println!(
        "│  Compile errors: {:>3}                               │",
        errors
    );
    println!(
        "│  Skipped:        {:>3}  (source not found)           │",
        skipped
    );
    println!("└─────────────────────────────────────────────────────┘");

    if failed > 0 || errors > 0 {
        bail!("{} suite(s) failed, {} compile error(s)", failed, errors);
    }

    if passed > 0 {
        println!("ALL HOST TESTS PASSED");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn repo_root() -> Result<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("failed to run git rev-parse")?;
    anyhow::ensure!(output.status.success(), "not in a git repository");
    let root = String::from_utf8(output.stdout)
        .context("git output is not valid UTF-8")?
        .trim()
        .to_string();
    Ok(Path::new(&root).to_path_buf())
}
