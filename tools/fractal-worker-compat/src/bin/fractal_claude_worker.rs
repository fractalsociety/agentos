//! fractal-claude-worker — host-side Claude compatibility worker CLI.
//!
//! Speaks fractal-worker/v1. Credentials arrive only as opaque handle IDs via
//! FRACTAL_CLAUDE_SECRET_HANDLE (never as embedded secrets).

use fractal_worker_compat::{
    claude_manifest_path, CancelRequest, ClaudeLauncher, OpenSessionOpts, SecretHandle,
    WorkerManifest, WorkspaceInput,
};
use std::env;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

fn usage() -> ! {
    eprintln!(
        "usage:\n  fractal-claude-worker discover-version\n  fractal-claude-worker open-session --workspace-id ID --root-object-id ID \\\n      --allowed-file PATH [--allowed-file PATH...] [--verify-command CMD] [--prompt TEXT] \\\n      [--seed-dir DIR] [--deadline-unix-ms MS] [--secret-handle ID]\n  fractal-claude-worker replay-session --workspace-id ID --root-object-id ID \\\n      --allowed-file PATH --jsonl-file PATH [--peak-rss-bytes N] [--secret-handle ID]"
    );
    std::process::exit(2);
}

fn main() -> ExitCode {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    let cmd = args.remove(0);
    let manifest = match WorkerManifest::load(claude_manifest_path()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("manifest error: {e}");
            return ExitCode::from(1);
        }
    };

    match cmd.as_str() {
        "discover-version" => match ClaudeLauncher::discover_version_live(&manifest) {
            Ok(v) => {
                println!("{}", serde_json::to_string(&v).unwrap());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::from(1)
            }
        },
        "open-session" => {
            let (ws, prompt, opts) = match parse_open_args(&args) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    usage();
                }
            };
            match ClaudeLauncher::open_session(&manifest, &ws, &prompt, opts) {
                Ok(result) => {
                    println!("{}", serde_json::to_string(&result).unwrap());
                    if result.exit_status == 0 {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(result.exit_status.clamp(1, 255) as u8)
                    }
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::from(1)
                }
            }
        }
        "replay-session" => {
            let (ws, jsonl_path, peak, secret) = match parse_replay_args(&args) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    usage();
                }
            };
            let jsonl = match std::fs::read_to_string(&jsonl_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("jsonl: {e}");
                    return ExitCode::from(1);
                }
            };
            let opts = OpenSessionOpts {
                replay_jsonl: Some(jsonl),
                replay_peak_rss_bytes: Some(peak),
                secret,
                ..Default::default()
            };
            match ClaudeLauncher::open_session(&manifest, &ws, "replay", opts) {
                Ok(result) => {
                    println!("{}", serde_json::to_string(&result).unwrap());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::from(1)
                }
            }
        }
        "cancel-demo" => {
            // Documents cancel propagation for harnesses; sets a flag and exits.
            let flag = Arc::new(AtomicBool::new(false));
            let req = CancelRequest {
                session_id: "demo".into(),
                reason: "operator-cancel".into(),
                deadline_unix_ms: None,
            };
            let _ = ClaudeLauncher::request_cancel(&flag, &req);
            println!("{{\"cancelled\":true}}");
            ExitCode::SUCCESS
        }
        _ => usage(),
    }
}

fn parse_open_args(args: &[String]) -> Result<(WorkspaceInput, String, OpenSessionOpts), String> {
    let mut workspace_id = None;
    let mut root_object_id = None;
    let mut allowed_files = Vec::new();
    let mut verify_command = None;
    let mut prompt = String::new();
    let mut seed_dir = None;
    let mut deadline_unix_ms = None;
    let mut secret_handle = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--workspace-id" => {
                i += 1;
                workspace_id = Some(args.get(i).cloned().ok_or("missing --workspace-id")?);
            }
            "--root-object-id" => {
                i += 1;
                root_object_id = Some(args.get(i).cloned().ok_or("missing --root-object-id")?);
            }
            "--allowed-file" => {
                i += 1;
                allowed_files.push(args.get(i).cloned().ok_or("missing --allowed-file")?);
            }
            "--verify-command" => {
                i += 1;
                verify_command = Some(args.get(i).cloned().ok_or("missing --verify-command")?);
            }
            "--prompt" => {
                i += 1;
                prompt = args.get(i).cloned().ok_or("missing --prompt")?;
            }
            "--seed-dir" => {
                i += 1;
                seed_dir = Some(std::path::PathBuf::from(
                    args.get(i).cloned().ok_or("missing --seed-dir")?,
                ));
            }
            "--deadline-unix-ms" => {
                i += 1;
                deadline_unix_ms = Some(
                    args.get(i)
                        .ok_or("missing --deadline-unix-ms")?
                        .parse()
                        .map_err(|_| "bad --deadline-unix-ms")?,
                );
            }
            "--secret-handle" => {
                i += 1;
                secret_handle = Some(SecretHandle {
                    id: args.get(i).cloned().ok_or("missing --secret-handle")?,
                    purpose: "cli-auth".into(),
                });
            }
            other => return Err(format!("unknown arg: {other}")),
        }
        i += 1;
    }
    let ws = WorkspaceInput {
        workspace_id: workspace_id.ok_or("required --workspace-id")?,
        root_object_id: root_object_id.ok_or("required --root-object-id")?,
        allowed_files,
        verify_command,
    };
    Ok((
        ws,
        prompt,
        OpenSessionOpts {
            secret: secret_handle,
            deadline_unix_ms,
            seed_dir,
            cancel: None,
            replay_jsonl: None,
            replay_peak_rss_bytes: None,
        },
    ))
}

fn parse_replay_args(
    args: &[String],
) -> Result<(WorkspaceInput, String, u64, Option<SecretHandle>), String> {
    let mut workspace_id = None;
    let mut root_object_id = None;
    let mut allowed_files = Vec::new();
    let mut jsonl_file = None;
    let mut peak = 0u64;
    let mut secret_handle = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--workspace-id" => {
                i += 1;
                workspace_id = Some(args.get(i).cloned().ok_or("missing")?);
            }
            "--root-object-id" => {
                i += 1;
                root_object_id = Some(args.get(i).cloned().ok_or("missing")?);
            }
            "--allowed-file" => {
                i += 1;
                allowed_files.push(args.get(i).cloned().ok_or("missing")?);
            }
            "--jsonl-file" => {
                i += 1;
                jsonl_file = Some(args.get(i).cloned().ok_or("missing")?);
            }
            "--peak-rss-bytes" => {
                i += 1;
                peak = args
                    .get(i)
                    .ok_or("missing")?
                    .parse()
                    .map_err(|_| "bad peak")?;
            }
            "--secret-handle" => {
                i += 1;
                secret_handle = Some(SecretHandle {
                    id: args.get(i).cloned().ok_or("missing")?,
                    purpose: "cli-auth".into(),
                });
            }
            other => return Err(format!("unknown arg: {other}")),
        }
        i += 1;
    }
    Ok((
        WorkspaceInput {
            workspace_id: workspace_id.ok_or("required --workspace-id")?,
            root_object_id: root_object_id.ok_or("required --root-object-id")?,
            allowed_files,
            verify_command: None,
        },
        jsonl_file.ok_or("required --jsonl-file")?,
        peak,
        secret_handle,
    ))
}
