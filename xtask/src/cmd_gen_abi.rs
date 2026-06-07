use crate::GenAbiArgs;
use anyhow::{bail, Context, Result};
use std::process::Command;

/// Invoke the `gen-abi` tool to regenerate (or validate) the per-PD ABI table
/// header from the source-of-truth TOML spec.
///
/// gen-abi hard-fails (nonzero exit) on a duplicate opcode within a PD, a
/// duplicate channel id, or a missing contract directory. We propagate that
/// exit status so `cargo xtask gen-abi` fails the same way the build does.
pub fn run(args: &GenAbiArgs) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.args(["run", "-q", "-p", "gen-abi", "--"]);
    cmd.arg(&args.spec);
    if args.check {
        cmd.arg("--check");
    } else {
        cmd.arg("-o").arg(&args.out);
    }

    let status = cmd
        .status()
        .with_context(|| "failed to launch gen-abi via cargo")?;

    if !status.success() {
        bail!(
            "gen-abi exited with {} — ABI spec validation failed",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}
