//! Versioned diagnostic contract for external boot-screen consumers.
//! See platform/include/platform/clef_boot.h. No display code lives here.
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const MODEL_BYTES: u64 = 6_486_448_288;
const STAGES: [&str; 9] = [
    "starting",
    "block_ready",
    "loading",
    "backbone",
    "routing",
    "joint",
    "checking",
    "ready",
    "failed",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Event {
    stage: usize,
    done: u64,
    total: u64,
}
impl Event {
    fn parse(line: &str) -> Result<Option<Self>> {
        let Some(record) = line.trim_end().strip_prefix("[clef_native] CLEF_BOOT ") else {
            return Ok(None);
        };
        let fields: Vec<_> = record.split_ascii_whitespace().collect();
        ensure!(
            fields.len() == 4 && fields[0] == "v=1",
            "invalid Clef boot record/version"
        );
        let stage = fields[1]
            .strip_prefix("stage=")
            .and_then(|s| STAGES.iter().position(|x| *x == s))
            .context("unknown Clef boot stage")?;
        let done: u64 = fields[2]
            .strip_prefix("done=")
            .context("missing completed count")?
            .parse()?;
        let total: u64 = fields[3]
            .strip_prefix("total=")
            .context("missing total count")?
            .parse()?;
        let expected = match stage {
            2 => MODEL_BYTES,
            3 => 32,
            4 => 2,
            5 => 4,
            _ => 1,
        };
        ensure!(
            total == expected && done <= total,
            "invalid Clef boot bounds"
        );
        if matches!(stage, 0 | 6 | 8) {
            ensure!(done == 0, "invalid start/failure count");
        }
        if matches!(stage, 1 | 7) {
            ensure!(done == 1, "invalid readiness count");
        }
        Ok(Some(Self { stage, done, total }))
    }
}

#[derive(Default)]
struct Trace {
    last: Option<Event>,
    block_ready: bool,
}
impl Trace {
    fn accept(&mut self, e: Event) -> Result<()> {
        if let Some(p) = &self.last {
            ensure!(p.stage < 7, "progress after terminal Clef state");
            if e.stage != 8 {
                if e.stage == p.stage {
                    ensure!(
                        (2..=5).contains(&e.stage) && e.done > p.done,
                        "repeated/regressing Clef progress"
                    );
                    if e.stage >= 3 {
                        ensure!(e.done == p.done + 1, "missing Clef layer progress");
                    }
                } else {
                    ensure!(e.stage == p.stage + 1, "skipped/reordered Clef stage");
                    ensure!(
                        matches!(p.stage, 0 | 6) || p.done == p.total,
                        "unfinished Clef stage"
                    );
                    let first = if matches!(e.stage, 1 | 4 | 5 | 7) {
                        1
                    } else {
                        0
                    };
                    ensure!(e.done == first, "missing first Clef progress record");
                }
            }
        } else {
            ensure!(e.stage == 0 || e.stage == 8, "missing Clef boot start");
        }
        self.block_ready |= e.stage == 1;
        self.last = Some(e);
        Ok(())
    }
    fn ready(&self) -> bool {
        self.last.as_ref().is_some_and(|e| e.stage == 7)
    }
}

pub fn validate(log: &str) -> Result<()> {
    let mut trace = Trace::default();
    for line in log.lines() {
        if let Some(e) = Event::parse(line)? {
            trace.accept(e)?;
        }
    }
    ensure!(trace.ready(), "missing complete Clef boot progress trace");
    Ok(())
}

pub struct Monitor {
    dir: PathBuf,
    start: Instant,
    stage_start: Instant,
    run_id: String,
    sequence: u64,
    phase: String,
    source: &'static str,
    trace: Trace,
    events: fs::File,
    consumed: usize,
    snapshot: Value,
}
impl Monitor {
    pub fn new(dir: &Path) -> Result<Self> {
        let start = Instant::now();
        let mut m = Self {
            dir: dir.to_owned(),
            start,
            stage_start: start,
            run_id: format!(
                "{}-{}",
                std::process::id(),
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
            ),
            sequence: 0,
            phase: String::new(),
            source: "host",
            trace: Trace::default(),
            events: fs::File::create(dir.join("boot-events.jsonl"))?,
            consumed: 0,
            snapshot: Value::Null,
        };
        m.phase("preparing")?;
        Ok(m)
    }
    pub fn phase(&mut self, phase: &str) -> Result<()> {
        self.set_phase(phase, "host");
        self.publish("running", None, None, None)
    }
    fn set_phase(&mut self, phase: &str, source: &'static str) {
        if phase != self.phase {
            self.stage_start = Instant::now();
        }
        self.phase = phase.to_owned();
        self.source = source;
    }
    fn publish(
        &mut self,
        state: &str,
        done: Option<u64>,
        total: Option<u64>,
        error: Option<&str>,
    ) -> Result<()> {
        self.sequence += 1;
        self.snapshot = json!({
            "version": 1, "run_id": self.run_id, "sequence": self.sequence,
            "state": state, "phase": self.phase, "source": self.source,
            "completed": done, "total": total,
            "unit": if self.phase == "loading" { "bytes" } else if matches!(self.phase.as_str(), "backbone" | "routing" | "joint") { "layers" } else { "steps" },
            "elapsed_seconds": self.start.elapsed().as_secs_f64(),
            "stage_elapsed_seconds": self.stage_start.elapsed().as_secs_f64(),
            "block_service_ready": self.trace.block_ready,
            "clef_ready": state == "ready", "error": error,
            "scope": "native seL4/QEMU fixed-choice test; physical PC and general allocator service unqualified"
        });
        let data = serde_json::to_vec(&self.snapshot)?;
        self.events.write_all(&data)?;
        self.events.write_all(b"\n")?;
        self.events.flush()?;
        // Rename within one directory: a reader never sees half a JSON record.
        let temporary = self.dir.join("boot-status.json.tmp");
        fs::write(&temporary, &data)?;
        fs::rename(temporary, self.dir.join("boot-status.json"))?;
        Ok(())
    }
    pub fn ingest(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() >= self.consumed,
            "native log truncated during boot"
        );
        while let Some(end) = bytes[self.consumed..].iter().position(|b| *b == b'\n') {
            let end = self.consumed + end + 1;
            let line = String::from_utf8_lossy(&bytes[self.consumed..end]);
            self.consumed = end;
            if let Some(e) = Event::parse(&line)? {
                self.trace.accept(e.clone())?;
                self.set_phase(STAGES[e.stage], "native");
                // A native ready record is provisional until numerical PASS
                // and the complete inference trace have both been validated.
                self.publish("running", Some(e.done), Some(e.total), None)?;
                if e.stage == 8 {
                    bail!("native Clef initialization failed");
                }
            }
        }
        Ok(())
    }
    pub fn ready(&mut self) -> Result<()> {
        ensure!(self.trace.ready(), "Clef readiness lacks native progress");
        self.publish("ready", Some(1), Some(1), None)
    }
    pub fn fail(&mut self, error: &str) -> Result<()> {
        // Keep the failing phase so a screen can explain where boot stopped.
        let done = self.snapshot["completed"].as_u64();
        let total = self.snapshot["total"].as_u64();
        self.publish("failed", done, total, Some(error))
    }
    pub fn summary(&self) -> Value {
        self.snapshot.clone()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    fn line(stage: &str, done: u64, total: u64) -> String {
        format!("[clef_native] CLEF_BOOT v=1 stage={stage} done={done} total={total}\r\n")
    }
    pub(crate) fn valid_trace() -> String {
        let mut s = line("starting", 0, 1)
            + &line("block_ready", 1, 1)
            + &line("loading", 0, MODEL_BYTES)
            + &line("loading", MODEL_BYTES, MODEL_BYTES);
        for (stage, n, first) in [("backbone", 32, 0), ("routing", 2, 1), ("joint", 4, 1)] {
            for done in first..=n {
                s += &line(stage, done, n);
            }
        }
        s + &line("checking", 0, 1) + &line("ready", 1, 1)
    }
    #[test]
    fn requires_order_bounds_and_completion() {
        let log = valid_trace();
        assert!(validate(&log).is_ok());
        for bad in [
            line("ready", 1, 1),
            log.replace("v=1", "v=2"),
            log.replace(&line("backbone", 17, 32), ""),
            log.replace(
                &line("loading", MODEL_BYTES, MODEL_BYTES),
                &line("loading", 123, MODEL_BYTES),
            ),
            log.replace("done=32 total=32", "done=33 total=32"),
            log.clone() + &line("failed", 0, 1),
        ] {
            assert!(validate(&bad).is_err(), "accepted {bad}");
        }
    }
    #[test]
    fn partial_lines_never_publish_ready_and_failures_clear_readiness() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = Monitor::new(dir.path()).unwrap();
        let log = valid_trace();
        let mut bytes = vec![0xe2, 0x95, b'\n'];
        bytes.extend_from_slice(log.as_bytes());
        for end in 0..=bytes.len() {
            m.ingest(&bytes[..end]).unwrap();
        }
        assert_eq!(m.snapshot["state"], "running");
        assert_eq!(m.snapshot["clef_ready"], false);
        m.ready().unwrap();
        assert_eq!(m.snapshot["clef_ready"], true);
        m.fail("QEMU exited").unwrap();
        let saved: Value =
            serde_json::from_slice(&fs::read(dir.path().join("boot-status.json")).unwrap())
                .unwrap();
        assert_eq!(saved["state"], "failed");
        assert_eq!(saved["clef_ready"], false);
        assert_eq!(saved["error"], "QEMU exited");
        let old_run = saved["run_id"].clone();
        let next = Monitor::new(dir.path()).unwrap();
        assert_ne!(next.snapshot["run_id"], old_run);
        assert_eq!(next.snapshot["state"], "running");
    }
    #[test]
    fn model_failure_is_terminal_before_inference() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = Monitor::new(dir.path()).unwrap();
        let log = line("starting", 0, 1) + &line("failed", 0, 1);
        assert!(m.ingest(log.as_bytes()).is_err());
        assert!(m.ready().is_err());
    }
}
