use serde::Serialize;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Serialize)]
pub struct BenchBudget {
    pub name: &'static str,
    pub budget: &'static str,
}

#[derive(Serialize)]
struct BenchEnvironment {
    os: &'static str,
    arch: &'static str,
    rustc: Option<String>,
    cpu: Option<String>,
    features: Vec<String>,
}

#[derive(Serialize)]
struct BenchMetadata<'a> {
    test_type: &'static str,
    bench: &'a str,
    generated_at_ms: u64,
    wa_version: &'static str,
    budgets: &'a [BenchBudget],
    environment: BenchEnvironment,
}

pub fn emit_bench_metadata(bench: &str, budgets: &[BenchBudget]) {
    let metadata = BenchMetadata {
        test_type: "bench",
        bench,
        generated_at_ms: now_ms(),
        wa_version: env!("CARGO_PKG_VERSION"),
        budgets,
        environment: BenchEnvironment {
            os: env::consts::OS,
            arch: env::consts::ARCH,
            rustc: rustc_version(),
            cpu: cpu_model(),
            features: cargo_features(),
        },
    };

    if let Ok(line) = serde_json::to_string(&metadata) {
        println!("[BENCH] {line}");
        let _ = append_jsonl("target/criterion/wa-bench-meta.jsonl", &line);
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or_default()
}

fn rustc_version() -> Option<String> {
    let output = Command::new("rustc").arg("-vV").output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("release: ") {
            return Some(rest.trim().to_string());
        }
    }
    stdout.lines().next().map(|line| line.trim().to_string())
}

fn cpu_model() -> Option<String> {
    if cfg!(target_os = "linux") {
        let contents = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        for line in contents.lines() {
            if line.starts_with("model name") {
                return line
                    .split_once(':')
                    .map(|(_, value)| value.trim().to_string());
            }
        }
        None
    } else if cfg!(target_os = "macos") {
        let output = Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let cpu = stdout.trim();
        if cpu.is_empty() {
            None
        } else {
            Some(cpu.to_string())
        }
    } else {
        env::var("PROCESSOR_IDENTIFIER").ok()
    }
}

fn cargo_features() -> Vec<String> {
    let mut features: Vec<String> = env::vars()
        .filter_map(|(key, _)| key.strip_prefix("CARGO_FEATURE_").map(str::to_string))
        .map(|feature| feature.to_lowercase().replace('_', "-"))
        .collect();
    features.sort();
    features
}

fn append_jsonl(path: &str, line: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}
