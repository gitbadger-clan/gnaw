// xtask/src/bin/rule-memory.rs — per-pattern compile cost via a counting
// allocator. SEQUENTIAL by design: LIVE is global, parallel compiles would
// interleave and destroy per-pattern attribution. Run:
//   cargo run --release -p xtask --bin rule-memory
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(l.size(), Ordering::Relaxed) + l.size();
        PEAK.fetch_max(live, Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static A: Counting = Counting;

#[derive(serde::Deserialize)]
struct RawConfig {
    #[serde(default)]
    rules: Vec<RawRule>,
}
#[derive(serde::Deserialize)]
struct RawRule {
    id: String,
    #[serde(default)]
    regex: String,
    #[serde(default)]
    allowlists: Vec<RawAllowlist>,
    #[serde(default)]
    allowlist: Option<RawAllowlist>,
    #[serde(default)]
    keywords: Vec<String>,
}
#[derive(serde::Deserialize)]
struct RawAllowlist {
    #[serde(default)]
    regexes: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let toml_src = std::fs::read_to_string("crates/gnaw-core/assets/gitleaks.toml")?;
    let cfg: RawConfig = toml::from_str(&toml_src)?;

    // (id, retained_bytes, peak_delta, keyword_gated, compiled_regexes) —
    // keep every Regex ALIVE in `hold` so `retained` measures residency,
    // not compile-then-drop.
    let mut hold: Vec<regex::Regex> = Vec::new();
    let mut rows: Vec<(String, usize, usize, bool)> = Vec::new();

    for raw in &cfg.rules {
        if raw.regex.trim().is_empty() {
            continue;
        }
        let before = LIVE.load(Ordering::Relaxed);
        PEAK.store(before, Ordering::Relaxed);

        let mut ok = true;
        match gnaw_core::secret_scan::compile_pattern_for_diagnostics(&raw.regex) {
            Ok(re) => hold.push(re),
            Err(_) => ok = false,
        }
        for al in raw.allowlists.iter().chain(raw.allowlist.iter()) {
            for r in &al.regexes {
                if let Ok(re) = gnaw_core::secret_scan::compile_pattern_for_diagnostics(r) {
                    hold.push(re);
                }
            }
        }

        let retained = LIVE.load(Ordering::Relaxed).saturating_sub(before);
        let peak = PEAK.load(Ordering::Relaxed).saturating_sub(before);
        let id = if ok {
            raw.id.clone()
        } else {
            format!("{} [DROPPED]", raw.id)
        };
        rows.push((id, retained, peak, !raw.keywords.is_empty()));
    }

    rows.sort_by(|a, b| b.1.cmp(&a.1));
    let total: usize = rows.iter().map(|r| r.1).sum();

    println!(
        "{:<44} {:>12} {:>12}  {}",
        "rule", "retained", "peak", "gate"
    );
    for (id, retained, peak, gated) in &rows {
        println!(
            "{:<44} {:>10.2}MB {:>10.2}MB  {}",
            id,
            *retained as f64 / 1048576.0,
            *peak as f64 / 1048576.0,
            if *gated { "keyword" } else { "ALWAYS-ON" }
        );
    }
    println!(
        "\ntotal retained: {:.1} MB across {} rules",
        total as f64 / 1048576.0,
        rows.len()
    );
    println!(
        "(rule regex + its allowlist regexes per row; sequential; settings = shipping compile_pattern)"
    );
    Ok(())
}
