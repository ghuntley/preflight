//! Aggregate counters only: no client-controlled labels or content identifiers.
use std::sync::atomic::{AtomicU64, Ordering};
pub static REQUESTS: AtomicU64 = AtomicU64::new(0);
pub static REJECTED: AtomicU64 = AtomicU64::new(0);
pub static FINDINGS: AtomicU64 = AtomicU64::new(0);
pub static CACHE_HITS: AtomicU64 = AtomicU64::new(0);
pub static ATTACHMENTS: AtomicU64 = AtomicU64::new(0);
static DURATION_US: AtomicU64 = AtomicU64::new(0);
static BUCKETS: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
const LIMITS: [u64; 8] = [
    5000, 10000, 50000, 100000, 1000000, 5000000, 30000000, 180000000,
];
pub fn observe(duration: std::time::Duration, status: u16) {
    REQUESTS.fetch_add(1, Ordering::Relaxed);
    if status >= 400 {
        REJECTED.fetch_add(1, Ordering::Relaxed);
    }
    let micros = duration.as_micros().min(u64::MAX as u128) as u64;
    DURATION_US.fetch_add(micros, Ordering::Relaxed);
    for (bucket, limit) in BUCKETS.iter().zip(LIMITS) {
        if micros <= limit {
            bucket.fetch_add(1, Ordering::Relaxed);
        }
    }
}
pub fn render() -> String {
    let mut out = String::new();
    for (name, counter) in [
        ("requests_total", &REQUESTS),
        ("rejected_total", &REJECTED),
        ("findings_total", &FINDINGS),
        ("cache_hits_total", &CACHE_HITS),
        ("attachments_inspected_total", &ATTACHMENTS),
    ] {
        out.push_str(&format!(
            "# TYPE preflight_{name} counter\npreflight_{name} {}\n",
            counter.load(Ordering::Relaxed)
        ));
    }
    out.push_str("# TYPE preflight_request_to_headers_seconds histogram\n");
    for (bucket, limit) in BUCKETS.iter().zip(LIMITS) {
        out.push_str(&format!(
            "preflight_request_to_headers_seconds_bucket{{le=\"{}\"}} {}\n",
            limit as f64 / 1_000_000.0,
            bucket.load(Ordering::Relaxed)
        ));
    }
    out.push_str(&format!("preflight_request_to_headers_seconds_bucket{{le=\"+Inf\"}} {}\npreflight_request_to_headers_seconds_count {}\npreflight_request_to_headers_seconds_sum {}\n",REQUESTS.load(Ordering::Relaxed),REQUESTS.load(Ordering::Relaxed),DURATION_US.load(Ordering::Relaxed) as f64/1_000_000.0));
    out
}
