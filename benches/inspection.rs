use preflight::scanner::Scanner;
use std::{collections::HashSet, time::Instant};

fn main() {
    let scanner = Scanner::new(HashSet::new()).unwrap();
    let corpus = "Review this Rust source and explain its behavior.\nfn public_method(value: usize) -> usize { value.saturating_add(1) }\n";
    for size in [100 * 1024, 1024 * 1024] {
        let mut source = corpus.repeat(size / corpus.len() + 1);
        source.truncate(size);
        let mut micros = Vec::new();
        for _ in 0..30 {
            let start = Instant::now();
            assert!(scanner.scan(std::hint::black_box(&source)).is_empty());
            micros.push(start.elapsed().as_micros());
        }
        micros.sort();
        let p95 = micros[28];
        println!(
            "{}",
            serde_json::json!({"bytes":size,"p50_us":micros[15],"p95_us":p95,"profile":scanner.profile})
        );
        // Broad regression ceiling, not a deployment latency guarantee.
        assert!(p95 < 1_000_000, "text inspection exceeded one second");
    }
}
