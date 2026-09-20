use preflight::scanner::Scanner;
use serde::Deserialize;
use std::{
    collections::HashSet,
    io::Write,
    process::{Command, Stdio},
};

#[derive(Deserialize)]
struct Finding {
    #[serde(rename = "RuleID")]
    rule_id: String,
}

#[test]
fn pinned_database_github_semantics_match_upstream_on_fixture_corpus() {
    let scanner = Scanner::configured(HashSet::new(), HashSet::new(), true).unwrap();
    let suffix = preflight::digest(b"deterministic differential fixture");
    let secret = format!("ghp_{}", &suffix[..36]);
    let samples = [
        format!("credential: {secret}"),
        "let api_key_name = \"fixture\"; // no credential".into(),
        format!("unicode λ \"{secret}\""),
        "ghp_too_short".into(),
        "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
    ];
    let dir = tempfile::tempdir().unwrap();
    for (index, text) in samples.iter().enumerate() {
        let report = dir.path().join(format!("report-{index}.json"));
        let mut child = Command::new("gitleaks")
            .args([
                "stdin",
                "--no-banner",
                "--redact",
                "--report-format",
                "json",
                "--enable-rule",
                "github-pat",
                "--config",
            ])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/vendor/gitleaks/gitleaks.toml"
            ))
            .arg("--report-path")
            .arg(&report)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("gitleaks is a mandatory devenv test dependency");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        let status = child.wait().unwrap();
        assert!(
            matches!(status.code(), Some(0 | 1)),
            "reference detector failed"
        );
        let findings: Vec<Finding> =
            serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
        let expected = findings.iter().any(|f| f.rule_id == "github-pat");
        assert_eq!(
            scanner.scan(text).iter().any(|f| f.rule == "github-pat"),
            expected,
            "fixture {index}"
        );
    }
}
