use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Deserialize)]
struct Database {
    rules: Vec<RawRule>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    ids: HashSet<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    regex: Option<String>,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default, rename = "secretGroup")]
    secret_group: usize,
    #[serde(default)]
    entropy: f64,
    path: Option<String>,
    #[serde(default)]
    required: Vec<toml::Value>,
    #[serde(default, rename = "skipReport")]
    skip_report: bool,
    #[serde(rename = "description")]
    _description: Option<String>,
    #[serde(rename = "tags")]
    _tags: Option<Vec<String>>,
    #[serde(rename = "allowlist")]
    _allowlist: Option<toml::Value>,
    #[serde(rename = "allowlists")]
    _allowlists: Option<Vec<toml::Value>>,
}
struct Rule {
    id: String,
    regex: Regex,
    keywords: Vec<String>,
    group: usize,
    entropy: f64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub rule: String,
    pub start: usize,
    pub end: usize,
}
pub struct Scanner {
    rules: Vec<Rule>,
    hashes: HashSet<String>,
    stopwords: HashSet<String>,
    pub profile: String,
    wrapped_jwt: Regex,
}

impl Scanner {
    pub fn new(hashes: HashSet<String>) -> Result<Self> {
        Self::configured(hashes, HashSet::new(), false)
    }
    pub fn configured(
        hashes: HashSet<String>,
        stopwords: HashSet<String>,
        upstream_entropy: bool,
    ) -> Result<Self> {
        let raw = include_str!("../vendor/gitleaks/gitleaks.toml");
        let db: Database = toml::from_str(raw)?;
        let profile_text = include_str!("../rules/default-profile.toml");
        let profile: Profile = toml::from_str(profile_text)?;
        let mut missing = profile.ids.clone();
        let mut seen = HashSet::new();
        let mut rules = Vec::new();
        for r in db.rules {
            anyhow::ensure!(seen.insert(r.id.clone()), "duplicate upstream rule id");
            let enabled = profile.ids.contains(&r.id);
            if enabled {
                missing.remove(&r.id);
                anyhow::ensure!(
                    r.path.is_none() && r.required.is_empty() && !r.skip_report,
                    "unsupported enabled rule constraints"
                );
                let pattern = r.regex.context("enabled rule has no regex")?;
                let pattern = pattern
                    .replace(r"\w", "[A-Za-z0-9_]")
                    .replace(r"\b", r"(?-u:\b)");
                let regex = Regex::new(&pattern)?;
                anyhow::ensure!(
                    r.secret_group < regex.captures_len(),
                    "invalid capture group"
                );
                rules.push(Rule {
                    id: r.id,
                    regex,
                    keywords: r
                        .keywords
                        .into_iter()
                        .map(|s| s.to_ascii_lowercase())
                        .collect(),
                    group: r.secret_group,
                    entropy: if upstream_entropy { r.entropy } else { 0.0 },
                });
            }
        }
        anyhow::ensure!(missing.is_empty(), "enabled rules missing upstream");
        for (id, pattern, keyword) in [
            (
                "openrouter-api-key",
                r"\bsk-or-v1-[a-fA-F0-9]{64}\b",
                "sk-or-v1-",
            ),
            (
                "private-key-fragment",
                r"(?is)-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-----|$)",
                "-----begin",
            ),
        ] {
            rules.push(Rule {
                id: id.into(),
                regex: Regex::new(pattern)?,
                keywords: vec![keyword.into()],
                group: 0,
                entropy: 0.0,
            });
        }
        let mut sorted: Vec<_> = hashes.iter().cloned().collect();
        sorted.sort();
        let mut words: Vec<_> = stopwords.iter().cloned().collect();
        words.sort();
        let profile = crate::digest(
            format!(
                "v4:{raw}:{profile_text}:{}:{}:{upstream_entropy}:{}",
                sorted.join(","),
                words.join("\0"),
                crate::digest(include_bytes!("scanner.rs"))
            )
            .as_bytes(),
        );
        Ok(Self {
            rules,
            hashes,
            stopwords,
            profile,
            wrapped_jwt: Regex::new(
                r"(?-u:\b)ey[A-Za-z0-9_+/\r\n\t -]{17,2048}\.[ \t\r\n]*ey[A-Za-z0-9_+/\r\n\t -]{17,4096}\.[A-Za-z0-9_+/=\r\n\t -]{10,2048}",
            )?,
        })
    }
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let lower = text.to_ascii_lowercase();
        let mut found = Vec::new();
        for rule in &self.rules {
            if !rule.keywords.is_empty() && !rule.keywords.iter().any(|k| lower.contains(k)) {
                continue;
            }
            for captures in rule.regex.captures_iter(text) {
                let m = if rule.group > 0 {
                    captures.get(rule.group)
                } else {
                    (1..captures.len())
                        .find_map(|i| captures.get(i).filter(|m| !m.is_empty()))
                        .or_else(|| captures.get(0))
                };
                if let Some(m) = m
                    && !self.hashes.contains(&crate::digest(m.as_str().as_bytes()))
                    && !self.stopwords.contains(m.as_str())
                    && (rule.entropy == 0.0 || entropy(m.as_str()) > rule.entropy)
                {
                    found.push(Finding {
                        rule: rule.id.clone(),
                        start: m.start(),
                        end: m.end(),
                    });
                }
            }
        }
        // Normalize only bounded three-segment candidates, never whole prompts.
        for candidate in self
            .wrapped_jwt
            .find_iter(text)
            .filter(|m| m.as_str().contains('\n'))
        {
            let mut compact = String::new();
            let mut map = Vec::new();
            for (offset, ch) in candidate.as_str().char_indices() {
                if matches!(ch, '\r' | '\n' | '\t' | ' ') {
                    continue;
                }
                compact.push(ch);
                for i in 0..ch.len_utf8() {
                    map.push(candidate.start() + offset + i);
                }
            }
            if let Some(rule) = self.rules.iter().find(|r| r.id == "jwt") {
                for captures in rule.regex.captures_iter(&compact) {
                    if let Some(m) = captures.get(1).or_else(|| captures.get(0))
                        && !m.is_empty()
                        && !self.hashes.contains(&crate::digest(m.as_str().as_bytes()))
                        && !self.stopwords.contains(m.as_str())
                        && (rule.entropy == 0.0 || entropy(m.as_str()) > rule.entropy)
                    {
                        let start = map[m.start()];
                        let end = map[m.end() - 1] + 1;
                        if end - start <= 8192 && text[start..end].contains('\n') {
                            found.push(Finding {
                                rule: "jwt".into(),
                                start,
                                end,
                            });
                        }
                    }
                }
            }
        }
        found.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then(b.end.cmp(&a.end))
                .then(a.rule.cmp(&b.rule))
        });
        found.dedup();
        found
    }
    pub fn redact(&self, text: &str) -> (String, Vec<Finding>) {
        let findings = self.scan(text);
        let mut spans: Vec<Finding> = Vec::new();
        for f in &findings {
            if let Some(last) = spans.last_mut()
                && f.start < last.end
            {
                last.end = last.end.max(f.end);
                continue;
            }
            spans.push(f.clone());
        }
        let mut output = text.to_owned();
        for f in spans.iter().rev() {
            output.replace_range(f.start..f.end, &format!("[REDACTED:{}]", f.rule));
        }
        (output, findings)
    }
}
fn entropy(text: &str) -> f64 {
    let mut counts = [0usize; 256];
    for b in text.bytes() {
        counts[b as usize] += 1;
    }
    counts
        .into_iter()
        .filter(|n| *n > 0)
        .map(|n| {
            let p = n as f64 / text.len() as f64;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn embedded_rules_compile_and_redact() {
        let s = Scanner::new(HashSet::new()).unwrap();
        let token = format!("ghp_{}", "aB3d".repeat(9));
        let (out, f) = s.redact(&format!("hello {token} goodbye"));
        assert!(!f.is_empty());
        assert!(!out.contains(&token));
        assert!(out.ends_with(" goodbye"));
    }
    #[test]
    fn wrapped_jwt_preserves_surrounding_prose() {
        use base64::Engine;
        let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut jwt = format!(
            "{}.{}.{}",
            encoder.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
            encoder.encode(br#"{"sub":"synthetic-fixture","exp":1234567890}"#),
            encoder.encode(b"synthetic-signature-not-a-real-session")
        );
        jwt.insert_str(50, "\n  ");
        let scanner = Scanner::new(HashSet::new()).unwrap();
        let (redacted, findings) = scanner.redact(&format!("before '{jwt}' after"));
        assert!(findings.iter().any(|f| f.rule == "jwt"));
        assert_eq!(redacted, "before '[REDACTED:jwt]' after");
    }
    #[test]
    fn default_provider_families_have_positive_fixtures() {
        let scanner = Scanner::new(HashSet::new()).unwrap();
        let fixtures = [
            ("aws-access-token", format!("AKIA{}", "JZQW2345".repeat(2))),
            (
                "github-fine-grained-pat",
                format!("github_pat_{}", "aB9".repeat(28)[..82].to_owned()),
            ),
            (
                "openai-api-key",
                format!("sk-{}T3BlbkFJ{}", "aB39".repeat(5), "cD47".repeat(5)),
            ),
            (
                "anthropic-api-key",
                format!("sk-ant-api03-{}AA", "aB9".repeat(31)),
            ),
            ("gcp-api-key", format!("AIza{}", "aB39x".repeat(7))),
            (
                "openrouter-api-key",
                format!("sk-or-v1-{}", "abcdef09".repeat(8)),
            ),
            (
                "slack-bot-token",
                format!("xoxb-1234567890-1234567890-{}", "aBcD09".repeat(4)),
            ),
            (
                "stripe-access-token",
                format!("sk_live_{}", "aBcD09".repeat(4)),
            ),
        ];
        for (id, secret) in fixtures {
            let (redacted, found) = scanner.redact(&format!("before '{secret}' after"));
            assert!(
                found.iter().any(|f| f.rule == id),
                "missing provider fixture {id}"
            );
            assert!(!redacted.contains(&secret));
            assert!(redacted.starts_with("before '"));
            assert!(redacted.ends_with("' after"));
        }
    }
    #[test]
    fn entropy_soup_is_not_a_generic_finding() {
        let scanner = Scanner::new(HashSet::new()).unwrap();
        let text = format!(
            "const random_identifier = '{}';\nOPENAI_API_KEY=placeholder\n",
            crate::digest(b"benign source hash")
        );
        assert!(scanner.scan(&text).is_empty());
    }
}
