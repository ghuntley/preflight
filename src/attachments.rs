use crate::worker::Manifest as Output;
use crate::{
    cache::{Cache, Verdict},
    scanner::Scanner,
};
use anyhow::{Context, Result, bail};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::{io::AsyncReadExt, sync::Semaphore};

pub struct Attachments {
    pub scanner: Arc<Scanner>,
    pub cache: Arc<Mutex<Cache>>,
    pub slots: Arc<Semaphore>,
    pub scan_slots: Arc<Semaphore>,
    pub executable: PathBuf,
    pub sandbox: bool,
    pub allow_page_redaction: bool,
    pub toolchain_id: String,
    flights: Mutex<HashMap<String, std::sync::Weak<tokio::sync::Mutex<()>>>>,
}
pub struct Outcome {
    pub rules: Vec<String>,
    pub replacement: Option<Vec<u8>>,
}
impl Attachments {
    pub async fn check(&self) -> Result<()> {
        let temp = tempfile::tempdir()?;
        self.worker(temp.path(), "check").await?;
        Ok(())
    }
    pub fn new(
        scanner: Arc<Scanner>,
        cache: Arc<Mutex<Cache>>,
        executable: PathBuf,
        sandbox: bool,
    ) -> Self {
        Self {
            scanner,
            cache,
            slots: Arc::new(Semaphore::new(2)),
            scan_slots: Arc::new(Semaphore::new(4)),
            executable,
            sandbox,
            allow_page_redaction: false,
            toolchain_id: std::env::var("PREFLIGHT_TOOLCHAIN_ID").unwrap_or_default(),
            flights: Mutex::new(HashMap::new()),
        }
    }
    /// @cc [owner:ghuntley,label:security] artifact-inspection-complete
    /// Only successful complete worker output MAY be reused. Replacements MUST
    /// pass a fresh inspection before being returned or cached as approved bytes.
    pub async fn inspect(&self, bytes: &[u8], scope: &str, sanitize: bool) -> Result<Outcome> {
        if bytes.len() > 32 * 1024 * 1024 {
            bail!("attachment_size_limit");
        }
        if !bytes.starts_with(b"%PDF-")
            && !bytes.starts_with(b"\x89PNG")
            && !bytes.starts_with(&[0xff, 0xd8, 0xff])
        {
            let text = if bytes.starts_with(&[0xff, 0xfe]) {
                encoding_rs::UTF_16LE
                    .decode_without_bom_handling_and_without_replacement(&bytes[2..])
            } else if bytes.starts_with(&[0xfe, 0xff]) {
                encoding_rs::UTF_16BE
                    .decode_without_bom_handling_and_without_replacement(&bytes[2..])
            } else {
                std::str::from_utf8(bytes)
                    .ok()
                    .map(std::borrow::Cow::Borrowed)
            };
            if let Some(text) = text.filter(|s| {
                s.chars()
                    .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
            }) {
                let (clean, findings) = self.scanner.redact(&text);
                let rules = findings.into_iter().map(|f| f.rule).collect::<Vec<_>>();
                let replacement = if sanitize && !rules.is_empty() {
                    Some(clean.into_bytes())
                } else {
                    None
                };
                return Ok(Outcome { rules, replacement });
            }
            bail!("unsupported_attachment");
        }
        let toolchain = &self.toolchain_id;
        let cache_enabled = !toolchain.is_empty();
        let key = format!(
            "{scope}:{}",
            crate::digest(
                format!(
                    "{}:{}:{}:{}:{sanitize}:{}:{}:{}:worker-v3",
                    scope,
                    self.scanner.profile,
                    crate::digest(bytes),
                    toolchain,
                    self.allow_page_redaction,
                    self.sandbox,
                    self.executable.display()
                )
                .as_bytes(),
            )
        );
        let flight = {
            let mut map = self.flights.lock().unwrap();
            map.retain(|_, v| v.strong_count() > 0);
            let v = map
                .get(&key)
                .and_then(|v| v.upgrade())
                .unwrap_or_else(|| Arc::new(tokio::sync::Mutex::new(())));
            map.insert(key.clone(), Arc::downgrade(&v));
            v
        };
        let _flight = flight.lock().await;
        let generation = {
            let mut cache = self.cache.lock().unwrap();
            if cache_enabled && let Some((v, replacement)) = cache.get(&key) {
                tracing::info!(event = "attachment.cache_hit");
                crate::metrics::CACHE_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(Outcome {
                    rules: v.rules,
                    replacement,
                });
            }
            cache.generation()
        };
        let _slot = self.slots.acquire().await?;
        let temp = tempfile::tempdir()?;
        tokio::fs::write(temp.path().join("input"), bytes).await?;
        let output = self.worker(temp.path(), "inspect").await?;
        let mut rules = vec![];
        let mut selected = vec![];
        let mut unmapped = vec![];
        let mut visual = std::collections::HashSet::new();
        for segment in &output.segments {
            if segment.bounds.is_some() {
                for finding in self.scanner.scan(&segment.text) {
                    visual.insert((
                        segment.page,
                        crate::digest(&segment.text.as_bytes()[finding.start..finding.end]),
                    ));
                }
            }
        }
        for (index, segment) in output.segments.iter().enumerate() {
            let found = self.scanner.scan(&segment.text);
            if found.is_empty() {
                continue;
            }
            rules.extend(found.iter().map(|f| f.rule.clone()));
            if segment.page.is_some() && segment.bounds.is_none() {
                if found.iter().all(|f| {
                    visual.contains(&(
                        segment.page,
                        crate::digest(&segment.text.as_bytes()[f.start..f.end]),
                    ))
                }) {
                    continue;
                }
                if !self.allow_page_redaction {
                    unmapped.push(index);
                    continue;
                }
            }
            selected.push(index);
        }
        rules.sort();
        rules.dedup();
        let replacement = if sanitize && !rules.is_empty() && unmapped.is_empty() {
            tokio::fs::write(
                temp.path().join("redactions.json"),
                serde_json::to_vec(&selected)?,
            )
            .await?;
            self.worker(temp.path(), "sanitize").await?;
            let artifact = tokio::fs::read(temp.path().join("replacement")).await?;
            if artifact.len() > 64 * 1024 * 1024 {
                bail!("replacement_limit");
            }
            let check = tempfile::tempdir()?;
            tokio::fs::write(check.path().join("input"), &artifact).await?;
            let verified = self.worker(check.path(), "inspect").await?;
            if verified
                .segments
                .iter()
                .any(|s| !self.scanner.scan(&s.text).is_empty())
            {
                bail!("replacement_not_clean");
            }
            Some(artifact)
        } else {
            None
        };
        if cache_enabled {
            let verdict = Verdict {
                rules: rules.clone(),
                ..Default::default()
            };
            if self
                .cache
                .lock()
                .unwrap()
                .put(&key, generation, verdict, replacement.as_deref())
                .is_err()
            {
                tracing::warn!(event = "cache.write_failed");
            }
        }
        tracing::info!(
            event = "attachment.inspected",
            finding_count = rules.len(),
            rebuilt = replacement.is_some()
        );
        crate::metrics::ATTACHMENTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(Outcome { rules, replacement })
    }
    async fn worker(&self, job: &Path, action: &str) -> Result<Output> {
        let mut command = if self.sandbox {
            let mut c = tokio::process::Command::new("bwrap");
            c.args([
                "--die-with-parent",
                "--unshare-all",
                "--new-session",
                "--ro-bind",
                "/nix/store",
                "/nix/store",
                "--dir",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
            ]);
            c.arg("--ro-bind").arg(&self.executable).arg("/worker");
            c.arg("--bind").arg(job).arg("/job");
            c.args(["/worker", "/job"]);
            c
        } else {
            let mut c = tokio::process::Command::new(&self.executable);
            c.arg(job);
            c
        };
        command.arg(action);
        let tool_path =
            std::env::var("PREFLIGHT_WORKER_PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());
        command
            .env_clear()
            .env("PATH", tool_path)
            .env("OMP_THREAD_LIMIT", "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().context("worker_unavailable")?;
        let mut stdout = child
            .stdout
            .take()
            .context("worker_stdout")?
            .take(16 * 1024 * 1024 + 1);
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).await?;
            if bytes.len() > 16 * 1024 * 1024 {
                bail!("worker_output_limit");
            }
            if !child.wait().await?.success() {
                bail!("attachment_inspection_incomplete");
            }
            let out: Output = serde_json::from_slice(&bytes)?;
            if !out.complete {
                bail!("attachment_inspection_incomplete");
            }
            Ok(out)
        })
        .await
        .context("attachment_timeout")?
    }
}
