use anyhow::{Context, Result};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::io::Read;
#[derive(Deserialize)]
struct Release {
    tag_name: String,
}
#[derive(Deserialize)]
struct Commit {
    sha: String,
}
#[derive(Serialize)]
struct Manifest {
    tag: String,
    commit: String,
    database_sha256: String,
    source_sha256: String,
    source_url: String,
}
/// @cc [owner:ghuntley,label:supply-chain] immutable-rule-source
/// The updater MUST resolve a release to an immutable commit and derive the
/// database and license from the same downloaded source archive.
#[tokio::main]
async fn main() -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent("preflight-rules-updater")
        .timeout(std::time::Duration::from_secs(60))
        .build()?;
    let tag = match std::env::args().nth(1) {
        Some(t) => t,
        None => {
            client
                .get("https://api.github.com/repos/gitleaks/gitleaks/releases/latest")
                .send()
                .await?
                .error_for_status()?
                .json::<Release>()
                .await?
                .tag_name
        }
    };
    anyhow::ensure!(
        tag.starts_with('v')
            && tag
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
        "invalid tag"
    );
    let commit = client
        .get(format!(
            "https://api.github.com/repos/gitleaks/gitleaks/commits/{tag}"
        ))
        .send()
        .await?
        .error_for_status()?
        .json::<Commit>()
        .await?
        .sha;
    anyhow::ensure!(
        commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid commit"
    );
    let source_url = format!("https://codeload.github.com/gitleaks/gitleaks/tar.gz/{commit}");
    let mut stream = client
        .get(&source_url)
        .send()
        .await?
        .error_for_status()?
        .bytes_stream();
    let mut source = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        anyhow::ensure!(
            source.len() + chunk.len() <= 64 * 1024 * 1024,
            "source limit"
        );
        source.extend_from_slice(&chunk);
    }
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(source.as_slice()));
    let mut database = None;
    let mut license = None;
    for entry in archive.entries()? {
        let entry = entry?;
        let path = entry.path()?.into_owned();
        let relative = path.components().skip(1).collect::<std::path::PathBuf>();
        if relative == std::path::Path::new("config/gitleaks.toml")
            || relative == std::path::Path::new("LICENSE")
        {
            let mut bytes = Vec::new();
            entry.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes.len() <= 4 * 1024 * 1024, "file limit");
            if relative.ends_with("gitleaks.toml") {
                database = Some(bytes);
            } else {
                license = Some(bytes);
            }
        }
    }
    let database = database.context("missing database")?;
    let license = license.context("missing license")?;
    let _: toml::Value = toml::from_str(std::str::from_utf8(&database)?)?;
    let manifest = Manifest {
        tag,
        commit,
        database_sha256: preflight::digest(&database),
        source_sha256: preflight::digest(&source),
        source_url,
    };
    let directory = std::env::current_dir()?.join("vendor/gitleaks");
    anyhow::ensure!(directory.is_dir(), "run updater from a preflight checkout");
    std::fs::write(directory.join("gitleaks.toml"), database)?;
    std::fs::write(directory.join("LICENSE"), license)?;
    std::fs::write(
        directory.join("upstream.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    println!("{}", serde_json::to_string(&manifest)?);
    Ok(())
}
