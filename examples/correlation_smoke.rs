//! Exercise the real preflight and underclass binaries with isolated local state.
use anyhow::{Context, Result, ensure};
use std::{path::Path, process::Stdio};

fn port() -> Result<std::net::SocketAddr> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?)
}
fn request_id(response: &reqwest::Response) -> Result<String> {
    let value = response
        .headers()
        .get("x-request-id")
        .context("missing request ID")?
        .to_str()?;
    ensure!(
        uuid::Uuid::parse_str(value)?.get_version() == Some(uuid::Version::Random),
        "invalid request ID"
    );
    ensure!(
        !response.headers().contains_key("x-preflight-request-id"),
        "obsolete header returned"
    );
    Ok(value.into())
}
async fn wait(client: &reqwest::Client, url: &str) -> Result<()> {
    for _ in 0..300 {
        if client.get(url).send().await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    anyhow::bail!("proxy did not become ready")
}
fn logged(text: &str, id: &str) -> bool {
    text.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .any(|v| v["fields"]["request_id"] == id || v["span"]["request_id"] == id)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    ensure!(
        args.len() == 3,
        "usage: correlation_smoke UNDERCLASS_BINARY PREFLIGHT_BINARY"
    );
    let underclass = std::fs::canonicalize(Path::new(&args[1]))?;
    let preflight = std::fs::canonicalize(Path::new(&args[2]))?;
    let temp = tempfile::tempdir()?;
    let underclass_addr = port()?;
    let preflight_addr = port()?;
    let underclass_log = temp.path().join("underclass.log");
    let preflight_log = temp.path().join("preflight.log");
    let mut uc = tokio::process::Command::new(underclass)
        .args([
            "--log-format",
            "json",
            "serve",
            "--bind",
            &underclass_addr.to_string(),
        ])
        .env(
            "UNDERCLASS_CONFIG_DIR",
            temp.path().join("underclass-config"),
        )
        .env("UNDERCLASS_DATA_DIR", temp.path().join("underclass-data"))
        .env("UNDERCLASS_PROXY_KEY", "fixture-proxy-key")
        .env("UNDERCLASS_UI_TOKEN", "fixture-ui-token")
        .env("RUST_LOG", "info")
        .stdout(std::fs::File::create(&underclass_log)?)
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let uc_base = format!("http://{underclass_addr}");
    wait(&client, &format!("{uc_base}/v1/models")).await?;
    let config = temp.path().join("preflight.toml");
    std::fs::write(
        &config,
        format!(
            "bind = '{preflight_addr}'\nupstream = '{uc_base}'\nmode = 'no-go'\ncache_dir = '{}'\ncontrol_socket = '{}'\n",
            temp.path().join("cache").display(),
            temp.path().join("control.sock").display()
        ),
    )?;
    let mut pf = tokio::process::Command::new(preflight)
        .args(["serve", "--config"])
        .arg(&config)
        .env_remove("PREFLIGHT_CLIENT_KEY")
        .env("PREFLIGHT_UPSTREAM_KEY", "fixture-proxy-key")
        .env("RUST_LOG", "info")
        .stdout(std::fs::File::create(&preflight_log)?)
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let base = format!("http://{preflight_addr}");
    wait(&client, &format!("{base}/readyz")).await?;
    let response = client
        .get(format!("{base}/v1/models"))
        .header("x-request-id", "client-supplied-id")
        .send()
        .await?;
    ensure!(response.status().is_success(), "model discovery failed");
    let models_id = request_id(&response)?;
    response.bytes().await?;
    let response = client
        .post(format!("{base}/v1/responses"))
        .json(&serde_json::json!({"model":"test-model","input":"hello"}))
        .send()
        .await?;
    ensure!(
        response.status() == 503,
        "isolated underclass should have no accounts"
    );
    let shared_id = request_id(&response)?;
    response.bytes().await?;
    let secret = format!("ghp_{}", "aB39".repeat(9));
    let response = client
        .post(format!("{base}/v1/responses"))
        .json(&serde_json::json!({"input":secret}))
        .send()
        .await?;
    ensure!(response.status() == 409, "secret was not blocked");
    let blocked_id = request_id(&response)?;
    response.bytes().await?;
    let response = client
        .post(format!("{base}/v1/responses"))
        .body("{invalid")
        .send()
        .await?;
    ensure!(
        response.status() == 400,
        "malformed request was not rejected"
    );
    let malformed_id = request_id(&response)?;
    response.bytes().await?;
    let response = client
        .get(format!("{uc_base}/v1/models"))
        .header("x-request-id", "client-supplied-id")
        .send()
        .await?;
    ensure!(
        response.status() == 401,
        "unauthenticated underclass request was not rejected"
    );
    let auth_id = request_id(&response)?;
    response.bytes().await?;
    pf.kill().await?;
    uc.kill().await?;
    let pf_logs = std::fs::read_to_string(preflight_log)?;
    let uc_logs = std::fs::read_to_string(underclass_log)?;
    for id in [&models_id, &shared_id] {
        ensure!(
            logged(&pf_logs, id) && logged(&uc_logs, id),
            "shared request ID missing from proxy logs"
        );
    }
    for id in [&blocked_id, &malformed_id] {
        ensure!(
            logged(&pf_logs, id) && !logged(&uc_logs, id),
            "blocked request crossed the proxy boundary"
        );
    }
    ensure!(
        logged(&uc_logs, &auth_id),
        "authentication failure was not correlated"
    );
    ensure!(
        !pf_logs.contains("client-supplied-id") && !uc_logs.contains("client-supplied-id"),
        "untrusted ID entered logs"
    );
    ensure!(
        !pf_logs.contains(&secret) && !uc_logs.contains(&secret),
        "secret entered logs"
    );
    println!(
        "{}",
        serde_json::json!({"passed":true,"shared_request_id":shared_id,"blocked_request_id":blocked_id,"models_request_id":models_id})
    );
    Ok(())
}
