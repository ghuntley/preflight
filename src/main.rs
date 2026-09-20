use anyhow::Result;
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::{Parser, Subcommand, ValueEnum};
use preflight::{attachments::Attachments, cache::Cache, document, scanner::Scanner};
use serde::Deserialize;
use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tracing::Instrument;
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone, Copy, Deserialize, ValueEnum, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
enum Mode {
    #[default]
    Redact,
    NoGo,
    Advisory,
}
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Serve {
        #[arg(long, env = "PREFLIGHT_CONFIG")]
        config: Option<PathBuf>,
    },
    Check {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Cache {
        #[arg(value_parser=["status","purge"])]
        action: String,
        #[arg(long)]
        scope: Option<String>,
        #[arg(
            long,
            env = "PREFLIGHT_CONTROL",
            default_value = "/tmp/preflight-control.sock"
        )]
        socket: PathBuf,
    },
}
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    bind: String,
    upstream: String,
    mode: Mode,
    cache_dir: PathBuf,
    control_socket: PathBuf,
    worker: PathBuf,
    sandbox: bool,
    carnet: Option<PathBuf>,
    allow_page_redaction: bool,
    cache: preflight::cache::Limits,
    resolver: preflight::resolver::Resolver,
    stopwords: HashSet<String>,
    upstream_entropy: bool,
    max_body_bytes: usize,
    request_timeout_secs: u64,
}
impl Default for Config {
    fn default() -> Self {
        let base = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".cache")
            });
        Self {
            bind: "127.0.0.1:8081".into(),
            upstream: "http://127.0.0.1:8080".into(),
            mode: Mode::Redact,
            cache_dir: base.join("preflight"),
            control_socket: "/tmp/preflight-control.sock".into(),
            worker: std::env::var_os("PREFLIGHT_WORKER")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::current_exe()
                        .unwrap_or_default()
                        .with_file_name("preflight-worker")
                }),
            sandbox: true,
            carnet: None,
            allow_page_redaction: false,
            cache: Default::default(),
            resolver: Default::default(),
            stopwords: HashSet::new(),
            upstream_entropy: false,
            max_body_bytes: 64 * 1024 * 1024,
            request_timeout_secs: 180,
        }
    }
}
struct App {
    config: Config,
    scanner: Arc<Scanner>,
    attachments: Attachments,
    client: reqwest::Client,
    client_key: Option<String>,
    upstream_key: Option<String>,
    admission: Arc<tokio::sync::Semaphore>,
}
struct Live {
    current: RwLock<Arc<App>>,
}
impl Live {
    fn snapshot(&self) -> Arc<App> {
        self.current.read().unwrap().clone()
    }
}

fn load(path: Option<PathBuf>) -> Result<Config> {
    let mut c: Config = match path {
        Some(p) => toml::from_str(&std::fs::read_to_string(p)?)?,
        None => Config::default(),
    };
    c.resolver.file_api_key = std::env::var("PREFLIGHT_FILE_API_KEY").ok();
    let url = reqwest::Url::parse(&c.upstream)?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none(),
        "invalid upstream"
    );
    anyhow::ensure!(
        c.max_body_bytes > 0 && c.max_body_bytes <= 64 * 1024 * 1024 && c.request_timeout_secs > 0,
        "invalid limits"
    );
    Ok(c)
}
fn scanner(config: &Config) -> Result<Scanner> {
    let hashes = match &config.carnet {
        Some(p) => {
            let v: HashSet<String> = serde_json::from_slice(&std::fs::read(p)?)?;
            anyhow::ensure!(
                v.iter()
                    .all(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())),
                "invalid carnet"
            );
            v.into_iter().map(|s| s.to_lowercase()).collect()
        }
        None => HashSet::new(),
    };
    Scanner::configured(hashes, config.stopwords.clone(), config.upstream_entropy)
}
#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(false)
                .with_filter(tracing_subscriber::filter::filter_fn(|m| {
                    m.target().starts_with("preflight")
                })),
        )
        .init();
    if run().await.is_err() {
        tracing::error!(event = "startup.failed");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    match Cli::parse().command {
        Commands::Cache {
            action,
            socket,
            scope,
        } => {
            let action = if let Some(scope) = scope {
                anyhow::ensure!(
                    action == "purge"
                        && scope.len() == 64
                        && scope.bytes().all(|b| b.is_ascii_hexdigit()),
                    "invalid scope"
                );
                format!("purge {scope}")
            } else {
                action
            };
            let mut stream = tokio::net::UnixStream::connect(socket).await?;
            stream.write_all(format!("{action}\n").as_bytes()).await?;
            let mut response = String::new();
            BufReader::new(stream.take(4096))
                .read_line(&mut response)
                .await?;
            print!("{response}");
            Ok(())
        }
        Commands::Check { config } => {
            let c = load(config)?;
            let s = scanner(&c)?;
            println!("{{\"valid\":true,\"profile\":\"{}\"}}", s.profile);
            Ok(())
        }
        Commands::Serve { config } => {
            let config_path = config.clone();
            let config = load(config)?;
            let scanner = Arc::new(scanner(&config)?);
            let cache = Arc::new(Mutex::new(Cache::with_limits(
                &config.cache_dir,
                config.cache.clone(),
            )?));
            let control = bind_control(&config.control_socket).await?;
            let cc = cache.clone();
            tokio::spawn(async move {
                while let Ok((stream, _)) = control.accept().await {
                    let cc = cc.clone();
                    tokio::spawn(async move {
                        let (read, mut write) = stream.into_split();
                        let mut line = String::new();
                        let read = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            BufReader::new(read.take(128)).read_line(&mut line),
                        )
                        .await;
                        let result = if matches!(read, Ok(Ok(_))) && line.len() < 128 {
                            let mut cache = cc.lock().unwrap();
                            match line.trim() {
                                "purge" => {
                                    cache.purge().map(|_| serde_json::json!({"purged":true}))
                                }
                                "status" => cache.count().map(|n| serde_json::json!({"entries":n})),
                                command if command.starts_with("purge ") => cache
                                    .purge_scope(&command[6..])
                                    .map(|_| serde_json::json!({"purged":true})),
                                _ => Err(anyhow::anyhow!("command")),
                            }
                        } else {
                            Err(anyhow::anyhow!("command"))
                        };
                        let response = result.unwrap_or_else(
                            |_| serde_json::json!({"error":"cache_command_failed"}),
                        );
                        let _ = write.write_all(format!("{response}\n").as_bytes()).await;
                    });
                }
            });
            let sweep_cache = cache.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
                loop {
                    interval.tick().await;
                    if sweep_cache.lock().unwrap().sweep().is_err() {
                        tracing::warn!(event = "cache.sweep_failed");
                    }
                }
            });
            let mut attachments = Attachments::new(
                scanner.clone(),
                cache,
                config.worker.clone(),
                config.sandbox,
            );
            attachments.allow_page_redaction = config.allow_page_redaction;
            attachments.check().await?;
            let listener = tokio::net::TcpListener::bind(&config.bind).await?;
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()?;
            tracing::info!(event="service.ready",profile=%scanner.profile);
            let app = Arc::new(App {
                config,
                scanner,
                attachments,
                client,
                client_key: std::env::var("PREFLIGHT_CLIENT_KEY").ok(),
                upstream_key: std::env::var("PREFLIGHT_UPSTREAM_KEY").ok(),
                admission: Arc::new(tokio::sync::Semaphore::new(16)),
            });
            let live = Arc::new(Live {
                current: RwLock::new(app),
            });
            let reload_state = live.clone();
            let mut hangup =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
            tokio::spawn(async move {
                while hangup.recv().await.is_some() {
                    if reload(&reload_state, config_path.clone()).await.is_err() {
                        tracing::warn!(event = "configuration.reload_failed");
                    }
                }
            });
            let router = Router::new()
                .route("/healthz", get(|| async { "ok" }))
                .route("/readyz", get(|| async { "ok" }))
                .route(
                    "/metrics",
                    get(|| async {
                        (
                            [("content-type", "text/plain; version=0.0.4")],
                            preflight::metrics::render(),
                        )
                    }),
                )
                .route("/v1/models", get(models))
                .route("/v1/responses", post(infer))
                .route("/v1/chat/completions", post(infer))
                .with_state(live);
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
            Ok(())
        }
    }
}
/// @cc [owner:ghuntley,label:security] atomic-profile-reload
/// A failed reload MUST leave the previous runtime active. Admitted requests MUST
/// retain their immutable runtime snapshot through approval and forwarding.
async fn reload(live: &Live, path: Option<PathBuf>) -> Result<()> {
    let old = live.snapshot();
    let config = load(path)?;
    anyhow::ensure!(
        config.bind == old.config.bind
            && config.cache_dir == old.config.cache_dir
            && config.control_socket == old.config.control_socket
            && config.cache == old.config.cache,
        "restart_required"
    );
    let scanner = Arc::new(scanner(&config)?);
    let mut attachments = Attachments::new(
        scanner.clone(),
        old.attachments.cache.clone(),
        config.worker.clone(),
        config.sandbox,
    );
    attachments.allow_page_redaction = config.allow_page_redaction;
    attachments.slots = old.attachments.slots.clone();
    attachments.scan_slots = old.attachments.scan_slots.clone();
    attachments.check().await?;
    tracing::info!(event="configuration.reloaded",profile=%scanner.profile);
    *live.current.write().unwrap() = Arc::new(App {
        config,
        scanner,
        attachments,
        client: old.client.clone(),
        client_key: old.client_key.clone(),
        upstream_key: old.upstream_key.clone(),
        admission: old.admission.clone(),
    });
    Ok(())
}
async fn bind_control(path: &std::path::Path) -> Result<tokio::net::UnixListener> {
    if path.exists() {
        anyhow::ensure!(
            tokio::net::UnixStream::connect(path).await.is_err(),
            "service already active"
        );
        use std::os::unix::fs::FileTypeExt;
        anyhow::ensure!(
            std::fs::symlink_metadata(path)?.file_type().is_socket(),
            "control path occupied"
        );
        std::fs::remove_file(path)?;
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}
fn error(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        axum::Json(
            serde_json::json!({"error":{"type":"preflight_error","code":code,"message":code}}),
        ),
    )
        .into_response()
}
fn authorized(app: &App, h: &HeaderMap) -> bool {
    app.client_key.as_ref().is_none_or(|k| {
        h.get("authorization")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == format!("Bearer {k}"))
    })
}
struct ApprovedRequest {
    bytes: Vec<u8>,
}
/// @cc [owner:ghuntley,label:security] approval-gate
/// Enforcing modes MUST reject binary findings that lack a sanitized replacement;
/// no-go MUST reject every non-allowlisted finding before constructing approval.
fn approve(
    original: &[u8],
    inspection: document::Inspection,
    mode: Mode,
    finding_ids: &[String],
) -> std::result::Result<ApprovedRequest, Box<Response>> {
    if mode != Mode::Advisory
        && (!inspection.rules.is_empty() && mode == Mode::NoGo || inspection.unsafe_findings)
    {
        return Err(Box::new((StatusCode::CONFLICT,axum::Json(serde_json::json!({"error":{"type":"preflight_error","code":"secrets_detected","finding_ids":finding_ids}}))).into_response()));
    }
    let bytes = if mode == Mode::Redact && inspection.changed {
        serde_json::to_vec(&inspection.body)
            .map_err(|_| Box::new(error(StatusCode::BAD_REQUEST, "serialization_failed")))?
    } else {
        original.to_vec()
    };
    Ok(ApprovedRequest { bytes })
}
async fn infer(State(live): State<Arc<Live>>, req: Request) -> Response {
    let app = live.snapshot();
    let Ok(_permit) = app.admission.try_acquire() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "inspection_capacity");
    };
    let id = uuid::Uuid::new_v4().to_string();
    let start = std::time::Instant::now();
    let mut response = match tokio::time::timeout(
        std::time::Duration::from_secs(app.config.request_timeout_secs),
        inspect_and_forward(&app, req)
            .instrument(tracing::info_span!("request",request_id=%id,profile=%app.scanner.profile)),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => error(StatusCode::REQUEST_TIMEOUT, "inspection_deadline"),
    };
    response
        .headers_mut()
        .insert("x-preflight-request-id", id.parse().unwrap());
    tracing::info!(event="request.policy_completed",request_id=%id,status=response.status().as_u16(),duration_ms=start.elapsed().as_millis() as u64);
    preflight::metrics::observe(start.elapsed(), response.status().as_u16());
    response
}
async fn inspect_and_forward(app: &App, req: Request) -> Response {
    if !authorized(app, req.headers()) {
        return error(StatusCode::UNAUTHORIZED, "authentication_failed");
    }
    if req.headers().contains_key("content-encoding") {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content_encoding_unsupported",
        );
    }
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, app.config.max_body_bytes).await {
        Ok(b) => b,
        Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "body_limit"),
    };
    let mut value = match document::parse(&bytes) {
        Ok(v) if v.is_object() => v,
        _ => return error(StatusCode::BAD_REQUEST, "invalid_json"),
    };
    let materialized = match app.config.resolver.materialize(&mut value).await {
        Ok(c) => c,
        Err(_) => {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "attachment_resolution_failed",
            );
        }
    };
    let scope = preflight::digest(
        parts
            .headers
            .get("authorization")
            .map(|v| v.as_bytes())
            .unwrap_or(b"local"),
    );
    let mut inspection = match document::inspect(
        value,
        &app.scanner,
        &app.attachments,
        &scope,
        app.config.mode == Mode::Redact,
    )
    .await
    {
        Ok(v) => v,
        Err(_) => return error(StatusCode::UNPROCESSABLE_ENTITY, "inspection_incomplete"),
    };
    inspection.changed |= materialized;
    // No-go clean requests also need their inspected references materialized.
    let original = if materialized && app.config.mode == Mode::NoGo {
        match serde_json::to_vec(&inspection.body) {
            Ok(v) => v,
            Err(_) => return error(StatusCode::BAD_REQUEST, "serialization_failed"),
        }
    } else {
        bytes.to_vec()
    };
    tracing::info!(
        event = "inspection.completed",
        finding_count = inspection.rules.len()
    );
    preflight::metrics::FINDINGS.fetch_add(
        inspection.rules.len() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );
    let ids: Vec<String> = document::unique_rules(&inspection.rules)
        .into_iter()
        .map(|rule| {
            let id = uuid::Uuid::new_v4().to_string();
            tracing::warn!(event="inspection.finding",finding_id=%id,rule_id=%rule);
            id
        })
        .collect();
    let finding_count = inspection.rules.len();
    let mut response = match approve(&original, inspection, app.config.mode, &ids) {
        Ok(approved) => forward(app, parts.uri.path(), parts.headers, Some(approved)).await,
        Err(r) => *r,
    };
    response.headers_mut().insert(
        "x-preflight-finding-count",
        finding_count.to_string().parse().unwrap(),
    );
    response
}
async fn models(State(live): State<Arc<Live>>, req: Request) -> Response {
    let app = live.snapshot();
    if !authorized(&app, req.headers()) {
        return error(StatusCode::UNAUTHORIZED, "authentication_failed");
    }
    forward(&app, "/v1/models", req.headers().clone(), None).await
}
fn strip_headers(headers: &mut HeaderMap) {
    let nominated: Vec<String> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|s| s.trim().to_owned()))
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    ] {
        headers.remove(name);
    }
}
/// @cc [owner:ghuntley,label:security] forward-approved-only
/// Inference body bytes MUST originate from ApprovedRequest. Redirects MUST NOT
/// resend inference content to a different destination.
async fn forward(
    app: &App,
    path: &str,
    mut headers: HeaderMap,
    body: Option<ApprovedRequest>,
) -> Response {
    strip_headers(&mut headers);
    headers.remove("accept-encoding");
    if let Some(key) = &app.upstream_key {
        match format!("Bearer {key}").parse() {
            Ok(v) => {
                headers.insert("authorization", v);
            }
            Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "upstream_configuration"),
        }
    }
    let url = format!("{}{}", app.config.upstream.trim_end_matches('/'), path);
    let request = match body {
        Some(b) => app.client.post(url).headers(headers).body(b.bytes),
        None => app.client.get(url).headers(headers),
    };
    match request.send().await {
        Ok(upstream) => {
            let status = upstream.status();
            if status.is_redirection() {
                return error(StatusCode::BAD_GATEWAY, "upstream_redirect_rejected");
            }
            let mut headers = upstream.headers().clone();
            strip_headers(&mut headers);
            let stream = ObservedStream {
                inner: Box::pin(upstream.bytes_stream()),
                span: tracing::Span::current(),
                finished: false,
                bytes: 0,
                started: std::time::Instant::now(),
            };
            let mut response = Response::new(Body::from_stream(stream));
            *response.status_mut() = status;
            *response.headers_mut() = headers;
            response
        }
        Err(_) => error(StatusCode::BAD_GATEWAY, "upstream_unavailable"),
    }
}
struct ObservedStream {
    inner: std::pin::Pin<
        Box<
            dyn futures::Stream<Item = std::result::Result<axum::body::Bytes, reqwest::Error>>
                + Send,
        >,
    >,
    span: tracing::Span,
    finished: bool,
    bytes: u64,
    started: std::time::Instant,
}
impl futures::Stream for ObservedStream {
    type Item = std::result::Result<axum::body::Bytes, reqwest::Error>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let result = self.inner.as_mut().poll_next(cx);
        match &result {
            std::task::Poll::Ready(Some(Ok(bytes))) => self.bytes += bytes.len() as u64,
            std::task::Poll::Ready(Some(Err(_))) => {
                self.finished = true;
                let _entered = self.span.enter();
                tracing::warn!(event = "response.stream_failed");
            }
            std::task::Poll::Ready(None) => {
                self.finished = true;
                let _entered = self.span.enter();
                tracing::info!(
                    event = "response.completed",
                    bytes = self.bytes,
                    duration_ms = self.started.elapsed().as_millis() as u64
                );
            }
            _ => {}
        }
        result
    }
}
impl Drop for ObservedStream {
    fn drop(&mut self) {
        if !self.finished {
            let _entered = self.span.enter();
            tracing::info!(event = "response.cancelled", bytes = self.bytes);
        }
    }
}

#[cfg(test)]
mod policy_properties {
    use super::*;
    use hegel::{TestCase, generators as gs};
    #[hegel::test]
    fn enforcing_policy_never_approves_unrewritable_findings(tc: TestCase) {
        let count = tc.draw(gs::integers::<usize>().min_value(1).max_value(20));
        let no_go = tc.draw(gs::integers::<u8>().min_value(0).max_value(1)) == 1;
        let inspection = document::Inspection {
            body: serde_json::json!({"input":"sanitized"}),
            rules: vec!["test-rule".into(); count],
            changed: true,
            unsafe_findings: true,
        };
        let mode = if no_go { Mode::NoGo } else { Mode::Redact };
        assert!(approve(b"original", inspection, mode, &["opaque".into()]).is_err());
    }
    #[hegel::test]
    fn advisory_always_preserves_original_bytes_after_complete_inspection(tc: TestCase) {
        let text = tc.draw(gs::text());
        let original = serde_json::to_vec(&serde_json::json!({"input":text})).unwrap();
        let inspection = document::Inspection {
            body: serde_json::json!({"input":"changed"}),
            rules: vec!["test-rule".into()],
            changed: true,
            unsafe_findings: true,
        };
        let approved = approve(&original, inspection, Mode::Advisory, &[]).unwrap();
        assert_eq!(approved.bytes, original);
    }
}
