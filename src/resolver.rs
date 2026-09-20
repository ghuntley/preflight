//! Attachment retrieval is separate from networkless document processing.
use anyhow::{Context, Result, bail};
use base64::Engine;
use futures::StreamExt;
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Resolver {
    pub file_api_base: Option<String>,
    #[serde(skip)]
    pub file_api_key: Option<String>,
}
#[derive(Default)]
struct Budget {
    count: usize,
    bytes: usize,
    acquired: std::collections::HashMap<String, Vec<u8>>,
}
impl Budget {
    fn begin(&mut self) -> Result<()> {
        self.count += 1;
        anyhow::ensure!(self.count <= 16, "attachment_count_limit");
        Ok(())
    }
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.bytes += bytes;
        anyhow::ensure!(self.bytes <= 64 * 1024 * 1024, "attachment_total_limit");
        Ok(())
    }
    async fn url(&mut self, url: &str) -> Result<Vec<u8>> {
        if let Some(bytes) = self.acquired.get(url) {
            return Ok(bytes.clone());
        }
        self.begin()?;
        let bytes = fetch(url).await?;
        self.charge(bytes.len())?;
        self.acquired.insert(url.into(), bytes.clone());
        Ok(bytes)
    }
}
impl Resolver {
    /// @cc [owner:ghuntley,label:security] pin-remote-content
    /// Remote attachment references MUST be replaced by the exact acquired bytes.
    /// Arbitrary URL retrieval MUST NOT send inference or provider credentials.
    pub async fn materialize(&self, value: &mut Value) -> Result<bool> {
        self.inner(value, &mut Budget::default(), 0).await
    }
    fn inner<'a>(
        &'a self,
        value: &'a mut Value,
        budget: &'a mut Budget,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            anyhow::ensure!(depth <= 64, "nesting_limit");
            let mut changed = false;
            match value {
                Value::Object(map) => {
                    if let Some(id) = map
                        .get("file_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                    {
                        anyhow::ensure!(
                            id.len() < 256
                                && id
                                    .bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                            "file_id_invalid"
                        );
                        let base = self
                            .file_api_base
                            .as_ref()
                            .context("file_adapter_missing")?;
                        let url = reqwest::Url::parse(&format!(
                            "{}/files/{id}/content",
                            base.trim_end_matches('/')
                        ))?;
                        anyhow::ensure!(
                            url.scheme() == "https"
                                && url.username().is_empty()
                                && url.password().is_none(),
                            "file_adapter_url"
                        );
                        let client = reqwest::Client::builder()
                            .redirect(reqwest::redirect::Policy::none())
                            .timeout(std::time::Duration::from_secs(30))
                            .build()?;
                        let mut request = client.get(url);
                        if let Some(key) = &self.file_api_key {
                            request = request.bearer_auth(key);
                        }
                        budget.begin()?;
                        let bytes = bounded(request.send().await?).await?;
                        budget.charge(bytes.len())?;
                        map.remove("file_id");
                        map.insert("file_data".into(), data_url(&bytes).into());
                        if !map.contains_key("filename") {
                            map.insert("filename".into(), filename(&bytes).into());
                        }
                        changed = true;
                    }
                    if let Some(url) = map
                        .get("file_url")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                    {
                        let bytes = budget.url(&url).await?;
                        map.remove("file_url");
                        map.insert("file_data".into(), data_url(&bytes).into());
                        if !map.contains_key("filename") {
                            map.insert("filename".into(), filename(&bytes).into());
                        }
                        changed = true;
                    }
                    for (key, v) in map.iter_mut() {
                        if key == "image_url"
                            && let Some(url) = v
                                .as_str()
                                .filter(|s| s.starts_with("https://") || s.starts_with("http://"))
                                .map(str::to_owned)
                        {
                            *v = data_url(&budget.url(&url).await?).into();
                            changed = true;
                            continue;
                        }
                        if key == "image_url"
                            && let Some(url) = v
                                .get("url")
                                .and_then(Value::as_str)
                                .filter(|s| s.starts_with("https://") || s.starts_with("http://"))
                                .map(str::to_owned)
                        {
                            v["url"] = data_url(&budget.url(&url).await?).into();
                            changed = true;
                        }
                        changed |= self.inner(v, budget, depth + 1).await?;
                    }
                }
                Value::Array(a) => {
                    for v in a {
                        changed |= self.inner(v, budget, depth + 1).await?;
                    }
                }
                Value::String(s)
                    if s.trim_start().starts_with('{') || s.trim_start().starts_with('[') =>
                {
                    if let Ok(mut inner) = crate::document::parse(s.as_bytes())
                        && self.inner(&mut inner, budget, depth + 1).await?
                    {
                        *s = serde_json::to_string(&inner)?;
                        changed = true;
                    }
                }
                _ => {}
            }
            Ok(changed)
        })
    }
}
pub fn data_url(bytes: &[u8]) -> String {
    let mime = if bytes.starts_with(b"%PDF-") {
        "application/pdf"
    } else if bytes.starts_with(b"\x89PNG") {
        "image/png"
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        "image/jpeg"
    } else {
        "text/plain"
    };
    format!(
        "data:{mime};base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}
fn filename(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"%PDF-") {
        "attachment.pdf"
    } else if bytes.starts_with(b"\x89PNG") {
        "attachment.png"
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        "attachment.jpg"
    } else {
        "attachment.txt"
    }
}
fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, _, _] = v.octets();
            !v.is_private()
                && !v.is_loopback()
                && !v.is_link_local()
                && !v.is_broadcast()
                && !v.is_documentation()
                && !v.is_unspecified()
                && !v.is_multicast()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 198 && (b == 18 || b == 19))
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            v.to_ipv4_mapped().is_none()
                && (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] == 0xdb8 || s[1] < 0x200))
        }
    }
}
async fn fetch(raw: &str) -> Result<Vec<u8>> {
    let url = reqwest::Url::parse(raw)?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        bail!("attachment_url_rejected");
    }
    let host = url.host_str().context("host")?;
    let port = url.port_or_known_default().context("port")?;
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if addresses.is_empty() || addresses.iter().any(|a| !public(a.ip())) {
        bail!("attachment_destination_rejected");
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &addresses)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    bounded(client.get(url).send().await?).await
}
async fn bounded(response: reqwest::Response) -> Result<Vec<u8>> {
    if !response.status().is_success() {
        bail!("attachment_fetch_failed");
    }
    if response
        .content_length()
        .is_some_and(|n| n > 32 * 1024 * 1024)
    {
        bail!("attachment_download_limit");
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len() + chunk.len() > 32 * 1024 * 1024 {
            bail!("attachment_download_limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
