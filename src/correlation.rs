//! Request-scoped identity shared with underclass through x-request-id.
use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue},
    middleware::Next,
    response::Response,
};
use tracing::Instrument;
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
pub struct RequestId(Uuid);
impl RequestId {
    pub fn fresh() -> Self {
        Self(Uuid::new_v4())
    }
    pub fn header(self) -> HeaderValue {
        HeaderValue::from_str(&self.0.to_string()).expect("UUID is a valid header")
    }
    pub fn set_header(self, headers: &mut HeaderMap) {
        headers.insert("x-request-id", self.header());
    }
}
impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// @cc [owner:ghuntley,label:logging] ingress-owned-request-id
/// Every ingress request MUST receive a new UUIDv4 before routing or admission.
/// Client-supplied IDs MUST NOT become log fields or the propagated identity.
pub async fn middleware(mut request: Request, next: Next) -> Response {
    let id = RequestId::fresh();
    request.headers_mut().remove("x-preflight-request-id");
    id.set_header(request.headers_mut());
    request.extensions_mut().insert(id);
    let started = std::time::Instant::now();
    let mut response = next
        .run(request)
        .instrument(tracing::info_span!("request",request_id=%id))
        .await;
    response.headers_mut().remove("x-preflight-request-id");
    id.set_header(response.headers_mut());
    tracing::info!(event="request.finished",request_id=%id,status=response.status().as_u16(),duration_ms=started.elapsed().as_millis() as u64);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::{TestCase, generators as gs};
    #[hegel::test]
    fn forwarded_identity_replaces_all_header_values(tc: TestCase) {
        let count = tc.draw(gs::integers::<usize>().min_value(0).max_value(8));
        let mut headers = HeaderMap::new();
        for _ in 0..count {
            headers.append("x-request-id", HeaderValue::from_static("untrusted-input"));
        }
        let id = RequestId::fresh();
        id.set_header(&mut headers);
        assert_eq!(headers.get_all("x-request-id").iter().count(), 1);
        let parsed = Uuid::parse_str(headers["x-request-id"].to_str().unwrap()).unwrap();
        assert_eq!(parsed.get_version(), Some(uuid::Version::Random));
        assert_eq!(id.to_string(), parsed.to_string());
    }
}
