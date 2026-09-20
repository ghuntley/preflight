use axum::{
    Router,
    body::Body,
    extract::{Extension, Request},
    http::{HeaderMap, StatusCode},
    middleware,
    routing::get,
};
use preflight::correlation::{self, RequestId};

#[tokio::test]
async fn ingress_ids_cover_success_errors_and_unmatched_routes() {
    let app = Router::new()
        .route(
            "/ok",
            get(
                |Extension(id): Extension<RequestId>, request: Request| async move {
                    assert_eq!(request.headers()["x-request-id"], id.header());
                    assert!(!request.headers().contains_key("x-preflight-request-id"));
                    let mut response = axum::response::Response::new(Body::from("ok"));
                    response
                        .headers_mut()
                        .insert("x-request-id", "untrusted-upstream-value".parse().unwrap());
                    response
                },
            ),
        )
        .route("/denied", get(|| async { StatusCode::UNAUTHORIZED }))
        .layer(middleware::from_fn(correlation::middleware));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let supplied = uuid::Uuid::new_v4().to_string();
    let mut seen = std::collections::HashSet::new();
    for (path, status) in [("/ok", 200), ("/denied", 401), ("/missing", 404)] {
        let mut headers = HeaderMap::new();
        headers.append("x-request-id", supplied.parse().unwrap());
        headers.append("x-request-id", "client-input".parse().unwrap());
        headers.insert("x-preflight-request-id", "old-input".parse().unwrap());
        let response = client
            .get(format!("http://{address}{path}"))
            .headers(headers)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        let id = response.headers()["x-request-id"].to_str().unwrap();
        assert_ne!(id, supplied);
        assert_eq!(
            uuid::Uuid::parse_str(id).unwrap().get_version(),
            Some(uuid::Version::Random)
        );
        assert!(seen.insert(id.to_owned()));
        assert!(!response.headers().contains_key("x-preflight-request-id"));
    }
    task.abort();
}
