use axum::{
    Router,
    body::Bytes,
    http::HeaderMap,
    routing::{get, post},
};
use base64::Engine;
use preflight::{attachments::Attachments, cache::Cache, scanner::Scanner};
use std::{
    collections::HashSet,
    process::Stdio,
    sync::{Arc, Mutex},
};
mod common;

#[tokio::test]
async fn jpeg_png_and_scanned_pdf_visual_secrets_are_removed() {
    let temp = tempfile::tempdir().unwrap();
    let screenshot = common::screenshot(&token());
    let mut e = engine(&temp.path().join("cache"));
    e.allow_page_redaction = true;
    for format in [image::ImageFormat::Png, image::ImageFormat::Jpeg] {
        let mut original = std::io::Cursor::new(Vec::new());
        screenshot.write_to(&mut original, format).unwrap();
        let original = original.into_inner();
        let result = e.inspect(&original, "scope", true).await.unwrap();
        assert!(
            !result.rules.is_empty(),
            "visible credential missed in {format:?}"
        );
        let replacement = result
            .replacement
            .expect("visual match must have safe coordinates");
        assert!(replacement.starts_with(b"\x89PNG"));
        assert!(
            e.inspect(&replacement, "scope", false)
                .await
                .unwrap()
                .rules
                .is_empty()
        );
        assert_ne!(
            image::load_from_memory(&original).unwrap().to_rgb8(),
            image::load_from_memory(&replacement).unwrap().to_rgb8()
        );
    }
    let pdf = common::scanned_pdf(&screenshot);
    let result = e.inspect(&pdf, "scope", true).await.unwrap();
    assert!(!result.rules.is_empty());
    assert!(result.replacement.unwrap().starts_with(b"%PDF-"));
}

#[tokio::test]
async fn rotated_screenshot_credentials_are_inspected() {
    let temp = tempfile::tempdir().unwrap();
    let original = common::screenshot(&token());
    let e = engine(temp.path());
    for image in [
        image::imageops::rotate90(&original),
        image::imageops::rotate180(&original),
        image::imageops::rotate270(&original),
    ] {
        let mut encoded = std::io::Cursor::new(Vec::new());
        image
            .write_to(&mut encoded, image::ImageFormat::Png)
            .unwrap();
        let result = e
            .inspect(&encoded.into_inner(), "scope", true)
            .await
            .unwrap();
        assert!(
            !result.rules.is_empty(),
            "rotated visible credential was missed"
        );
        assert!(result.replacement.is_some());
    }
}

#[tokio::test]
async fn persistent_sanitized_cache_survives_restart_and_purge_forces_inspection() {
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let mut original = std::io::Cursor::new(Vec::new());
    common::screenshot(&token())
        .write_to(&mut original, image::ImageFormat::Png)
        .unwrap();
    let original = original.into_inner();
    let mut first = engine(&cache_dir);
    let worker = temp.path().join("worker");
    std::fs::copy(env!("CARGO_BIN_EXE_preflight-worker"), &worker).unwrap();
    first.executable = worker.clone();
    first.toolchain_id = "integration-fixture-v1".into();
    let approved = first
        .inspect(&original, "scope", true)
        .await
        .unwrap()
        .replacement
        .unwrap();
    drop(first);
    let mut second = engine(&cache_dir);
    second.toolchain_id = "integration-fixture-v1".into();
    std::fs::remove_file(&worker).unwrap();
    second.executable = worker;
    assert_eq!(
        second
            .inspect(&original, "scope", true)
            .await
            .unwrap()
            .replacement
            .unwrap(),
        approved
    );
    assert!(
        second
            .inspect(&original, "different-scope", true)
            .await
            .is_err()
    );
    second.cache.lock().unwrap().purge().unwrap();
    assert!(second.inspect(&original, "scope", true).await.is_err());
}

fn token() -> String {
    format!("ghp_{}", "aB39".repeat(9))
}
fn engine(dir: &std::path::Path) -> Attachments {
    Attachments::new(
        Arc::new(Scanner::new(HashSet::new()).unwrap()),
        Arc::new(Mutex::new(Cache::open(dir).unwrap())),
        env!("CARGO_BIN_EXE_preflight-worker").into(),
        true,
    )
}

#[tokio::test]
async fn pdf_visible_text_is_scanned_and_rebuilt() {
    use lopdf::{Document, Object, Stream, dictionary};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("fixture.pdf");
    let mut doc = Document::with_version("1.5");
    let pages = doc.new_object_id();
    let font =
        doc.add_object(dictionary! {"Type"=>"Font","Subtype"=>"Type1","BaseFont"=>"Courier"});
    let content = doc.add_object(Stream::new(
        dictionary! {},
        format!("BT /F1 12 Tf 30 150 Td ({}) Tj ET", token()).into_bytes(),
    ));
    let page=doc.add_object(dictionary!{"Type"=>"Page","Parent"=>pages,"MediaBox"=>vec![0.into(),0.into(),600.into(),200.into()],"Resources"=>dictionary!{"Font"=>dictionary!{"F1"=>font}},"Contents"=>content});
    doc.objects.insert(
        pages,
        Object::Dictionary(
            dictionary! {"Type"=>"Pages","Kids"=>vec![Object::Reference(page)],"Count"=>1},
        ),
    );
    let catalog = doc.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages});
    doc.trailer.set("Root", catalog);
    doc.save(&path).unwrap();
    let mut e = engine(&temp.path().join("cache"));
    e.allow_page_redaction = true;
    let bytes = std::fs::read(path).unwrap();
    let outcome = e.inspect(&bytes, "scope", true).await.unwrap();
    assert!(!outcome.rules.is_empty());
    let replacement = outcome.replacement.unwrap();
    assert!(replacement.starts_with(b"%PDF-"));
    assert!(
        e.inspect(&replacement, "scope", false)
            .await
            .unwrap()
            .rules
            .is_empty()
    );
}

#[tokio::test]
async fn image_metadata_is_scanned_and_rebuilt_in_rust() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("fixture.png");
    image::RgbImage::from_pixel(100, 100, image::Rgb([255, 255, 255]))
        .save(&file)
        .unwrap();
    let status = std::process::Command::new("exiftool")
        .arg("-overwrite_original")
        .arg(format!("-Comment={}", token()))
        .arg(&file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let e = engine(&temp.path().join("cache"));
    let original = std::fs::read(file).unwrap();
    let blocked = e.inspect(&original, "scope", false).await.unwrap();
    assert!(!blocked.rules.is_empty());
    assert!(blocked.replacement.is_none());
    let clean = e.inspect(&original, "scope", true).await.unwrap();
    assert!(!clean.rules.is_empty());
    let replacement = clean.replacement.unwrap();
    assert_ne!(original, replacement);
    assert!(
        e.inspect(&replacement, "scope", false)
            .await
            .unwrap()
            .rules
            .is_empty()
    );
}

#[tokio::test]
async fn malformed_pdf_never_becomes_clean() {
    let temp = tempfile::tempdir().unwrap();
    let e = engine(temp.path());
    assert!(e.inspect(b"%PDF-not-a-pdf", "scope", true).await.is_err());
    assert_eq!(e.cache.lock().unwrap().count().unwrap(), 0);
}

#[tokio::test]
async fn embedded_pdf_text_attachment_is_inspected_and_removed() {
    use lopdf::{Document, Object, Stream, dictionary};
    let temp = tempfile::tempdir().unwrap();
    let clean = common::scanned_pdf(&image::RgbImage::from_pixel(
        100,
        100,
        image::Rgb([255, 255, 255]),
    ));
    let mut doc = Document::load_mem(&clean).unwrap();
    let embedded = doc.add_object(Stream::new(
        dictionary! {"Type"=>"EmbeddedFile"},
        token().into_bytes(),
    ));
    let file=doc.add_object(dictionary!{"Type"=>"Filespec","F"=>Object::string_literal("fixture.txt"),"EF"=>dictionary!{"F"=>embedded}});
    let names = doc.add_object(
        dictionary! {"Names"=>vec![Object::string_literal("fixture.txt"),Object::Reference(file)]},
    );
    let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    doc.get_object_mut(root)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Names", dictionary! {"EmbeddedFiles"=>names});
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    let e = engine(&temp.path().join("cache"));
    let result = e.inspect(&bytes, "scope", true).await.unwrap();
    assert!(!result.rules.is_empty());
    let replacement = result.replacement.unwrap();
    assert!(
        e.inspect(&replacement, "scope", false)
            .await
            .unwrap()
            .rules
            .is_empty()
    );
}

#[tokio::test]
async fn reference_and_encoding_failures_do_not_bypass_inspection() {
    let temp = tempfile::tempdir().unwrap();
    let e = engine(temp.path());
    for body in [
        serde_json::json!({"input":[{"type":"input_image","image_url":"https://127.0.0.1/private"}]}),
        serde_json::json!({"input":[{"type":"input_file","file_id":"file-missing"}]}),
    ] {
        let mut body = body;
        assert!(
            preflight::resolver::Resolver::default()
                .materialize(&mut body)
                .await
                .is_err()
        );
    }
    let body = serde_json::json!({"input":[{"type":"input_image","image_url":"data:image/png;base64,%%%"}]});
    assert!(
        preflight::document::inspect(body, &e.scanner, &e, "scope", true)
            .await
            .is_err()
    );
    assert!(
        e.inspect(b"\x89PNG\r\n\x1a\ntruncated", "scope", true)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn tool_arguments_and_split_pem_preserve_structure() {
    let temp = tempfile::tempdir().unwrap();
    let e = engine(temp.path());
    let body = serde_json::json!({"model":"example","messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"run","arguments":serde_json::json!({"key":token(),"number":7}).to_string()}}]}]});
    let inspected = preflight::document::inspect(body, &e.scanner, &e, "scope", true)
        .await
        .unwrap();
    let args: serde_json::Value = serde_json::from_str(
        inspected.body["messages"][0]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(args["number"], 7);
    assert!(!args["key"].as_str().unwrap().contains(&token()));
    let body = serde_json::json!({"input":[{"role":"user","content":[{"type":"input_text","text":"-----BEGIN PRIVATE KEY-----"},{"type":"input_text","text":"sensitive key material\n-----END PRIVATE KEY-----"}]}]});
    let inspected = preflight::document::inspect(body, &e.scanner, &e, "scope", true)
        .await
        .unwrap();
    assert!(
        !inspected
            .body
            .to_string()
            .contains("sensitive key material")
    );
}

#[tokio::test]
async fn proxy_preserves_clean_bytes_redacts_and_blocks_without_forwarding() {
    let seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let capture = seen.clone();
    let headers = Arc::new(Mutex::new(Vec::<HeaderMap>::new()));
    let captured_headers = headers.clone();
    let handler = move |request_headers: HeaderMap, body: Bytes| {
        let capture = capture.clone();
        let headers = captured_headers.clone();
        async move {
            headers.lock().unwrap().push(request_headers);
            capture.lock().unwrap().push(body.to_vec());
            (
                [("content-type", "text/event-stream")],
                "data: {\"ok\":true}\n\ndata: [DONE]\n\n",
            )
        }
    };
    let upstream = Router::new()
        .route("/v1/responses", post(handler.clone()))
        .route("/v1/chat/completions", post(handler))
        .route(
            "/v1/models",
            get(|| async {
                axum::Json(serde_json::json!({"object":"list","data":[{"id":"test-model"}]}))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    for mode in ["redact", "no-go", "advisory"] {
        let temp = tempfile::tempdir().unwrap();
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = reservation.local_addr().unwrap();
        drop(reservation);
        let config = temp.path().join("config.toml");
        std::fs::write(&config,format!("bind = '{addr}'\nupstream = 'http://{upstream_addr}'\nmode = '{mode}'\ncache_dir = '{}'\ncontrol_socket = '{}'\n",temp.path().join("cache").display(),temp.path().join("control.sock").display())).unwrap();
        let log = std::fs::File::create(temp.path().join("log")).unwrap();
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_preflight"))
            .args(["serve", "--config"])
            .arg(&config)
            .env_remove("PREFLIGHT_CLIENT_KEY")
            .env_remove("PREFLIGHT_UPSTREAM_KEY")
            .env_remove("PREFLIGHT_FILE_API_KEY")
            .env("RUST_LOG", "trace")
            .stdout(log)
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let client = reqwest::Client::new();
        let base = format!("http://{addr}");
        let mut ready = false;
        for _ in 0..1000 {
            if client.get(format!("{base}/readyz")).send().await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        }
        assert!(ready, "proxy failed to start");
        let clean = b"{ \"model\": \"example\", \"input\": \"hello\", \"stream\": true }";
        let response = client
            .post(format!("{base}/v1/responses"))
            .body(clean.to_vec())
            .header("authorization", "Bearer fixture-credential")
            .header("session-id", "fixture-session")
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        assert!(response.text().await.unwrap().ends_with("data: [DONE]\n\n"));
        assert_eq!(seen.lock().unwrap().last().unwrap(), clean);
        assert_eq!(
            headers.lock().unwrap().last().unwrap()["authorization"],
            "Bearer fixture-credential"
        );
        assert_eq!(
            headers.lock().unwrap().last().unwrap()["session-id"],
            "fixture-session"
        );
        let models: serde_json::Value = client
            .get(format!("{base}/v1/models"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(models["data"][0]["id"], "test-model");
        let chat = serde_json::json!({"model":"test-model","stream":true,"messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"read","arguments":"{\"path\":\"README.md\"}"}}]},{"role":"tool","tool_call_id":"call_1","content":"safe source dump"}]});
        assert_eq!(
            client
                .post(format!("{base}/v1/chat/completions"))
                .json(&chat)
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(seen.lock().unwrap().last().unwrap())
                .unwrap(),
            chat
        );
        let before = seen.lock().unwrap().len();
        let response = client
            .post(format!("{base}/v1/responses"))
            .json(&serde_json::json!({"input":token()}))
            .send()
            .await
            .unwrap();
        if mode == "no-go" {
            assert_eq!(response.status(), 409);
            assert_eq!(seen.lock().unwrap().len(), before);
            assert!(!response.text().await.unwrap().contains(&token()));
        } else {
            assert!(response.status().is_success());
            let forwarded =
                String::from_utf8(seen.lock().unwrap().last().unwrap().clone()).unwrap();
            assert_eq!(forwarded.contains(&token()), mode == "advisory");
        }
        let mut image = std::io::Cursor::new(Vec::new());
        common::screenshot(&token())
            .write_to(&mut image, image::ImageFormat::Jpeg)
            .unwrap();
        let image = image.into_inner();
        let original_url = preflight::resolver::data_url(&image);
        let image_body = serde_json::json!({"input":[{"role":"user","content":[{"type":"input_image","image_url":original_url}]}]});
        let before_image = seen.lock().unwrap().len();
        let response = client
            .post(format!("{base}/v1/responses"))
            .json(&image_body)
            .send()
            .await
            .unwrap();
        if mode == "no-go" {
            assert_eq!(response.status(), 409);
            assert_eq!(seen.lock().unwrap().len(), before_image);
        } else {
            assert_eq!(response.status(), 200);
            let forwarded: serde_json::Value =
                serde_json::from_slice(seen.lock().unwrap().last().unwrap()).unwrap();
            let url = forwarded["input"][0]["content"][0]["image_url"]
                .as_str()
                .unwrap();
            if mode == "advisory" {
                assert_eq!(url, original_url);
            } else {
                assert_ne!(url, original_url);
                assert!(url.starts_with("data:image/png;base64,"));
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(url.split_once(',').unwrap().1)
                    .unwrap();
                let checker = engine(&temp.path().join("checker"));
                assert!(
                    checker
                        .inspect(&bytes, "test", false)
                        .await
                        .unwrap()
                        .rules
                        .is_empty()
                );
            }
        }
        let before = seen.lock().unwrap().len();
        let data = base64::engine::general_purpose::STANDARD.encode(b"%PDF-broken");
        let response=client.post(format!("{base}/v1/responses")).json(&serde_json::json!({"input":[{"type":"input_file","file_data":format!("data:application/pdf;base64,{data}")}]})).send().await.unwrap();
        assert_eq!(response.status(), 422);
        assert_eq!(seen.lock().unwrap().len(), before);
        if mode == "redact" {
            let config_text = std::fs::read_to_string(&config).unwrap();
            std::fs::write(
                &config,
                config_text.replace("mode = 'redact'", "mode = 'no-go'"),
            )
            .unwrap();
            // SAFETY: this is the child process created by this test.
            assert_eq!(
                unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGHUP) },
                0
            );
            for _ in 0..200 {
                if std::fs::read_to_string(temp.path().join("log"))
                    .unwrap()
                    .contains("configuration.reloaded")
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            let response = client
                .post(format!("{base}/v1/responses"))
                .json(&serde_json::json!({"input":token()}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 409);
            std::fs::write(&config, "not valid TOML !!").unwrap();
            // SAFETY: this is the child process created by this test.
            assert_eq!(
                unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGHUP) },
                0
            );
            for _ in 0..100 {
                if std::fs::read_to_string(temp.path().join("log"))
                    .unwrap()
                    .contains("configuration.reload_failed")
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            let response = client
                .post(format!("{base}/v1/responses"))
                .json(&serde_json::json!({"input":token()}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 409);
        }
        child.kill().await.unwrap();
        let logs = std::fs::read_to_string(temp.path().join("log")).unwrap();
        assert!(!logs.contains(&token()));
        assert!(!logs.contains("fixture-credential"));
    }
    server.abort();
}
