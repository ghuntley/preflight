# preflight

A Rust request-inspection proxy in front of [underclass](https://github.com/ghuntley/underclass).
Change your OpenAI-compatible harness's base URL to `http://127.0.0.1:8081/v1`.
Preflight inspects outbound content before sending it to underclass at port 8080.

## Run

```sh
devenv shell -- cargo build --locked --bins
devenv shell -- cargo run --locked --bin preflight -- serve
# Complete packaged runtime, including document tools:
nix run .#default -- serve
```

Supported inference routes: `POST /v1/responses`, `POST /v1/chat/completions`.
`GET /v1/models` forwards discovery. `/healthz` and `/readyz` are local probes;
readiness is established only after the sandboxed native toolchain passes checks.
`/metrics` exposes aggregate Prometheus counters and request-to-headers timings.
Unknown routes are not pass-through routes. Responses stream from underclass;
inference is not retried. Unmodified clean requests preserve their original body.

Optional configuration: `preflight serve --config /path/to/config.toml`.

```toml
bind = "127.0.0.1:8081"
upstream = "http://127.0.0.1:8080"
mode = "redact" # redact | no-go | advisory
sandbox = true
allow_page_redaction = false
max_body_bytes = 67108864
request_timeout_secs = 180
# carnet = "/run/secrets/preflight-carnet.json"

[cache]
memory_entries = 50000
disk_entries = 100000
artifact_bytes = 1073741824
max_artifact_bytes = 67108864
ttl_secs = 604800

# Optional trusted OpenAI-compatible file retrieval adapter:
# [resolver]
# file_api_base = "https://api.openai.com/v1"
```

`PREFLIGHT_CLIENT_KEY` optionally gates clients; `PREFLIGHT_UPSTREAM_KEY` optionally
replaces their credential when contacting underclass. Otherwise authorization is
passed through. `PREFLIGHT_FILE_API_KEY` is separately scoped to the configured file
API. Arbitrary attachment URL retrieval never receives these credentials.

## Policies

* **redact:** replace text findings with `[REDACTED:rule-id]`. Supported images and
  PDFs are reconstructed and reinspected. Findings without a safe replacement
  return HTTP 409.
* **no-go:** any non-allowlisted finding returns 409 and opaque finding IDs; nothing
  is sent to underclass.
* **advisory:** report findings and forward original content. This implementation
  still rejects acquisition/extraction failures rather than forwarding incomplete
  inspection; advisory is not a malformed-input bypass.

Inspection failures return 422, malformed JSON 400, body limits 413, and deadline
exhaustion 408. Errors contain static codes, never matched content.

## Detection

The embedded Gitleaks v8.30.1 source database is retained with its MIT license and
commit/checksum manifest in `vendor/gitleaks`. Default enabled families: AWS IDs,
GitHub PATs, OpenAI, Anthropic, Google/Gemini, OpenRouter, Slack, Stripe, private
keys, and JWT. Generic entropy heuristics stay disabled.

Rules use keyword filtering, regex capture spans, and a strict carnet. Strong
prefix rules have entropy suppression disabled by default; `upstream_entropy=true`
enables upstream thresholds. Upstream path exclusions, broad regex allowlists,
and `gitleaks:allow` comments are deliberately not inherited. A carnet file is a
JSON array of SHA-256 hashes of exact decoded secret values. Optional `stopwords`
are exact whole-secret values, not substring exemptions.

JSON is decoded before scanning; duplicate object keys are rejected. Nested JSON
tool arguments are decoded and rewritten structurally. Ordered text parts have a
reconstructed-text pass; wrapped JWT text has mapped normalization. Control-field
and property-name findings are rejected when changing them would alter semantics.

## Attachments

All project-owned executables are Rust. The isolated worker uses typed subprocess
adapters for Poppler, QPDF, Tesseract, ExifTool, and ZBar. Rust image codecs handle
JPEG/PNG and `lopdf` constructs replacement PDFs. Nix pins the runtime toolchain.

* JPEG/PNG: pixel OCR, barcode decoding, and metadata inspection.
* APNG: frame inspection; sanitization currently fails closed for multiple frames.
* PDF: extracted text, QPDF object strings, metadata, original embedded-image OCR,
  and rendered-page OCR. Embedded documents are extracted recursively within
  depth/count/byte limits. Unsupported active content, optional layers, encrypted
  files, and incremental revisions fail closed. Annotations/forms visible through
  object strings are inspected.
* UTF-8 and BOM-marked UTF-16 text attachments: decoded and scanned directly.
* Base64/data URLs: decoded before inspection.
* Remote HTTPS: public-address-only DNS-pinned retrieval, no redirects, bounded
  download, then inline the exact inspected bytes.
* File IDs: supported only with the explicit OpenAI-compatible file adapter;
  retrieved contents are materialized as inline files.

Images are re-encoded without original metadata after opaque pixel redaction.
PDF replacements contain only rendered raster pages. If extracted secrets cannot
be mapped to OCR regions, `allow_page_redaction=true` permits blacking out the
affected page; otherwise the request is rejected. PDF reconstruction is lossy.
OCR is imperfect and does not prove absence of every visually readable secret.
OCR includes quarter-turn orientations and a reduced-resolution pass for large
images. Coordinate maps bring every OCR finding back to original pixels.

Workers run without network access in a Bubblewrap PID/mount/network namespace,
with CPU/address-space/file-size limits and a parent wall-clock deadline. Native
stderr is discarded. The standalone worker is an internal executable, not a safe
public CLI: its stdout contains private extraction data for the parent to inspect.

## Cache and purge

Memory verdicts are backed by SQLite; sanitized artifacts are separate private
files. Keys bind exact bytes, credential-derived security scope, rules/carnet,
sanitization settings, and pinned worker/toolchain identity. Development builds
disable persistent verdict reuse unless `PREFLIGHT_TOOLCHAIN_ID` is supplied.

Only complete verdicts are cached. Rejected attachments can reuse detection;
sanitized entries require an existing artifact with a matching checksum. Missing
or corrupted artifacts trigger inspection. Concurrent identical jobs share a lock.
The first request's cancellation may cause a waiting request to restart inspection.

Expiry and size cleanup runs on admission and every five minutes. Memory has an
entry bound; SQLite has an entry bound rather than a strict physical-byte quota.
Scratch rendering space is separate from retained artifact storage.

```sh
preflight cache status --socket /run/preflight/control.sock
preflight cache purge --socket /run/preflight/control.sock
preflight cache purge --scope <64-character-scope-id> --socket /run/preflight/control.sock
```

The local socket is mode 0600. On NixOS, run administration as root. Purging
invalidates memory and disk records and advances a generation so existing jobs
cannot repopulate the old cache. Already approved in-flight requests can finish.
Deletion is not forensic erasure from storage snapshots or backups.

Send SIGHUP to reload configuration and the carnet. Reload validates a complete
new runtime before activation; failure retains the old one, and admitted requests
retain their snapshots. Listener, cache directory/budgets, and control-socket
changes require a restart. NixOS exposes this as `systemctl reload preflight`.

## NixOS

```nix
{
  imports = [ inputs.preflight.nixosModules.default ];
  services.preflight = {
    enable = true;
    upstream = "http://127.0.0.1:8080";
    mode = "redact";
    environmentFile = "/run/secrets/preflight.env";
  };
}
```

The module uses a dynamic user, private cache/runtime directories, resource
limits, and JSON logs to journald. Credentials are runtime files, not Nix values.

## Development and releases

```sh
devenv test
nix build .#preflight
nix build .#checks.x86_64-linux.preflight-vm
devenv shell -- cargo run --bin preflight-update-rules -- v8.30.1
```

`devenv test` runs formatting, clippy, unit/integration tests, Hegel properties,
and Code Contracts syntax validation. Tests use synthetic credentials only.
Hegel is pinned and runs outside the Nix package sandbox because its bootstrap
needs network access. Never commit `.hegel`, target artifacts, caches, or OCR data.

Weekly GitHub CI downloads a release-pinned Gitleaks source archive, refreshes the
database, executes checks, and produces a Nix closure artifact with provenance.
It does not deploy to running NixOS services automatically.

## Verification scope

Integration tests generate JPEGs, PNGs, rotated screenshots, text PDFs, scanned
PDFs, and embedded attachments. They exercise actual native tools, safe artifact
reconstruction, cache restart/purge behavior, and an HTTP mock underclass. Hegel
checks redaction, JSON, policy, coordinate, and cache invariants. Differential
fixtures compare GitHub detection semantics with Gitleaks using the same database.
The benchmark exercises benign 100 KiB and 1 MiB text inputs. NixOS VM tests submit
generated image/PDF requests through the installed service to a Rust mock server.

These checks establish the tested HTTP paths, not universal harness compatibility
or perfect OCR accuracy. Real provider credentials and live account pools are not
required or exercised by the test suite. File retrieval currently targets the
OpenAI-compatible `/files/{id}/content` API; additional provider protocols need
explicit adapters.
