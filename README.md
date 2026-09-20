# preflight

**A local proxy that scans LLM requests and attachments for secrets before they reach the model.**

```text
                       ┌────────────────────────────────────┐
                       │             preflight              │
                       │                                    │
 coding harness ──────►│  /v1/responses                     │
 (any supported        │  /v1/chat/completions              │────► underclass ────► model
  OpenAI-compatible    │  /v1/models                        │
  client)              │                                    │
                       │  decode · inspect · redact/block   │
                       │  local OCR · content-addressed     │
                       │  cache · structured logging        │
                       └────────────────────────────────────┘
                             127.0.0.1:8081                     127.0.0.1:8080
```

Someone pastes an `.env` file? Detected credentials become stable placeholders and the request continues. A screenshot or PDF contains a key? preflight decodes it, runs local extraction and OCR, and sanitizes it where supported. When inspection or safe rewriting is impossible, the request stays grounded.

---

## Why

Coding agents read source files, shell output, screenshots, and documents. Secrets can arrive through any of them. preflight sits between the harness and [underclass](https://github.com/ghuntley/underclass), inspecting the outbound copy before inference starts:

- **One base URL change** — keep the supported OpenAI HTTP endpoints, tool-call structure, session headers, and response streams.
- **Redact by default** — replace detected secrets with `[REDACTED:rule-id]` so ordinary pasted-key incidents do not stop the agent.
- **Attachments get inspected too** — decode images and PDFs locally; scan extracted text, metadata, barcodes, and OCR output.
- **No repeated OCR tax** — identical attachments reuse completed inspection results while their scope and inspection profile remain the same.
- **No generic randomness detector** — prompts and source dumps are entropy soup. Default rules use recognizable credential shapes.
- **Nothing forwarded halfway through inspection** — the whole request is checked before it goes to underclass.

## Quick start

With underclass running on `127.0.0.1:8080`, start preflight with its complete document-processing toolchain:

```sh
nix run github:ghuntley/preflight -- serve
```

Point the harness at:

```text
http://127.0.0.1:8081/v1
```

Keep using the existing underclass API key. By default, preflight passes authorization through. You can also configure separate client-facing and upstream credentials.

For a local checkout:

```sh
devenv shell -- cargo build --locked --bins
devenv shell -- cargo run --locked --bin preflight -- serve
```

Building all binaries also builds the Rust attachment worker. Startup checks the sandboxed native toolchain before the proxy becomes ready.

## How inspection works

- **Parse first.** Walk decoded JSON string leaves, including messages, instructions, tool results, and nested JSON tool arguments. Duplicate object keys are rejected.
- **Match structured content.** Each text unit goes through keyword filtering, a Gitleaks-derived regex, optional entropy filtering, and the trusted allowlist. Ordered text parts and wrapped JWTs get mapped reconstruction passes.
- **Inspect attachments locally.** Resolve their bytes, decode them, extract text, render PDF pages, and run OCR. External attachment URLs never receive the underclass credential.
- **Apply one request-wide decision.** Redact supported spans, rebuild affected artifacts, or reject the request. Rebuilt attachments are inspected again before approval.
- **Forward approved content.** Enforcing modes send the exact approved bytes or sanitized replacement. Unchanged clean requests preserve their original body bytes; underclass's response streams through.

Preflight does not retry inference requests. Underclass owns provider routing and failover.

Design decisions and their trade-offs live in [`docs/adr/`](docs/adr) — start with [ADR 0001](docs/adr/0001-inspection-transaction.md) for the inspection transaction and [ADR 0002](docs/adr/0002-rust-workers-and-content-cache.md) for workers and caching.

## Policy

| mode | what happens |
|---|---|
| `redact` | Default. Replace text findings and sanitize supported attachments. Forward the rewritten request; return HTTP 409 when a finding has no safe replacement. |
| `no-go` | Return HTTP 409 for any non-allowlisted finding. Nothing reaches underclass. The response contains opaque finding IDs, never the secret. |
| `advisory` | Report findings and forward the original content. Useful for tuning; detected secrets can reach the model in this mode. |

All modes reject acquisition or extraction failures. Inspection failures return `422`, malformed JSON `400`, body limits `413`, and deadline exhaustion `408`. Preflight-generated errors use static codes rather than matched content.

## Configuration

Optional TOML configuration, supplied explicitly:

```sh
preflight serve --config /path/to/config.toml
```

| key | default | meaning |
|---|---|---|
| `bind` | `127.0.0.1:8081` | listen address |
| `upstream` | `http://127.0.0.1:8080` | underclass base URL, without `/v1` |
| `mode` | `redact` | enforcement policy |
| `sandbox` | `true` | isolate attachment workers with Bubblewrap |
| `allow_page_redaction` | `false` | permit blacking out a PDF page when a finding cannot be mapped to an OCR region |
| `max_body_bytes` | `67108864` | maximum request body size: 64 MiB |
| `request_timeout_secs` | `180` | deadline covering inspection and waiting for upstream response headers |
| `carnet` | unset | path to a JSON array of exact secret SHA-256 hashes |
| `stopwords` | empty | exact whole-secret exemptions |
| `upstream_entropy` | `false` | apply upstream entropy thresholds to enabled rules |
| `cache_dir` | `$XDG_CACHE_HOME/preflight` or `~/.cache/preflight` | persistent verdicts and sanitized artifacts |
| `control_socket` | `/tmp/preflight-control.sock` | local cache administration socket |
| `resolver.file_api_base` | unset | trusted OpenAI-compatible file API base, such as `https://api.openai.com/v1` |

Example:

```toml
bind = "127.0.0.1:8081"
upstream = "http://127.0.0.1:8080"
mode = "redact"
carnet = "/run/secrets/preflight-carnet.json"

[cache]
memory_entries = 50000
disk_entries = 100000
artifact_bytes = 1073741824
max_artifact_bytes = 67108864
ttl_secs = 604800
```

Runtime environment:

| variable | purpose |
|---|---|
| `PREFLIGHT_CONFIG` | configuration path for `serve` |
| `PREFLIGHT_CLIENT_KEY` | optional bearer credential required from clients |
| `PREFLIGHT_UPSTREAM_KEY` | optional replacement credential sent to underclass |
| `PREFLIGHT_FILE_API_KEY` | separate credential for the configured file API |
| `PREFLIGHT_CONTROL` | socket path for cache administration commands |
| `RUST_LOG` | logging filter; output is structured JSON |

Send SIGHUP to reload configuration and the carnet. A failed reload keeps the previous runtime active, and admitted requests retain their original snapshots. Listener, cache directory/budgets, and control-socket changes require a restart. On NixOS: `systemctl reload preflight`.

## CLI

```text
preflight serve [--config PATH]
preflight check [--config PATH]
preflight cache status [--socket PATH]
preflight cache purge [--scope SCOPE_ID] [--socket PATH]
```

`check` validates configuration and compiles the detection rules. Cache commands talk to the running daemon through a mode-`0600` Unix socket. On NixOS, run administration as root.

## Endpoints

| route | auth | purpose |
|---|---|---|
| `POST /v1/responses` | client key, if configured | inspect a Responses request, then stream through underclass |
| `POST /v1/chat/completions` | client key, if configured | inspect a Chat Completions request, then stream through underclass |
| `GET /v1/models` | client key, if configured | forward model discovery |
| `GET /healthz` | none | local liveness probe |
| `GET /readyz` | none | readiness after startup toolchain checks |
| `GET /metrics` | none | aggregate Prometheus counters and request-to-headers timings |

Inference responses carry `x-preflight-request-id`. Completed inspections also attach `x-preflight-finding-count`. JSON logs correlate requests and safe finding IDs without recording prompts or matched secrets. Unknown routes are not pass-through routes.

## JSON logs

Preflight prints one JSON object per log line. These representative excerpts omit tracing's `span` and `spans` metadata for readability; in the full output, inspection events carry the request ID and inspection-profile fingerprint in their request span. Timestamps, IDs, and timings below are illustrative.

The headings identify the configured policy. The current log schema does **not** include a `mode` or `action` field, and HTTP 200 alone does not distinguish redaction from advisory forwarding. Successful-forwarding examples assume underclass returns 200.

### No secret found — any mode

Inspection completes with zero findings, and the request continues normally:

```jsonl
{"timestamp":"2026-09-20T12:00:00.001Z","level":"INFO","fields":{"event":"inspection.completed","finding_count":0}}
{"timestamp":"2026-09-20T12:00:00.024Z","level":"INFO","fields":{"event":"request.policy_completed","request_id":"9031b620-66aa-4a59-9228-bb7f40f567a1","status":200,"duration_ms":24}}
```

There is no `inspection.finding` event for this request. An allowlisted fixture also contributes no finding.

### Secret found — `redact`

A text finding produces a warning with its rule and opaque finding ID. Preflight replaces the detected span with a token such as `[REDACTED:github-pat]`, then forwards the sanitized request:

```jsonl
{"timestamp":"2026-09-20T12:01:00.002Z","level":"INFO","fields":{"event":"inspection.completed","finding_count":1}}
{"timestamp":"2026-09-20T12:01:00.002Z","level":"WARN","fields":{"event":"inspection.finding","finding_id":"8a4f0571-4751-4d64-94da-55c3626a12de","rule_id":"github-pat"}}
{"timestamp":"2026-09-20T12:01:00.031Z","level":"INFO","fields":{"event":"request.policy_completed","request_id":"aa7445a8-b378-4b93-8ed1-b25ae80dfc01","status":200,"duration_ms":31}}
```

For rebuilt attachments, an additional `attachment.inspected` event includes `finding_count` and `rebuilt: true`. A finding that cannot be safely rewritten is blocked instead.

### Secret found — `no-go`

The finding is reported, then preflight returns 409 without sending the request to underclass:

```jsonl
{"timestamp":"2026-09-20T12:02:00.002Z","level":"INFO","fields":{"event":"inspection.completed","finding_count":1}}
{"timestamp":"2026-09-20T12:02:00.002Z","level":"WARN","fields":{"event":"inspection.finding","finding_id":"4b23f164-cc68-4852-b34d-1c6bd0ee13bd","rule_id":"github-pat"}}
{"timestamp":"2026-09-20T12:02:00.003Z","level":"INFO","fields":{"event":"request.policy_completed","request_id":"9bf853df-9d39-4f05-a189-a857de29596a","status":409,"duration_ms":3}}
```

The client error contains the same finding ID, letting the operator locate the rule in logs. Neither the log nor the error contains the secret. The completion event stays at `INFO`; the finding itself is `WARN`.

### Secret found — `advisory`

The finding is reported, but the original request is forwarded unchanged:

```jsonl
{"timestamp":"2026-09-20T12:03:00.002Z","level":"INFO","fields":{"event":"inspection.completed","finding_count":1}}
{"timestamp":"2026-09-20T12:03:00.002Z","level":"WARN","fields":{"event":"inspection.finding","finding_id":"c5aebff1-7b5a-4ad1-9ae7-2c351b96106f","rule_id":"github-pat"}}
{"timestamp":"2026-09-20T12:03:00.028Z","level":"INFO","fields":{"event":"request.policy_completed","request_id":"ce36b020-0321-41e4-8d27-a9d81999a91e","status":200,"duration_ms":28}}
```

The model can receive the detected secret in this mode. Reporting remains secret-free.

### Inspection could not finish

A decoding or extraction failure is different from a clean scan. For example:

```jsonl
{"timestamp":"2026-09-20T12:04:00.015Z","level":"INFO","fields":{"event":"request.policy_completed","request_id":"2dc4f68c-adfd-4886-8965-708dabd14374","status":422,"duration_ms":15}}
```

There is no successful request-wide `inspection.completed` event in this case. All modes reject incomplete inspection. `request.policy_completed.duration_ms` measures time through the response headers; a forwarded response later emits `response.completed`, `response.stream_failed`, or `response.cancelled` for its stream outcome.

## Rules and carnet

The Gitleaks database is embedded in the binary. The vendored snapshot includes its license and a release/commit/checksum manifest in [`vendor/gitleaks/`](vendor/gitleaks). [`rules/default-profile.toml`](rules/default-profile.toml) explicitly selects the enabled upstream rules, so new upstream additions do not silently expand enforcement.

Defaults cover AWS access-key IDs, GitHub PATs, OpenAI, Anthropic, Google/Gemini, OpenRouter, Slack, Stripe, private keys, and JWTs. Generic entropy heuristics stay disabled. Strong prefix rules use no entropy suppression unless `upstream_entropy=true` is configured.

**The allowlist is a carnet: exact hashes and stopwords.** A carnet entry exempts the SHA-256 hash of an exact decoded secret value. Stopwords match whole secrets, not surrounding prose or substrings. Upstream path exclusions, broad regex allowlists, and inline `gitleaks:allow` comments do not grant exemptions.

Property-name and control-field findings are rejected in enforcing modes when rewriting them would change request semantics.

## Attachments

All project-owned executables are Rust. The worker uses typed subprocess adapters for Poppler, QPDF, Tesseract, ExifTool, and ZBar; Rust image codecs handle JPEG/PNG and `lopdf` constructs replacement PDFs. Nix pins the toolchain.

| content | inspection |
|---|---|
| JPEG / PNG | pixel OCR, barcode decoding, and metadata |
| APNG | frame inspection; multi-frame sanitization currently fails closed |
| PDF | extracted text, QPDF object strings, metadata, original embedded images, and rendered-page OCR |
| Embedded PDF attachments | recursive extraction within depth, count, and byte limits |
| UTF-8 / BOM-marked UTF-16 text | decode and scan text directly |
| Base64 / data URLs | decode the transport representation before inspection |
| Remote HTTPS URLs | bounded, public-address-only, DNS-pinned retrieval with no redirects; inline the inspected bytes in enforcing modes |
| Provider file IDs | retrieve through the configured OpenAI-compatible `/files/{id}/content` adapter |

OCR includes quarter-turn orientations and a reduced-resolution pass for large images. Coordinate maps bring findings back to original pixels. Scanning original embedded images as well as rendered PDF pages catches details that PDF resampling can erase.

Images are re-encoded after opaque pixel redaction, without original metadata. PDF replacements contain only rendered raster pages. `allow_page_redaction=true` permits removing an entire affected page's visual content when precise mapping is unavailable; otherwise the request is rejected. PDF reconstruction is lossy, and OCR does not prove the absence of every visually readable secret.

Unsupported PDF active content, optional layers, encryption, and incremental revisions fail closed. Annotations and forms exposed through object strings are inspected. Other file protocols need explicit adapters.

## Cache and purge

**Same bytes, same scope, same inspection profile: reuse the result.** Memory verdicts are backed by SQLite, with sanitized artifacts stored as separate private files.

- **Content-addressed.** Keys bind exact bytes, credential-derived scope, rules/carnet, sanitization settings, and worker/toolchain identity.
- **Complete results only.** Clean and rejected inspections can be reused. Sanitized entries require an existing artifact with a matching checksum; missing or corrupt artifacts trigger inspection.
- **Concurrent duplicates share work.** Identical jobs share a lock. If the first request is cancelled, a waiting request may restart inspection.
- **Bounded retention.** Defaults are 50,000 memory entries, 100,000 persistent entries, 1 GiB of artifacts, and seven-day idle retention. Cleanup runs on admission and every five minutes.
- **Live purge.** Invalidate memory and disk records and advance the cache generation, preventing older jobs from repopulating it. Already approved requests can finish.

```sh
preflight cache status --socket /run/preflight/control.sock
preflight cache purge --socket /run/preflight/control.sock
```

Memory and SQLite use entry limits; SQLite does not have a strict physical-byte quota. Rendering scratch space is separate from retained artifacts. Deletion is not forensic erasure from snapshots or backups.

Packaged builds supply the pinned toolchain identity. Development builds disable persistent verdict reuse unless `PREFLIGHT_TOOLCHAIN_ID` is supplied.

## Nix flake

The flake exposes the CLI as a package/app, the complete document-processing runtime, and the devenv shell as `devShells.default`. Package outputs target `x86_64-linux` and `aarch64-linux`.

Run without installing:

```sh
nix run github:ghuntley/preflight -- serve
```

Install into your profile:

```sh
nix profile install github:ghuntley/preflight
```

Use the development shell:

```sh
nix develop --no-pure-eval
cargo build --locked --bins
```

The devenv shell requires `--no-pure-eval` because it inspects the working directory. Package/app builds are pure. `devenv shell` and `devenv test` use the same [`devenv.nix`](devenv.nix).

### NixOS module

Add preflight to your flake inputs and import its module:

```nix
{
  inputs.preflight.url = "github:ghuntley/preflight";

  outputs = { nixpkgs, preflight, ... }: {
    nixosConfigurations.my-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        preflight.nixosModules.default
        {
          services.preflight = {
            enable = true;
            listenAddress = "127.0.0.1";
            port = 8081;
            upstream = "http://127.0.0.1:8080";
            mode = "redact";
            environmentFile = "/run/secrets/preflight.env";
          };
        }
      ];
    };
  };
}
```

The runtime environment file supplies credentials without putting them in the Nix store. Additional nonsecret TOML options go in `services.preflight.settings`.

The service uses a dynamic user, private cache/runtime directories, resource limits, and JSON logs to journald. It binds to localhost and leaves the firewall closed by default. The flake also exports `overlays.default`.

Validate the package and QEMU machine test:

```sh
nix build .#preflight
nix build .#checks.x86_64-linux.preflight-vm
```

The package builds from `Cargo.lock`. Hegel's bootstrap needs network access, so `nix build` skips `cargo test`; CI runs the full suite through devenv.

## Security

- Prompts, matched secrets, authorization values, original filenames, and OCR text are **never logged** by preflight. Generated errors contain static codes and opaque finding IDs; upstream response bodies stream through.
- Workers run without network access in Bubblewrap PID/mount/network namespaces, with CPU, address-space, file-size, and wall-clock limits. Native stderr is discarded.
- The worker executable is an internal interface: its stdout carries private extraction data to the parent. Use the proxy CLI for normal operation.
- Attachment retrieval uses separate credentials from inference. Arbitrary URLs never receive the underclass or file-API credential.
- Cache storage is private. Never commit credentials, caches, OCR output, or `.hegel` artifacts.

## Development

```sh
devenv test
devenv shell -- cargo bench --locked --bench inspection
```

`devenv test` runs formatting, clippy, unit tests, [Hegel](https://hegel.dev) properties, integration tests, differential fixtures, and Code Contracts syntax validation.

Testing covers several layers:

- **Unit tests** check exact rule behavior, supported provider fixtures, parsing, and cache bookkeeping.
- **Hegel properties** exercise redaction, JSON preservation, policy decisions, coordinate mapping, and cache invariants.
- **Integration tests** generate JPEGs, PNGs, rotated screenshots, text PDFs, scanned PDFs, and embedded attachments. They run actual native tools and check reconstruction, cache restart/purge, reload, and HTTP forwarding against a mock underclass.
- **Differential tests** compare GitHub detection semantics with Gitleaks using the same database.
- **NixOS tests** send generated image/PDF requests through the installed service to a Rust mock server.

Fixtures use synthetic credentials. The benchmark exercises benign 100 KiB and 1 MiB text inputs. Tests establish the covered HTTP paths; live provider accounts and universal harness compatibility are outside that verification scope.

Agent conventions and Code Contracts guidance are in [`AGENTS.md`](AGENTS.md). Architecture decisions live in [`docs/adr/`](docs/adr).

### Weekly rule updates

The [weekly workflow](.github/workflows/rules.yml) downloads the latest stable Gitleaks source archive, pins its commit and checksums, refreshes the database, runs validation and benchmarks, and rebuilds preflight. It also runs the NixOS VM test and uploads a Nix closure artifact with provenance.

When the snapshot changes, the job opens or updates a PR from `automation/gitleaks-rules` into `main`, then enables squash auto-merge. Normal CI runs on that PR, and GitHub merges it once main's requirements pass. Only the database, upstream license, and provenance manifest are committed. The workflow still rebuilds every week when there is no update. Deployment remains an operator action.

Repository setup:

1. Enable **Allow auto-merge** and **Allow squash merging** under Settings → General.
2. Protect `main` with required status checks **`test`** and **`build`** from the CI workflow, and enable **Require branches to be up to date before merging**. Required human reviews will still need a human; this automation does not bypass or supply approvals.
3. Create a fine-grained personal access token restricted to this repository with **Contents: read/write** and **Pull requests: read/write**. Store it as the Actions repository secret **`PREFLIGHT_UPDATE_TOKEN`**. Renew it before expiry.
4. Once this workflow is on `main`, use Actions → **Weekly rules rebuild** → **Run workflow** to exercise the setup.

The dedicated token allows PR and post-merge events to trigger CI. The built-in `GITHUB_TOKEN` generally suppresses those runs, so it is not used as a fallback. Its default repository permissions can remain read-only. The updater checks for its token and a protected main before starting. See [ADR 0003](docs/adr/0003-automatic-rules-update-merges.md).

Refresh a specific snapshot locally:

```sh
devenv shell -- cargo run --locked --bin preflight-update-rules -- v8.30.1
```

## License

[MIT](LICENSE). The vendored Gitleaks database retains its [upstream MIT license](vendor/gitleaks/LICENSE).

## Project layout

```text
src/
  main.rs                  CLI, configuration, approval gate, proxy, streaming
  scanner.rs               embedded rules, carnet, detection, text redaction
  document.rs              JSON traversal, nested arguments, source mapping
  resolver.rs              attachment acquisition and reference materialization
  attachments.rs           worker orchestration, inspection, reconstruction checks
  worker.rs                typed worker protocol and coordinate transforms
  cache.rs                 memory/SQLite verdicts, artifact storage, purge
  metrics.rs               aggregate counters and timing metrics
  bin/
    preflight-worker.rs    isolated native-tool adapters and artifact rebuilding
    preflight-update-rules.rs  release-pinned Gitleaks database updater
tests/
  properties.rs            Hegel properties and regression fixtures
  integration.rs           document and HTTP integration tests
  differential.rs          comparison with Gitleaks
  common/                  generated image/PDF fixtures
rules/                     explicit default rule profile
vendor/gitleaks/            upstream database, license, and provenance
nixos/                     service module and VM test
benches/                   text-inspection benchmark
```
