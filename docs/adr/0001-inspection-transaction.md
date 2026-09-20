# 0001 — Structured request-wide inspection

## Status
Accepted

## Context
Preflight fronts underclass's HTTP inference endpoints. Text and binary content
must be inspected before inference starts, without corrupting tool protocols.

## Decision
Use Rust/Axum with a synchronous detection core, local isolated document tools,
immutable rule profiles, content-addressed complete-result caching, and bounded
request-wide inspection. Preserve original bytes for unchanged requests. Supported
images and PDFs are reconstructed and reinspected; findings without an approved
replacement fail closed. Unknown attachment references fail closed. Advisory
reports without rewriting.

## Consequences
OCR adds first-token latency and remains imperfect. Supported coverage is explicit.
No inferred claim of universal attachment coverage or absolute OCR accuracy.
