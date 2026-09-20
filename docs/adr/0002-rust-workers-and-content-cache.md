# 0002 — Rust workers, native tools, and versioned cache

## Status
Accepted

## Context
Attachment OCR is expensive and prompts repeatedly resend identical documents.
Native document tools have mature parsing support but need process isolation.

## Decision
All project-owned executable code is Rust, including the worker and updater.
Invoke native tools directly with argument arrays, never interpolated shells.
The worker has no provider credentials or network access. Extraction results are
private parent/worker protocol messages, never logging events. Nix pins tools.

Store complete verdicts in SQLite and memory, with reconstructed artifact files.
Bind cache keys to content, scope, full detection settings, and immutable toolchain
identity. Development without immutable toolchain identity does not reuse verdicts.
Purge increments generation before deletion; stale work cannot insert afterwards.

## Consequences
Tool failures reject inspection. Stateful disk caches require cleanup and exclusive
daemon ownership. Whole-cache and scope-selective purge invalidate generations.
Native CLI coverage is verified through generated integration fixtures. SIGHUP
reloads immutable runtime snapshots; changes to storage/listener settings require
a service restart.

The worker sandbox uses an empty `/proc` rather than mounting procfs. This avoids
exposing host process information and remains compatible with systemd's masked
kernel interfaces (`ProtectKernelTunables`). The PID namespace still guarantees
child-process teardown when the sandbox is killed.
