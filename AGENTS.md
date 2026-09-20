# Preflight

Use the `code-contracts` skill for every code change and code review. Follow its
contract discovery, writing, and enforcement procedures before submitting commits
or pull requests. The format is documented at https://code-contracts.cc/.

- Read `CONTRACTS` and declaration `/// @cc` comments before edits.
- Contract owner is `ghuntley`; do not add notify unless explicitly requested.
- Validate with `cc-check format`; review semantic compliance manually.
- Pure synchronous core; async I/O at the edges.
- `devenv test` runs formatting, clippy, unit, Hegel, and integration tests.
- Never commit credentials, caches, OCR outputs, or `.hegel` artifacts.
- Record nontrivial decisions in `docs/adr`.

## Static typing (required)

- Project-owned executable code, workers, and update utilities MUST be Rust.
  Reuse native document tools through typed Rust subprocess adapters; do not add
  Python or another scripting language for application glue.
- All programming languages used in this project MUST use static types.
- New and generated code MUST follow the same static-typing requirements as
  handwritten code; generators MUST emit statically typed code.
- Use explicit API parameter and return types and typed models for structured
  data. Compiler and static-type checks are mandatory in `devenv test` and CI.
- Do not bypass type checking with blanket ignores or untyped replacement code.
- Rust changes MUST pass the compiler and clippy. Other programming languages
  require an appropriate compiler or static type checker before adoption.
