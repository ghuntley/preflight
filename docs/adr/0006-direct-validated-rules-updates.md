# 0006 — Direct validated rules updates using GITHUB_TOKEN

## Status
Accepted; supersedes ADR 0003.

## Context
The repository owner enabled GitHub Actions write permissions and chose direct
updates to an unprotected main branch. A separate PAT and pull-request auto-merge
are no longer required.

## Decision
The weekly/manual workflow checks out main, downloads the latest stable Gitleaks
source, and completes all test, benchmark, package, VM, and artifact gates before
staging only the database, upstream license, and provenance manifest.

If those files changed, fetch main and require it to equal the tested base. Commit
with ghuntley@ghuntley.com as the repository-local Git email, then push normally.
Do not rebase or force-push over concurrent changes. An unchanged snapshot still
gets a full validation/rebuild but no empty commit.

Grant GITHUB_TOKEN contents:write and actions:write. Explicitly dispatch CI after
a successful push because token-generated push events ordinarily suppress CI.
Compress the Nix closure while exporting to reduce hosted-runner disk use.

## Consequences
No PAT, PR, or protected-branch prerequisite is needed. A concurrent update to
main causes the push phase to fail so a later run validates the new base. The
workflow cannot silently apply tested rule changes to untested application code.
