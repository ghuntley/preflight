# 0003 — Validated rules PRs with automatic merging

## Status
Superseded by [0006](0006-direct-validated-rules-updates.md).

## Context
The weekly job rebuilt preflight with fresh rules but left the repository's
vendored snapshot unchanged. Nix users following main therefore did not receive
the refreshed rules when updating their flake input.

## Decision
Check out main, refresh the stable Gitleaks snapshot, and finish all validation,
benchmark, package, and NixOS VM gates. Then create or update a single PR from
`automation/gitleaks-rules`, committing only the three vendored upstream files.
Request squash auto-merge with the PR's exact head SHA. Existing main protection
and required checks govern the merge; the workflow cannot bypass them.

Use a dedicated fine-grained PAT in `PREFLIGHT_UPDATE_TOKEN` with Contents and
Pull requests read/write access to this repository. Events created using the
built-in GITHUB_TOKEN ordinarily do not start additional workflows; the dedicated
token permits ordinary PR and post-merge CI to run.

Update commits use ghuntley@ghuntley.com for author and committer. The merge request
also specifies that squash-author email. GitHub controls its own merge-committer
identity.

## Consequences
Main must be protected with required CI jobs `test` and `build`, and branches must
be up to date before merging. Auto-merge and squash merging must be enabled.
Required human reviews would still require human action, so an unattended update
policy must account for that. No protection bypass or automatic approval is added.
The workflow refuses to start without its token or a protected main branch.

Concurrent refresh jobs are serialized. No upstream change produces no new PR,
while the weekly recompilation still runs. Merged rules become available through
normal Git/Nix updates; running services are not redeployed by the workflow.
