# 0004 — Scoped user-namespace permission on hosted runners

## Status
Accepted

## Context
The package build passes on GitHub while attachment integration tests fail at
worker startup. Ubuntu hosted runners restrict unprivileged user namespaces via
AppArmor. The Nix-store Bubblewrap executable is outside the paths covered by
distribution-provided executable profiles.

## Decision
Both CI and the weekly update workflow run a shared setup action after installing
devenv. It resolves the exact pinned Bubblewrap executable. When Ubuntu's
user-namespace restriction is active, it loads an AppArmor profile granting that
executable user-namespace permission, without disabling the global restriction.

The setup action then runs a small namespace probe with visible diagnostics.
Actual attachment tests continue to use their normal networkless sandbox.

## Consequences
The Ubuntu runner needs its existing sudo and AppArmor tooling for setup. Other
hosts with no such restriction need no profile change. Sandbox setup errors are
reported before test compilation rather than appearing as generic worker errors.
The runtime package and NixOS service isolation are unchanged.
