# 0005 — One request identity across preflight and underclass

## Status
Accepted

## Context
Preflight minted an inspection ID but did not propagate it to underclass.
Underclass's routing logs therefore could not be joined to preflight's findings.

## Decision
Use `x-request-id` as the sole wire correlation header and `request_id` as the log
field in both services. Preflight mints a UUIDv4 at ingress, replacing client IDs,
and propagates it after hop-by-hop header stripping. Underclass accepts a single
hyphenated RFC4122 UUIDv4, normalizes it, and otherwise generates a fresh ID.

Middleware assigns identity before authentication, admission, and routing, and
echoes it on every handled response, including errors and blocked requests.
Preflight's existing `x-preflight-request-id` header is removed with no alias.
No request IDs are derived from secrets, content hashes, or session identifiers.

## Consequences
An operator can search both proxies and underclass's request history with one ID.
Underclass retries retain that ID. IDs are diagnostic metadata, not authorization
or proof that a request passed inspection. Invalid/duplicate input IDs are never
logged as correlation fields. Provider-generated IDs cannot replace this identity.
