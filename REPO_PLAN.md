# Clawgress Repo Plan (vyos-1x fork)

## Alignment to MVPv1 (SPEC/PLAN)
This repo is the **core OS and services** layer. All bind9/RPZ, policy engine, CLI/API, forced DNS, firewall, and observability changes live here.

## Scope
- bind9 integration + RPZ generation
- Policy engine (policy.json) + CLI/API
- Forced DNS + egress firewall enforcement
- Logging + deny-reason mapping
- Defaults and configs shipped in image

## Current Status
- Policy engine + CLI/API + health endpoint: **done**
- Logging/deny-reason mapping: **in progress**
- Forced DNS + firewall: **queued**

## Next Actions
- Implement deny-reason mapping in RPZ logs
- Implement forced DNS defaults
- Implement egress firewall rules (53/80/443 allowlist, default deny)
- Update docs snippets in clawgress-documentation

## Dependencies
- `clawgress-build` for image build integration
- `clawgress-documentation` for user-facing docs
