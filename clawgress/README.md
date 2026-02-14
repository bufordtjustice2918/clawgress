# Clawgress (VyOS Fork)

OpenClaw egress control appliance (VyOS‑based). DNS/RPZ allowlist + egress firewall + audit logging, configured from a single JSON policy.

## Distinctions
- **Agent‑focused egress control:** Purpose‑built for agentic workloads and LLM tooling, not a general‑purpose firewall.
  - General firewalls aren’t built around what agents should be allowed to talk to; Clawgress makes that explicit and auditable.
- **Policy‑JSON as source of truth:** Deterministic allowlists that are easy to version, review, and audit.
- **DNS RPZ + firewall enforcement:** Network‑edge enforcement outside the host even if a machine is compromised.
- **Clear deny‑reason mapping:** Policy labels map to loggable deny reasons for observability.
- **Appliance model:** VyOS‑based gateway for predictable, repeatable deployments.
