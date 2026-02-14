# Clawgress Positioning (1‑pager)

## What it is
Clawgress is a **purpose‑built agentic egress firewall**. It enforces a deterministic, auditable allowlist for AI agents using DNS RPZ + firewall rules at the network edge. Policy is managed by a single JSON source of truth and applied via a simple API or CLI.

## Why now
Agentic workflows expand the attack surface. Traditional firewalls and DNS filters are general‑purpose, not agent‑aware. Clawgress makes egress controls **explicit, testable, and reviewable** for LLM tools and integrations.

## Who it’s for
- AI labs and startups running agentic systems
- Security‑sensitive teams needing strict egress controls
- Infrastructure teams wanting deterministic allowlists and clear audit trails

## Core distinctions
- **Agent‑focused egress control** (not a generic firewall)
- **Policy‑JSON as source of truth** (versionable, reviewable, auditable)
- **DNS RPZ + firewall enforcement** at the network edge
- **Clear deny‑reason mapping** for observability
- **Appliance model** (repeatable, predictable deployments)

## How it works (high‑level)
1) You post a policy.json allowlist to Clawgress.
2) Clawgress generates RPZ zones and firewall rules.
3) DNS requests and egress traffic are allowed only for approved destinations.
4) Denied traffic is logged with a reason tag.

## Adoption path
1) **Turnkey appliance** (OVA/QCOW2/AMI) with 5‑minute setup
2) **Default allowlist bundle** for common LLM providers + tooling
3) **One‑command onboarding** (POST policy + health check)
4) **Proof of safety** via deny‑reason logs + audit trail
5) **Ops integrations** (CloudWatch, Terraform, dashboards)
6) **Case studies** highlighting reduced data‑exfil risk

## What it replaces or complements
- Complements traditional firewalls and DNS filters
- Provides deterministic, agent‑aware egress policies
- Acts as a network‑edge guard even if a host is compromised

## Future expansion
- Per‑host policies
- SNI/proxy mode
- Policy signing and approval workflows
- Alerting and dashboards

---

# Launch Checklist (v1)

## Product
- [ ] Release builds: OVA + QCOW2 + AMI
- [ ] Policy engine and API stable
- [ ] Default allowlist bundles
- [ ] Logging + deny‑reason mapping

## Docs
- [ ] Quickstart (5‑minute setup)
- [ ] Policy.json reference
- [ ] CLI + API examples
- [ ] AWS/GCP/Azure deployment guides

## Operations
- [ ] Telemetry/log shipping
- [ ] Upgrade path
- [ ] Support/feedback loop

## GTM
- [ ] Security‑first positioning
- [ ] Pilot customers identified
- [ ] Case study plan
