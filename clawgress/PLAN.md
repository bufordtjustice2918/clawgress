# Clawgress Plan (Initial + Ongoing)

## Initial Build Effort (MVP)
**Estimated: 2–4 weeks** (1–2 engineers)

1) **VyOS base + build tooling** (3–4 days)
- fork VyOS, set up build pipeline for images
- base hardening

2) **bind9 integration + RPZ generation** (4–6 days)
- install bind9
- RPZ zone generation from policy.json
- logging + deny reason mapping

3) **Egress firewall + DNS enforcement** (4–6 days)
- default deny rules
- allowlist for 53/80/443
- forced DNS

4) **Policy engine + CLI** (3–5 days)
- parse policy.json
- generate bind9 + firewall config
- apply + reload

5) **Observability + docs** (3–4 days)
- syslog structure
- dashboards later
- README + install docs

## Ongoing Maintenance
**Estimated: 1–2 days/month** for a small deployment

- VyOS updates + security patches
- bind9 CVEs and RPZ changes
- support for new allowlist categories
- improvements in logging + reporting

## Risks / Dependencies
- VyOS build pipeline stability
- bind9 packaging on VyOS
- UX around policy updates

