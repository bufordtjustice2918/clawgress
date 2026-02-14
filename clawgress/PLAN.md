# Clawgress Plan (Initial + Ongoing)

## Versioning Strategy

**Clawgress versions track VyOS base versions.**

| Clawgress | VyOS Base | Status |
|-----------|-----------|--------|
| 1.5.0 | 1.5 (current) | In Development |

- **Major.Minor** = VyOS base version (e.g., 1.5)
- **Patch** = Clawgress release (e.g., .0 = initial, .1 = first update)

This ensures users know exactly which VyOS codebase Clawgress is built on, and makes it easier to track upstream security patches and updates.

## Initial Build Effort (MVP)
**Estimated: 2–4 weeks** (1–2 engineers)

1) **VyOS base + build tooling** (3–4 days)
- fork VyOS 1.5, set up build pipeline for images
- base hardening
- version aligned with VyOS (Clawgress 1.5.0)

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
- add API endpoint for policy updates

5) **Observability + docs** (3–4 days)
- syslog structure
- dashboards later
- README + install docs

## Ongoing Maintenance
**Estimated: 1–2 days/month** for a small deployment

- **VyOS updates**: Track VyOS 1.5.x security patches, merge upstream changes
- **bind9 CVEs** and RPZ changes
- **Clawgress releases**: Bump patch version for fixes (1.5.1, 1.5.2, etc.)
- support for new allowlist categories
- improvements in logging + reporting

**Upgrade Path**:
- When VyOS releases 1.6, Clawgress will release 1.6.0
- Maintain 1.5.x branch for critical security fixes until 1.6 is stable

## Rebranding (Pending legal review)
- Full "VyOS" → "Clawgress" rebrand in code, CLI, docs, and artifacts
- **Do not use "VyOS" name/logo/branding**; clean rebrand is required
- Check artwork/marks files (e.g., `LICENSE.artwork`) for restrictions
- Preserve license notices and required attributions
- Complete only after legal review/approval

## Risks / Dependencies
- VyOS build pipeline stability
- bind9 packaging on VyOS
- UX around policy updates
- **VyOS version updates**: Must stay in lockstep with upstream for security

