# Clawgress Spec (Draft)

## Goal
Provide a VyOS‑based appliance that enforces **egress allowlists** for OpenClaw deployments using DNS RPZ + firewall rules, with clear logging and a single JSON policy source of truth.

## Key Decisions
- **Base distro:** VyOS
- **DNS:** **bind9** (not dnsmasq)
- **Policy format:** `policy.json` (supports large allowlists)
- **Targets:** OpenClaw clusters needing zero‑trust egress control

## MVP (v1)
1. **Appliance**
   - VyOS VM image distribution (OVA/QCOW2)
   - Default mgmt access (SSH) with hardened baseline

2. **DNS & RPZ**
   - bind9 installed
   - RPZ policy derived from `policy.json` allowlist
   - Forced DNS (clients must use Clawgress)
   - Logging of DNS blocks + reason

3. **Egress Firewall**
   - Allow only domains/IPs resolved via allowlist
   - Default deny with logged reason
   - Basic TCP/UDP rules for ports 80/443 + DNS

4. **Policy Engine**
   - `policy.json` contains:
     - Allowlist domains
     - Optional IP ranges
     - Allowed ports
     - Labels for reason tags
   - CLI command to import/update policy and regenerate bind9 + firewall
   - **API endpoint** `POST /clawgress/policy` to submit `policy.json` and trigger reload

5. **Observability**
   - Syslog / structured log for allow/deny
   - Deny reason metadata
   - Health endpoint/CLI status

## v2 (Expansion)
- Proxy mode (SNI allowlist)
- Per‑host policies (grouping clients)
- Agent telemetry (usage, denied domains, cache hits)
- mTLS between gateways/agents
- Rate limiting + connection shaping
- Policy signing + change approval workflow
- Alerting on policy violations
- Security dashboards (deny spikes, top blocked domains)
- Time‑based policy windows
- Data exfiltration caps (payload size limits)

## policy.json (Draft)
```json
{
  "version": 1,
  "allow": {
    "domains": [
      "api.openai.com",
      "api.anthropic.com",
      "api.openrouter.ai"
    ],
    "ips": ["1.2.3.0/24"],
    "ports": [53, 80, 443]
  },
  "labels": {
    "api.openai.com": "llm-provider",
    "api.anthropic.com": "llm-provider"
  }
}
```

## VyOS Integration Notes
- Use VyOS templates/CLI to manage bind9 + firewall config.
- Package bind9 and create service wrapper.
- Provide `clawgress` CLI wrapper for policy updates.

