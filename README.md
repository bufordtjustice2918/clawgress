# Clawgress

**OpenClaw egress control appliance** — A VyOS-based network gateway that enforces egress allowlists using DNS RPZ + firewall rules, with clear logging and a single JSON policy source of truth.

## Overview

Clawgress is purpose-built for agentic workloads and LLM tooling deployments that need zero-trust egress control. Instead of trying to retrofit general-purpose firewalls for agent workloads, Clawgress makes egress policies explicit, auditable, and enforceable at the network edge.

## Key Features

- **DNS RPZ + Firewall Enforcement**: Block unwanted egress at the DNS layer with nftables fallback
- **Policy-JSON as Source of Truth**: Deterministic allowlists that are easy to version, review, and audit
- **Clear Deny-Reason Mapping**: Policy labels map to loggable deny reasons for observability
- **VyOS-based Appliance**: Predictable, repeatable deployments with familiar CLI
- **API + CLI Management**: Configure via REST API or VyOS-style CLI commands

## Quick Start

```bash
# Install Clawgress (after booting the ISO)
set service clawgress enable
set service clawgress policy domain api.openai.com label llm-provider
set service clawgress policy domain api.anthropic.com label llm-provider
set service clawgress policy port 443
commit
```

## Policy Format

```json
{
  "version": 1,
  "allow": {
    "domains": [
      "api.openai.com",
      "api.anthropic.com"
    ],
    "ips": ["1.2.3.0/24"],
    "ports": [53, 80, 443]
  },
  "labels": {
    "api.openai.com": "llm-provider",
    "api.anthropic.com": "llm-provider"
  },
  "proxy": {
    "mode": "sni-allowlist",
    "domains": ["api.openai.com", "api.anthropic.com"]
  },
  "hosts": {
    "agent-1": {
      "sources": ["192.168.10.10/32"],
      "allow": {
        "domains": ["api.openai.com"],
        "ports": [443]
      },
      "limits": {
        "egress_kbps": 2000
      }
    }
  }
}
```

### Proxy/SNI allowlist mode

Set `proxy.mode` to `sni-allowlist` to allow outbound TLS only when the ClientHello SNI matches the allowlist. By default this reuses `allow.domains` (or `proxy.domains` when provided) and removes port 443 from the IP-based allowlist.

### Per-host policies

Define `hosts` to apply host-scoped allowlists, proxy settings, and limits based on source IPs. Hosts bypass the global allowlist and drop any traffic that is not explicitly permitted by their host policy.

## API Usage

```bash
# Submit policy via API
curl -X POST https://clawgress/api/clawgress/policy \
  -H "Content-Type: application/json" \
  -d '{
    "key": "your-api-key",
    "policy": {
      "version": 1,
      "allow": {
        "domains": ["api.openai.com"],
        "ports": [443]
      }
    },
    "apply": true
  }'

# Check health
curl -X POST https://clawgress/api/clawgress/health \
  -H "Content-Type: application/json" \
  -d '{"key": "your-api-key"}'
```

## CLI Commands

```bash
# Show status
clawgress status

# Show deny statistics
clawgress stats

# Show firewall rules
clawgress firewall

# Show RPZ zone
clawgress rpz

# Apply custom policy
clawgress policy import file /tmp/my-policy.json
```

## Architecture

```
┌─────────────────────────────────────────┐
│           Client Traffic                │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  Clawgress Gateway (bind9 + nftables)  │
│  • DNS RPZ allowlist enforcement        │
│  • Forced DNS redirection               │
│  • Egress firewall rules                │
│  • Structured logging                   │
└──────────────┬──────────────────────────┘
               │
       Allowed ▼
┌─────────────────────────────────────────┐
│         External Services               │
│    (api.openai.com, etc.)               │
└─────────────────────────────────────────┘
```

## Project Structure

```
clawgress/
├── data/                    # Jinja2 templates
├── interface-definitions/   # CLI command definitions
├── op-mode-definitions/     # Operational commands
├── python/                  # Python libraries
├── src/
│   ├── conf_mode/          # Configuration scripts
│   ├── op_mode/            # Operational scripts
│   ├── helpers/            # Policy + firewall helpers
│   └── services/api/       # HTTP API
└── smoketest/              # Integration tests
```

## Building

```bash
# Clone and build ISO
git clone https://github.com/bufordtjustice2918/clawgress.git
cd clawgress
make iso

# Or use Docker
docker run -v $(pwd):/vyos vyos/vyos-build:current \
  ./build-vyos-image generic --version clawgress
```

## License

Clawgress is based on VyOS and retains all original VyOS copyright notices and licenses. See LICENSE and LICENSE.artwork for details.

## Acknowledgments

Clawgress is a fork of [VyOS](https://vyos.io), the open-source network operating system. We are grateful to the VyOS maintainers and contributors for their excellent work.
