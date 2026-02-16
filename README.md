# Clawgress (mvpv2)

Clawgress is a VyOS-based egress policy appliance for agent and LLM workloads. It enforces allowlists with DNS RPZ + nftables, keeps policy in JSON, and exposes both CLI and REST management paths.

## MVP Scope

### MVPv1 (baseline)

- Service enable/disable via `service clawgress`
- Domain/IP/port allowlist policy compilation to `/config/clawgress/policy.json`
- DNS enforcement through bind9 RPZ
- Egress enforcement through nftables table `inet clawgress`
- Operational visibility commands:
  - `show clawgress status`
  - `show clawgress stats`
  - `show clawgress firewall`
  - `show clawgress rpz`
  - `show clawgress policy show`
  - `show clawgress policy apply`
  - `show clawgress policy import file <path>`

### MVPv2 (additions)

- Global time window policy (`policy.time_window`)
- Per-domain time windows (`policy.domain_time_windows`)
- Global egress rate limiting (`policy.limits.egress_kbps`)
- Per-host policy blocks (`policy.hosts.<name>`) with:
  - source CIDRs
  - host-scoped allowlists
  - host-scoped time windows
  - host/domain exfil caps (`bytes` per `second|minute|hour|day`)
- Telemetry command and API:
  - `show clawgress telemetry`
  - `POST /clawgress/telemetry`
- REST endpoints for write + health:
  - `POST /clawgress/policy`
  - `POST /clawgress/health`

## CLI Configuration Examples

### 1) MVPv1 baseline policy

```bash
configure
set service clawgress enable
set service clawgress policy domain api.openai.com label llm-provider
set service clawgress policy domain api.anthropic.com label llm-provider
set service clawgress policy ip 1.2.3.0/24
set service clawgress policy port 443
commit
save
exit
```

### 2) MVPv2 global + domain time windows and rate limit

```bash
configure
set service clawgress enable
set service clawgress policy domain api.openai.com label llm-provider
set service clawgress policy time-window day mon
set service clawgress policy time-window day tue
set service clawgress policy time-window start 09:00
set service clawgress policy time-window end 17:00
set service clawgress policy domain api.openai.com time-window day fri
set service clawgress policy domain api.openai.com time-window start 10:00
set service clawgress policy domain api.openai.com time-window end 11:00
set service clawgress policy rate-limit-kbps 8000
commit
save
exit
```

### 3) MVPv2 per-host policy and exfil cap

```bash
configure
set service clawgress enable
set service clawgress policy host agent-1 source 192.168.10.10/32
set service clawgress policy host agent-1 exfil domain api.openai.com bytes 1048576
set service clawgress policy host agent-1 exfil domain api.openai.com period hour
commit
save
exit
```

## Operational Commands

Run through VyOS op-mode:

```bash
show clawgress status
show clawgress stats
show clawgress telemetry
show clawgress firewall
show clawgress rpz
show clawgress policy show
show clawgress policy apply
show clawgress policy import file /tmp/policy.json
```

Direct utility command path is also available:

```bash
/usr/bin/clawgress status
/usr/bin/clawgress telemetry
/usr/bin/clawgress show --policy /config/clawgress/policy.json
/usr/bin/clawgress import --policy /tmp/policy.json
```

## Policy JSON (MVPv2)

```json
{
  "version": 1,
  "allow": {
    "domains": [
      "api.openai.com",
      "api.anthropic.com"
    ],
    "ips": [
      "1.2.3.0/24"
    ],
    "ports": [
      53,
      80,
      443
    ]
  },
  "labels": {
    "api.openai.com": "llm-provider",
    "api.anthropic.com": "llm-provider"
  },
  "time_window": {
    "days": [
      "mon",
      "tue"
    ],
    "start": "09:00",
    "end": "17:00"
  },
  "domain_time_windows": {
    "api.openai.com": {
      "days": [
        "fri"
      ],
      "start": "10:00",
      "end": "11:00"
    }
  },
  "limits": {
    "egress_kbps": 8000
  },
  "hosts": {
    "agent-1": {
      "sources": [
        "192.168.10.10/32"
      ],
      "allow": {
        "domains": [
          "api.openai.com"
        ],
        "ports": [
          443
        ]
      },
      "time_window": {
        "days": [
          "mon"
        ],
        "start": "08:00",
        "end": "18:00"
      },
      "domain_time_windows": {
        "api.openai.com": {
          "days": [
            "fri"
          ],
          "start": "10:00",
          "end": "11:00"
        }
      },
      "exfil": {
        "domains": {
          "api.openai.com": {
            "bytes": 1048576,
            "period": "hour"
          }
        }
      }
    }
  }
}
```

## REST API Examples

All endpoints use API key payload model (`key` required in body).

### Write/apply policy

```bash
curl -sS -X POST http://<vyos-host>/api/clawgress/policy \
  -H "Content-Type: application/json" \
  -d '{
    "key": "id_key",
    "policy": {
      "version": 1,
      "allow": {
        "domains": ["api.openai.com"],
        "ports": [443]
      },
      "labels": {
        "api.openai.com": "llm-provider"
      },
      "limits": {
        "egress_kbps": 4000
      }
    },
    "apply": true
  }'
```

### Health

```bash
curl -sS -X POST http://<vyos-host>/api/clawgress/health \
  -H "Content-Type: application/json" \
  -d '{"key":"id_key"}'
```

### Telemetry

```bash
curl -sS -X POST http://<vyos-host>/api/clawgress/telemetry \
  -H "Content-Type: application/json" \
  -d '{"key":"id_key"}'
```

## Notes

- Primary persisted policy path: `/config/clawgress/policy.json`
- bind9 RPZ + nftables are both part of enforcement; health/status should be checked after each policy update.
- In live ISO sessions, config warnings about non-persistence are expected until installed.

## License

Clawgress is based on VyOS and retains upstream copyright/license notices. See `LICENSE`, `LICENSE.GPL`, and `LICENSE.LGPL`.
