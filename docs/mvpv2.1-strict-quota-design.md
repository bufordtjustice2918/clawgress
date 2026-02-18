# MVPv2.1 Strict Quota Design (Future Mode)

## Current State
- Current exfil behavior is `rate_limit` enforced via nftables `limit rate`.
- This is not a durable quota ledger and does not persist counters across restarts.

## Proposed Mode
- Add future `strict_quota` mode to enforce hard byte caps per window and fail closed.

## Control Model
- Policy shape (future):
  - `policy.hosts.<agent>.exfil.domains.<fqdn>.bytes`
  - `policy.hosts.<agent>.exfil.domains.<fqdn>.period` (`second|minute|hour|day`)
  - `policy.hosts.<agent>.exfil.mode` (`rate_limit|strict_quota`)

## Runtime Components
- Counter store:
  - Local durable DB under `/var/lib/clawgress/quotas.db`.
  - Key: `agent + source_ip + domain + window_start`.
  - Values: `bytes_used`, `packets_used`, `last_seen`.
- Window manager:
  - Deterministic window boundary rollover for each period type.
  - Garbage collection for expired windows.
- Enforcement hook:
  - Before allow decision, check `bytes_used + packet_size <= quota`.
  - If exceeded: deny and log reason `strict_quota_exceeded`.

## Failure Behavior
- Default fail-close in strict mode:
  - If quota DB unavailable or corrupted, deny matching strict-quota flows.
  - Emit health warning in `show clawgress status` and telemetry.
- Optional future policy toggle for fail-open (not in MVPv2.1).

## Telemetry/Observability
- Add fields:
  - `exfil_mode`, `quota_bytes`, `bytes_used`, `bytes_remaining`, `quota_window_start`.
- Add counters:
  - denies by reason `strict_quota_exceeded`.
- Export schema should preserve strict-quota reasons for SIEM correlation.

## Rollout Plan
1. Keep MVPv2.1 default at `rate_limit`.
2. Build strict-quota in shadow mode (observe-only) with telemetry.
3. Enable strict-quota enforcement behind explicit policy flag.
