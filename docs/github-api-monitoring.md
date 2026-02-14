# GitHub API Rate Limits - Clawgress Monitoring

## Current Token Limits (Free/Personal Account)

| Resource | Limit | Per | Notes |
|----------|-------|-----|-------|
| **core** | 5,000 | hour | Most API calls (GET repos, runs, etc.) |
| **search** | 30 | minute | Search API only |
| **graphql** | 5,000 | hour | GraphQL queries |
| **actions_runner_registration** | 10,000 | hour | Runner registration |

**Current usage:** 29/5000 core calls used (0.6%)

## Monitoring Cadence Recommendations

### For Build Monitoring

| Scenario | Cadence | API Calls/Hour | Safe? |
|----------|---------|----------------|-------|
| **Every 1 minute** | 60/hour | ~120 | ✅ Yes |
| **Every 5 minutes** | 12/hour | ~24 | ✅ Ideal |
| **Every 10 minutes** | 6/hour | ~12 | ✅ Very safe |
| **Every 30 seconds** | 120/hour | ~240 | ⚠️ Risky with multiple jobs |

### Recommended Setup for Clawgress

**Current cron: 5 minutes (12 checks/hour)**
- 1 call to get run status
- 1 call to get job details if running
- ~24 calls/hour total
- **Safety margin: 99.5% remaining** ✅

### Best Practices

1. **Use conditional checks**
   - Don't call API if last check was recent
   - Cache results for 30-60 seconds

2. **Backoff on completion**
   - Once build completes, wait longer before next check
   - Or delete cron job entirely on success

3. **Avoid parallel monitors**
   - Don't run multiple cron jobs checking same build
   - Consolidate into single monitor

4. **Use webhooks instead of polling** (ideal but requires server)
   - GitHub can POST to your server on build events
   - Zero API usage for monitoring

### Current Clawgress Setup Analysis

```
Cron: Every 5 minutes
API calls per check: ~2
API calls per hour: ~24
Daily usage: ~576 calls
Monthly usage: ~17,280 calls

vs 5,000/hour limit = 120,000/day
Safety margin: 99.5% ✅
```

### Recommended Changes

1. **Keep 5-minute cadence** — Safe and responsive
2. **Delete cron on success** — Save API calls
3. **Add backoff on failure** — Wait 10 min after fail before retry
4. **Batch operations** — Get run + jobs in single call if possible

### Emergency: If Rate Limited

```bash
# Check current status
curl -H "Authorization: Bearer $TOKEN" \
  https://api.github.com/rate_limit

# Response will show reset timestamp
```

**Wait until `reset` timestamp before resuming.**
