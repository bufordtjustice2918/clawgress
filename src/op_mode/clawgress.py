#!/usr/bin/env python3
#
# Clawgress policy operations (op-mode)
#
# Copyright VyOS maintainers and contributors <maintainers@vyos.io>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import calendar
import json
import os
import re
import time
import hashlib
import ipaddress

from vyos.utils.file import makedir, write_file
from vyos.utils.process import call, cmd, rc_cmd

POLICY_DIR = '/config/clawgress'
POLICY_PATH = f'{POLICY_DIR}/policy.json'
APPLY_BIN = '/usr/bin/clawgress-policy-apply'
FIREWALL_APPLY_BIN = '/usr/bin/clawgress-firewall-apply'
LABELS_FILE = '/etc/bind/rpz/labels.json'
TELEMETRY_DIR = '/var/lib/clawgress'
TELEMETRY_PATH = f'{TELEMETRY_DIR}/telemetry.json'
TELEMETRY_EXPORT_PATH = f'{TELEMETRY_DIR}/telemetry-export.json'
TELEMETRY_HISTORY_PATH = f'{TELEMETRY_DIR}/telemetry-history.ndjson'
APPLY_STATE_PATH = f'{TELEMETRY_DIR}/apply-state.json'
RPZ_ALLOW_PATH = '/etc/bind/rpz/allow.rpz'
RPZ_DENY_PATH = '/etc/bind/rpz/default-deny.rpz'
TELEMETRY_SCHEMA_VERSION = 2
TELEMETRY_HISTORY_MAX_ENTRIES = 200
TELEMETRY_HISTORY_TTL_SECONDS = 7 * 24 * 3600
TELEMETRY_WINDOWS = {
    '1m': '1 minute ago',
    '5m': '5 minutes ago',
    '1h': '1 hour ago',
    '24h': '24 hours ago',
}


def _load_policy(path: str) -> dict:
    with open(path, 'r', encoding='utf-8') as handle:
        return json.load(handle)


def _write_policy(policy: dict, path: str) -> None:
    payload = json.dumps(policy, indent=2, sort_keys=True)
    write_file(path, payload + '\n', user='root', group='root', mode=0o644)


def _write_apply_state(state: dict) -> None:
    makedir(TELEMETRY_DIR, user='root', group='root')
    write_file(APPLY_STATE_PATH, json.dumps(state, indent=2, sort_keys=True) + '\n',
               user='root', group='root', mode=0o644)


def _load_apply_state() -> dict | None:
    try:
        if os.path.isfile(APPLY_STATE_PATH):
            with open(APPLY_STATE_PATH, 'r', encoding='utf-8') as handle:
                return json.load(handle)
    except Exception:
        pass
    return None


def apply_policy(policy_path: str | None) -> None:
    policy_hash = None
    try:
        effective_path = policy_path or POLICY_PATH
        if os.path.isfile(effective_path):
            policy_hash = _policy_hash(_load_policy(effective_path))
    except Exception:
        policy_hash = None

    if policy_path:
        rc = call(f'{APPLY_BIN} --policy {policy_path}')
        if rc != 0:
            _write_apply_state({
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'success': False,
                'error': f'{APPLY_BIN} failed (rc={rc})',
            })
            raise RuntimeError(f'{APPLY_BIN} failed with rc={rc}')
        rc = call(f'{FIREWALL_APPLY_BIN} --policy {policy_path}')
        if rc != 0:
            _write_apply_state({
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'success': False,
                'error': f'{FIREWALL_APPLY_BIN} failed (rc={rc})',
            })
            raise RuntimeError(f'{FIREWALL_APPLY_BIN} failed with rc={rc}')
    else:
        rc = call(f'{APPLY_BIN}')
        if rc != 0:
            _write_apply_state({
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'success': False,
                'error': f'{APPLY_BIN} failed (rc={rc})',
            })
            raise RuntimeError(f'{APPLY_BIN} failed with rc={rc}')
        rc = call(f'{FIREWALL_APPLY_BIN}')
        if rc != 0:
            _write_apply_state({
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'success': False,
                'error': f'{FIREWALL_APPLY_BIN} failed (rc={rc})',
            })
            raise RuntimeError(f'{FIREWALL_APPLY_BIN} failed with rc={rc}')

    rc = call('systemctl enable --now named || systemctl restart bind9 || systemctl restart named')
    if rc != 0:
        _write_apply_state({
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'success': False,
            'error': f'bind9 enable/start failed (rc={rc})',
        })
        raise RuntimeError(f'bind9 enable/start failed with rc={rc}')

    expected_backend = None
    policy = _load_policy_safe()
    if isinstance(policy, dict):
        proxy_cfg = policy.get('proxy') or {}
        if isinstance(proxy_cfg, dict):
            mode = proxy_cfg.get('mode')
            backend = proxy_cfg.get('backend')
            if mode == 'sni-allowlist' and backend == 'haproxy':
                expected_backend = backend

    effective_state = _verify_runtime_state(policy_hash, expected_proxy_backend=expected_backend)
    success = not effective_state['failed_checks']
    _write_apply_state({
        'timestamp': effective_state['checked_at'],
        'success': success,
        'policy_hash': policy_hash,
        'verification': effective_state,
    })
    if not success:
        failed_checks = ', '.join(effective_state['failed_checks'])
        raise RuntimeError(f'Clawgress apply verification failed: {failed_checks}')


def _verify_runtime_state(policy_hash: str | None, expected_proxy_backend: str | None = None) -> dict:
    bind9_active = False
    try:
        output = cmd('systemctl is-active bind9')
        bind9_active = output.strip() == 'active'
    except Exception:
        bind9_active = False

    nft_output = ''
    nftables_active = False
    try:
        nft_output = cmd('nft list table inet clawgress 2>/dev/null || echo ""')
        nftables_active = 'table inet clawgress' in nft_output
    except Exception:
        nftables_active = False

    rc, _ = rc_cmd('named-checkconf -z /etc/bind/named.conf >/dev/null 2>&1')
    bind_config_valid = rc == 0

    checks = {
        'bind9_active': bind9_active,
        'bind_config_valid': bind_config_valid,
        'rpz_allow_present': os.path.isfile(RPZ_ALLOW_PATH),
        'rpz_default_deny_present': os.path.isfile(RPZ_DENY_PATH),
        'nft_table_present': nftables_active,
        'nft_forward_policy_drop': 'chain forward' in nft_output and 'policy drop;' in nft_output,
        'nft_dns_redirect_present': 'udp dport 53 redirect to :53' in nft_output and 'tcp dport 53 redirect to :53' in nft_output,
        'nft_policy_hash_present': bool(policy_hash) and (f'policy={policy_hash}' in nft_output),
    }
    if expected_proxy_backend == 'haproxy':
        rc, output = rc_cmd('systemctl is-active haproxy 2>/dev/null || true')
        checks['haproxy_active'] = rc == 0 and output.strip() == 'active'
    failed_checks = sorted([name for name, ok in checks.items() if not ok])
    return {
        'checked_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'policy_hash': policy_hash,
        'checks': checks,
        'failed_checks': failed_checks,
    }


def import_policy(source_path: str) -> None:
    policy = _load_policy(source_path)
    makedir(POLICY_DIR, user='root', group='root')
    _write_policy(policy, POLICY_PATH)
    apply_policy(POLICY_PATH)


def show_policy(path: str | None) -> None:
    policy_path = path or POLICY_PATH
    policy = _load_policy(policy_path)
    print(json.dumps(policy, indent=2, sort_keys=True))


def show_status() -> None:
    policy_exists = os.path.isfile(POLICY_PATH)
    policy = _load_policy_safe()
    policy_hash = _policy_hash(policy)
    bind9_active = False
    try:
        output = cmd('systemctl is-active bind9')
        bind9_active = output.strip() == 'active'
    except Exception:
        bind9_active = False

    nftables_active = False
    try:
        output = cmd('nft list table inet clawgress 2>/dev/null || echo "not found"')
        nftables_active = 'clawgress' in output and 'not found' not in output
    except Exception:
        nftables_active = False

    # Get deny statistics from syslog
    deny_count = 0
    recent_denies = []
    try:
        rc, output = rc_cmd('journalctl -u bind9 --since "1 hour ago" -o cat 2>/dev/null | grep -c "rpz" || echo 0')
        deny_count = int(output.strip()) if rc == 0 else 0
        
        rc, output = rc_cmd('journalctl -u bind9 --since "1 hour ago" -o cat 2>/dev/null | grep "rpz" | tail -10')
        if rc == 0 and output:
            recent_denies = output.strip().split('\n')[-5:]
    except Exception:
        pass

    apply_state = _load_apply_state()
    expected_backend = None
    if isinstance(policy, dict):
        proxy_cfg = policy.get('proxy') or {}
        if isinstance(proxy_cfg, dict):
            mode = proxy_cfg.get('mode')
            backend = proxy_cfg.get('backend')
            if mode == 'sni-allowlist' and backend == 'haproxy':
                expected_backend = backend
    effective_state = _verify_runtime_state(policy_hash, expected_proxy_backend=expected_backend)
    proxy_summary = _policy_proxy_summary(policy)

    status = {
        'policy_path': POLICY_PATH,
        'policy_present': policy_exists,
        'policy_hash': policy_hash,
        'policy_proxy': proxy_summary,
        'exfil_enforcement': 'rate_limit',
        'bind9_active': bind9_active,
        'nftables_active': nftables_active,
        'apply_state_path': APPLY_STATE_PATH,
        'last_apply': apply_state,
        'effective_state': effective_state,
        'stats': {
            'denies_last_hour': deny_count,
            'recent_denies': recent_denies,
        }
    }
    print(json.dumps(status, indent=2))


def _load_labels() -> dict:
    try:
        if os.path.isfile(LABELS_FILE):
            with open(LABELS_FILE, 'r', encoding='utf-8') as handle:
                return json.load(handle)
    except Exception:
        pass
    return {}


def show_stats() -> None:
    """Show detailed deny statistics"""
    stats = {
        'time_periods': {}
    }

    # Try to get stats from journalctl
    for period, since in [('1h', '1 hour ago'), ('24h', '24 hours ago'), ('7d', '7 days ago')]:
        try:
            rc, output = rc_cmd(f'journalctl -u bind9 --since "{since}" -o cat 2>/dev/null | grep -c "rpz" || echo 0')
            count = int(output.strip()) if rc == 0 else 0
            stats['time_periods'][period] = count
        except Exception:
            stats['time_periods'][period] = None

    # Get top blocked domains (if we can parse the logs)
    try:
        labels = _load_labels()
        rc, output = rc_cmd('journalctl -u bind9 --since "24 hours ago" -o cat 2>/dev/null | grep "rpz" | grep -oE "query:\s*[^\s]+" | sort | uniq -c | sort -rn | head -10')
        if rc == 0 and output:
            top_blocked = []
            for line in output.strip().split('\n'):
                parts = line.strip().split()
                if len(parts) >= 2:
                    domain = parts[1]
                    reason = labels.get(domain, 'default-deny')
                    top_blocked.append({'count': parts[0], 'domain': domain, 'reason': reason})
            stats['top_blocked_24h'] = top_blocked
    except Exception:
        stats['top_blocked_24h'] = []

    print(json.dumps(stats, indent=2))


def _count_journal(pattern: str, since: str, unit: str | None = None) -> int:
    unit_clause = f'-u {unit}' if unit else ''
    rc, output = rc_cmd(
        f'journalctl {unit_clause} --since "{since}" -o cat 2>/dev/null | grep -c "{pattern}" || echo 0'
    )
    if rc != 0:
        return 0
    try:
        return int(output.strip())
    except (TypeError, ValueError):
        return 0


def _sum_nft_counters() -> dict:
    rc, output = rc_cmd('nft list table inet clawgress 2>/dev/null || echo ""')
    if rc != 0 or not output:
        return {'packets': 0, 'bytes': 0}
    packets = 0
    bytes_total = 0
    for match in re.finditer(r'counter packets (\d+) bytes (\d+)', output):
        packets += int(match.group(1))
        bytes_total += int(match.group(2))
    return {'packets': packets, 'bytes': bytes_total}


def _sum_nft_host_counters() -> dict:
    rc, output = rc_cmd('nft list table inet clawgress 2>/dev/null || echo ""')
    if rc != 0 or not output:
        return {}

    host_usage = {}
    chain_pattern = re.compile(r'chain (clawgress_host_[A-Za-z0-9_]+)\s*\{(.*?)\n\s*\}', re.S)
    for chain_name, body in chain_pattern.findall(output):
        host_name = chain_name.replace('clawgress_host_', '')
        packets = 0
        bytes_total = 0
        for pkt, num in re.findall(r'counter packets (\d+) bytes (\d+)', body):
            packets += int(pkt)
            bytes_total += int(num)
        host_usage[host_name] = {'packets': packets, 'bytes': bytes_total}
    return host_usage


def _load_policy_safe() -> dict | None:
    try:
        if os.path.isfile(POLICY_PATH):
            return _load_policy(POLICY_PATH)
    except Exception:
        pass
    return None


def _policy_hash(policy: dict | None) -> str | None:
    if not policy:
        return None
    try:
        payload = json.dumps(policy, sort_keys=True).encode('utf-8')
        return hashlib.sha256(payload).hexdigest()[:12]
    except Exception:
        return None


def _build_agent_source_map(policy: dict | None) -> list:
    mapping = []
    if not isinstance(policy, dict):
        return mapping
    hosts = policy.get('hosts') or {}
    if not isinstance(hosts, dict):
        return mapping
    for agent, cfg in hosts.items():
        if not isinstance(cfg, dict):
            continue
        for source in cfg.get('sources') or []:
            try:
                mapping.append((agent, ipaddress.ip_network(source, strict=False)))
            except Exception:
                continue
    return mapping


def _resolve_agent_for_source(source_ip: str, source_map: list) -> str:
    if not source_ip:
        return 'unmapped'
    try:
        ip_obj = ipaddress.ip_address(source_ip)
    except Exception:
        return 'unmapped'
    for agent, network in source_map:
        if ip_obj in network:
            return agent
    return 'unmapped'


def _parse_rpz_domain_counts(since: str = '1 hour ago') -> dict:
    rc, output = rc_cmd(
        f'journalctl -u bind9 --since "{since}" -o cat 2>/dev/null | grep "rpz" || true'
    )
    if rc != 0 or not output:
        return {}
    counts = {}
    for line in output.splitlines():
        match = re.search(r'query:\s*([A-Za-z0-9_.-]+)', line)
        if not match:
            continue
        domain = match.group(1).strip().strip('.').lower()
        if not domain:
            continue
        counts[domain] = counts.get(domain, 0) + 1
    return counts


def _parse_haproxy_sni_events(since: str = '1 hour ago') -> list:
    rc, output = rc_cmd(
        f'journalctl -u haproxy --since "{since}" -o cat 2>/dev/null | grep "clawgress_sni" || true'
    )
    if rc != 0 or not output:
        return []
    events = []
    for line in output.splitlines():
        src_match = re.search(r'src=([0-9a-fA-F:.]+)', line)
        sni_match = re.search(r'sni=([A-Za-z0-9_.-]+)', line)
        if not src_match and not sni_match:
            continue
        events.append({
            'source_ip': src_match.group(1) if src_match else 'unknown',
            'domain': sni_match.group(1).strip('.').lower() if sni_match else 'unknown',
        })
    return events


def _parse_egress_deny_reasons(since: str = '1 hour ago') -> dict:
    rc, output = rc_cmd(
        f'journalctl --since "{since}" -o cat 2>/dev/null | grep "clawgress-deny" || true'
    )
    if rc != 0 or not output:
        return {}
    counts = {}
    for line in output.splitlines():
        match = re.search(r'reason=([A-Za-z0-9_.:-]+)', line)
        reason = match.group(1) if match else 'unknown'
        counts[reason] = counts.get(reason, 0) + 1
    return counts


def _top_n_counts(counts: dict, key_name: str, n: int = 10) -> list:
    ordered = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return [{key_name: key, 'count': count} for key, count in ordered[:n]]


def _extract_proxy_allow_domains(policy: dict | None) -> set[str]:
    if not isinstance(policy, dict):
        return set()
    proxy = policy.get('proxy') or {}
    if not isinstance(proxy, dict):
        return set()
    domains = proxy.get('domains') or []
    if not isinstance(domains, list):
        return set()
    return {str(item).strip().strip('.').lower() for item in domains if str(item).strip()}


def _collect_grouped_window(policy: dict | None, window_key: str, since: str) -> dict:
    source_map = _build_agent_source_map(policy)
    host_usage = _sum_nft_host_counters() if window_key == '1h' else {}
    rpz_counts = _parse_rpz_domain_counts(since)
    haproxy_events = _parse_haproxy_sni_events(since)
    deny_reasons = _parse_egress_deny_reasons(since)
    allow_domains = _extract_proxy_allow_domains(policy)

    agents = {}
    domains = {}
    proxy_denied_domain_counts = {}

    for host_name, usage in host_usage.items():
        entry = agents.setdefault(host_name, {
            'bytes': 0,
            'packets': 0,
            'domains': {},
            'requests': 0,
            'allows': 0,
            'denies': 0,
            'source_ips': {},
        })
        entry['bytes'] += usage.get('bytes', 0)
        entry['packets'] += usage.get('packets', 0)

    for event in haproxy_events:
        agent = _resolve_agent_for_source(event.get('source_ip', ''), source_map)
        source_ip = event.get('source_ip', 'unknown')
        domain = event.get('domain', 'unknown') or 'unknown'
        is_allowed = domain in allow_domains if allow_domains else False
        action = 'allow' if is_allowed else 'deny'
        if action == 'deny':
            proxy_denied_domain_counts[domain] = proxy_denied_domain_counts.get(domain, 0) + 1

        agent_entry = agents.setdefault(agent, {
            'bytes': 0,
            'packets': 0,
            'domains': {},
            'requests': 0,
            'allows': 0,
            'denies': 0,
            'source_ips': {},
        })
        agent_entry['requests'] += 1
        if action == 'allow':
            agent_entry['allows'] += 1
        else:
            agent_entry['denies'] += 1
        agent_entry['domains'][domain] = agent_entry['domains'].get(domain, 0) + 1
        agent_entry['source_ips'][source_ip] = agent_entry['source_ips'].get(source_ip, 0) + 1

        domain_entry = domains.setdefault(domain, {'requests': 0, 'agents': {}, 'allows': 0, 'denies': 0})
        domain_entry['requests'] += 1
        domain_entry['agents'][agent] = domain_entry['agents'].get(agent, 0) + 1
        if action == 'allow':
            domain_entry['allows'] += 1
        else:
            domain_entry['denies'] += 1

    for domain, count in rpz_counts.items():
        domain_entry = domains.setdefault(domain, {'requests': 0, 'agents': {}, 'allows': 0, 'denies': 0})
        domain_entry['denies_rpz'] = count

    denies = {
        'rpz_by_domain': rpz_counts,
        'proxy_sni_denied_by_domain': proxy_denied_domain_counts,
        'egress_by_reason': deny_reasons,
        'rpz_total': sum(rpz_counts.values()),
        'proxy_sni_denied_total': sum(proxy_denied_domain_counts.values()),
        'egress_total': sum(deny_reasons.values()),
    }

    return {
        'window': window_key,
        'agents': agents,
        'domains': domains,
        'denies': denies,
        'top_n': {
            'domains_by_requests': _top_n_counts({d: info.get('requests', 0) for d, info in domains.items()}, 'domain'),
            'agents_by_requests': _top_n_counts({a: info.get('requests', 0) for a, info in agents.items()}, 'agent'),
            'denied_domains': _top_n_counts(proxy_denied_domain_counts, 'domain'),
        },
    }


def _collect_grouped_telemetry(policy: dict | None) -> dict:
    windows = {
        key: _collect_grouped_window(policy, key, since)
        for key, since in TELEMETRY_WINDOWS.items()
    }
    one_hour = windows.get('1h', {})
    return {
        'telemetry_schema_version': TELEMETRY_SCHEMA_VERSION,
        'window': '1h',
        'windows': windows,
        'agents': one_hour.get('agents', {}),
        'domains': one_hour.get('domains', {}),
        'denies': one_hour.get('denies', {}),
        'top_n': one_hour.get('top_n', {}),
    }


def _policy_proxy_summary(policy: dict | None) -> dict:
    summary = {
        'mode': 'disabled',
        'backend': 'none',
        'domains': [],
        'host_overrides': 0,
    }
    if not isinstance(policy, dict):
        return summary

    proxy = policy.get('proxy') or {}
    if isinstance(proxy, dict):
        mode = proxy.get('mode')
        backend = proxy.get('backend')
        domains = proxy.get('domains') or []
        if mode in ('disabled', 'sni-allowlist'):
            summary['mode'] = mode
        if backend in ('none', 'haproxy'):
            summary['backend'] = backend
        if isinstance(domains, list):
            summary['domains'] = domains

    hosts = policy.get('hosts') or {}
    if isinstance(hosts, dict):
        for host_cfg in hosts.values():
            if not isinstance(host_cfg, dict):
                continue
            host_proxy = host_cfg.get('proxy')
            if isinstance(host_proxy, dict) and host_proxy:
                summary['host_overrides'] += 1

    return summary


def collect_telemetry() -> dict:
    usage = _sum_nft_counters()

    denies = {
        '1h': {
            'dns_rpz': _count_journal('rpz', '1 hour ago', unit='bind9'),
            'egress': _count_journal('clawgress-deny', '1 hour ago'),
        },
        '24h': {
            'dns_rpz': _count_journal('rpz', '24 hours ago', unit='bind9'),
            'egress': _count_journal('clawgress-deny', '24 hours ago'),
        },
    }

    policy = _load_policy_safe()
    apply_state = _load_apply_state()
    expected_backend = None
    if isinstance(policy, dict):
        proxy_cfg = policy.get('proxy') or {}
        if isinstance(proxy_cfg, dict):
            mode = proxy_cfg.get('mode')
            backend = proxy_cfg.get('backend')
            if mode == 'sni-allowlist' and backend == 'haproxy':
                expected_backend = backend
    effective_state = _verify_runtime_state(_policy_hash(policy), expected_proxy_backend=expected_backend)
    proxy_summary = _policy_proxy_summary(policy)
    telemetry = {
        'telemetry_schema_version': TELEMETRY_SCHEMA_VERSION,
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'usage': usage,
        'denies': denies,
        'policy': {
            'path': POLICY_PATH,
            'present': bool(policy),
            'hash': _policy_hash(policy),
            'version': policy.get('version') if policy else None,
            'proxy': proxy_summary,
            'exfil_enforcement': 'rate_limit',
        },
        'apply': {
            'state_path': APPLY_STATE_PATH,
            'last_apply': apply_state,
            'effective_state': effective_state,
        },
        'cache': {
            'status': 'unavailable'
        },
    }
    return telemetry


def _safe_write_telemetry_outputs(telemetry: dict) -> None:
    makedir(TELEMETRY_DIR, user='root', group='root')
    write_file(TELEMETRY_PATH, json.dumps(telemetry, indent=2) + '\n', user='root', group='root', mode=0o664)
    write_file(
        TELEMETRY_HISTORY_PATH,
        json.dumps({'generated_at': telemetry.get('generated_at'), 'grouped': telemetry.get('grouped', {})}) + '\n',
        user='root',
        group='root',
        mode=0o664,
        append=True,
    )

    now_ts = int(time.time())
    cutoff = now_ts - TELEMETRY_HISTORY_TTL_SECONDS
    pruned = []
    try:
        with open(TELEMETRY_HISTORY_PATH, 'r', encoding='utf-8') as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except Exception:
                    continue
                generated_at = item.get('generated_at')
                if not generated_at:
                    continue
                try:
                    item_ts = int(calendar.timegm(time.strptime(generated_at, '%Y-%m-%dT%H:%M:%SZ')))
                except Exception:
                    continue
                if item_ts >= cutoff:
                    pruned.append(item)
    except FileNotFoundError:
        pruned = []

    if len(pruned) > TELEMETRY_HISTORY_MAX_ENTRIES:
        pruned = pruned[-TELEMETRY_HISTORY_MAX_ENTRIES:]

    if pruned:
        payload = ''.join(json.dumps(item) + '\n' for item in pruned)
        write_file(TELEMETRY_HISTORY_PATH, payload, user='root', group='root', mode=0o664)


def _redact_payload(value):
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if key in {'source_ip', 'source_ips', 'dest_ip', 'agent_id'}:
                redacted[key] = '<redacted>'
            else:
                redacted[key] = _redact_payload(item)
        return redacted
    if isinstance(value, list):
        return [_redact_payload(item) for item in value]
    return value


def _export_payload(telemetry: dict, window: str, redact: bool = True) -> dict:
    grouped = telemetry.get('grouped', {})
    selected = grouped.get('windows', {}).get(window, grouped.get('windows', {}).get('1h', {}))
    payload = {
        'telemetry_schema_version': TELEMETRY_SCHEMA_VERSION,
        'exported_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'window': window,
        'policy_hash': telemetry.get('policy', {}).get('hash'),
        'backend_mode': telemetry.get('policy', {}).get('proxy', {}).get('backend', 'none'),
        'exfil_enforcement': telemetry.get('policy', {}).get('exfil_enforcement', 'rate_limit'),
        'agents': selected.get('agents', {}),
        'domains': selected.get('domains', {}),
        'denies': selected.get('denies', {}),
        'top_n': selected.get('top_n', {}),
    }
    if redact:
        payload = _redact_payload(payload)
    write_file(TELEMETRY_EXPORT_PATH, json.dumps(payload, indent=2) + '\n', user='root', group='root', mode=0o664)
    return payload


def show_telemetry(view: str | None = None, target: str | None = None, window: str = '1h', redact: bool = True) -> None:
    telemetry = collect_telemetry()
    grouped = _collect_grouped_telemetry(_load_policy_safe())
    telemetry['grouped'] = grouped
    selected = grouped.get('windows', {}).get(window, grouped.get('windows', {}).get('1h', {}))
    telemetry_storage = {'status': 'ok'}
    try:
        _safe_write_telemetry_outputs(telemetry)
    except Exception as exc:
        telemetry_storage = {'status': 'degraded', 'reason': str(exc)}
    telemetry['storage'] = telemetry_storage

    if view == 'export':
        print(json.dumps(_export_payload(telemetry, window=window, redact=redact), indent=2))
        return
    if view == 'agents':
        print(json.dumps({'telemetry_schema_version': TELEMETRY_SCHEMA_VERSION, 'window': window, 'agents': selected.get('agents', {})}, indent=2))
        return
    if view == 'domains':
        print(json.dumps({'telemetry_schema_version': TELEMETRY_SCHEMA_VERSION, 'window': window, 'domains': selected.get('domains', {})}, indent=2))
        return
    if view == 'agent':
        agent = target or ''
        print(json.dumps({'telemetry_schema_version': TELEMETRY_SCHEMA_VERSION, 'window': window, 'agent': agent, 'data': selected.get('agents', {}).get(agent, {})}, indent=2))
        return
    if view == 'domain':
        domain = (target or '').strip().strip('.').lower()
        print(json.dumps({'telemetry_schema_version': TELEMETRY_SCHEMA_VERSION, 'window': window, 'domain': domain, 'data': selected.get('domains', {}).get(domain, {})}, indent=2))
        return
    if view == 'denies':
        print(json.dumps({'telemetry_schema_version': TELEMETRY_SCHEMA_VERSION, 'window': window, 'denies': selected.get('denies', {}), 'top_n': selected.get('top_n', {})}, indent=2))
        return
    print(json.dumps(telemetry, indent=2))


def show_firewall() -> None:
    rc, output = rc_cmd('nft list table inet clawgress 2>/dev/null || echo "Table not found"')
    print(output)


def show_rpz() -> None:
    rc, output = rc_cmd('cat /etc/bind/rpz/allow.rpz 2>/dev/null || echo "RPZ not configured"')
    print(output)


def main() -> None:
    parser = argparse.ArgumentParser(description='Clawgress policy operations')
    subparsers = parser.add_subparsers(dest='command', required=True)

    apply_parser = subparsers.add_parser('apply', help='Apply policy to bind9 RPZ')
    apply_parser.add_argument('--policy', help='Path to policy.json')

    import_parser = subparsers.add_parser('import', help='Import policy.json to /config and apply')
    import_parser.add_argument('--policy', required=True, help='Path to policy.json')

    show_parser = subparsers.add_parser('show', help='Show policy.json')
    show_parser.add_argument('--policy', help='Path to policy.json')

    subparsers.add_parser('status', help='Show Clawgress status')

    subparsers.add_parser('firewall', help='Show nftables firewall rules')

    subparsers.add_parser('rpz', help='Show bind9 RPZ zone')

    subparsers.add_parser('stats', help='Show deny statistics')

    telemetry_parser = subparsers.add_parser('telemetry', help='Show telemetry snapshot')
    telemetry_parser.add_argument(
        'view',
        nargs='?',
        choices=['agents', 'domains', 'agent', 'domain', 'denies', 'export'],
        help='Optional grouped telemetry view',
    )
    telemetry_parser.add_argument(
        'target',
        nargs='?',
        help='Target for "agent" or "domain" views',
    )
    telemetry_parser.add_argument(
        '--window',
        choices=list(TELEMETRY_WINDOWS.keys()),
        default='1h',
        help='Telemetry time window for grouped views',
    )
    telemetry_parser.add_argument(
        '--no-redact',
        action='store_true',
        help='Disable redaction in telemetry export view',
    )

    args = parser.parse_args()

    if args.command == 'apply':
        apply_policy(args.policy)
        return

    if args.command == 'import':
        import_policy(args.policy)
        return

    if args.command == 'show':
        show_policy(args.policy)
        return

    if args.command == 'status':
        show_status()
        return

    if args.command == 'firewall':
        show_firewall()
        return

    if args.command == 'rpz':
        show_rpz()
        return

    if args.command == 'stats':
        show_stats()
        return

    if args.command == 'telemetry':
        show_telemetry(
            getattr(args, 'view', None),
            getattr(args, 'target', None),
            getattr(args, 'window', '1h'),
            not getattr(args, 'no_redact', False),
        )
        return


if __name__ == '__main__':
    main()
