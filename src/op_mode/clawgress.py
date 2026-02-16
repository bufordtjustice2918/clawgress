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
import json
import os
import re
import time
import hashlib

from vyos.utils.file import makedir, write_file
from vyos.utils.process import call, cmd, rc_cmd

POLICY_DIR = '/config/clawgress'
POLICY_PATH = f'{POLICY_DIR}/policy.json'
APPLY_BIN = '/usr/bin/clawgress-policy-apply'
FIREWALL_APPLY_BIN = '/usr/bin/clawgress-firewall-apply'
LABELS_FILE = '/etc/bind/rpz/labels.json'
TELEMETRY_DIR = '/var/lib/clawgress'
TELEMETRY_PATH = f'{TELEMETRY_DIR}/telemetry.json'
APPLY_STATE_PATH = f'{TELEMETRY_DIR}/apply-state.json'
RPZ_ALLOW_PATH = '/etc/bind/rpz/allow.rpz'
RPZ_DENY_PATH = '/etc/bind/rpz/default-deny.rpz'


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

    rc = call('systemctl enable --now bind9')
    if rc != 0:
        _write_apply_state({
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'success': False,
            'error': f'bind9 enable/start failed (rc={rc})',
        })
        raise RuntimeError(f'bind9 enable/start failed with rc={rc}')

    effective_state = _verify_runtime_state(policy_hash)
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


def _verify_runtime_state(policy_hash: str | None) -> dict:
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
    effective_state = _verify_runtime_state(policy_hash)

    status = {
        'policy_path': POLICY_PATH,
        'policy_present': policy_exists,
        'policy_hash': policy_hash,
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
    effective_state = _verify_runtime_state(_policy_hash(policy))
    telemetry = {
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'usage': usage,
        'denies': denies,
        'policy': {
            'path': POLICY_PATH,
            'present': bool(policy),
            'hash': _policy_hash(policy),
            'version': policy.get('version') if policy else None,
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


def show_telemetry() -> None:
    telemetry = collect_telemetry()
    makedir(TELEMETRY_DIR, user='root', group='root')
    write_file(TELEMETRY_PATH, json.dumps(telemetry, indent=2) + '\n', user='root', group='root', mode=0o644)
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

    subparsers.add_parser('telemetry', help='Show telemetry snapshot')

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
        show_telemetry()
        return


if __name__ == '__main__':
    main()
