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

from vyos.utils.file import makedir, write_file
from vyos.utils.process import call, cmd, rc_cmd

POLICY_DIR = '/config/clawgress'
POLICY_PATH = f'{POLICY_DIR}/policy.json'
APPLY_BIN = '/usr/bin/clawgress-policy-apply'
FIREWALL_APPLY_BIN = '/usr/bin/clawgress-firewall-apply'
LABELS_FILE = '/etc/bind/rpz/labels.json'


def _load_policy(path: str) -> dict:
    with open(path, 'r', encoding='utf-8') as handle:
        return json.load(handle)


def _write_policy(policy: dict, path: str) -> None:
    payload = json.dumps(policy, indent=2, sort_keys=True)
    write_file(path, payload + '\n', user='root', group='root', mode=0o644)


def apply_policy(policy_path: str | None) -> None:
    if policy_path:
        call(f'{APPLY_BIN} --policy {policy_path}')
        call(f'{FIREWALL_APPLY_BIN} --policy {policy_path}')
    else:
        call(f'{APPLY_BIN}')
        call(f'{FIREWALL_APPLY_BIN}')


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

    status = {
        'policy_path': POLICY_PATH,
        'policy_present': policy_exists,
        'bind9_active': bind9_active,
        'nftables_active': nftables_active,
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


if __name__ == '__main__':
    main()
