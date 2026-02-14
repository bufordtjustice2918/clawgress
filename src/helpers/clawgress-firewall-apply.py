#!/usr/bin/env python3
#
# Clawgress policy -> nftables egress/forced DNS rules
#
# Copyright VyOS maintainers and contributors <maintainers@vyos.io>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import json
import os
import ipaddress

from vyos.utils.file import makedir, write_file
from vyos.utils.process import call

POLICY_PATHS = [
    '/config/clawgress/policy.json',
    '/etc/clawgress/policy.json',
]

NFT_DIR = '/etc/nftables.d'
NFT_FILE = f'{NFT_DIR}/clawgress.nft'


def read_policy(path=None):
    if path:
        paths = [path]
    else:
        paths = POLICY_PATHS

    for candidate in paths:
        if os.path.isfile(candidate):
            with open(candidate, 'r', encoding='utf-8') as handle:
                return json.load(handle), candidate

    raise FileNotFoundError(
        f'No policy.json found in: {", ".join(paths)}'
    )


def normalize_ports(ports):
    cleaned = []
    for port in ports or []:
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            cleaned.append(port)
    return sorted(set(cleaned))


def normalize_ips(ips):
    v4 = []
    v6 = []
    for raw in ips or []:
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            v4.append(str(net))
        else:
            v6.append(str(net))
    return sorted(set(v4)), sorted(set(v6))


def render_nft(v4, v6, ports):
    port_set = ', '.join(str(p) for p in ports) if ports else ''
    v4_set = ', '.join(v4)
    v6_set = ', '.join(v6)

    lines = [
        'table inet clawgress {',
        '  chain prerouting {',
        '    type nat hook prerouting priority -100; policy accept;',
        '    udp dport 53 redirect to :53',
        '    tcp dport 53 redirect to :53',
        '  }',
        '  chain forward {',
        '    type filter hook forward priority 0; policy drop;',
        '    ct state established,related accept',
        '    udp dport 53 accept',
        '    tcp dport 53 accept',
    ]

    if v4_set and port_set:
        lines.append(f'    ip daddr {{ {v4_set} }} tcp dport {{ {port_set} }} accept')
        lines.append(f'    ip daddr {{ {v4_set} }} udp dport {{ {port_set} }} accept')
    elif v4_set:
        lines.append(f'    ip daddr {{ {v4_set} }} accept')

    if v6_set and port_set:
        lines.append(f'    ip6 daddr {{ {v6_set} }} tcp dport {{ {port_set} }} accept')
        lines.append(f'    ip6 daddr {{ {v6_set} }} udp dport {{ {port_set} }} accept')
    elif v6_set:
        lines.append(f'    ip6 daddr {{ {v6_set} }} accept')

    lines.extend([
        '    log prefix "clawgress-deny: " level info',
        '    drop',
        '  }',
        '}',
    ])

    return '\n'.join(lines) + '\n'


def apply_policy(policy_path=None):
    policy, policy_path = read_policy(policy_path)
    allow = policy.get('allow', {})
    ports = normalize_ports(allow.get('ports', [53, 80, 443]))
    v4, v6 = normalize_ips(allow.get('ips', []))

    makedir(NFT_DIR, user='root', group='root')
    write_file(NFT_FILE, render_nft(v4, v6, ports), user='root', group='root', mode=0o644)
    call(f'nft -f {NFT_FILE}')


def main():
    parser = argparse.ArgumentParser(description='Apply Clawgress policy to nftables')
    parser.add_argument('--policy', help='Path to policy.json (default: /config/clawgress/policy.json)')
    args = parser.parse_args()

    apply_policy(policy_path=args.policy)


if __name__ == '__main__':
    main()
