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
import hashlib
import re

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


def normalize_rate_limit_kbps(rate_kbps):
    if rate_kbps is None:
        return None
    try:
        rate_kbps = int(rate_kbps)
    except (TypeError, ValueError):
        return None
    if rate_kbps <= 0:
        return None
    return rate_kbps


def normalize_domains(domains):
    cleaned = []
    for domain in domains or []:
        if not domain:
            continue
        domain = domain.strip().strip('.').lower()
        if not domain:
            continue
        cleaned.append(domain)
    return sorted(set(cleaned))


def normalize_sni_domains(domains):
    normalized = []
    for domain in normalize_domains(domains):
        if domain.startswith('*.'):
            normalized.append(domain)
            normalized.append(domain[2:])
            continue
        normalized.append(domain)
        if '.' in domain:
            normalized.append(f'*.{domain}')
    return sorted(set(normalized))


def sanitize_chain_name(name):
    safe = re.sub(r'[^A-Za-z0-9_]', '_', name)
    if not safe:
        safe = 'host'
    return f'clawgress_host_{safe}'


def resolve_proxy_settings(proxy, allow):
    proxy = proxy or {}
    proxy_mode = (proxy.get('mode') or '').lower()
    sni_domains = []
    if proxy_mode == 'sni-allowlist':
        domain_source = proxy.get('domains') or allow.get('domains', [])
        sni_domains = normalize_sni_domains(domain_source)
    return proxy_mode, sni_domains


def render_allow_rules(lines, v4, v6, ports, sni_domains, limit_clause):
    port_set = ', '.join(str(p) for p in ports) if ports else ''
    v4_set = ', '.join(v4)
    v6_set = ', '.join(v6)
    sni_set = ', '.join(f'"{domain}"' for domain in (sni_domains or []))

    if sni_set:
        lines.append(f'    tcp dport 443 tls sni {{ {sni_set} }}{limit_clause} accept')

    if v4_set and port_set:
        lines.append(f'    ip daddr {{ {v4_set} }} tcp dport {{ {port_set} }}{limit_clause} accept')
        lines.append(f'    ip daddr {{ {v4_set} }} udp dport {{ {port_set} }}{limit_clause} accept')
    elif v4_set:
        lines.append(f'    ip daddr {{ {v4_set} }}{limit_clause} accept')

    if v6_set and port_set:
        lines.append(f'    ip6 daddr {{ {v6_set} }} tcp dport {{ {port_set} }}{limit_clause} accept')
        lines.append(f'    ip6 daddr {{ {v6_set} }} udp dport {{ {port_set} }}{limit_clause} accept')
    elif v6_set:
        lines.append(f'    ip6 daddr {{ {v6_set} }}{limit_clause} accept')


def render_nft(v4, v6, ports, policy_hash='', rate_limit_kbps=None, sni_domains=None, host_policies=None):
    reason = f'clawgress-deny: reason=egress-default-deny policy={policy_hash} '

    limit_clause = ''
    if rate_limit_kbps:
        rate_kbytes = max(1, rate_limit_kbps // 8)
        limit_clause = f' limit rate {rate_kbytes} kbytes/second'

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

    for host in host_policies or []:
        if host.get('source_v4'):
            src_v4 = ', '.join(host['source_v4'])
            lines.append(f'    ip saddr {{ {src_v4} }} jump {host["chain"]}')
        if host.get('source_v6'):
            src_v6 = ', '.join(host['source_v6'])
            lines.append(f'    ip6 saddr {{ {src_v6} }} jump {host["chain"]}')

    render_allow_rules(lines, v4, v6, ports, sni_domains, limit_clause)

    lines.extend([
        f'    log prefix "{reason}" level info',
        '    drop',
        '  }',
    ])

    for host in host_policies or []:
        host_limit_clause = ''
        if host.get('rate_limit_kbps'):
            rate_kbytes = max(1, host['rate_limit_kbps'] // 8)
            host_limit_clause = f' limit rate {rate_kbytes} kbytes/second'

        host_reason = (
            f'clawgress-deny: reason=egress-host-deny host={host["name"]} '
            f'policy={policy_hash} '
        )
        lines.append(f'  chain {host["chain"]} {{')
        lines.append('    ct state established,related accept')
        lines.append('    udp dport 53 accept')
        lines.append('    tcp dport 53 accept')
        render_allow_rules(lines, host['allow_v4'], host['allow_v6'], host['ports'], host['sni_domains'], host_limit_clause)
        lines.append(f'    log prefix "{host_reason}" level info')
        lines.append('    drop')
        lines.append('  }')

    lines.append('}')

    return '\n'.join(lines) + '\n'


def apply_policy(policy_path=None):
    policy, policy_path = read_policy(policy_path)
    allow = policy.get('allow', {})
    ports = normalize_ports(allow.get('ports', [53, 80, 443]))
    v4, v6 = normalize_ips(allow.get('ips', []))

    proxy = policy.get('proxy', {}) or {}
    proxy_mode, sni_domains = resolve_proxy_settings(proxy, allow)
    if proxy_mode == 'sni-allowlist':
        ports = [port for port in ports if port != 443]

    limits = policy.get('limits', {})
    rate_limit_kbps = normalize_rate_limit_kbps(limits.get('egress_kbps'))

    host_policies = []
    hosts = policy.get('hosts', {}) or {}
    if isinstance(hosts, dict):
        host_items = hosts.items()
    elif isinstance(hosts, list):
        host_items = [(host.get('name', f'host-{idx}'), host) for idx, host in enumerate(hosts, start=1)]
    else:
        host_items = []

    for host_name, host_policy in host_items:
        if not isinstance(host_policy, dict):
            continue
        sources = host_policy.get('sources') or host_policy.get('source_ips') or host_policy.get('source-ips')
        v4_sources, v6_sources = normalize_ips(sources or [])
        if not v4_sources and not v6_sources:
            continue

        host_allow = host_policy.get('allow', {}) or {}
        merged_allow = {
            'domains': host_allow.get('domains', allow.get('domains', [])),
            'ips': host_allow.get('ips', allow.get('ips', [])),
            'ports': host_allow.get('ports', allow.get('ports', [53, 80, 443])),
        }
        host_ports = normalize_ports(merged_allow.get('ports', [53, 80, 443]))
        host_v4, host_v6 = normalize_ips(merged_allow.get('ips', []))

        host_proxy = host_policy.get('proxy', {}) or {}
        host_proxy_mode, host_sni_domains = resolve_proxy_settings(host_proxy, merged_allow)
        if host_proxy_mode == 'sni-allowlist':
            host_ports = [port for port in host_ports if port != 443]

        host_limits = host_policy.get('limits', {}) or {}
        host_rate_limit_kbps = normalize_rate_limit_kbps(
            host_limits.get('egress_kbps', limits.get('egress_kbps'))
        )

        host_policies.append({
            'name': host_name,
            'chain': sanitize_chain_name(host_name),
            'source_v4': v4_sources,
            'source_v6': v6_sources,
            'allow_v4': host_v4,
            'allow_v6': host_v6,
            'ports': host_ports,
            'sni_domains': host_sni_domains,
            'rate_limit_kbps': host_rate_limit_kbps,
        })

    policy_hash = hashlib.sha256(json.dumps(policy, sort_keys=True).encode('utf-8')).hexdigest()[:12]

    makedir(NFT_DIR, user='root', group='root')
    write_file(
        NFT_FILE,
        render_nft(v4, v6, ports, policy_hash, rate_limit_kbps, sni_domains, host_policies),
        user='root',
        group='root',
        mode=0o644,
    )
    call(f'nft -f {NFT_FILE}')


def main():
    parser = argparse.ArgumentParser(description='Apply Clawgress policy to nftables')
    parser.add_argument('--policy', help='Path to policy.json (default: /config/clawgress/policy.json)')
    args = parser.parse_args()

    apply_policy(policy_path=args.policy)


if __name__ == '__main__':
    main()
