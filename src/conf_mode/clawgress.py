#!/usr/bin/env python3
#
# Clawgress configuration script (conf_mode)
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

import json
import os

from sys import exit

from vyos.config import Config
from vyos.configdict import node_changed
from vyos.utils.file import makedir, write_file
from vyos.utils.process import call
from vyos import ConfigError
from vyos import airbag

airbag.enable()

POLICY_DIR = '/config/clawgress'
POLICY_PATH = f'{POLICY_DIR}/policy.json'
APPLY_BIN = '/usr/bin/clawgress-policy-apply'
FIREWALL_APPLY_BIN = '/usr/bin/clawgress-firewall-apply'


def build_time_window(window_config):
    if not isinstance(window_config, dict):
        return None
    days = window_config.get('day') or window_config.get('days') or []
    if isinstance(days, str):
        days = [days]
    start = window_config.get('start')
    end = window_config.get('end')
    if not start or not end:
        return None
    payload = {
        'start': str(start),
        'end': str(end),
    }
    if days:
        payload['days'] = list(days)
    return payload


def _as_values(value):
    if value is None:
        return []
    if isinstance(value, dict):
        return list(value.keys())
    if isinstance(value, list):
        return value
    return [value]


def get_config(config=None):
    if config is None:
        config = Config()

    base = ['service', 'clawgress']
    clawgress = config.get_config_dict(base, key_mangling=('-', '_'),
                                        get_first_key=True)

    if not clawgress:
        return None

    return clawgress


def verify(clawgress):
    if not clawgress:
        return

    # Verify at least one domain is configured if service is enabled
    if 'enable' in clawgress:
        policy = clawgress.get('policy', {})
        domains = policy.get('domain', {})
        if not domains:
            raise ConfigError('At least one domain must be configured when Clawgress is enabled')


def generate(clawgress):
    if not clawgress:
        # Service disabled - clean up if needed
        return

    # Build policy.json from VyOS configuration
    policy = {
        'version': 1,
        'allow': {
            'domains': [],
            'ips': [],
            'ports': [],
        },
        'labels': {},
    }

    # Process domains with labels
    policy_config = clawgress.get('policy', {})

    time_window = build_time_window(policy_config.get('time_window') or {})
    if time_window:
        policy['time_window'] = time_window

    domain_time_windows = {}
    domains = policy_config.get('domain', {})
    for domain, domain_config in domains.items():
        policy['allow']['domains'].append(domain)
        if 'label' in domain_config:
            policy['labels'][domain] = domain_config['label']
        window = build_time_window(domain_config.get('time_window') or {})
        if window:
            domain_time_windows[domain] = window

    if domain_time_windows:
        policy['domain_time_windows'] = domain_time_windows

    # Process IPs
    ips = policy_config.get('ip')
    for ip in _as_values(ips):
        policy['allow']['ips'].append(ip)

    # Process ports (default to 53, 80, 443 if not specified)
    ports = policy_config.get('port')
    port_values = _as_values(ports)
    if port_values:
        policy['allow']['ports'] = [int(p) for p in port_values]
    else:
        policy['allow']['ports'] = [53, 80, 443]

    hosts_config = policy_config.get('host', {})
    if hosts_config:
        policy['hosts'] = {}
        for host_name, host_config in hosts_config.items():
            if not isinstance(host_config, dict):
                continue
            sources = host_config.get('source') or host_config.get('sources')
            if not sources:
                continue
            if isinstance(sources, str):
                sources = [sources]
            host_entry = {
                'sources': list(sources),
            }

            exfil = host_config.get('exfil', {}) or {}
            domain_caps = {}
            domains_config = exfil.get('domain', {}) or {}
            for domain, cap_config in domains_config.items():
                if not isinstance(cap_config, dict):
                    continue
                bytes_value = cap_config.get('bytes')
                period = cap_config.get('period')
                try:
                    bytes_value = int(bytes_value)
                except (TypeError, ValueError):
                    continue
                if bytes_value <= 0 or not period:
                    continue
                domain_caps[domain] = {
                    'bytes': bytes_value,
                    'period': period,
                }

            if domain_caps:
                host_entry['exfil'] = {
                    'domains': domain_caps,
                }

            policy['hosts'][host_name] = host_entry

    # Optional rate limits
    rate_limit_kbps = policy_config.get('rate_limit_kbps')
    if rate_limit_kbps is not None:
        try:
            rate_limit_kbps = int(rate_limit_kbps)
        except (TypeError, ValueError):
            rate_limit_kbps = None
        if rate_limit_kbps and rate_limit_kbps > 0:
            policy.setdefault('limits', {})['egress_kbps'] = rate_limit_kbps

    # Write policy.json
    makedir(POLICY_DIR, user='root', group='root')
    payload = json.dumps(policy, indent=2, sort_keys=True) + '\n'
    write_file(POLICY_PATH, payload, user='root', group='root', mode=0o644)


def apply(clawgress):
    if not clawgress or 'enable' not in clawgress:
        # Service disabled - stop bind9 if running
        call('systemctl stop bind9 2>/dev/null || true')
        call('nft delete table inet clawgress 2>/dev/null || true')
        return

    # Apply policy to bind9 and nftables
    call(f'{APPLY_BIN}')
    call(f'{FIREWALL_APPLY_BIN}')

    # Ensure bind9 is running
    call('systemctl enable --now bind9')


if __name__ == '__main__':
    try:
        c = get_config()
        verify(c)
        generate(c)
        apply(c)
    except ConfigError as e:
        print(e)
        exit(1)
